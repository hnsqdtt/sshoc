from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

import paramiko

from . import __version__
from .config import (
    config_from_dict,
    default_user_config_path,
    load_config,
    resolve_config_path_info,
)
from .host_keys import (
    HostKeyInfo,
    add_known_host,
    ensure_known_host,
    format_host_id,
    known_hosts_entries,
    scan_host_key,
)
from .jsonrpc import (
    JSONRPCInvalidRequest,
    JSONRPCParseError,
    JSONRPCMethodNotFound,
    _jsonrpc_error,
    safe_call,
    write_message,
)
from .ssh_client import AsyncTask, build_client


class _ServerState:
    """Mutable runtime state shared across the MCP message loop."""

    def __init__(self, cfg_path: str | None) -> None:
        self.cfg_path = cfg_path
        self._next_task_id: int = 0
        self._tasks: dict[str, AsyncTask] = {}
        self._tasks_lock = threading.Lock()

    def create_task(self, profile: str, command: str) -> AsyncTask:
        with self._tasks_lock:
            self._next_task_id += 1
            tid = str(self._next_task_id)
            task = AsyncTask(task_id=tid, profile=profile, command=command)
            self._tasks[tid] = task
            return task

    def get_task(self, task_id: str) -> AsyncTask | None:
        with self._tasks_lock:
            return self._tasks.get(task_id)


# Tools that work without a config file.
_NO_CONFIG_TOOLS = frozenset({"ssh.init_config", "ssh.scan_host_key", "ssh.task_status", "ssh.task_kill"})


LATEST_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS: list[str] = ["2024-11-05", "2025-03-26", "2025-06-18", LATEST_PROTOCOL_VERSION]


def _tool_error(
    *,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    suggested_fixes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if details:
        err["details"] = details
    if suggested_fixes:
        err["suggestedFixes"] = suggested_fixes
    structured = {"error": err}
    # Slim text for LLM: just code + message + suggested tool names.
    parts = [f"ERROR {code}: {message}"]
    if suggested_fixes:
        tools = ", ".join(f.get("tool", "?") for f in suggested_fixes)
        parts.append(f"suggested: {tools}")
    return {
        "content": _result_text_block("\n".join(parts)),
        "structuredContent": structured,
        "isError": True,
    }


def _server_from_profile(cfg, profile: str) -> tuple[str, int, str | None]:
    srv = cfg.get_server(profile)
    return srv.host, srv.port, srv.proxy_command


def _tool_list() -> list[dict[str, Any]]:
    return [
        {
            "name": "ssh.init_config",
            "description": (
                "Create sshoc.config.json so the MCP server can connect to SSH hosts. "
                "Call this first if other tools return CONFIG_NOT_FOUND. "
                "Only 'servers' is required; 'defaults' is optional (sensible values are used when omitted)."
            ),
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["servers"],
                "properties": {
                    "servers": {
                        "type": "object",
                        "description": (
                            "Map of profile name to server definition. "
                            "Each server uses EITHER 'ssh_command' (opaque ssh invocation) "
                            "OR 'host'+'port'+'username' (paramiko-native connection). "
                            "'auth' is always required."
                        ),
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "ssh_command": {
                                    "type": "string",
                                    "description": "Full ssh command, e.g. 'ssh -p 22 user@host'. Mutually exclusive with host/port/username.",
                                },
                                "host": {"type": "string"},
                                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                                "username": {"type": "string"},
                                "auth": {
                                    "type": "object",
                                    "required": ["type"],
                                    "properties": {
                                        "type": {
                                            "type": "string",
                                            "enum": ["password", "key"],
                                            "description": "'password': authenticate with password/password_env. 'key': authenticate with private key file.",
                                        },
                                        "password": {"type": ["string", "null"], "description": "Plaintext password (prefer password_env for security)."},
                                        "password_env": {"type": ["string", "null"], "description": "Environment variable name that holds the password."},
                                        "private_key_path": {"type": ["string", "null"], "description": "Path to private key file, e.g. '~/.ssh/id_rsa'."},
                                        "private_key_passphrase_env": {"type": ["string", "null"], "description": "Env var holding the passphrase for the private key."},
                                        "allow_agent": {"type": "boolean", "description": "Allow SSH agent forwarding (default true)."},
                                        "look_for_keys": {"type": "boolean", "description": "Auto-discover private keys in ~/.ssh (default true)."},
                                    },
                                    "additionalProperties": False,
                                },
                                "proxy_command": {"type": ["string", "null"], "description": "ProxyCommand for connecting through a jump host."},
                                "shell": {"type": ["string", "null"], "description": "Override default_shell for this server, e.g. 'bash -lc'."},
                                "command_prefix": {"type": ["string", "null"], "description": "String prepended to every command on this server."},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "defaults": {
                        "type": "object",
                        "description": "Optional global defaults. All fields have sensible built-in values when omitted.",
                        "additionalProperties": False,
                        "properties": {
                            "connect_timeout_sec": {"type": "number", "description": "TCP connect timeout in seconds (default 10)."},
                            "command_timeout_sec": {"type": "number", "description": "Per-command execution timeout in seconds (default 120)."},
                            "max_stdout_bytes": {"type": "integer", "description": "Max stdout capture size in bytes (default 10485760 = 10 MiB)."},
                            "max_stderr_bytes": {"type": "integer", "description": "Max stderr capture size in bytes (default 10485760 = 10 MiB)."},
                            "known_hosts_policy": {"type": "string", "enum": ["strict", "accept_new"], "description": "'strict' (default): reject unknown hosts. 'accept_new': auto-accept new host keys."},
                            "known_hosts_path": {"type": ["string", "null"], "description": "Path to known_hosts file (default '~/.ssh/known_hosts'). null disables host key checking."},
                            "default_shell": {"type": ["string", "null"], "description": "Shell wrapper for commands (default 'bash -lc'). null sends raw commands."},
                        },
                    },
                    "config_path": {
                        "type": ["string", "null"],
                        "description": "Where to write the config file. Default: platform user config dir (e.g. %APPDATA%/sshoc/ on Windows, ~/.config/sshoc/ on Linux).",
                    },
                    "overwrite": {
                        "type": "boolean",
                        "description": "If true, overwrite an existing config file. Default false (error if file exists).",
                    },
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
        },
        {
            "name": "ssh.list_profiles",
            "description": "List server profiles configured in sshoc.config.json",
            "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
        },
        {
            "name": "ssh.scan_host_key",
            "description": "Scan remote SSH host key (no auth) and return fingerprints / known_hosts line",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "profile": {"type": "string", "description": "Use host/port from a configured profile"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "proxy_command": {"type": "string"},
                    "timeout_sec": {"type": "number"},
                },
            },
            "outputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["host_key"],
                "properties": {
                    "profile": {"type": "string"},
                    "host_key": {
                        "type": "object",
                        "additionalProperties": True,
                    },
                },
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
        },
        {
            "name": "ssh.is_known_host",
            "description": "Check whether a host key exists in known_hosts_path for a profile/host",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "profile": {"type": "string"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "known_hosts_path": {"type": ["string", "null"]},
                },
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
        },
        {
            "name": "ssh.add_known_host",
            "description": "Add a host key entry to known_hosts_path",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["known_hosts_path", "key_type", "public_key_base64"],
                "properties": {
                    "profile": {"type": "string"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "known_hosts_path": {"type": "string"},
                    "key_type": {"type": "string"},
                    "public_key_base64": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        },
        {
            "name": "ssh.ensure_known_host",
            "description": "Scan and (optionally) write the remote host key into known_hosts_path",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["known_hosts_path"],
                "properties": {
                    "profile": {"type": "string"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "proxy_command": {"type": "string"},
                    "timeout_sec": {"type": "number"},
                    "known_hosts_path": {"type": "string"},
                    "expected_host_key_fingerprint": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        },
        {
            "name": "ssh.run",
            "description": "Run a command on remote server via SSH",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile", "command"],
                "properties": {
                    "profile": {"type": "string"},
                    "command": {"type": "string"},
                    "timeout_sec": {"type": "number"},
                    "cwd": {"type": "string"},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}},
                    "use_pty": {"type": "boolean"},
                    "known_hosts_policy": {"type": "string", "enum": ["strict", "accept_new"]},
                    "known_hosts_path": {"type": ["string", "null"]},
                    "expected_host_key_fingerprint": {"type": "string"},
                },
            },
            "outputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile", "command", "exit_code", "stdout", "stderr", "duration_ms"],
                "properties": {
                    "profile": {"type": "string"},
                    "command": {"type": "string"},
                    "exit_code": {"type": "integer"},
                    "stdout": {"type": "string"},
                    "stderr": {"type": "string"},
                    "duration_ms": {"type": "integer"},
                    "host_key": {"type": "object"},
                    "host_key_added": {"type": "boolean"},
                    "known_hosts_path": {"type": ["string", "null"]},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        },
        {
            "name": "ssh.upload",
            "description": "Upload a local file to remote server via SFTP",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile", "local_path", "remote_path", "overwrite"],
                "properties": {
                    "profile": {"type": "string"},
                    "local_path": {"type": "string"},
                    "remote_path": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                    "known_hosts_policy": {"type": "string", "enum": ["strict", "accept_new"]},
                    "known_hosts_path": {"type": ["string", "null"]},
                    "expected_host_key_fingerprint": {"type": "string"},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        },
        {
            "name": "ssh.download",
            "description": "Download a remote file to local via SFTP",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile", "remote_path", "local_path", "overwrite"],
                "properties": {
                    "profile": {"type": "string"},
                    "remote_path": {"type": "string"},
                    "local_path": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                    "known_hosts_policy": {"type": "string", "enum": ["strict", "accept_new"]},
                    "known_hosts_path": {"type": ["string", "null"]},
                    "expected_host_key_fingerprint": {"type": "string"},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        },
        {
            "name": "ssh.run_async",
            "description": (
                "Submit a command for background execution on a remote server via SSH. "
                "Returns a task_id immediately. Use ssh.task_status to poll for results and ssh.task_kill to terminate."
            ),
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile", "command"],
                "properties": {
                    "profile": {"type": "string"},
                    "command": {"type": "string"},
                    "timeout_sec": {
                        "type": "number",
                        "description": "Optional timeout in seconds. Default: no timeout (runs until completion).",
                    },
                    "cwd": {"type": "string"},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}},
                    "use_pty": {"type": "boolean"},
                    "known_hosts_policy": {"type": "string", "enum": ["strict", "accept_new"]},
                    "known_hosts_path": {"type": ["string", "null"]},
                    "expected_host_key_fingerprint": {"type": "string"},
                },
            },
            "outputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["task_id", "profile", "command", "status"],
                "properties": {
                    "task_id": {"type": "string"},
                    "profile": {"type": "string"},
                    "command": {"type": "string"},
                    "status": {"type": "string", "enum": ["running"]},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        },
        {
            "name": "ssh.task_status",
            "description": (
                "Query the status and output of a background SSH task by task_id. "
                "Returns current status, exit code (if finished), and accumulated stdout/stderr."
            ),
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["task_id"],
                "properties": {
                    "task_id": {"type": "string"},
                },
            },
            "outputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["task_id", "profile", "command", "status", "stdout", "stderr"],
                "properties": {
                    "task_id": {"type": "string"},
                    "profile": {"type": "string"},
                    "command": {"type": "string"},
                    "status": {"type": "string", "enum": ["running", "completed", "failed", "killed", "timeout"]},
                    "exit_code": {"type": "integer"},
                    "error": {"type": "string"},
                    "duration_ms": {"type": "integer"},
                    "stdout": {"type": "string"},
                    "stderr": {"type": "string"},
                    "stdout_bytes": {"type": "integer"},
                    "stderr_bytes": {"type": "integer"},
                },
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        },
        {
            "name": "ssh.task_kill",
            "description": "Terminate a running background SSH task by task_id",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["task_id"],
                "properties": {
                    "task_id": {"type": "string"},
                },
            },
            "outputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["task_id", "status"],
                "properties": {
                    "task_id": {"type": "string"},
                    "status": {"type": "string"},
                    "message": {"type": "string"},
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
        },
    ]


def _result_text_block(text: str) -> list[dict[str, Any]]:
    return [{"type": "text", "text": text}]


def _ok(structured: dict[str, Any], slim_text: str) -> dict[str, Any]:
    """Return a success result with slim text content for LLM and full structuredContent."""
    return {
        "content": _result_text_block(slim_text),
        "structuredContent": structured,
        "isError": False,
    }


def _slim_host_key(hk: dict[str, Any]) -> str:
    """One-line summary of a host key for LLM consumption."""
    return f"{hk.get('key_type', '?')} {hk.get('fingerprint_sha256', '?')}"


_DEFAULT_DEFAULTS: dict[str, Any] = {
    "connect_timeout_sec": 10,
    "command_timeout_sec": 120,
    "max_stdout_bytes": 10485760,
    "max_stderr_bytes": 10485760,
    "known_hosts_policy": "strict",
    "known_hosts_path": "~/.ssh/known_hosts",
    "default_shell": "bash -lc",
}


def _call_tool(state: _ServerState, *, tool_name: str, args: dict[str, Any] | None) -> dict[str, Any]:
    args = {} if args is None else args

    # --- ssh.init_config: works without existing config ---
    if tool_name == "ssh.init_config":
        servers_raw = args.get("servers")
        if not isinstance(servers_raw, dict) or not servers_raw:
            raise ValueError("ssh.init_config requires a non-empty 'servers' object")
        defaults_raw = args.get("defaults")
        if defaults_raw is not None and not isinstance(defaults_raw, dict):
            raise ValueError("'defaults' must be an object")
        merged_defaults = {**_DEFAULT_DEFAULTS, **(defaults_raw or {})}
        config_dict: dict[str, Any] = {
            "schema_version": 1,
            "defaults": merged_defaults,
            "servers": servers_raw,
        }
        # Validate before writing.
        config_from_dict(config_dict)

        raw_path = args.get("config_path")
        if raw_path is not None and not isinstance(raw_path, str):
            raise ValueError("config_path must be a string or null")
        if isinstance(raw_path, str) and raw_path:
            dest = Path(raw_path).expanduser().resolve()
        else:
            dest = default_user_config_path()

        overwrite = args.get("overwrite", False)
        if not isinstance(overwrite, bool):
            raise ValueError("overwrite must be a boolean")
        if dest.exists() and not overwrite:
            return _tool_error(
                code="CONFIG_ALREADY_EXISTS",
                message=f"Config file already exists at {dest}. Set overwrite=true to replace it.",
                details={"config_path": str(dest)},
            )

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(config_dict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        state.cfg_path = str(dest)

        structured = {"created": str(dest), "profiles": list(servers_raw.keys())}
        slim = f"Config created: {dest}\nProfiles: {', '.join(servers_raw.keys())}"
        return _ok(structured, slim)

    # --- No-config guard ---
    if state.cfg_path is None and tool_name not in _NO_CONFIG_TOOLS:
        return _tool_error(
            code="CONFIG_NOT_FOUND",
            message=(
                "No sshoc.config.json found. "
                "Call ssh.init_config to create one, or set the SSHOC_CONFIG environment variable."
            ),
            suggested_fixes=[{
                "tool": "ssh.init_config",
                "note": "Create a config file with at least one server profile.",
            }],
        )

    cfg = load_config(state.cfg_path) if state.cfg_path is not None else None

    if tool_name == "ssh.list_profiles":
        profiles = [
            {"profile": name, "host": srv.host, "port": srv.port, "username": srv.username}
            for name, srv in sorted(cfg.servers.items(), key=lambda kv: kv[0])
        ]
        slim_lines = [f"  {p['profile']}: {p['username']}@{p['host']}:{p['port']}" for p in profiles]
        return _ok({"profiles": profiles}, "Profiles:\n" + "\n".join(slim_lines))

    if tool_name == "ssh.scan_host_key":
        profile = args.get("profile")
        host = args.get("host")
        port = args.get("port")
        proxy_command = args.get("proxy_command")
        timeout_sec = args.get("timeout_sec", 10.0)

        if profile is not None:
            if not isinstance(profile, str):
                raise ValueError("profile must be a string")
            if cfg is None:
                raise ValueError("ssh.scan_host_key with 'profile' requires a config file; call ssh.init_config first or pass 'host' directly")
            host, port, profile_proxy = _server_from_profile(cfg, profile)
            if proxy_command is None:
                proxy_command = profile_proxy
        else:
            if not isinstance(host, str) or not host:
                raise ValueError("ssh.scan_host_key requires 'profile' or 'host'")
            if port is None:
                port = 22
        if not isinstance(port, int):
            raise ValueError("port must be an integer")
        if proxy_command is not None and not isinstance(proxy_command, str):
            raise ValueError("proxy_command must be a string")
        if timeout_sec is not None and not isinstance(timeout_sec, (int, float)):
            raise ValueError("timeout_sec must be a number")

        try:
            info, _key = scan_host_key(host, port, proxy_command=proxy_command, timeout_sec=timeout_sec)
        except Exception as exc:
            return _tool_error(
                code="HOST_KEY_SCAN_FAILED",
                message=f"{type(exc).__name__}: {exc}",
                details={"profile": profile, "host": host, "port": port},
            )

        structured: dict[str, Any] = {"host_key": info.to_dict()}
        if isinstance(profile, str):
            structured["profile"] = profile
        slim = _slim_host_key(info.to_dict())
        return _ok(structured, f"Host key: {slim}")

    if tool_name == "ssh.is_known_host":
        profile = args.get("profile")
        host = args.get("host")
        port = args.get("port")
        known_hosts_path = args["known_hosts_path"] if "known_hosts_path" in args else cfg.defaults.known_hosts_path

        if profile is not None:
            if not isinstance(profile, str):
                raise ValueError("profile must be a string")
            host, port, _proxy = _server_from_profile(cfg, profile)
        else:
            if not isinstance(host, str) or not host:
                raise ValueError("ssh.is_known_host requires 'profile' or 'host'")
            if port is None:
                port = 22
        if not isinstance(port, int):
            raise ValueError("port must be an integer")
        if known_hosts_path is not None and not isinstance(known_hosts_path, str):
            raise ValueError("known_hosts_path must be string or null")

        if known_hosts_path is None:
            return _tool_error(
                code="KNOWN_HOSTS_PATH_NULL",
                message="known_hosts_path is null; cannot inspect known_hosts (set defaults.known_hosts_path or pass known_hosts_path)",
                details={"profile": profile, "host": host, "port": port},
            )

        entries = known_hosts_entries(known_hosts_path=known_hosts_path, host=host, port=port)
        structured = {
            "known": bool(entries),
            "known_hosts_path": known_hosts_path,
            "host_id": format_host_id(host, port),
            "entries": [e.to_dict() for e in entries],
        }
        if isinstance(profile, str):
            structured["profile"] = profile
        status = "known" if entries else "not found"
        slim = f"Host {structured['host_id']}: {status}"
        return _ok(structured, slim)

    if tool_name == "ssh.add_known_host":
        profile = args.get("profile")
        host = args.get("host")
        port = args.get("port")
        known_hosts_path = args.get("known_hosts_path")
        key_type = args.get("key_type")
        public_key_base64 = args.get("public_key_base64")
        overwrite = args.get("overwrite", False)

        if not isinstance(known_hosts_path, str) or not known_hosts_path:
            raise ValueError("known_hosts_path must be a non-empty string")
        if profile is not None:
            if not isinstance(profile, str):
                raise ValueError("profile must be a string")
            host, port, _proxy = _server_from_profile(cfg, profile)
        else:
            if not isinstance(host, str) or not host:
                raise ValueError("ssh.add_known_host requires 'profile' or 'host'")
            if port is None:
                port = 22
        if not isinstance(port, int):
            raise ValueError("port must be an integer")
        if not isinstance(key_type, str) or not isinstance(public_key_base64, str):
            raise ValueError("key_type/public_key_base64 must be strings")
        if not isinstance(overwrite, bool):
            raise ValueError("overwrite must be a boolean")

        try:
            structured = add_known_host(
                known_hosts_path=known_hosts_path,
                host=host,
                port=port,
                key_type=key_type,
                public_key_base64=public_key_base64,
                overwrite=overwrite,
            )
            if isinstance(profile, str):
                structured["profile"] = profile
        except Exception as exc:
            return _tool_error(
                code="KNOWN_HOST_ADD_FAILED",
                message=f"{type(exc).__name__}: {exc}",
                details={"profile": profile, "host": host, "port": port, "known_hosts_path": known_hosts_path},
            )

        action = structured.get("action", "done")
        slim = f"Host key {action} in {structured.get('known_hosts_path', known_hosts_path)}"
        return _ok(structured, slim)

    if tool_name == "ssh.ensure_known_host":
        profile = args.get("profile")
        host = args.get("host")
        port = args.get("port")
        proxy_command = args.get("proxy_command")
        timeout_sec = args.get("timeout_sec", 10.0)
        known_hosts_path = args.get("known_hosts_path")
        expected_host_key_fingerprint = args.get("expected_host_key_fingerprint")
        overwrite = args.get("overwrite", False)

        if not isinstance(known_hosts_path, str) or not known_hosts_path:
            raise ValueError("known_hosts_path must be a non-empty string")
        if profile is not None:
            if not isinstance(profile, str):
                raise ValueError("profile must be a string")
            host, port, profile_proxy = _server_from_profile(cfg, profile)
            if proxy_command is None:
                proxy_command = profile_proxy
        else:
            if not isinstance(host, str) or not host:
                raise ValueError("ssh.ensure_known_host requires 'profile' or 'host'")
            if port is None:
                port = 22
        if not isinstance(port, int):
            raise ValueError("port must be an integer")
        if proxy_command is not None and not isinstance(proxy_command, str):
            raise ValueError("proxy_command must be a string")
        if timeout_sec is not None and not isinstance(timeout_sec, (int, float)):
            raise ValueError("timeout_sec must be a number")
        if expected_host_key_fingerprint is not None and not isinstance(expected_host_key_fingerprint, str):
            raise ValueError("expected_host_key_fingerprint must be a string")
        if not isinstance(overwrite, bool):
            raise ValueError("overwrite must be a boolean")

        try:
            structured = ensure_known_host(
                known_hosts_path=known_hosts_path,
                host=host,
                port=port,
                proxy_command=proxy_command,
                timeout_sec=timeout_sec,
                expected_host_key_fingerprint=expected_host_key_fingerprint,
                overwrite=overwrite,
            )
            if isinstance(profile, str):
                structured["profile"] = profile
        except Exception as exc:
            fixes: list[dict[str, Any]] = []
            if expected_host_key_fingerprint is not None:
                fixes.append(
                    {
                        "tool": "ssh.scan_host_key",
                        "arguments": {"profile": profile} if isinstance(profile, str) else {"host": host, "port": port},
                        "note": "Inspect remote host key and verify expected fingerprint/source.",
                    }
                )
            return _tool_error(
                code="ENSURE_KNOWN_HOST_FAILED",
                message=f"{type(exc).__name__}: {exc}",
                details={
                    "profile": profile,
                    "host": host,
                    "port": port,
                    "known_hosts_path": known_hosts_path,
                    "host_id": format_host_id(host, port),
                },
                suggested_fixes=fixes or None,
            )

        status = structured.get("status", "done")
        slim = f"Host key: {status} ({structured.get('known_hosts_path', known_hosts_path)})"
        return _ok(structured, slim)

    if tool_name == "ssh.run":
        profile = args.get("profile")
        command = args.get("command")
        if not isinstance(profile, str) or not isinstance(command, str):
            raise ValueError("ssh.run requires string args: profile, command")
        timeout_sec = args.get("timeout_sec")
        cwd = args.get("cwd")
        env = args.get("env")
        use_pty = args.get("use_pty", False)
        known_hosts_policy = args.get("known_hosts_policy")
        known_hosts_path = args.get("known_hosts_path") if "known_hosts_path" in args else None
        has_known_hosts_path_override = "known_hosts_path" in args
        expected_host_key_fingerprint = args.get("expected_host_key_fingerprint")

        if timeout_sec is not None and not isinstance(timeout_sec, (int, float)):
            raise ValueError("timeout_sec must be a number")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("cwd must be a string")
        if env is not None and not (
            isinstance(env, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
        ):
            raise ValueError("env must be an object of string->string")
        if not isinstance(use_pty, bool):
            raise ValueError("use_pty must be a boolean")
        if known_hosts_policy is not None and not isinstance(known_hosts_policy, str):
            raise ValueError("known_hosts_policy must be a string")
        if has_known_hosts_path_override and known_hosts_path is not None and not isinstance(known_hosts_path, str):
            raise ValueError("known_hosts_path must be a string or null")
        if expected_host_key_fingerprint is not None and not isinstance(expected_host_key_fingerprint, str):
            raise ValueError("expected_host_key_fingerprint must be a string")

        client = build_client(cfg, profile)
        run_kwargs: dict[str, Any] = {
            "timeout_sec": float(timeout_sec) if timeout_sec is not None else None,
            "cwd": cwd,
            "env": env,
            "use_pty": use_pty,
        }
        if known_hosts_policy is not None:
            run_kwargs["known_hosts_policy"] = known_hosts_policy
        if has_known_hosts_path_override:
            run_kwargs["known_hosts_path"] = known_hosts_path
        if expected_host_key_fingerprint is not None:
            run_kwargs["expected_host_key_fingerprint"] = expected_host_key_fingerprint

        try:
            rr = client.run(command, **run_kwargs)
            structured = rr.to_dict()
        except paramiko.ssh_exception.BadHostKeyException as exc:
            host, port, _proxy = _server_from_profile(cfg, profile)
            expected = HostKeyInfo.from_key(host=host, port=port, key=exc.expected_key).to_dict()
            got = HostKeyInfo.from_key(host=host, port=port, key=exc.key).to_dict()
            return _tool_error(
                code="KNOWN_HOST_CHANGED",
                message=str(exc),
                details={"profile": profile, "expected": expected, "got": got},
            )
        except paramiko.ssh_exception.SSHException as exc:
            msg = str(exc)
            if "not found in known_hosts" in msg:
                host, port, _proxy = _server_from_profile(cfg, profile)
                kh_path = (
                    known_hosts_path
                    if has_known_hosts_path_override
                    else cfg.defaults.known_hosts_path
                )
                ensure_args: dict[str, Any] = {
                    "profile": profile,
                    "known_hosts_path": kh_path or "~/.ssh/known_hosts",
                }
                if expected_host_key_fingerprint is not None:
                    ensure_args["expected_host_key_fingerprint"] = expected_host_key_fingerprint
                fixes = [
                    {
                        "tool": "ssh.ensure_known_host",
                        "arguments": ensure_args,
                        "note": "Prefer: scan+write known_hosts, optionally verify fingerprint from a trusted source.",
                    },
                    {
                        "tool": "ssh.run",
                        "arguments": {
                            "profile": profile,
                            "command": command,
                            "known_hosts_policy": "accept_new",
                        },
                        "note": "Quick TOFU: accept & save new host key (less safe).",
                    },
                ]
                return _tool_error(
                    code="KNOWN_HOST_MISSING",
                    message=msg,
                    details={
                        "profile": profile,
                        "host": host,
                        "port": port,
                        "host_id": format_host_id(host, port),
                        "known_hosts_path": kh_path,
                        "known_hosts_policy": known_hosts_policy or cfg.defaults.known_hosts_policy,
                    },
                    suggested_fixes=fixes,
                )
            if "host key fingerprint mismatch" in msg:
                fixes = [
                    {
                        "tool": "ssh.scan_host_key",
                        "arguments": {"profile": profile},
                        "note": "Inspect the remote host key and compare with the expected fingerprint source.",
                    }
                ]
                return _tool_error(
                    code="HOST_KEY_FINGERPRINT_MISMATCH",
                    message=msg,
                    details={"profile": profile, "expected_host_key_fingerprint": expected_host_key_fingerprint},
                    suggested_fixes=fixes,
                )
            return _tool_error(code="SSH_ERROR", message=f"{type(exc).__name__}: {exc}", details={"profile": profile})
        except Exception as exc:
            return _tool_error(code="RUN_FAILED", message=f"{type(exc).__name__}: {exc}", details={"profile": profile})

        # Slim content for LLM: only exit_code, stdout, stderr (if non-empty).
        slim_parts = [f"exit_code: {structured['exit_code']}"]
        stdout = structured.get("stdout", "")
        stderr = structured.get("stderr", "")
        if stdout:
            slim_parts.append(f"stdout:\n{stdout}")
        if stderr:
            slim_parts.append(f"stderr:\n{stderr}")
        return _ok(structured, "\n".join(slim_parts))

    if tool_name == "ssh.upload":
        profile = args.get("profile")
        local_path = args.get("local_path")
        remote_path = args.get("remote_path")
        overwrite = args.get("overwrite")
        known_hosts_policy = args.get("known_hosts_policy")
        known_hosts_path = args.get("known_hosts_path") if "known_hosts_path" in args else None
        has_known_hosts_path_override = "known_hosts_path" in args
        expected_host_key_fingerprint = args.get("expected_host_key_fingerprint")
        if not all(isinstance(x, str) for x in (profile, local_path, remote_path)) or not isinstance(overwrite, bool):
            raise ValueError("ssh.upload requires args: profile(str), local_path(str), remote_path(str), overwrite(bool)")
        if known_hosts_policy is not None and not isinstance(known_hosts_policy, str):
            raise ValueError("known_hosts_policy must be a string")
        if has_known_hosts_path_override and known_hosts_path is not None and not isinstance(known_hosts_path, str):
            raise ValueError("known_hosts_path must be a string or null")
        if expected_host_key_fingerprint is not None and not isinstance(expected_host_key_fingerprint, str):
            raise ValueError("expected_host_key_fingerprint must be a string")
        client = build_client(cfg, profile)
        upload_kwargs: dict[str, Any] = {"overwrite": overwrite}
        if known_hosts_policy is not None:
            upload_kwargs["known_hosts_policy"] = known_hosts_policy
        if has_known_hosts_path_override:
            upload_kwargs["known_hosts_path"] = known_hosts_path
        if expected_host_key_fingerprint is not None:
            upload_kwargs["expected_host_key_fingerprint"] = expected_host_key_fingerprint
        try:
            structured = client.upload(local_path, remote_path, **upload_kwargs)
        except paramiko.ssh_exception.BadHostKeyException as exc:
            host, port, _proxy = _server_from_profile(cfg, profile)
            expected = HostKeyInfo.from_key(host=host, port=port, key=exc.expected_key).to_dict()
            got = HostKeyInfo.from_key(host=host, port=port, key=exc.key).to_dict()
            return _tool_error(
                code="KNOWN_HOST_CHANGED",
                message=str(exc),
                details={"profile": profile, "expected": expected, "got": got},
            )
        except paramiko.ssh_exception.SSHException as exc:
            msg = str(exc)
            if "not found in known_hosts" in msg:
                host, port, _proxy = _server_from_profile(cfg, profile)
                kh_path = (
                    known_hosts_path
                    if has_known_hosts_path_override
                    else cfg.defaults.known_hosts_path
                )
                ensure_args: dict[str, Any] = {
                    "profile": profile,
                    "known_hosts_path": kh_path or "~/.ssh/known_hosts",
                }
                if expected_host_key_fingerprint is not None:
                    ensure_args["expected_host_key_fingerprint"] = expected_host_key_fingerprint
                return _tool_error(
                    code="KNOWN_HOST_MISSING",
                    message=msg,
                    details={
                        "profile": profile,
                        "host": host,
                        "port": port,
                        "host_id": format_host_id(host, port),
                        "known_hosts_path": kh_path,
                    },
                    suggested_fixes=[
                        {
                            "tool": "ssh.ensure_known_host",
                            "arguments": ensure_args,
                            "note": "Scan+write known_hosts, then retry upload.",
                        }
                    ],
                )
            if "host key fingerprint mismatch" in msg:
                return _tool_error(
                    code="HOST_KEY_FINGERPRINT_MISMATCH",
                    message=msg,
                    details={"profile": profile, "expected_host_key_fingerprint": expected_host_key_fingerprint},
                    suggested_fixes=[{"tool": "ssh.scan_host_key", "arguments": {"profile": profile}}],
                )
            return _tool_error(code="SSH_ERROR", message=f"{type(exc).__name__}: {exc}", details={"profile": profile})
        except Exception as exc:
            return _tool_error(code="UPLOAD_FAILED", message=f"{type(exc).__name__}: {exc}", details={"profile": profile})
        slim = f"Uploaded {local_path} -> {profile}:{remote_path}"
        return _ok(structured, slim)

    if tool_name == "ssh.download":
        profile = args.get("profile")
        remote_path = args.get("remote_path")
        local_path = args.get("local_path")
        overwrite = args.get("overwrite")
        known_hosts_policy = args.get("known_hosts_policy")
        known_hosts_path = args.get("known_hosts_path") if "known_hosts_path" in args else None
        has_known_hosts_path_override = "known_hosts_path" in args
        expected_host_key_fingerprint = args.get("expected_host_key_fingerprint")
        if not all(isinstance(x, str) for x in (profile, remote_path, local_path)) or not isinstance(overwrite, bool):
            raise ValueError(
                "ssh.download requires args: profile(str), remote_path(str), local_path(str), overwrite(bool)"
            )
        if known_hosts_policy is not None and not isinstance(known_hosts_policy, str):
            raise ValueError("known_hosts_policy must be a string")
        if has_known_hosts_path_override and known_hosts_path is not None and not isinstance(known_hosts_path, str):
            raise ValueError("known_hosts_path must be a string or null")
        if expected_host_key_fingerprint is not None and not isinstance(expected_host_key_fingerprint, str):
            raise ValueError("expected_host_key_fingerprint must be a string")
        client = build_client(cfg, profile)
        dl_kwargs: dict[str, Any] = {"overwrite": overwrite}
        if known_hosts_policy is not None:
            dl_kwargs["known_hosts_policy"] = known_hosts_policy
        if has_known_hosts_path_override:
            dl_kwargs["known_hosts_path"] = known_hosts_path
        if expected_host_key_fingerprint is not None:
            dl_kwargs["expected_host_key_fingerprint"] = expected_host_key_fingerprint
        try:
            structured = client.download(remote_path, local_path, **dl_kwargs)
        except paramiko.ssh_exception.BadHostKeyException as exc:
            host, port, _proxy = _server_from_profile(cfg, profile)
            expected = HostKeyInfo.from_key(host=host, port=port, key=exc.expected_key).to_dict()
            got = HostKeyInfo.from_key(host=host, port=port, key=exc.key).to_dict()
            return _tool_error(
                code="KNOWN_HOST_CHANGED",
                message=str(exc),
                details={"profile": profile, "expected": expected, "got": got},
            )
        except paramiko.ssh_exception.SSHException as exc:
            msg = str(exc)
            if "not found in known_hosts" in msg:
                host, port, _proxy = _server_from_profile(cfg, profile)
                kh_path = (
                    known_hosts_path
                    if has_known_hosts_path_override
                    else cfg.defaults.known_hosts_path
                )
                ensure_args: dict[str, Any] = {
                    "profile": profile,
                    "known_hosts_path": kh_path or "~/.ssh/known_hosts",
                }
                if expected_host_key_fingerprint is not None:
                    ensure_args["expected_host_key_fingerprint"] = expected_host_key_fingerprint
                return _tool_error(
                    code="KNOWN_HOST_MISSING",
                    message=msg,
                    details={
                        "profile": profile,
                        "host": host,
                        "port": port,
                        "host_id": format_host_id(host, port),
                        "known_hosts_path": kh_path,
                    },
                    suggested_fixes=[
                        {
                            "tool": "ssh.ensure_known_host",
                            "arguments": ensure_args,
                            "note": "Scan+write known_hosts, then retry download.",
                        }
                    ],
                )
            if "host key fingerprint mismatch" in msg:
                return _tool_error(
                    code="HOST_KEY_FINGERPRINT_MISMATCH",
                    message=msg,
                    details={"profile": profile, "expected_host_key_fingerprint": expected_host_key_fingerprint},
                    suggested_fixes=[{"tool": "ssh.scan_host_key", "arguments": {"profile": profile}}],
                )
            return _tool_error(code="SSH_ERROR", message=f"{type(exc).__name__}: {exc}", details={"profile": profile})
        except Exception as exc:
            return _tool_error(code="DOWNLOAD_FAILED", message=f"{type(exc).__name__}: {exc}", details={"profile": profile})
        slim = f"Downloaded {profile}:{remote_path} -> {local_path}"
        return _ok(structured, slim)

    if tool_name == "ssh.run_async":
        profile = args.get("profile")
        command = args.get("command")
        if not isinstance(profile, str) or not isinstance(command, str):
            raise ValueError("ssh.run_async requires string args: profile, command")
        timeout_sec = args.get("timeout_sec")
        cwd = args.get("cwd")
        env = args.get("env")
        use_pty = args.get("use_pty", False)
        known_hosts_policy = args.get("known_hosts_policy")
        known_hosts_path = args.get("known_hosts_path") if "known_hosts_path" in args else None
        has_known_hosts_path_override = "known_hosts_path" in args
        expected_host_key_fingerprint = args.get("expected_host_key_fingerprint")

        if timeout_sec is not None and not isinstance(timeout_sec, (int, float)):
            raise ValueError("timeout_sec must be a number")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("cwd must be a string")
        if env is not None and not (
            isinstance(env, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
        ):
            raise ValueError("env must be an object of string->string")
        if not isinstance(use_pty, bool):
            raise ValueError("use_pty must be a boolean")
        if known_hosts_policy is not None and not isinstance(known_hosts_policy, str):
            raise ValueError("known_hosts_policy must be a string")
        if has_known_hosts_path_override and known_hosts_path is not None and not isinstance(known_hosts_path, str):
            raise ValueError("known_hosts_path must be a string or null")
        if expected_host_key_fingerprint is not None and not isinstance(expected_host_key_fingerprint, str):
            raise ValueError("expected_host_key_fingerprint must be a string")

        ssh_client = build_client(cfg, profile)
        task = state.create_task(profile=profile, command=command)

        run_kwargs: dict[str, Any] = {
            "timeout_sec": float(timeout_sec) if timeout_sec is not None else None,
            "cwd": cwd,
            "env": env,
            "use_pty": use_pty,
        }
        if known_hosts_policy is not None:
            run_kwargs["known_hosts_policy"] = known_hosts_policy
        if has_known_hosts_path_override:
            run_kwargs["known_hosts_path"] = known_hosts_path
        if expected_host_key_fingerprint is not None:
            run_kwargs["expected_host_key_fingerprint"] = expected_host_key_fingerprint

        thread = threading.Thread(
            target=ssh_client.run_async_worker,
            args=(task,),
            kwargs=run_kwargs,
            daemon=True,
            name=f"sshoc-task-{task.task_id}",
        )
        task._thread = thread
        thread.start()

        structured = {
            "task_id": task.task_id,
            "profile": profile,
            "command": command,
            "status": "running",
        }
        slim = f"Task {task.task_id} started: {command[:80]}"
        return _ok(structured, slim)

    if tool_name == "ssh.task_status":
        task_id = args.get("task_id")
        if not isinstance(task_id, str):
            raise ValueError("ssh.task_status requires string arg: task_id")

        task = state.get_task(task_id)
        if task is None:
            return _tool_error(
                code="TASK_NOT_FOUND",
                message=f"No task with id={task_id!r}",
                details={"task_id": task_id},
            )

        structured = task.to_status_dict()
        slim_parts = [f"task_id: {task_id}", f"status: {task.status}"]
        if task.exit_code is not None:
            slim_parts.append(f"exit_code: {task.exit_code}")
        if task.error:
            slim_parts.append(f"error: {task.error}")
        stdout = task.get_stdout()
        stderr = task.get_stderr()
        if stdout:
            slim_parts.append(f"stdout:\n{stdout}")
        if stderr:
            slim_parts.append(f"stderr:\n{stderr}")
        return _ok(structured, "\n".join(slim_parts))

    if tool_name == "ssh.task_kill":
        task_id = args.get("task_id")
        if not isinstance(task_id, str):
            raise ValueError("ssh.task_kill requires string arg: task_id")

        task = state.get_task(task_id)
        if task is None:
            return _tool_error(
                code="TASK_NOT_FOUND",
                message=f"No task with id={task_id!r}",
                details={"task_id": task_id},
            )

        if task.status != "running":
            structured = {
                "task_id": task_id,
                "status": task.status,
                "message": f"Task already {task.status}; nothing to kill.",
            }
            slim = f"Task {task_id}: already {task.status}"
            return _ok(structured, slim)

        task._kill_requested = True
        channel = task._channel
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass

        structured = {
            "task_id": task_id,
            "status": "killed",
            "message": "Kill signal sent. Task will terminate shortly.",
        }
        slim = f"Task {task_id}: kill signal sent"
        return _ok(structured, slim)

    return {
        "content": _result_text_block(f"unknown tool: {tool_name}"),
        "structuredContent": {"error": {"message": f"unknown tool: {tool_name}"}},
        "isError": True,
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    debug = os.environ.get("SSHOC_DEBUG", "") not in ("", "0", "false", "False")

    config_path = None
    if argv:
        if argv[0] in ("-h", "--help"):
            sys.stderr.write("usage: sshoc-mcp [--config PATH]\\n")
            return 0
        if argv[0] == "--config":
            if len(argv) < 2:
                sys.stderr.write("--config requires a path\\n")
                return 2
            config_path = argv[1]
        else:
            sys.stderr.write(f"unknown arg: {argv[0]}\\n")
            return 2

    cfg_info = resolve_config_path_info(cli_path=config_path)
    state = _ServerState(cfg_path=str(cfg_info.path) if cfg_info.exists else None)

    initialized = False
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            write_message(_jsonrpc_error(id_value=None, code=JSONRPCParseError, message="parse error"))
            continue

        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            write_message(_jsonrpc_error(id_value=None, code=JSONRPCInvalidRequest, message="invalid JSON-RPC message"))
            continue

        method = msg.get("method")
        if not isinstance(method, str):
            write_message(_jsonrpc_error(id_value=msg.get("id"), code=JSONRPCInvalidRequest, message="missing method"))
            continue

        is_request = "id" in msg
        request_id = msg.get("id")
        params = msg.get("params")

        if method == "initialize":
            if not is_request:
                continue

            def _handle_init() -> dict[str, Any]:
                if not isinstance(params, dict):
                    raise ValueError("initialize params must be object")
                requested = params.get("protocolVersion")
                requested_s = str(requested)
                negotiated = requested_s if requested_s in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
                return {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "sshoc", "version": __version__},
                    "instructions": "Use tools/list then tools/call. If no config file exists yet, call ssh.init_config first to create one. Tools include ssh.run / ssh.upload / ssh.download and host key helpers (ssh.scan_host_key / ssh.ensure_known_host).",
                }

            write_message(safe_call(_handle_init, request_id=request_id, debug=debug))
            initialized = True
            continue

        if method == "notifications/initialized":
            initialized = True
            continue

        if method == "ping":
            if is_request:
                write_message({"jsonrpc": "2.0", "id": request_id, "result": {}})
            continue

        if not initialized:
            if is_request:
                write_message(
                    _jsonrpc_error(
                        id_value=request_id,
                        code=JSONRPCInvalidRequest,
                        message="received request before initialization",
                    )
                )
            continue

        if method == "tools/list":
            if not is_request:
                continue

            def _handle_list() -> dict[str, Any]:
                return {"tools": _tool_list()}

            write_message(safe_call(_handle_list, request_id=request_id, debug=debug))
            continue

        if method == "tools/call":
            if not is_request:
                continue

            def _handle_call() -> dict[str, Any]:
                if not isinstance(params, dict):
                    raise ValueError("tools/call params must be object")
                name = params.get("name")
                if not isinstance(name, str) or not name:
                    raise ValueError("tools/call requires non-empty name")
                arguments = params.get("arguments")
                if arguments is not None and not isinstance(arguments, dict):
                    raise ValueError("tools/call arguments must be object")
                return _call_tool(state, tool_name=name, args=arguments)

            write_message(safe_call(_handle_call, request_id=request_id, debug=debug))
            continue

        if is_request:
            write_message(_jsonrpc_error(id_value=request_id, code=JSONRPCMethodNotFound, message="method not found"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
