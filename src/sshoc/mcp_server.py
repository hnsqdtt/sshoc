from __future__ import annotations

import json
import os
import sys
from typing import Any

from . import __version__
from .config import load_config, resolve_default_config_path
from .jsonrpc import (
    JSONRPCInvalidRequest,
    JSONRPCParseError,
    JSONRPCMethodNotFound,
    _jsonrpc_error,
    safe_call,
    write_message,
)
from .ssh_client import build_client


LATEST_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS: list[str] = ["2024-11-05", "2025-03-26", "2025-06-18", LATEST_PROTOCOL_VERSION]


def _tool_list() -> list[dict[str, Any]]:
    return [
        {
            "name": "ssh.list_profiles",
            "description": "List server profiles configured in sshoc.config.json",
            "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
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
                },
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        },
    ]


def _result_text_block(text: str) -> list[dict[str, Any]]:
    return [{"type": "text", "text": text}]


def _call_tool(cfg_path: str, *, tool_name: str, args: dict[str, Any] | None) -> dict[str, Any]:
    cfg = load_config(cfg_path)
    args = {} if args is None else args

    if tool_name == "ssh.list_profiles":
        profiles = [
            {"profile": name, "host": srv.host, "port": srv.port, "username": srv.username}
            for name, srv in sorted(cfg.servers.items(), key=lambda kv: kv[0])
        ]
        return {
            "content": _result_text_block(json.dumps({"profiles": profiles}, ensure_ascii=False, indent=2)),
            "structuredContent": {"profiles": profiles},
            "isError": False,
        }

    if tool_name == "ssh.run":
        profile = args.get("profile")
        command = args.get("command")
        if not isinstance(profile, str) or not isinstance(command, str):
            raise ValueError("ssh.run requires string args: profile, command")
        timeout_sec = args.get("timeout_sec")
        cwd = args.get("cwd")
        env = args.get("env")
        use_pty = args.get("use_pty", False)

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

        client = build_client(cfg, profile)
        rr = client.run(
            command,
            timeout_sec=float(timeout_sec) if timeout_sec is not None else None,
            cwd=cwd,
            env=env,
            use_pty=use_pty,
        )
        structured = rr.to_dict()
        return {
            "content": _result_text_block(json.dumps(structured, ensure_ascii=False, indent=2)),
            "structuredContent": structured,
            "isError": False,
        }

    if tool_name == "ssh.upload":
        profile = args.get("profile")
        local_path = args.get("local_path")
        remote_path = args.get("remote_path")
        overwrite = args.get("overwrite")
        if not all(isinstance(x, str) for x in (profile, local_path, remote_path)) or not isinstance(overwrite, bool):
            raise ValueError("ssh.upload requires args: profile(str), local_path(str), remote_path(str), overwrite(bool)")
        client = build_client(cfg, profile)
        structured = client.upload(local_path, remote_path, overwrite=overwrite)
        return {
            "content": _result_text_block(json.dumps(structured, ensure_ascii=False, indent=2)),
            "structuredContent": structured,
            "isError": False,
        }

    if tool_name == "ssh.download":
        profile = args.get("profile")
        remote_path = args.get("remote_path")
        local_path = args.get("local_path")
        overwrite = args.get("overwrite")
        if not all(isinstance(x, str) for x in (profile, remote_path, local_path)) or not isinstance(overwrite, bool):
            raise ValueError(
                "ssh.download requires args: profile(str), remote_path(str), local_path(str), overwrite(bool)"
            )
        client = build_client(cfg, profile)
        structured = client.download(remote_path, local_path, overwrite=overwrite)
        return {
            "content": _result_text_block(json.dumps(structured, ensure_ascii=False, indent=2)),
            "structuredContent": structured,
            "isError": False,
        }

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

    cfg_path = str(resolve_default_config_path(cli_path=config_path))

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
                    "instructions": "Use tools/list then tools/call with ssh.run / ssh.upload / ssh.download.",
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
                return _call_tool(cfg_path, tool_name=name, args=arguments)

            write_message(safe_call(_handle_call, request_id=request_id, debug=debug))
            continue

        if is_request:
            write_message(_jsonrpc_error(id_value=request_id, code=JSONRPCMethodNotFound, message="method not found"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
