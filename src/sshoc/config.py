from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .errors import ConfigError


_PROFILE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _err(ctx: str, msg: str) -> ConfigError:
    return ConfigError(f"[config] {ctx}: {msg}")


def _as_dict(value: Any, *, ctx: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _err(ctx, f"expected object/dict, got {type(value).__name__}")
    return value


def _as_int(value: Any, *, ctx: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _err(ctx, f"expected int, got {type(value).__name__}")
    return value


def _as_float(value: Any, *, ctx: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _err(ctx, f"expected number, got {type(value).__name__}")
    return float(value)


def _as_str(value: Any, *, ctx: str) -> str:
    if not isinstance(value, str):
        raise _err(ctx, f"expected string, got {type(value).__name__}")
    if value == "":
        raise _err(ctx, "must not be empty")
    return value


def _as_opt_str(value: Any, *, ctx: str) -> str | None:
    if value is None:
        return None
    return _as_str(value, ctx=ctx)


def _assert_no_extra_keys(obj: dict[str, Any], *, allowed: set[str], ctx: str) -> None:
    extra = set(obj.keys()) - allowed
    if extra:
        raise _err(ctx, f"unknown keys: {sorted(extra)}")


def _require_keys(obj: dict[str, Any], *, required: set[str], ctx: str) -> None:
    missing = required - set(obj.keys())
    if missing:
        raise _err(ctx, f"missing keys: {sorted(missing)}")


def _expand_path(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


KnownHostsPolicy = Literal["strict", "accept_new"]


@dataclass(frozen=True)
class Defaults:
    connect_timeout_sec: float
    command_timeout_sec: float
    max_stdout_bytes: int
    max_stderr_bytes: int
    known_hosts_policy: KnownHostsPolicy
    known_hosts_path: str | None
    default_shell: str | None


AuthType = Literal["password", "key"]


@dataclass(frozen=True)
class Auth:
    type: AuthType
    password: str | None
    password_env: str | None
    private_key_path: str | None
    private_key_passphrase_env: str | None
    allow_agent: bool
    look_for_keys: bool

    def resolve_password(self) -> str | None:
        if self.password is not None:
            return self.password
        if self.password_env is None:
            return None
        value = os.environ.get(self.password_env)
        if value is None or value == "":
            raise ConfigError(
                f"[config] auth.password_env '{self.password_env}' is not set (or empty) in environment"
            )
        return value

    def resolve_private_key_passphrase(self) -> str | None:
        if self.private_key_passphrase_env is None:
            return None
        value = os.environ.get(self.private_key_passphrase_env)
        if value is None or value == "":
            raise ConfigError(
                f"[config] auth.private_key_passphrase_env '{self.private_key_passphrase_env}' is not set (or empty) in environment"
            )
        return value


@dataclass(frozen=True)
class Server:
    host: str
    port: int
    username: str
    auth: Auth
    proxy_command: str | None
    shell: str | None
    command_prefix: str | None


@dataclass(frozen=True)
class Config:
    defaults: Defaults
    servers: dict[str, Server]

    def get_server(self, profile: str) -> Server:
        try:
            return self.servers[profile]
        except KeyError as exc:
            raise ConfigError(f"[config] unknown profile: {profile!r}") from exc


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    raw = json.loads(p.read_text(encoding="utf-8"))
    return config_from_dict(raw)


def config_from_dict(raw: Any) -> Config:
    root = _as_dict(raw, ctx="root")
    _assert_no_extra_keys(root, allowed={"$schema", "schema_version", "defaults", "servers"}, ctx="root")
    _require_keys(root, required={"schema_version", "defaults", "servers"}, ctx="root")

    schema_version = _as_int(root["schema_version"], ctx="root.schema_version")
    if schema_version != 1:
        raise _err("root.schema_version", f"unsupported schema_version: {schema_version} (expected 1)")

    defaults = _parse_defaults(_as_dict(root["defaults"], ctx="root.defaults"))
    servers_raw = _as_dict(root["servers"], ctx="root.servers")
    servers: dict[str, Server] = {}
    for profile, srv_raw in servers_raw.items():
        if not isinstance(profile, str):
            raise _err("root.servers", "profile keys must be strings")
        if not _PROFILE_RE.match(profile):
            raise _err(f"root.servers.{profile}", "invalid profile name (allowed: A-Za-z0-9_-)")
        srv = _parse_server(_as_dict(srv_raw, ctx=f"root.servers.{profile}"), defaults=defaults, profile=profile)
        servers[profile] = srv

    return Config(defaults=defaults, servers=servers)


def _parse_defaults(obj: dict[str, Any]) -> Defaults:
    _assert_no_extra_keys(
        obj,
        allowed={
            "connect_timeout_sec",
            "command_timeout_sec",
            "max_stdout_bytes",
            "max_stderr_bytes",
            "known_hosts_policy",
            "known_hosts_path",
            "default_shell",
        },
        ctx="root.defaults",
    )
    _require_keys(
        obj,
        required={
            "connect_timeout_sec",
            "command_timeout_sec",
            "max_stdout_bytes",
            "max_stderr_bytes",
            "known_hosts_policy",
            "known_hosts_path",
            "default_shell",
        },
        ctx="root.defaults",
    )

    connect_timeout_sec = _as_float(obj["connect_timeout_sec"], ctx="root.defaults.connect_timeout_sec")
    command_timeout_sec = _as_float(obj["command_timeout_sec"], ctx="root.defaults.command_timeout_sec")
    max_stdout_bytes = _as_int(obj["max_stdout_bytes"], ctx="root.defaults.max_stdout_bytes")
    max_stderr_bytes = _as_int(obj["max_stderr_bytes"], ctx="root.defaults.max_stderr_bytes")
    known_hosts_policy = _as_str(obj["known_hosts_policy"], ctx="root.defaults.known_hosts_policy")
    if known_hosts_policy not in ("strict", "accept_new"):
        raise _err(
            "root.defaults.known_hosts_policy",
            "must be one of: strict, accept_new",
        )
    known_hosts_path = _as_opt_str(obj["known_hosts_path"], ctx="root.defaults.known_hosts_path")
    if known_hosts_path is not None:
        known_hosts_path = _expand_path(known_hosts_path)

    default_shell = _as_opt_str(obj["default_shell"], ctx="root.defaults.default_shell")
    return Defaults(
        connect_timeout_sec=connect_timeout_sec,
        command_timeout_sec=command_timeout_sec,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        known_hosts_policy=known_hosts_policy,  # type: ignore[arg-type]
        known_hosts_path=known_hosts_path,
        default_shell=default_shell,
    )


def _parse_server(obj: dict[str, Any], *, defaults: Defaults, profile: str) -> Server:
    _assert_no_extra_keys(
        obj,
        allowed={"ssh_command", "host", "port", "username", "auth", "proxy_command", "shell", "command_prefix"},
        ctx=f"root.servers.{profile}",
    )
    _require_keys(obj, required={"auth"}, ctx=f"root.servers.{profile}")

    ssh_command = _as_opt_str(obj.get("ssh_command"), ctx=f"root.servers.{profile}.ssh_command")
    if ssh_command is not None:
        for k in ("host", "port", "username"):
            if k in obj:
                raise _err(
                    f"root.servers.{profile}",
                    f"do not set '{k}' when using 'ssh_command' (use one or the other)",
                )
        host, port, username = _parse_ssh_command(ssh_command, ctx=f"root.servers.{profile}.ssh_command")
    else:
        _require_keys(obj, required={"host", "port", "username"}, ctx=f"root.servers.{profile}")
        host = _as_str(obj["host"], ctx=f"root.servers.{profile}.host")
        port = _as_int(obj["port"], ctx=f"root.servers.{profile}.port")
        if not (1 <= port <= 65535):
            raise _err(f"root.servers.{profile}.port", "must be in [1, 65535]")
        username = _as_str(obj["username"], ctx=f"root.servers.{profile}.username")

    auth = _parse_auth(_as_dict(obj["auth"], ctx=f"root.servers.{profile}.auth"), profile=profile)

    proxy_command = _as_opt_str(obj.get("proxy_command"), ctx=f"root.servers.{profile}.proxy_command")
    shell = _as_opt_str(obj.get("shell", defaults.default_shell), ctx=f"root.servers.{profile}.shell")
    command_prefix = _as_opt_str(obj.get("command_prefix"), ctx=f"root.servers.{profile}.command_prefix")

    return Server(
        host=host,
        port=port,
        username=username,
        auth=auth,
        proxy_command=proxy_command,
        shell=shell,
        command_prefix=command_prefix,
    )


def _parse_ssh_command(cmd: str, *, ctx: str) -> tuple[str, int, str]:
    """
    Minimal parser for common SSH command patterns.

    Supported:
      - ssh -p <port> user@host
      - ssh -l <user> -p <port> host

    Unsupported options (fail fast): most flags besides -p / -l.
    """
    import shlex

    try:
        parts = shlex.split(cmd, posix=True)
    except ValueError as exc:
        raise _err(ctx, f"failed to parse ssh_command: {exc}") from exc

    if not parts:
        raise _err(ctx, "ssh_command must not be empty")
    if parts[0] != "ssh":
        raise _err(ctx, "ssh_command must start with 'ssh'")

    user: str | None = None
    host: str | None = None
    port: int = 22

    i = 1
    while i < len(parts):
        p = parts[i]
        if p == "-p":
            if i + 1 >= len(parts):
                raise _err(ctx, "ssh_command: -p requires a port")
            try:
                port = int(parts[i + 1])
            except ValueError as exc:
                raise _err(ctx, f"ssh_command: invalid port: {parts[i + 1]!r}") from exc
            i += 2
            continue
        if p == "-l":
            if i + 1 >= len(parts):
                raise _err(ctx, "ssh_command: -l requires a username")
            user = parts[i + 1]
            if user == "":
                raise _err(ctx, "ssh_command: -l username must not be empty")
            i += 2
            continue
        if p.startswith("-"):
            raise _err(
                ctx,
                f"ssh_command contains unsupported option {p!r}; use explicit config fields instead",
            )

        # positional host spec
        if host is not None:
            raise _err(ctx, "ssh_command must specify exactly one host")
        host_spec = p
        if "@" in host_spec:
            u, h = host_spec.split("@", 1)
            if u == "" or h == "":
                raise _err(ctx, f"ssh_command: invalid host spec: {host_spec!r}")
            user = u if user is None else user
            host = h
        else:
            host = host_spec
        i += 1

    if host is None:
        raise _err(ctx, "ssh_command must include a host")
    if user is None:
        raise _err(ctx, "ssh_command must include username (use user@host or -l user)")
    if not (1 <= port <= 65535):
        raise _err(ctx, "ssh_command: port must be in [1, 65535]")

    return host, port, user


def _parse_auth(obj: dict[str, Any], *, profile: str) -> Auth:
    _assert_no_extra_keys(
        obj,
        allowed={
            "type",
            "password",
            "password_env",
            "private_key_path",
            "private_key_passphrase_env",
            "allow_agent",
            "look_for_keys",
        },
        ctx=f"root.servers.{profile}.auth",
    )
    _require_keys(obj, required={"type"}, ctx=f"root.servers.{profile}.auth")
    auth_type = _as_str(obj["type"], ctx=f"root.servers.{profile}.auth.type")
    if auth_type not in ("password", "key"):
        raise _err(f"root.servers.{profile}.auth.type", "must be one of: password, key")

    password = _as_opt_str(obj.get("password"), ctx=f"root.servers.{profile}.auth.password")
    password_env = _as_opt_str(obj.get("password_env"), ctx=f"root.servers.{profile}.auth.password_env")
    private_key_path = _as_opt_str(
        obj.get("private_key_path"), ctx=f"root.servers.{profile}.auth.private_key_path"
    )
    if private_key_path is not None:
        private_key_path = _expand_path(private_key_path)
    private_key_passphrase_env = _as_opt_str(
        obj.get("private_key_passphrase_env"),
        ctx=f"root.servers.{profile}.auth.private_key_passphrase_env",
    )
    allow_agent = obj.get("allow_agent", True)
    if not isinstance(allow_agent, bool):
        raise _err(f"root.servers.{profile}.auth.allow_agent", "expected bool")
    look_for_keys = obj.get("look_for_keys", True)
    if not isinstance(look_for_keys, bool):
        raise _err(f"root.servers.{profile}.auth.look_for_keys", "expected bool")

    if auth_type == "password":
        if password is None and password_env is None:
            raise _err(
                f"root.servers.{profile}.auth",
                "password auth requires 'password' or 'password_env'",
            )
        if private_key_path is not None:
            raise _err(f"root.servers.{profile}.auth.private_key_path", "not allowed for password auth")
        if private_key_passphrase_env is not None:
            raise _err(
                f"root.servers.{profile}.auth.private_key_passphrase_env",
                "not allowed for password auth",
            )
    else:
        if private_key_path is None:
            raise _err(
                f"root.servers.{profile}.auth.private_key_path",
                "key auth requires 'private_key_path'",
            )
        if password is not None or password_env is not None:
            raise _err(f"root.servers.{profile}.auth", "password/password_env not allowed for key auth")

    if password_env is not None and not _ENV_KEY_RE.match(password_env):
        raise _err(f"root.servers.{profile}.auth.password_env", "invalid env var name")
    if private_key_passphrase_env is not None and not _ENV_KEY_RE.match(private_key_passphrase_env):
        raise _err(f"root.servers.{profile}.auth.private_key_passphrase_env", "invalid env var name")

    return Auth(
        type=auth_type,  # type: ignore[arg-type]
        password=password,
        password_env=password_env,
        private_key_path=private_key_path,
        private_key_passphrase_env=private_key_passphrase_env,
        allow_agent=allow_agent,
        look_for_keys=look_for_keys,
    )


def resolve_default_config_path(*, cli_path: str | None) -> Path:
    if cli_path is not None:
        p = Path(_expand_path(cli_path))
        if not p.exists():
            raise FileNotFoundError(str(p))
        return p

    env_path = os.environ.get("SSHOC_CONFIG")
    if env_path:
        p = Path(_expand_path(env_path))
        if not p.exists():
            raise FileNotFoundError(str(p))
        return p

    cwd = Path.cwd() / "sshoc.config.json"
    if cwd.exists():
        return cwd

    user_path = default_user_config_path()
    if user_path.exists():
        return user_path

    component_dir = Path(__file__).resolve().parents[2]  # .../src/sshoc/config.py -> component root
    candidate = component_dir / "sshoc.config.json"
    if candidate.exists():
        return candidate

    raise FileNotFoundError(
        "sshoc.config.json (use --config, set SSHOC_CONFIG, or create one at "
        f"{cwd} or {user_path})"
    )


ConfigPathSource = Literal["cli", "env", "cwd", "user", "package"]


@dataclass(frozen=True)
class ConfigPathInfo:
    path: Path
    source: ConfigPathSource
    exists: bool


def resolve_config_path_info(*, cli_path: str | None) -> ConfigPathInfo:
    """
    Resolve the config path and report where it comes from.

    Unlike `resolve_default_config_path`, this never raises if the chosen path
    doesn't exist (useful for diagnostics).
    """
    if cli_path is not None:
        p = Path(_expand_path(cli_path))
        return ConfigPathInfo(path=p, source="cli", exists=p.exists())

    env_path = os.environ.get("SSHOC_CONFIG")
    if env_path:
        p = Path(_expand_path(env_path))
        return ConfigPathInfo(path=p, source="env", exists=p.exists())

    cwd = Path.cwd() / "sshoc.config.json"
    if cwd.exists():
        return ConfigPathInfo(path=cwd, source="cwd", exists=True)

    user_path = default_user_config_path()
    if user_path.exists():
        return ConfigPathInfo(path=user_path, source="user", exists=True)

    component_dir = Path(__file__).resolve().parents[2]  # .../src/sshoc/config.py -> component root
    candidate = component_dir / "sshoc.config.json"
    if candidate.exists():
        return ConfigPathInfo(path=candidate, source="package", exists=True)

    # Nothing found: report the preferred default location.
    return ConfigPathInfo(path=user_path, source="user", exists=False)


def default_user_config_path() -> Path:
    """
    Default per-user config location.

    - Windows: %APPDATA%\\sshoc\\sshoc.config.json
    - macOS: ~/Library/Application Support/sshoc/sshoc.config.json
    - Linux: $XDG_CONFIG_HOME/sshoc/sshoc.config.json (fallback: ~/.config/sshoc/sshoc.config.json)
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        base_dir = Path(base) if base else (Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base_dir = Path.home() / "Library" / "Application Support"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base_dir = Path(_expand_path(xdg)) if xdg else (Path.home() / ".config")
    return base_dir / "sshoc" / "sshoc.config.json"
