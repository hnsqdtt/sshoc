from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .config import (
    config_from_dict,
    default_user_config_path,
    load_config,
    resolve_config_path_info,
    resolve_default_config_path,
)
from .host_keys import (
    add_known_host,
    ensure_known_host,
    format_host_id,
    known_hosts_entries,
    remove_known_host,
    scan_host_key,
)
from .ssh_client import build_client


def _add_config_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="Path to sshoc.config.json (or set SSHOC_CONFIG)")


def _configure_utf8_stdio() -> None:
    """
    Best-effort UTF-8 output on Windows consoles (avoid garbled non-ASCII paths).
    """
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _subcmd_requires_config(args: argparse.Namespace) -> bool:
    subcmd = getattr(args, "subcmd", None)
    if subcmd in (None, "init"):
        return False
    if subcmd == "config" and getattr(args, "config_subcmd", None) == "path":
        return False
    return True


def _eprint(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def _print_missing_config_hint() -> None:
    _eprint("Next:")
    _eprint("  sshoc init --local")
    _eprint('  sshoc init demo --ssh "ssh -p 22 user@host" --password-env SSHOC_DEMO_PASSWORD')


def _cmd_list(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    rows = [
        {"profile": name, "host": srv.host, "port": srv.port, "username": srv.username}
        for name, srv in sorted(cfg.servers.items(), key=lambda kv: kv[0])
    ]
    sys.stdout.write(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    client = build_client(cfg, args.profile)
    env = None
    if args.env:
        env = {}
        for kv in args.env:
            if "=" not in kv:
                raise ValueError(f"--env must be KEY=VALUE, got: {kv!r}")
            k, v = kv.split("=", 1)
            env[k] = v
    rr = client.run(
        args.command,
        timeout_sec=args.timeout_sec,
        cwd=args.cwd,
        env=env,
        use_pty=args.pty,
    )
    sys.stdout.write(json.dumps(rr.to_dict(), ensure_ascii=False, indent=2) + "\n")
    return 0 if rr.exit_code == 0 else rr.exit_code


def _cmd_upload(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    client = build_client(cfg, args.profile)
    result = client.upload(args.local, args.remote, overwrite=args.overwrite)
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


def _cmd_download(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    client = build_client(cfg, args.profile)
    result = client.download(args.remote, args.local, overwrite=args.overwrite)
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


def _resolve_hostkey_target(cfg, args: argparse.Namespace) -> tuple[str, int, str | None, str | None]:
    """
    Resolve (host, port, proxy_command, profile) from either:
      - positional <profile>
      - or: --host/--port/--proxy-command
    """
    profile = getattr(args, "profile", None)
    host = getattr(args, "host", None)
    port = getattr(args, "port", 22)
    proxy_command = getattr(args, "proxy_command", None)

    if profile is not None and host is not None:
        raise ValueError("provide either <profile> or --host/--port, not both")

    if profile is not None:
        if not isinstance(profile, str) or profile == "":
            raise ValueError("<profile> must be a non-empty string")
        srv = cfg.get_server(profile)
        return srv.host, srv.port, srv.proxy_command, profile

    if host is None:
        raise ValueError("hostkey commands require <profile> or --host")
    if not isinstance(host, str) or host == "":
        raise ValueError("--host must be a non-empty string")
    if not isinstance(port, int):
        raise ValueError("--port must be an integer")
    return host, port, proxy_command, None


def _resolve_known_hosts_path(cfg, args: argparse.Namespace) -> str:
    kh_path = getattr(args, "known_hosts_path", None)
    if kh_path is None:
        kh_path = cfg.defaults.known_hosts_path
    if kh_path is None:
        raise ValueError("known_hosts_path is null; set defaults.known_hosts_path or pass --known-hosts-path")
    if not isinstance(kh_path, str) or kh_path == "":
        raise ValueError("--known-hosts-path must be a non-empty string")
    return kh_path


def _cmd_hostkey_scan(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    host, port, proxy_command, profile = _resolve_hostkey_target(cfg, args)

    info, _key = scan_host_key(host, port, proxy_command=proxy_command, timeout_sec=args.timeout_sec)
    out: dict[str, Any] = {"host_key": info.to_dict()}
    if profile is not None:
        out["profile"] = profile
    sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    return 0


def _cmd_hostkey_is_known(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    host, port, _proxy_command, profile = _resolve_hostkey_target(cfg, args)
    kh_path = _resolve_known_hosts_path(cfg, args)

    entries = known_hosts_entries(known_hosts_path=kh_path, host=host, port=port)
    out: dict[str, Any] = {
        "known": bool(entries),
        "known_hosts_path": kh_path,
        "host_id": format_host_id(host, port),
        "entries": [e.to_dict() for e in entries],
    }
    if profile is not None:
        out["profile"] = profile
    sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    return 0


def _cmd_hostkey_add(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    host, port, _proxy_command, profile = _resolve_hostkey_target(cfg, args)
    kh_path = _resolve_known_hosts_path(cfg, args)

    result = add_known_host(
        known_hosts_path=kh_path,
        host=host,
        port=port,
        key_type=args.key_type,
        public_key_base64=args.public_key_base64,
        overwrite=args.overwrite,
    )
    if profile is not None:
        result["profile"] = profile
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


def _cmd_hostkey_ensure(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    host, port, proxy_command, profile = _resolve_hostkey_target(cfg, args)
    kh_path = _resolve_known_hosts_path(cfg, args)

    result = ensure_known_host(
        known_hosts_path=kh_path,
        host=host,
        port=port,
        proxy_command=proxy_command,
        timeout_sec=args.timeout_sec,
        expected_host_key_fingerprint=args.expected_fingerprint,
        overwrite=args.overwrite,
    )
    if profile is not None:
        result["profile"] = profile
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


def _cmd_hostkey_remove(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    host, port, _proxy_command, profile = _resolve_hostkey_target(cfg, args)
    kh_path = _resolve_known_hosts_path(cfg, args)

    result = remove_known_host(
        known_hosts_path=kh_path,
        host=host,
        port=port,
        key_type=args.key_type,
        remove_all_types=args.all_types,
    )
    if profile is not None:
        result["profile"] = profile
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


def _cmd_prefix(args: argparse.Namespace) -> int:
    cfg_path = resolve_default_config_path(cli_path=args.config)
    cfg = load_config(cfg_path)
    profile = args.profile
    if not profile.endswith(":"):
        raise ValueError("prefix mode requires '<profile>:'")
    profile = profile[:-1]
    command = " ".join(args.command_parts)
    client = build_client(cfg, profile)
    rr = client.run(command)
    sys.stdout.write(json.dumps(rr.to_dict(), ensure_ascii=False, indent=2) + "\n")
    return 0 if rr.exit_code == 0 else rr.exit_code


def _default_template_config() -> dict:
    return {
        "schema_version": 1,
        "defaults": {
            "connect_timeout_sec": 10,
            "command_timeout_sec": 120,
            "max_stdout_bytes": 10485760,
            "max_stderr_bytes": 10485760,
            "known_hosts_policy": "strict",
            "known_hosts_path": "~/.ssh/known_hosts",
            "default_shell": "bash -lc",
        },
        "servers": {
            "demo": {
                "ssh_command": "ssh -p 22 user@your-host",
                "auth": {"type": "password", "password_env": "SSHOC_DEMO_PASSWORD"},
            }
        },
    }

def _single_profile_config(*, profile: str, ssh_command: str, auth: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "defaults": _default_template_config()["defaults"],
        "servers": {profile: {"ssh_command": ssh_command, "auth": auth}},
    }

def _read_config_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"config root must be an object, got {type(raw).__name__}")
    return raw


def _write_json_atomic(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _cmd_init(args: argparse.Namespace) -> int:
    # Determine target path.
    if args.output:
        target = Path(os.path.expandvars(os.path.expanduser(args.output))).resolve()
    elif args.local:
        target = Path.cwd() / "sshoc.config.json"
    else:
        target = default_user_config_path()

    existed = target.exists()
    if target.exists() and not args.force:
        raise FileExistsError(f"{target} already exists (use --force to overwrite)")

    # Build config content.
    if args.profile is None:
        if any(
            x is not None
            for x in (
                args.ssh_command,
                args.password_env,
                args.password,
                args.key_path,
                args.key_passphrase_env,
            )
        ):
            raise ValueError("init without <profile> does not accept --ssh/--password-env/--password/--key-* flags")
        cfg_dict = _default_template_config()
    else:
        if not isinstance(args.profile, str) or args.profile == "":
            raise ValueError("<profile> must be a non-empty string")
        if args.ssh_command is None:
            raise ValueError("init <profile> requires --ssh")

        if args.key_passphrase_env is not None and args.key_path is None:
            raise ValueError("--key-passphrase-env requires --key-path")

        auth: dict
        if args.password_env is not None:
            auth = {"type": "password", "password_env": args.password_env}
        elif args.password is not None:
            auth = {"type": "password", "password": args.password}
        elif args.key_path is not None:
            auth = {"type": "key", "private_key_path": args.key_path}
            if args.key_passphrase_env is not None:
                auth["private_key_passphrase_env"] = args.key_passphrase_env
        else:
            raise ValueError("init <profile> requires one of: --password-env, --password, --key-path")

        cfg_dict = _single_profile_config(profile=args.profile, ssh_command=args.ssh_command, auth=auth)

    # Validate (fail fast) before writing.
    config_from_dict(cfg_dict)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(cfg_dict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    action = "overwritten" if existed else "created"
    sys.stdout.write(json.dumps({"path": str(target), "action": action}, ensure_ascii=False) + "\n")
    return 0


def _cmd_config_path(args: argparse.Namespace) -> int:
    info = resolve_config_path_info(cli_path=args.config)
    sys.stdout.write(
        json.dumps({"path": str(info.path), "source": info.source, "exists": info.exists}, ensure_ascii=False) + "\n"
    )
    return 0 if info.exists else 2


def _cmd_profile_remove(args: argparse.Namespace) -> int:
    info = resolve_config_path_info(cli_path=args.config)
    if info.source == "package" and args.config is None:
        raise FileNotFoundError("refusing to modify package config; run `sshoc init` or pass --config")
    if not info.exists:
        raise FileNotFoundError(str(info.path))

    cfg_path = info.path
    raw = _read_config_json(cfg_path)
    servers = raw.get("servers")
    if not isinstance(servers, dict):
        raise TypeError(f"root.servers must be an object, got {type(servers).__name__}")

    profile = args.profile
    if profile not in servers:
        raise KeyError(f"unknown profile: {profile!r}")

    servers.pop(profile)
    raw["servers"] = servers

    config_from_dict(raw)
    _write_json_atomic(cfg_path, raw)
    sys.stdout.write(
        json.dumps(
            {"path": str(cfg_path), "action": "removed", "profile": profile, "remaining": len(servers)},
            ensure_ascii=False,
        )
        + "\n"
    )
    return 0


def _cmd_profile_clear(args: argparse.Namespace) -> int:
    info = resolve_config_path_info(cli_path=args.config)
    if info.source == "package" and args.config is None:
        raise FileNotFoundError("refusing to modify package config; run `sshoc init` or pass --config")
    if not info.exists:
        raise FileNotFoundError(str(info.path))

    cfg_path = info.path
    raw = _read_config_json(cfg_path)
    servers = raw.get("servers")
    if not isinstance(servers, dict):
        raise TypeError(f"root.servers must be an object, got {type(servers).__name__}")
    removed_count = len(servers)
    raw["servers"] = {}

    config_from_dict(raw)
    _write_json_atomic(cfg_path, raw)
    sys.stdout.write(
        json.dumps({"path": str(cfg_path), "action": "cleared", "removed": removed_count}, ensure_ascii=False) + "\n"
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sshoc", add_help=True)
    _add_config_arg(p)
    sub = p.add_subparsers(dest="subcmd", required=False)

    sp = sub.add_parser("list", help="List configured server profiles")
    _add_config_arg(sp)
    sp.set_defaults(_handler=_cmd_list)

    sp = sub.add_parser("run", help="Run a remote command")
    _add_config_arg(sp)
    sp.add_argument("profile")
    sp.add_argument("--cmd", dest="command", required=True)
    sp.add_argument("--timeout-sec", type=float)
    sp.add_argument("--cwd")
    sp.add_argument("--env", action="append", help="KEY=VALUE (repeatable)")
    sp.add_argument("--pty", action="store_true")
    sp.set_defaults(_handler=_cmd_run)

    sp = sub.add_parser("upload", help="Upload local file to remote")
    _add_config_arg(sp)
    sp.add_argument("profile")
    sp.add_argument("--local", required=True)
    sp.add_argument("--remote", required=True)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(_handler=_cmd_upload)

    sp = sub.add_parser("download", help="Download remote file to local")
    _add_config_arg(sp)
    sp.add_argument("profile")
    sp.add_argument("--remote", required=True)
    sp.add_argument("--local", required=True)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(_handler=_cmd_download)

    sp = sub.add_parser("hostkey", help="Host key / known_hosts helpers")
    sub2 = sp.add_subparsers(dest="hostkey_subcmd", required=True)

    sp2 = sub2.add_parser("scan", help="Scan remote SSH host key (no auth)")
    _add_config_arg(sp2)
    sp2.add_argument("profile", nargs="?", help="Profile name (omit when using --host)")
    sp2.add_argument("--host", help="Host (when not using profile)")
    sp2.add_argument("--port", type=int, default=22, help="Port (when not using profile)")
    sp2.add_argument("--proxy-command", dest="proxy_command", help="ProxyCommand (when not using profile)")
    sp2.add_argument("--timeout-sec", dest="timeout_sec", type=float, default=10.0)
    sp2.set_defaults(_handler=_cmd_hostkey_scan)

    sp2 = sub2.add_parser("is-known", help="Check known_hosts for a host")
    _add_config_arg(sp2)
    sp2.add_argument("profile", nargs="?", help="Profile name (omit when using --host)")
    sp2.add_argument("--host", help="Host (when not using profile)")
    sp2.add_argument("--port", type=int, default=22, help="Port (when not using profile)")
    sp2.add_argument("--known-hosts-path", dest="known_hosts_path")
    sp2.set_defaults(_handler=_cmd_hostkey_is_known)

    sp2 = sub2.add_parser("add", help="Add a host key entry to known_hosts")
    _add_config_arg(sp2)
    sp2.add_argument("profile", nargs="?", help="Profile name (omit when using --host)")
    sp2.add_argument("--host", help="Host (when not using profile)")
    sp2.add_argument("--port", type=int, default=22, help="Port (when not using profile)")
    sp2.add_argument("--known-hosts-path", dest="known_hosts_path")
    sp2.add_argument("--key-type", required=True)
    sp2.add_argument("--public-key-base64", required=True)
    sp2.add_argument("--overwrite", action="store_true")
    sp2.set_defaults(_handler=_cmd_hostkey_add)

    sp2 = sub2.add_parser("ensure", help="Scan and write the host key into known_hosts")
    _add_config_arg(sp2)
    sp2.add_argument("profile", nargs="?", help="Profile name (omit when using --host)")
    sp2.add_argument("--host", help="Host (when not using profile)")
    sp2.add_argument("--port", type=int, default=22, help="Port (when not using profile)")
    sp2.add_argument("--proxy-command", dest="proxy_command", help="ProxyCommand (when not using profile)")
    sp2.add_argument("--timeout-sec", dest="timeout_sec", type=float, default=10.0)
    sp2.add_argument("--known-hosts-path", dest="known_hosts_path")
    sp2.add_argument("--expected-fingerprint", dest="expected_fingerprint")
    sp2.add_argument("--overwrite", action="store_true")
    sp2.set_defaults(_handler=_cmd_hostkey_ensure)

    sp2 = sub2.add_parser("remove", help="Remove a host key entry from known_hosts")
    _add_config_arg(sp2)
    sp2.add_argument("profile", nargs="?", help="Profile name (omit when using --host)")
    sp2.add_argument("--host", help="Host (when not using profile)")
    sp2.add_argument("--port", type=int, default=22, help="Port (when not using profile)")
    sp2.add_argument("--known-hosts-path", dest="known_hosts_path")
    group = sp2.add_mutually_exclusive_group(required=True)
    group.add_argument("--key-type")
    group.add_argument("--all-types", action="store_true")
    sp2.set_defaults(_handler=_cmd_hostkey_remove)

    sp = sub.add_parser("init", help="Create a sshoc.config.json (template or single-profile)")
    sp.add_argument("profile", nargs="?", help="Profile name to create (omit to write full template)")
    sp.add_argument("--ssh", dest="ssh_command", help='SSH command, e.g. "ssh -p 22 user@host"')
    auth = sp.add_mutually_exclusive_group()
    auth.add_argument("--password-env", help="ENV var name for password (recommended)")
    auth.add_argument("--password", help="Password value (NOT recommended; do not commit)")
    auth.add_argument("--key-path", help="Private key path for key auth")
    sp.add_argument("--key-passphrase-env", help="ENV var name for private key passphrase (key auth)")
    sp.add_argument(
        "--output",
        help="Write to path (default: per-user config path; use --local for ./sshoc.config.json)",
    )
    sp.add_argument("--local", action="store_true", help="Write ./sshoc.config.json in current directory")
    sp.add_argument("--force", action="store_true", help="Overwrite if target already exists")
    sp.set_defaults(_handler=_cmd_init)

    sp = sub.add_parser("config", help="Config helpers")
    sub2 = sp.add_subparsers(dest="config_subcmd", required=True)
    sp2 = sub2.add_parser("path", help="Print the resolved config path (and whether it exists)")
    _add_config_arg(sp2)
    sp2.set_defaults(_handler=_cmd_config_path)

    sp = sub.add_parser("profile", help="Profile management")
    sub2 = sp.add_subparsers(dest="profile_subcmd", required=True)

    sp2 = sub2.add_parser("remove", help="Remove a profile from config")
    _add_config_arg(sp2)
    sp2.add_argument("profile")
    sp2.set_defaults(_handler=_cmd_profile_remove)

    sp2 = sub2.add_parser("clear", help="Clear all profiles (servers) in config")
    _add_config_arg(sp2)
    sp2.set_defaults(_handler=_cmd_profile_clear)

    # Prefix mode: sshoc demo: <command...>
    sp = sub.add_parser(":", help=argparse.SUPPRESS)
    _add_config_arg(sp)
    sp.add_argument("profile")
    sp.add_argument("command_parts", nargs=argparse.REMAINDER)
    sp.set_defaults(_handler=_cmd_prefix)

    return p


def _rewrite_prefix_argv(argv: list[str]) -> list[str]:
    # Accept: sshoc <profile>: <command...>
    i = 1
    if len(argv) >= 3 and argv[1] == "--config":
        i = 3
    if len(argv) > i and argv[i].endswith(":") and argv[i] != ":":
        return [*argv[:i], ":", argv[i], *argv[i + 1 :]]
    return argv


def main(argv: list[str] | None = None) -> int:
    _configure_utf8_stdio()
    argv = sys.argv if argv is None else [sys.argv[0], *argv]
    argv = _rewrite_prefix_argv(list(argv))
    parser = _build_parser()
    args = parser.parse_args(argv[1:])

    if not hasattr(args, "_handler"):
        parser.print_help()
        return 2

    handler = getattr(args, "_handler")
    try:
        return int(handler(args))
    except FileNotFoundError as exc:
        _eprint(f"sshoc: error: {exc}")
        info = resolve_config_path_info(cli_path=getattr(args, "config", None))
        if _subcmd_requires_config(args) and not info.exists:
            _print_missing_config_hint()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
