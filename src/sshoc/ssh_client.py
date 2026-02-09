from __future__ import annotations

import shlex
import time
from dataclasses import asdict, dataclass
from typing import Any

import paramiko

from .config import Config, Defaults, Server
from .errors import OutputLimitExceeded


@dataclass(frozen=True)
class RunResult:
    profile: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ensure_valid_env_key(k: str) -> None:
    if not k or not (k[0].isalpha() or k[0] == "_") or not all(c.isalnum() or c == "_" for c in k[1:]):
        raise ValueError(f"invalid env key: {k!r}")


def _build_inner_command(
    *,
    raw_command: str,
    cwd: str | None,
    env: dict[str, str] | None,
    command_prefix: str | None,
) -> str:
    pieces: list[str] = []
    if cwd:
        pieces.append(f"cd {shlex.quote(cwd)}")

    if env:
        exports: list[str] = []
        for k, v in env.items():
            _ensure_valid_env_key(k)
            exports.append(f"{k}={shlex.quote(v)}")
        pieces.append("export " + " ".join(exports))

    pieces.append(raw_command)
    inner = " && ".join(pieces)

    if command_prefix:
        prefix = command_prefix
        if not prefix.endswith(("\n", ";")):
            prefix = prefix + ";"
        return f"{prefix} {inner}"

    return inner


def _wrap_with_shell(*, shell: str | None, inner: str) -> str:
    if shell is None:
        return inner
    return f"{shell} {shlex.quote(inner)}"


class SSHClient:
    def __init__(self, *, profile: str, server: Server, defaults: Defaults):
        self._profile = profile
        self._server = server
        self._defaults = defaults

    def run(
        self,
        command: str,
        *,
        timeout_sec: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        use_pty: bool = False,
    ) -> RunResult:
        timeout = self._defaults.command_timeout_sec if timeout_sec is None else float(timeout_sec)

        inner = _build_inner_command(
            raw_command=command,
            cwd=cwd,
            env=env,
            command_prefix=self._server.command_prefix,
        )
        final = _wrap_with_shell(shell=self._server.shell, inner=inner)

        start = time.monotonic()
        stdout_b: bytearray = bytearray()
        stderr_b: bytearray = bytearray()

        client = self._connect()
        try:
            transport = client.get_transport()
            if transport is None:
                raise RuntimeError("paramiko transport is None (unexpected)")

            channel = transport.open_session(timeout=self._defaults.connect_timeout_sec)
            if use_pty:
                channel.get_pty()
            channel.exec_command(final)

            while True:
                if channel.recv_ready():
                    data = channel.recv(32768)
                    if data:
                        stdout_b += data
                        if len(stdout_b) > self._defaults.max_stdout_bytes:
                            channel.close()
                            raise OutputLimitExceeded(stream="stdout", limit_bytes=self._defaults.max_stdout_bytes)

                if channel.recv_stderr_ready():
                    data = channel.recv_stderr(32768)
                    if data:
                        stderr_b += data
                        if len(stderr_b) > self._defaults.max_stderr_bytes:
                            channel.close()
                            raise OutputLimitExceeded(stream="stderr", limit_bytes=self._defaults.max_stderr_bytes)

                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break

                if (time.monotonic() - start) > timeout:
                    channel.close()
                    raise TimeoutError(f"command timed out after {timeout} sec")

                time.sleep(0.01)

            exit_code = channel.recv_exit_status()
        finally:
            client.close()

        duration_ms = int((time.monotonic() - start) * 1000)
        stdout = bytes(stdout_b).decode("utf-8")
        stderr = bytes(stderr_b).decode("utf-8")
        return RunResult(
            profile=self._profile,
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
        )

    def upload(self, local_path: str, remote_path: str, *, overwrite: bool) -> dict[str, Any]:
        from pathlib import Path

        lp = Path(local_path)
        if not lp.exists():
            raise FileNotFoundError(str(lp))
        if not lp.is_file():
            raise ValueError(f"local_path is not a file: {lp}")

        client = self._connect()
        try:
            sftp = client.open_sftp()
            try:
                if not overwrite:
                    try:
                        sftp.stat(remote_path)
                    except OSError as exc:
                        if getattr(exc, "errno", None) == 2:
                            pass
                        else:
                            raise
                    else:
                        raise FileExistsError(remote_path)
                sftp.put(str(lp), remote_path)
            finally:
                sftp.close()
        finally:
            client.close()

        return {"profile": self._profile, "local_path": str(lp), "remote_path": remote_path}

    def download(self, remote_path: str, local_path: str, *, overwrite: bool) -> dict[str, Any]:
        from pathlib import Path

        lp = Path(local_path)
        if lp.exists() and not overwrite:
            raise FileExistsError(str(lp))
        if not lp.parent.exists():
            raise FileNotFoundError(str(lp.parent))

        client = self._connect()
        try:
            sftp = client.open_sftp()
            try:
                sftp.get(remote_path, str(lp))
            finally:
                sftp.close()
        finally:
            client.close()

        return {"profile": self._profile, "remote_path": remote_path, "local_path": str(lp)}

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()

        if self._defaults.known_hosts_path is not None:
            try:
                client.load_host_keys(self._defaults.known_hosts_path)
            except FileNotFoundError:
                # strict policy will fail on unknown keys anyway
                pass
        client.load_system_host_keys()

        if self._defaults.known_hosts_policy == "strict":
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        sock = None
        if self._server.proxy_command:
            sock = paramiko.ProxyCommand(self._server.proxy_command)

        password = self._server.auth.resolve_password() if self._server.auth.type == "password" else None
        key_path = self._server.auth.private_key_path if self._server.auth.type == "key" else None
        passphrase = self._server.auth.resolve_private_key_passphrase() if self._server.auth.type == "key" else None

        client.connect(
            hostname=self._server.host,
            port=self._server.port,
            username=self._server.username,
            password=password,
            key_filename=key_path,
            passphrase=passphrase,
            timeout=self._defaults.connect_timeout_sec,
            auth_timeout=self._defaults.connect_timeout_sec,
            banner_timeout=self._defaults.connect_timeout_sec,
            allow_agent=self._server.auth.allow_agent,
            look_for_keys=self._server.auth.look_for_keys,
            sock=sock,
        )

        if self._defaults.known_hosts_policy == "accept_new" and self._defaults.known_hosts_path is not None:
            client.save_host_keys(self._defaults.known_hosts_path)

        return client


def build_client(cfg: Config, profile: str) -> SSHClient:
    server = cfg.get_server(profile)
    return SSHClient(profile=profile, server=server, defaults=cfg.defaults)
