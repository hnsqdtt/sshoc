from __future__ import annotations

import os
import shlex
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import paramiko

from .config import Config, Defaults, KnownHostsPolicy, Server
from .errors import OutputLimitExceeded
from .host_keys import (
    HostKeyInfo,
    fingerprint_md5,
    fingerprint_sha256,
    format_host_id,
    matches_expected_fingerprint,
    normalize_expected_fingerprint,
)


@dataclass(frozen=True)
class RunResult:
    profile: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    host_key: dict[str, Any] | None = None
    host_key_added: bool | None = None
    known_hosts_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "profile": self.profile,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
        }
        if self.host_key is not None:
            d["host_key"] = self.host_key
            d["host_key_added"] = bool(self.host_key_added)
            d["known_hosts_path"] = self.known_hosts_path
        return d


TaskStatus = Literal["running", "completed", "failed", "killed", "timeout"]


@dataclass
class AsyncTask:
    """Mutable state for one background SSH command execution."""

    task_id: str
    profile: str
    command: str
    status: TaskStatus = "running"
    exit_code: int | None = None
    error: str | None = None
    duration_ms: int | None = None
    started_at: float = field(default_factory=time.monotonic)

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _stdout_buf: bytearray = field(default_factory=bytearray, repr=False)
    _stderr_buf: bytearray = field(default_factory=bytearray, repr=False)
    _channel: paramiko.Channel | None = field(default=None, repr=False)
    _client: paramiko.SSHClient | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _kill_requested: bool = field(default=False, repr=False)

    def append_stdout(self, data: bytes) -> int:
        with self._lock:
            self._stdout_buf += data
            return len(self._stdout_buf)

    def append_stderr(self, data: bytes) -> int:
        with self._lock:
            self._stderr_buf += data
            return len(self._stderr_buf)

    def get_stdout(self) -> str:
        with self._lock:
            return bytes(self._stdout_buf).decode("utf-8", errors="replace")

    def get_stderr(self) -> str:
        with self._lock:
            return bytes(self._stderr_buf).decode("utf-8", errors="replace")

    def get_stdout_bytes(self) -> int:
        with self._lock:
            return len(self._stdout_buf)

    def get_stderr_bytes(self) -> int:
        with self._lock:
            return len(self._stderr_buf)

    def to_status_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "task_id": self.task_id,
            "profile": self.profile,
            "command": self.command,
            "status": self.status,
        }
        if self.exit_code is not None:
            d["exit_code"] = self.exit_code
        if self.error is not None:
            d["error"] = self.error
        if self.duration_ms is not None:
            d["duration_ms"] = self.duration_ms
        d["stdout"] = self.get_stdout()
        d["stderr"] = self.get_stderr()
        d["stdout_bytes"] = self.get_stdout_bytes()
        d["stderr_bytes"] = self.get_stderr_bytes()
        return d


def _sanitize_str(s: str) -> str:
    """Replace lone surrogates (U+D800-U+DFFF) so paramiko UTF-8 encoding never fails."""
    return s.encode("utf-8", errors="replace").decode("utf-8")


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

_UNSET = object()


class _AcceptNewIfFingerprintMatches(paramiko.MissingHostKeyPolicy):
    def __init__(self, *, expected_fingerprint: str, host_id: str):
        self._expected_fingerprint = expected_fingerprint
        self._host_id = host_id

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:  # noqa: ARG002
        if not matches_expected_fingerprint(expected=self._expected_fingerprint, key=key):
            kind, val = normalize_expected_fingerprint(self._expected_fingerprint)
            got = (
                fingerprint_sha256(key).split(":", 1)[1]
                if kind == "sha256"
                else fingerprint_md5(key).split(":", 1)[1].replace(":", "").lower()
            )
            raise paramiko.SSHException(
                f"host key fingerprint mismatch for {self._host_id} ({kind}); expected={val!r} got={got!r}"
            )
        client.get_host_keys().add(self._host_id, key.get_name(), key)


def _expand_path(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


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
        known_hosts_policy: KnownHostsPolicy | None = None,
        known_hosts_path: str | None | object = _UNSET,
        expected_host_key_fingerprint: str | None = None,
        report_host_key: bool = False,
    ) -> RunResult:
        timeout = self._defaults.command_timeout_sec if timeout_sec is None else float(timeout_sec)
        command = _sanitize_str(command)

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

        client, hk_info, hk_added, kh_path = self._connect(
            known_hosts_policy=known_hosts_policy,
            known_hosts_path=known_hosts_path,
            expected_host_key_fingerprint=expected_host_key_fingerprint,
        )
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
        stdout = bytes(stdout_b).decode("utf-8", errors="replace")
        stderr = bytes(stderr_b).decode("utf-8", errors="replace")
        return RunResult(
            profile=self._profile,
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            host_key=hk_info.to_dict() if report_host_key else None,
            host_key_added=hk_added if report_host_key else None,
            known_hosts_path=kh_path if report_host_key else None,
        )

    def run_async_worker(
        self,
        task: AsyncTask,
        *,
        timeout_sec: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        use_pty: bool = False,
        known_hosts_policy: KnownHostsPolicy | None = None,
        known_hosts_path: str | None | object = _UNSET,
        expected_host_key_fingerprint: str | None = None,
    ) -> None:
        """Worker function for daemon thread. Updates *task* in place."""
        try:
            task.command = _sanitize_str(task.command)
            inner = _build_inner_command(
                raw_command=task.command,
                cwd=cwd,
                env=env,
                command_prefix=self._server.command_prefix,
            )
            final = _wrap_with_shell(shell=self._server.shell, inner=inner)

            max_out = self._defaults.max_stdout_bytes
            max_err = self._defaults.max_stderr_bytes

            client, _hk_info, _hk_added, _kh_path = self._connect(
                known_hosts_policy=known_hosts_policy,
                known_hosts_path=known_hosts_path,
                expected_host_key_fingerprint=expected_host_key_fingerprint,
            )
            task._client = client
            try:
                transport = client.get_transport()
                if transport is None:
                    raise RuntimeError("paramiko transport is None (unexpected)")

                channel = transport.open_session(timeout=self._defaults.connect_timeout_sec)
                task._channel = channel
                if use_pty:
                    channel.get_pty()
                channel.exec_command(final)

                while True:
                    if task._kill_requested:
                        channel.close()
                        task.duration_ms = int((time.monotonic() - task.started_at) * 1000)
                        task.status = "killed"
                        return

                    if channel.recv_ready():
                        data = channel.recv(32768)
                        if data:
                            cur = task.append_stdout(data)
                            if cur > max_out:
                                channel.close()
                                task.error = f"stdout exceeded {max_out} bytes"
                                task.duration_ms = int((time.monotonic() - task.started_at) * 1000)
                                task.status = "failed"
                                return

                    if channel.recv_stderr_ready():
                        data = channel.recv_stderr(32768)
                        if data:
                            cur = task.append_stderr(data)
                            if cur > max_err:
                                channel.close()
                                task.error = f"stderr exceeded {max_err} bytes"
                                task.duration_ms = int((time.monotonic() - task.started_at) * 1000)
                                task.status = "failed"
                                return

                    if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        break

                    if timeout_sec is not None and (time.monotonic() - task.started_at) > timeout_sec:
                        channel.close()
                        task.error = f"command timed out after {timeout_sec} sec"
                        task.duration_ms = int((time.monotonic() - task.started_at) * 1000)
                        task.status = "timeout"
                        return

                    time.sleep(0.01)

                task.exit_code = channel.recv_exit_status()
                task.duration_ms = int((time.monotonic() - task.started_at) * 1000)
                task.status = "completed"
            finally:
                client.close()
        except Exception as exc:
            task.error = f"{type(exc).__name__}: {exc}"
            task.duration_ms = int((time.monotonic() - task.started_at) * 1000)
            task.status = "failed"

    def upload(
        self,
        local_path: str,
        remote_path: str,
        *,
        overwrite: bool,
        known_hosts_policy: KnownHostsPolicy | None = None,
        known_hosts_path: str | None | object = _UNSET,
        expected_host_key_fingerprint: str | None = None,
        report_host_key: bool = False,
    ) -> dict[str, Any]:
        from pathlib import Path

        lp = Path(local_path)
        if not lp.exists():
            raise FileNotFoundError(str(lp))
        if not lp.is_file():
            raise ValueError(f"local_path is not a file: {lp}")

        client, hk_info, hk_added, kh_path = self._connect(
            known_hosts_policy=known_hosts_policy,
            known_hosts_path=known_hosts_path,
            expected_host_key_fingerprint=expected_host_key_fingerprint,
        )
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

        out: dict[str, Any] = {"profile": self._profile, "local_path": str(lp), "remote_path": remote_path}
        if report_host_key:
            out["host_key"] = hk_info.to_dict()
            out["host_key_added"] = hk_added
            out["known_hosts_path"] = kh_path
        return out

    def download(
        self,
        remote_path: str,
        local_path: str,
        *,
        overwrite: bool,
        known_hosts_policy: KnownHostsPolicy | None = None,
        known_hosts_path: str | None | object = _UNSET,
        expected_host_key_fingerprint: str | None = None,
        report_host_key: bool = False,
    ) -> dict[str, Any]:
        from pathlib import Path

        lp = Path(local_path)
        if lp.exists() and not overwrite:
            raise FileExistsError(str(lp))
        if not lp.parent.exists():
            raise FileNotFoundError(str(lp.parent))

        client, hk_info, hk_added, kh_path = self._connect(
            known_hosts_policy=known_hosts_policy,
            known_hosts_path=known_hosts_path,
            expected_host_key_fingerprint=expected_host_key_fingerprint,
        )
        try:
            sftp = client.open_sftp()
            try:
                sftp.get(remote_path, str(lp))
            finally:
                sftp.close()
        finally:
            client.close()

        out: dict[str, Any] = {"profile": self._profile, "remote_path": remote_path, "local_path": str(lp)}
        if report_host_key:
            out["host_key"] = hk_info.to_dict()
            out["host_key_added"] = hk_added
            out["known_hosts_path"] = kh_path
        return out

    def _connect(
        self,
        *,
        known_hosts_policy: KnownHostsPolicy | None,
        known_hosts_path: str | None | object,
        expected_host_key_fingerprint: str | None,
    ) -> tuple[paramiko.SSHClient, HostKeyInfo, bool, str | None]:
        client = paramiko.SSHClient()

        policy: KnownHostsPolicy = self._defaults.known_hosts_policy if known_hosts_policy is None else known_hosts_policy
        if policy not in ("strict", "accept_new"):
            raise ValueError("known_hosts_policy must be one of: strict, accept_new")

        kh_path: str | None
        if known_hosts_path is _UNSET:
            kh_path = self._defaults.known_hosts_path
        else:
            kh_path = known_hosts_path if known_hosts_path is None else str(known_hosts_path)
        if kh_path is not None:
            kh_path = _expand_path(kh_path)

        host_id = format_host_id(self._server.host, self._server.port)

        preexisting_types: set[str] = set()
        if kh_path is not None:
            try:
                client.load_host_keys(kh_path)
            except FileNotFoundError:
                # strict policy will fail on unknown keys anyway
                pass
        client.load_system_host_keys()

        if kh_path is not None:
            entry = client.get_host_keys().lookup(host_id)
            if entry:
                preexisting_types = set(entry.keys())

        if policy == "strict":
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif expected_host_key_fingerprint is not None:
            client.set_missing_host_key_policy(
                _AcceptNewIfFingerprintMatches(expected_fingerprint=expected_host_key_fingerprint, host_id=host_id)
            )
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

        transport = client.get_transport()
        if transport is None:
            client.close()
            raise RuntimeError("paramiko transport is None (unexpected)")
        remote_key = transport.get_remote_server_key()
        hk_info = HostKeyInfo.from_key(host=self._server.host, port=self._server.port, key=remote_key)

        if expected_host_key_fingerprint is not None and not matches_expected_fingerprint(
            expected=expected_host_key_fingerprint, key=remote_key
        ):
            kind, val = normalize_expected_fingerprint(expected_host_key_fingerprint)
            got = hk_info.fingerprint_sha256 if kind == "sha256" else hk_info.fingerprint_md5
            client.close()
            raise paramiko.SSHException(
                f"host key fingerprint mismatch for {host_id} ({kind}); expected={val!r} got={got}"
            )

        hk_added = False
        if policy == "accept_new" and kh_path is not None:
            hk_added = remote_key.get_name() not in preexisting_types
            client.save_host_keys(kh_path)

        return client, hk_info, hk_added, kh_path


def build_client(cfg: Config, profile: str) -> SSHClient:
    server = cfg.get_server(profile)
    return SSHClient(profile=profile, server=server, defaults=cfg.defaults)
