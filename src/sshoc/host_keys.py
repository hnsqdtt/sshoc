from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko


def _expand_path(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


def format_host_id(host: str, port: int) -> str:
    """
    OpenSSH known_hosts host pattern.

    - port 22: "host"
    - non-22: "[host]:port"
    """
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("port must be an int in [1, 65535]")
    if port == 22:
        return host
    return f"[{host}]:{port}"


def _sha256_fingerprint_from_blob(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64}"


def fingerprint_sha256(key: paramiko.PKey) -> str:
    return _sha256_fingerprint_from_blob(key.asbytes())


def fingerprint_md5(key: paramiko.PKey) -> str:
    digest_hex = hashlib.md5(key.asbytes()).hexdigest()  # noqa: S324 (for display/interop only)
    pairs = ":".join(digest_hex[i : i + 2] for i in range(0, len(digest_hex), 2))
    return f"MD5:{pairs}"


def normalize_expected_fingerprint(fp: str) -> tuple[str, str]:
    """
    Normalize an expected fingerprint string.

    Supported forms:
      - "SHA256:<base64>"
      - "<base64>" (treated as sha256 base64)
      - "MD5:<hex-with-or-without-colons>"
      - "<hex-with-colons>" (treated as md5)
    """
    if not isinstance(fp, str):
        raise TypeError("expected_host_key_fingerprint must be a string")
    s = fp.strip()
    if not s:
        raise ValueError("expected_host_key_fingerprint must not be empty")

    if s.lower().startswith("sha256:"):
        v = s.split(":", 1)[1].strip()
        if not v:
            raise ValueError("expected_host_key_fingerprint SHA256 value must not be empty")
        return ("sha256", v)

    if s.lower().startswith("md5:"):
        v = s.split(":", 1)[1].strip().replace(":", "").lower()
        if not v:
            raise ValueError("expected_host_key_fingerprint MD5 value must not be empty")
        return ("md5", v)

    # Heuristic: colon-separated hex => md5
    if ":" in s and all(c in "0123456789abcdefABCDEF:" for c in s):
        return ("md5", s.replace(":", "").lower())

    # Default: sha256 base64
    return ("sha256", s)


@dataclass(frozen=True)
class HostKeyInfo:
    host: str
    port: int
    host_id: str
    key_type: str
    public_key_base64: str
    fingerprint_sha256: str
    fingerprint_md5: str

    @classmethod
    def from_key(cls, *, host: str, port: int, key: paramiko.PKey) -> HostKeyInfo:
        host_id = format_host_id(host, port)
        return cls(
            host=host,
            port=port,
            host_id=host_id,
            key_type=key.get_name(),
            public_key_base64=key.get_base64(),
            fingerprint_sha256=fingerprint_sha256(key),
            fingerprint_md5=fingerprint_md5(key),
        )

    def known_hosts_line(self) -> str:
        return f"{self.host_id} {self.key_type} {self.public_key_base64}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "host_id": self.host_id,
            "key_type": self.key_type,
            "public_key_base64": self.public_key_base64,
            "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_md5": self.fingerprint_md5,
            "known_hosts_line": self.known_hosts_line(),
        }


def matches_expected_fingerprint(*, expected: str, key: paramiko.PKey) -> bool:
    kind, val = normalize_expected_fingerprint(expected)
    if kind == "sha256":
        actual = fingerprint_sha256(key).split(":", 1)[1]
        return actual == val
    actual = fingerprint_md5(key).split(":", 1)[1].replace(":", "").lower()
    return actual == val


def scan_host_key(
    host: str,
    port: int,
    *,
    proxy_command: str | None = None,
    timeout_sec: float | None = 10.0,
) -> tuple[HostKeyInfo, paramiko.PKey]:
    if timeout_sec is not None and not isinstance(timeout_sec, (int, float)):
        raise TypeError("timeout_sec must be a number or null")

    sock = None
    if proxy_command:
        sock = paramiko.ProxyCommand(proxy_command)

    transport = paramiko.Transport(sock if sock is not None else (host, port))
    try:
        transport.start_client(timeout=float(timeout_sec) if timeout_sec is not None else None)
        key = transport.get_remote_server_key()
        return HostKeyInfo.from_key(host=host, port=port, key=key), key
    finally:
        try:
            transport.close()
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


def load_known_hosts(path: str) -> paramiko.HostKeys:
    p = Path(_expand_path(path))
    hk = paramiko.HostKeys()
    try:
        hk.load(str(p))
    except FileNotFoundError:
        pass
    return hk


def known_hosts_entries(*, known_hosts_path: str, host: str, port: int) -> list[HostKeyInfo]:
    hk = load_known_hosts(known_hosts_path)
    host_id = format_host_id(host, port)
    entry = hk.lookup(host_id)
    if not entry:
        return []
    out: list[HostKeyInfo] = []
    for _key_type, key in sorted(entry.items(), key=lambda kv: kv[0]):
        out.append(HostKeyInfo.from_key(host=host, port=port, key=key))
    return out


def add_known_host(
    *,
    known_hosts_path: str,
    host: str,
    port: int,
    key_type: str,
    public_key_base64: str,
    overwrite: bool,
) -> dict[str, Any]:
    if not isinstance(key_type, str) or not key_type:
        raise ValueError("key_type must be a non-empty string")
    if not isinstance(public_key_base64, str) or not public_key_base64:
        raise ValueError("public_key_base64 must be a non-empty string")

    path = Path(_expand_path(known_hosts_path))
    host_id = format_host_id(host, port)

    hk = load_known_hosts(str(path))
    existing = hk.lookup(host_id) or {}
    if (key_type in existing) and not overwrite:
        raise FileExistsError(f"{host_id} already has key type {key_type} (set overwrite=true to replace)")

    entry = paramiko.hostkeys.HostKeyEntry.from_line(f"{host_id} {key_type} {public_key_base64}")
    if entry is None or entry.key is None:
        raise ValueError("failed to parse provided key_type/public_key_base64")
    hk.add(host_id, key_type, entry.key)

    path.parent.mkdir(parents=True, exist_ok=True)
    hk.save(str(path))
    info = HostKeyInfo.from_key(host=host, port=port, key=entry.key)
    return {"action": "replaced" if key_type in existing else "added", "known_hosts_path": str(path), "host_key": info.to_dict()}


def ensure_known_host(
    *,
    known_hosts_path: str,
    host: str,
    port: int,
    proxy_command: str | None,
    timeout_sec: float | None,
    expected_host_key_fingerprint: str | None,
    overwrite: bool,
) -> dict[str, Any]:
    path = Path(_expand_path(known_hosts_path))
    host_id = format_host_id(host, port)

    scanned_info, scanned_key = scan_host_key(
        host,
        port,
        proxy_command=proxy_command,
        timeout_sec=timeout_sec,
    )

    if expected_host_key_fingerprint is not None and not matches_expected_fingerprint(
        expected=expected_host_key_fingerprint, key=scanned_key
    ):
        kind, val = normalize_expected_fingerprint(expected_host_key_fingerprint)
        raise ValueError(
            f"host key fingerprint mismatch ({kind}); expected={val!r} got={scanned_info.fingerprint_sha256 if kind=='sha256' else scanned_info.fingerprint_md5}"
        )

    hk = load_known_hosts(str(path))
    existing = hk.lookup(host_id) or {}
    if scanned_info.key_type in existing:
        existing_key = existing[scanned_info.key_type]
        if existing_key.get_base64() == scanned_info.public_key_base64:
            return {
                "status": "already_known",
                "known_hosts_path": str(path),
                "host_key_added": False,
                "host_key": scanned_info.to_dict(),
            }
        if not overwrite:
            raise ValueError(
                f"known_hosts conflict for {host_id} {scanned_info.key_type}: existing key differs (possible MITM or host reprovisioned)"
            )
        # Explicit overwrite requested.
        entry = paramiko.hostkeys.HostKeyEntry.from_line(scanned_info.known_hosts_line())
        if entry is None or entry.key is None:
            raise ValueError("failed to parse scanned host key (unexpected)")
        hk.add(host_id, scanned_info.key_type, entry.key)
        path.parent.mkdir(parents=True, exist_ok=True)
        hk.save(str(path))
        return {
            "status": "replaced",
            "known_hosts_path": str(path),
            "host_key_added": True,
            "host_key": scanned_info.to_dict(),
        }

    if existing and not overwrite:
        # Host is present with other key types; adding a new type is OK.
        pass

    entry = paramiko.hostkeys.HostKeyEntry.from_line(scanned_info.known_hosts_line())
    if entry is None or entry.key is None:
        raise ValueError("failed to parse scanned host key (unexpected)")
    hk.add(host_id, scanned_info.key_type, entry.key)

    path.parent.mkdir(parents=True, exist_ok=True)
    hk.save(str(path))
    return {
        "status": "added",
        "known_hosts_path": str(path),
        "host_key_added": True,
        "host_key": scanned_info.to_dict(),
    }


def remove_known_host(
    *,
    known_hosts_path: str,
    host: str,
    port: int,
    key_type: str | None,
    remove_all_types: bool,
) -> dict[str, Any]:
    if not isinstance(known_hosts_path, str) or not known_hosts_path:
        raise ValueError("known_hosts_path must be a non-empty string")
    if key_type is not None and (not isinstance(key_type, str) or not key_type):
        raise ValueError("key_type must be a non-empty string or null")
    if not isinstance(remove_all_types, bool):
        raise TypeError("remove_all_types must be a boolean")

    path = Path(_expand_path(known_hosts_path))
    host_id = format_host_id(host, port)

    hk = load_known_hosts(str(path))

    if host_id not in hk:
        return {"action": "not_found", "known_hosts_path": str(path), "host_id": host_id, "key_type": key_type}

    if remove_all_types:
        removed = sorted((hk.get(host_id) or {}).keys())
        hk.pop(host_id, None)
    else:
        if key_type is None:
            raise ValueError("remove requires key_type or remove_all_types=true")
        entry = hk.get(host_id) or {}
        if key_type not in entry:
            return {"action": "not_found", "known_hosts_path": str(path), "host_id": host_id, "key_type": key_type}
        removed = [key_type]
        del entry[key_type]
        if not entry:
            hk.pop(host_id, None)

    path.parent.mkdir(parents=True, exist_ok=True)
    hk.save(str(path))
    return {"action": "removed", "known_hosts_path": str(path), "host_id": host_id, "removed_key_types": removed}
