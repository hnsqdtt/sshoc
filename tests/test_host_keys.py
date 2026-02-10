from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import paramiko

from sshoc.host_keys import (
    HostKeyInfo,
    add_known_host,
    fingerprint_md5,
    fingerprint_sha256,
    format_host_id,
    matches_expected_fingerprint,
    known_hosts_entries,
    normalize_expected_fingerprint,
)
from sshoc.ssh_client import RunResult


_ED25519_PUBLIC_BASE64 = "AAAAC3NzaC1lZDI1NTE5AAAAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class HostKeysTests(unittest.TestCase):
    def test_format_host_id(self) -> None:
        self.assertEqual(format_host_id("example.com", 22), "example.com")
        self.assertEqual(format_host_id("example.com", 2222), "[example.com]:2222")

    def test_normalize_expected_fingerprint(self) -> None:
        self.assertEqual(normalize_expected_fingerprint("SHA256:abc"), ("sha256", "abc"))
        self.assertEqual(normalize_expected_fingerprint("abc"), ("sha256", "abc"))
        self.assertEqual(normalize_expected_fingerprint("MD5:aa:bb"), ("md5", "aabb"))
        self.assertEqual(normalize_expected_fingerprint("aa:bb"), ("md5", "aabb"))

    def test_add_and_list_known_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kh_path = Path(tmp) / "known_hosts"
            r = add_known_host(
                known_hosts_path=str(kh_path),
                host="example.com",
                port=2222,
                key_type="ssh-ed25519",
                public_key_base64=_ED25519_PUBLIC_BASE64,
                overwrite=False,
            )
            self.assertEqual(r["action"], "added")

            entries = known_hosts_entries(known_hosts_path=str(kh_path), host="example.com", port=2222)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].host_id, "[example.com]:2222")
            self.assertEqual(entries[0].key_type, "ssh-ed25519")

    def test_matches_expected_fingerprint(self) -> None:
        entry = paramiko.hostkeys.HostKeyEntry.from_line(
            f"example.com ssh-ed25519 {_ED25519_PUBLIC_BASE64}"
        )
        assert entry is not None and entry.key is not None
        key = entry.key

        sha = fingerprint_sha256(key)
        md5 = fingerprint_md5(key)
        self.assertTrue(matches_expected_fingerprint(expected=sha, key=key))
        self.assertTrue(matches_expected_fingerprint(expected=sha.split(':', 1)[1], key=key))
        self.assertTrue(matches_expected_fingerprint(expected=md5, key=key))

    def test_host_key_info_to_dict(self) -> None:
        entry = paramiko.hostkeys.HostKeyEntry.from_line(
            f"example.com ssh-ed25519 {_ED25519_PUBLIC_BASE64}"
        )
        assert entry is not None and entry.key is not None
        info = HostKeyInfo.from_key(host="example.com", port=22, key=entry.key)
        d = info.to_dict()
        self.assertEqual(d["host"], "example.com")
        self.assertIn("fingerprint_sha256", d)
        self.assertIn("known_hosts_line", d)

    def test_run_result_to_dict_omits_host_key_when_none(self) -> None:
        rr = RunResult(profile="p", command="c", exit_code=0, stdout="", stderr="", duration_ms=1)
        d = rr.to_dict()
        self.assertNotIn("host_key", d)
        self.assertNotIn("host_key_added", d)
        self.assertNotIn("known_hosts_path", d)


if __name__ == "__main__":
    unittest.main()

