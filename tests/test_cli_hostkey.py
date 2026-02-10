from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sshoc.cli import main as cli_main


_ED25519_PUBLIC_BASE64 = "AAAAC3NzaC1lZDI1NTE5AAAAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _base_config(*, known_hosts_path: str, servers: dict) -> dict:
    return {
        "schema_version": 1,
        "defaults": {
            "connect_timeout_sec": 1,
            "command_timeout_sec": 1,
            "max_stdout_bytes": 1,
            "max_stderr_bytes": 1,
            "known_hosts_policy": "strict",
            "known_hosts_path": known_hosts_path,
            "default_shell": None,
        },
        "servers": servers,
    }


class CliHostKeyTests(unittest.TestCase):
    def test_hostkey_add_is_known_remove(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            kh_path = tmp_path / "known_hosts"
            cfg_path = tmp_path / "sshoc.config.json"
            cfg_path.write_text(
                json.dumps(
                    _base_config(
                        known_hosts_path=str(kh_path),
                        servers={
                            "demo": {
                                "host": "example.com",
                                "port": 2222,
                                "username": "u",
                                "auth": {"type": "password", "password": "x"},
                            }
                        },
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["hostkey", "is-known", "demo", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertFalse(out["known"])
            self.assertEqual(out["host_id"], "[example.com]:2222")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(
                    [
                        "hostkey",
                        "add",
                        "demo",
                        "--key-type",
                        "ssh-ed25519",
                        "--public-key-base64",
                        _ED25519_PUBLIC_BASE64,
                        "--config",
                        str(cfg_path),
                    ]
                )
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["action"], "added")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["hostkey", "is-known", "demo", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertTrue(out["known"])
            self.assertEqual(len(out["entries"]), 1)
            self.assertEqual(out["entries"][0]["key_type"], "ssh-ed25519")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["hostkey", "remove", "demo", "--key-type", "ssh-ed25519", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["action"], "removed")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["hostkey", "is-known", "demo", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertFalse(out["known"])

            # Remove again -> not found (still returns 0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["hostkey", "remove", "demo", "--key-type", "ssh-ed25519", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["action"], "not_found")

    def test_hostkey_remove_all_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            kh_path = tmp_path / "known_hosts"
            cfg_path = tmp_path / "sshoc.config.json"
            cfg_path.write_text(
                json.dumps(
                    _base_config(
                        known_hosts_path=str(kh_path),
                        servers={
                            "demo": {
                                "host": "example.com",
                                "port": 2222,
                                "username": "u",
                                "auth": {"type": "password", "password": "x"},
                            }
                        },
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(
                    [
                        "hostkey",
                        "add",
                        "demo",
                        "--key-type",
                        "ssh-ed25519",
                        "--public-key-base64",
                        _ED25519_PUBLIC_BASE64,
                        "--config",
                        str(cfg_path),
                    ]
                )
            self.assertEqual(rc, 0)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["hostkey", "remove", "demo", "--all-types", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["action"], "removed")


if __name__ == "__main__":
    unittest.main()

