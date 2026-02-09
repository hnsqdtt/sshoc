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


def _base_config(*, servers: dict) -> dict:
    return {
        "schema_version": 1,
        "defaults": {
            "connect_timeout_sec": 1,
            "command_timeout_sec": 1,
            "max_stdout_bytes": 1,
            "max_stderr_bytes": 1,
            "known_hosts_policy": "strict",
            "known_hosts_path": None,
            "default_shell": None,
        },
        "servers": servers,
    }


class CliProfileTests(unittest.TestCase):
    def test_profile_remove_edits_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "sshoc.config.json"
            cfg_path.write_text(
                json.dumps(
                    _base_config(
                        servers={
                            "demo": {
                                "ssh_command": "ssh -p 22 user@host",
                                "auth": {"type": "password", "password": "x"},
                            },
                            "other": {
                                "ssh_command": "ssh -p 22 user@host2",
                                "auth": {"type": "password", "password": "y"},
                            },
                        }
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["profile", "remove", "demo", "--config", str(cfg_path)])

            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["action"], "removed")
            self.assertEqual(out["profile"], "demo")
            self.assertEqual(out["remaining"], 1)

            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertNotIn("demo", raw["servers"])
            self.assertIn("other", raw["servers"])

    def test_profile_clear_edits_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "sshoc.config.json"
            cfg_path.write_text(
                json.dumps(
                    _base_config(
                        servers={
                            "demo": {
                                "ssh_command": "ssh -p 22 user@host",
                                "auth": {"type": "password", "password": "x"},
                            },
                            "other": {
                                "ssh_command": "ssh -p 22 user@host2",
                                "auth": {"type": "password", "password": "y"},
                            },
                        }
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["profile", "clear", "--config", str(cfg_path)])

            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["action"], "cleared")
            self.assertEqual(out["removed"], 2)

            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(raw["servers"], {})


if __name__ == "__main__":
    unittest.main()

