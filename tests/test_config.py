from __future__ import annotations

import unittest

import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sshoc.config import config_from_dict, default_user_config_path, resolve_config_path_info, resolve_default_config_path


class ConfigTests(unittest.TestCase):
    @contextmanager
    def _temp_env(self, **updates: str | None):
        old = {k: os.environ.get(k) for k in updates}
        try:
            for k, v in updates.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            yield
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_allow_dollar_schema(self) -> None:
        cfg = config_from_dict(
            {
                "$schema": "./sshoc.config.schema.json",
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
                "servers": {
                    "demo": {
                        "ssh_command": "ssh -p 22 root@1.2.3.4",
                        "auth": {"type": "password", "password": "x"},
                    }
                },
            }
        )
        self.assertEqual(cfg.get_server("demo").port, 22)

    def test_reject_unknown_top_keys(self) -> None:
        with self.assertRaises(Exception):
            config_from_dict({"schema_version": 1, "defaults": {}, "servers": {}, "extra": 1})

    def test_allow_empty_servers(self) -> None:
        cfg = config_from_dict(
            {
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
                "servers": {},
            }
        )
        self.assertEqual(cfg.servers, {})

    def test_password_auth_requires_secret(self) -> None:
        with self.assertRaises(Exception):
            config_from_dict(
                {
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
                    "servers": {
                        "demo": {
                            "host": "x",
                            "port": 22,
                            "username": "u",
                            "auth": {"type": "password"},
                        }
                    },
                }
            )

    def test_ssh_command_parsing(self) -> None:
        cfg = config_from_dict(
            {
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
                "servers": {
                    "demo": {
                        "ssh_command": "ssh -p 2222 root@1.2.3.4",
                        "auth": {"type": "password", "password": "x"},
                    }
                },
            }
        )
        srv = cfg.get_server("demo")
        self.assertEqual(srv.host, "1.2.3.4")
        self.assertEqual(srv.port, 2222)
        self.assertEqual(srv.username, "root")

    def test_resolve_default_config_path_prefers_cwd_then_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            (cwd / "sshoc.config.json").write_text("{}", encoding="utf-8")
            old_cwd = os.getcwd()
            try:
                os.chdir(str(cwd))
                with self._temp_env(SSHOC_CONFIG=None):
                    resolved = resolve_default_config_path(cli_path=None)
            finally:
                os.chdir(old_cwd)
        self.assertEqual(resolved, cwd / "sshoc.config.json")

    def test_resolve_default_config_path_uses_user_location(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._temp_env(
                SSHOC_CONFIG=None,
                # Windows uses APPDATA; Linux uses XDG_CONFIG_HOME; macOS uses HOME.
                APPDATA=str(base),
                XDG_CONFIG_HOME=str(base),
                HOME=str(base),
            ):
                user_cfg = default_user_config_path()
                user_cfg.parent.mkdir(parents=True, exist_ok=True)
                user_cfg.write_text("{}", encoding="utf-8")

                with tempfile.TemporaryDirectory() as other:
                    old_cwd = os.getcwd()
                    try:
                        os.chdir(other)
                        resolved = resolve_default_config_path(cli_path=None)
                    finally:
                        os.chdir(old_cwd)

        self.assertEqual(resolved, user_cfg)

    def test_resolve_config_path_info_reports_env_even_if_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            with self._temp_env(SSHOC_CONFIG=str(missing)):
                info = resolve_config_path_info(cli_path=None)
        self.assertEqual(info.source, "env")
        self.assertEqual(info.path, missing)
        self.assertFalse(info.exists)


if __name__ == "__main__":
    unittest.main()
