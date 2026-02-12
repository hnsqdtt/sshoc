# SSHOC

English | [简体中文](README.md)

A lightweight, config-driven SSH toolkit (CLI + optional MCP stdio adapter).

- **CLI**: `sshoc` (`list/run/upload/download/hostkey/...`, plus prefix mode `sshoc <profile>: <command...>`)
- **MCP (stdio)**: `sshoc-mcp` (line-delimited JSON-RPC, exposes `ssh.*` tools to MCP clients)
- **Dependency**: `paramiko` (SSH/SFTP)

> Goal: strict, predictable, easy to embed (especially for automation / AI workflows).

---

## Quick start (pip users)

1) Install:

```bash
python -m pip install -U sshoc
```

> Windows note: if `sshoc` is still “not recognized” after install, your Python scripts directory (where `sshoc.exe` is generated) is likely not on `PATH`. Print the scripts directory and add it to `PATH`, then reopen your terminal:
>
> ```bash
> python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
> ```

2) Initialize config (recommended: per-user config directory):

```bash
# Password auth (recommended: store password in an env var)
sshoc init demo --ssh "ssh -p 22 user@host" --password-env SSHOC_DEMO_PASSWORD

# Or: key auth
sshoc init demo --ssh "ssh -p 22 user@host" --key-path ~/.ssh/id_ed25519
```

3) Set the password env var (only needed for `password_env`):

```powershell
$env:SSHOC_DEMO_PASSWORD="your_password"
```

```bash
export SSHOC_DEMO_PASSWORD="your_password"
```

4) First connection (known_hosts):

Default `known_hosts_policy=strict`. If the host key is not present in your local `known_hosts`, the first connection will fail. Recommended: write the host key first (optionally verify a trusted fingerprint):

```bash
sshoc hostkey ensure demo
# Strongly recommended (if you can get a trusted fingerprint from your provider/admin):
# sshoc hostkey ensure demo --expected-fingerprint "SHA256:..."
```

5) Run a command:

```bash
sshoc demo: uname -a
# Or
sshoc run demo --cmd "uname -a"
```

---

## Installation (development)

Install from source (recommended: create a venv in this directory):

```bash
cd "SSH_Operation_Component (MCP)"
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install -U pip
python -m pip install -e .
```

---

## Configuration

### Where is the config file (and which one is in use)?

```bash
sshoc config path
```

### Practical tip: pin the config path with `SSHOC_CONFIG`

```powershell
$env:SSHOC_CONFIG="C:\\path\\to\\sshoc.config.json"
```

```bash
export SSHOC_CONFIG="/path/to/sshoc.config.json"
```

### Key fields (cheatsheet)

- `servers.<profile>`: profile name (recommended: `A-Za-z0-9_-`)
- `servers.<profile>.ssh_command`: common form `ssh -p <port> user@host`
- `auth.type`:
  - `password`: `password` or `password_env`
  - `key`: `private_key_path` (optional `private_key_passphrase_env`)
- `known_hosts_policy`:
  - `strict`: default; unknown host keys fail fast (safer)
  - `accept_new`: auto-write to `known_hosts_path` on first connect (TOFU)
- `known_hosts_path`: OpenSSH `known_hosts` path (template default: `~/.ssh/known_hosts`)
- `default_shell`: default `bash -lc` (set to `null` if the remote has no bash)

---

## CLI

### Common commands

```bash
sshoc list
sshoc demo: "ls -la /root"
sshoc run demo --cmd "python -V"
sshoc upload demo --local ./local.txt --remote /tmp/local.txt --overwrite
sshoc download demo --remote /tmp/local.txt --local ./downloaded.txt --overwrite
```

### Host key / known_hosts

These commands print JSON (friendly for scripts/CI/automation).

```bash
# Scan the remote host key (no auth)
sshoc hostkey scan demo

# Check whether the host is present in known_hosts
sshoc hostkey is-known demo

# Scan + write into known_hosts (optional fingerprint verification)
sshoc hostkey ensure demo
sshoc hostkey ensure demo --expected-fingerprint "SHA256:..."

# Manually add a key (if you already have key_type + base64)
sshoc hostkey add demo --key-type ssh-ed25519 --public-key-base64 "<BASE64>"

# Precise removal: remove one key type, or remove all key types for the host
sshoc hostkey remove demo --key-type ssh-ed25519
sshoc hostkey remove demo --all-types
```

---

## MCP (stdio) server

Start:

```bash
sshoc-mcp
```

Tools:

- `ssh.list_profiles`
- `ssh.scan_host_key`
- `ssh.is_known_host`
- `ssh.add_known_host`
- `ssh.ensure_known_host`
- `ssh.run`
- `ssh.upload`
- `ssh.download`

### Generic stdio config blueprint (for MCP clients)

Different MCP clients may use different config formats, but the essentials are usually: `command` / `args` / `env` / `cwd`. Below is a generic blueprint (field names are for reference—adapt to your client):

```jsonc
{
  "mcpServers": {
    "sshoc": {
      "command": "sshoc-mcp",
      "args": ["--config", "<ABS_CONFIG_PATH>"],
      "env": {
        "SSHOC_DEMO_PASSWORD": "your_password",
        "SSHOC_DEBUG": "0"
      },
      "cwd": "<OPTIONAL_WORKDIR>"
    }
  }
}
// Examples for <ABS_CONFIG_PATH>:
// - macOS/Linux: /path/to/sshoc.config.json
// - Windows: C:\\path\\to\\sshoc.config.json
```

---

## Security notes (strongly recommended)

- Never commit plaintext passwords; prefer `password_env`
- `accept_new` is TOFU (trust on first use); safer: verify with `--expected-fingerprint`
- This tool effectively gives automation/AI a remote execution entry point—use it only in environments you trust

---

## License

Apache-2.0 (see `LICENSE`)
