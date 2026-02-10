# SSHOC

English | [简体中文](README.md)

A lightweight, config-driven SSH toolkit (CLI + optional MCP stdio adapter). Configure multiple servers in `json`, then use:

- **CLI prefix command**: `sshoc <profile>: <command...>` (quickly run remote commands)
- **MCP (stdio) server**: Exposes `tools/list` / `tools/call` so MCP clients can call `ssh.run` / `ssh.upload` / `ssh.download`

> Dependency: `paramiko` (SSH/SFTP).

---

## Quick start (pip users)

1) Install:

```bash
python -m pip install -U sshoc
```

2) Initialize config (write to the per-user config directory, recommended):

```bash
# Password auth (recommended: store password in an env var)
sshoc init demo --ssh "ssh -p 22 user@host" --password-env SSHOC_DEMO_PASSWORD

# Or: key auth
sshoc init demo --ssh "ssh -p 22 user@host" --key-path ~/.ssh/id_ed25519
```

3) Set the password environment variable (only needed for `password_env`):

```powershell
$env:SSHOC_DEMO_PASSWORD="your_password"
```

```bash
export SSHOC_DEMO_PASSWORD="your_password"
```

4) Use:

```bash
sshoc list
sshoc demo: uname -a
```

---

## Installation

### Option A: Install from PyPI (recommended)

```bash
python -m pip install -U sshoc
```

### Option B: Install from source (development)

Recommended: create a virtual environment in this directory (or use your preferred workflow):

```bash
cd "SSH_Operation_Component (MCP)"
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install -U pip
python -m pip install -e .
```

---

## Configuration

### 1) Generate config (`sshoc init`)

```bash
# Write to the per-user config directory (recommended)
sshoc init

# Or write to ./sshoc.config.json in the current directory
sshoc init --local

# Or write to an arbitrary path
sshoc init --output /path/to/sshoc.config.json
```

Notes:

- `sshoc init` (without `<profile>`) writes the **full template** (including the demo profile).
- `sshoc init <profile> --ssh ... --password-env/--password/--key-path ...` writes a **single-profile config** (better for a quick start with pip).

### 2) Where is the config file (and which one is currently in use)?

Use this command to see which config file is being used:

```bash
sshoc config path
```

It prints:

- `path`: config file path
- `source`: where it comes from (`cli|env|cwd|user|package`)
- `exists`: whether the path exists

Default per-user config locations:

- Windows: `%APPDATA%\\sshoc\\sshoc.config.json`
- macOS: `~/Library/Application Support/sshoc/sshoc.config.json`
- Linux: `~/.config/sshoc/sshoc.config.json` (or `$XDG_CONFIG_HOME/sshoc/sshoc.config.json`)

### 3) Practical tip: pin the config path with `SSHOC_CONFIG`

If you want the same config to be used no matter which directory you run from, set `SSHOC_CONFIG`:

```powershell
$env:SSHOC_CONFIG="C:\\path\\to\\sshoc.config.json"
```

```bash
export SSHOC_CONFIG="/path/to/sshoc.config.json"
```

### 4) (Optional) Repo development: copy the template file

If you're developing in this repo, you can also copy the template to `sshoc.config.json` (it includes `$schema` pointing to `sshoc.config.schema.json` for IDE hints; the parser also allows this field):

```bash
# macOS / Linux
cp sshoc.config.template.json sshoc.config.json
```

```powershell
# Windows PowerShell / CMD
copy sshoc.config.template.json sshoc.config.json
# Or:
Copy-Item sshoc.config.template.json sshoc.config.json
```

Then set the password (recommended: use env vars and avoid committing plaintext passwords):

```powershell
$env:SSHOC_DEMO_PASSWORD="your_password"
```

### Key config fields

- `servers.<profile>`: your profile name (recommended: `a-zA-Z0-9_-`)
- `servers.<profile>.ssh_command`: supports common forms like `ssh -p <port> user@host` (for advanced ssh options, prefer explicit fields / feature extensions)
- `auth.type`:
  - `password`: supports `password` or `password_env`
  - `key`: supports `private_key_path` (optional `private_key_passphrase_env`)
- `known_hosts_policy`:
  - `strict`: default; unknown host keys fail fast (safer)
  - `accept_new`: on first connect, automatically writes to `known_hosts_path`
- `default_shell`: optional; commonly `bash -lc` (closer to an interactive environment). Set to `null` if the remote has no bash

---

## CLI usage (prefix command)

List all configured profiles:

```bash
sshoc list
```

### Profile management (edit the config file)

> These commands modify the currently effective config file in place. Use `sshoc config path` to confirm the path first, or specify it explicitly with `--config <path>`.

```bash
# Remove a profile
sshoc profile remove demo

# Clear all profiles (set `servers` to an empty object)
sshoc profile clear
```

Run a remote command (recommended prefix form):

```bash
sshoc demo: uname -a
sshoc demo: "ls -la /root"
```

Explicit subcommands (easier to parameterize):

```bash
sshoc run demo --cmd "python -V"
sshoc upload demo --local ./local.txt --remote /tmp/local.txt --overwrite
sshoc download demo --remote /tmp/local.txt --local ./downloaded.txt --overwrite
```

Default config resolution order:

1. `--config <path>`
2. Environment variable `SSHOC_CONFIG`
3. Current directory `./sshoc.config.json`
4. Per-user config directory (Windows: `%APPDATA%\\sshoc\\sshoc.config.json`; Linux: `~/.config/sshoc/sshoc.config.json`)
5. `sshoc.config.json` inside the package/source directory (dev fallback)

---

## MCP (stdio) server usage

Start:

```bash
sshoc-mcp
```

It communicates over `stdin/stdout` using **line-delimited JSON** (JSON-RPC), matching MCP's common stdio transport pattern.

Tools provided:

- `ssh.list_profiles`
- `ssh.run`
- `ssh.upload`
- `ssh.download`

### Generic stdio config blueprint (for MCP clients)

Different MCP clients may use different config file formats, but the essentials are usually: `command` / `args` / `env` / `cwd`. Below is a generic blueprint (field names are for reference—adapt to your client):

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

Two common variants (choose what fits your client):

- If your client can't easily pass `args`: pin the config path via `SSHOC_CONFIG` (and still inject the password env var required by `password_env` via `env`).
- If `sshoc-mcp` is not on `PATH`: start it via your venv with `python -m sshoc.mcp_server --config <ABS_CONFIG_PATH>`.

---

## Security notes (strongly recommended)

- Never commit plaintext server passwords. Prefer `password_env`.
- This tool effectively gives AI a remote execution entry point—use it only in environments you trust.

---

## License

Apache-2.0 (see `LICENSE`).

