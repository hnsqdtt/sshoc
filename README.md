# SSHOC

简体中文 | [English](README.en.md)

一个轻量、配置驱动的 SSH 工具集合（CLI + 可选 MCP stdio 适配）。用 `json` 配置多台服务器，然后通过：

- **CLI 前缀命令**：`sshoc <profile>: <command...>`（快速执行远端命令）
- **MCP(stdio) 服务**：对外暴露 `tools/list` / `tools/call`，让支持 MCP 的客户端直接调用 `ssh.run` / `ssh.upload` / `ssh.download`

> 依赖：`paramiko`（SSH/SFTP）。

---

## 快速上手（pip 用户）

1) 安装：

```bash
python -m pip install -U sshoc
```

2) 初始化配置（写入用户配置目录，推荐）：

```bash
# Password auth（推荐用环境变量保存密码）
sshoc init demo --ssh "ssh -p 22 user@host" --password-env SSHOC_DEMO_PASSWORD

# 或 Key auth
sshoc init demo --ssh "ssh -p 22 user@host" --key-path ~/.ssh/id_ed25519
```

3) 设置密码环境变量（仅 password_env 方式需要）：

```powershell
$env:SSHOC_DEMO_PASSWORD="your_password"
```

```bash
export SSHOC_DEMO_PASSWORD="your_password"
```

4) 使用：

```bash
sshoc list
sshoc demo: uname -a
```

---

## 安装

### 方式 A：从 PyPI 安装（推荐）

```bash
python -m pip install -U sshoc
```

### 方式 B：从源码安装（开发）

建议在本目录单独建虚拟环境（也可用你习惯的方式）：

```bash
cd "SSH_Operation_Component (MCP)"
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install -U pip
python -m pip install -e .
```

---

## 配置

### 1) 生成配置（`sshoc init`）

```bash
# 写入到用户配置目录（推荐）
sshoc init

# 或写入到当前目录 ./sshoc.config.json
sshoc init --local

# 或写入到任意路径
sshoc init --output /path/to/sshoc.config.json
```

说明：

- `sshoc init`（无 `<profile>`）会写入**完整模板**（包含 demo profile）。
- `sshoc init <profile> --ssh ... --password-env/--password/--key-path ...` 会写入**单 profile 配置**（更适合 pip 用户快速上手）。

### 2) 配置文件在哪里？（以及我现在用的是哪一份？）

用这条命令查看当前会读取哪份配置：

```bash
sshoc config path
```

它会输出：

- `path`：配置文件路径
- `source`：来源（`cli|env|cwd|user|package`）
- `exists`：该路径是否存在

用户配置目录默认位置：

- Windows：`%APPDATA%\\sshoc\\sshoc.config.json`
- macOS：`~/Library/Application Support/sshoc/sshoc.config.json`
- Linux：`~/.config/sshoc/sshoc.config.json`（或 `$XDG_CONFIG_HOME/sshoc/sshoc.config.json`）

### 3) 工程化建议：用 `SSHOC_CONFIG` 固定配置路径

如果你希望“在任何目录运行都读取同一份配置”，建议设置环境变量 `SSHOC_CONFIG`：

```powershell
$env:SSHOC_CONFIG="C:\\path\\to\\sshoc.config.json"
```

```bash
export SSHOC_CONFIG="/path/to/sshoc.config.json"
```

### 4)（可选）在仓库里开发：复制模板文件

如果你是在仓库里开发，也可以直接把模板复制为 `sshoc.config.json`（模板包含 `$schema` 指向 `sshoc.config.schema.json`，方便 IDE 做字段提示；解析时也允许该字段存在）：

```bash
# macOS / Linux
cp sshoc.config.template.json sshoc.config.json
```

```powershell
# Windows PowerShell / CMD
copy sshoc.config.template.json sshoc.config.json
# 或：
Copy-Item sshoc.config.template.json sshoc.config.json
```

然后设置密码（推荐用环境变量，避免把密码明文写进 git）：

```powershell
$env:SSHOC_DEMO_PASSWORD="your_password"
```

### 配置字段要点

- `servers.<profile>`：你自定义的 profile 名称（建议 `a-zA-Z0-9_-`）
- `servers.<profile>.ssh_command`：支持常见形式 `ssh -p <port> user@host`（高级 ssh 参数请改用显式字段/功能扩展）
- `auth.type`：
  - `password`：支持 `password` 或 `password_env`
  - `key`：支持 `private_key_path`（可选 `private_key_passphrase_env`）
- `known_hosts_policy`：
  - `strict`：默认，未知 host key 直接报错（更安全）
  - `accept_new`：首次连接自动写入 `known_hosts_path`
- `default_shell`：可选，常用 `bash -lc`（更接近交互环境）；若远端无 bash 可设为 `null`

---

## CLI 使用（前缀命令）

列出配置里的所有 profile：

```bash
sshoc list
```

### Profile 管理（编辑配置文件）

> 这些命令会直接修改当前生效的配置文件。建议先用 `sshoc config path` 确认路径；也可以通过 `--config <path>` 显式指定。

```bash
# 删除某个 profile
sshoc profile remove demo

# 清空所有 profiles（把 servers 置为空对象）
sshoc profile clear
```

执行远端命令（推荐的“前缀”形式）：

```bash
sshoc demo: uname -a
sshoc demo: "ls -la /root"
```

显式子命令形式（便于参数化）：

```bash
sshoc run demo --cmd "python -V"
sshoc upload demo --local ./local.txt --remote /tmp/local.txt --overwrite
sshoc download demo --remote /tmp/local.txt --local ./downloaded.txt --overwrite
```

默认配置文件查找顺序：

1. `--config <path>`
2. 环境变量 `SSHOC_CONFIG`
3. 当前目录 `./sshoc.config.json`
4. 用户配置目录（Windows: `%APPDATA%\\sshoc\\sshoc.config.json`；Linux: `~/.config/sshoc/sshoc.config.json`）
5. 包/源码目录内 `sshoc.config.json`（开发兜底）

---

## MCP(stdio) server 使用

启动：

```bash
sshoc-mcp
```

它会在 `stdin/stdout` 上用**按行 JSON**的方式收发 JSON-RPC（对齐 MCP 的 stdio transport 习惯）。

提供的工具：

- `ssh.list_profiles`
- `ssh.run`
- `ssh.upload`
- `ssh.download`

### 通用 stdio 配置蓝图（供 MCP 客户端参考）

不同 MCP 客户端的配置文件格式可能不同，但核心都离不开：`command` / `args` / `env` / `cwd`。下面给一个“通用蓝图”示例（字段名仅供参考，请按你的客户端实际格式填入）：

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
// <ABS_CONFIG_PATH> 示例：
// - macOS/Linux: /path/to/sshoc.config.json
// - Windows: C:\\path\\to\\sshoc.config.json
```

两个常见变体（按需选择其一）：

- 如果你的客户端不方便传 `args`：用环境变量 `SSHOC_CONFIG` 固定配置路径（并继续在 `env` 注入 `password_env` 对应的密码变量）。
- 如果 `sshoc-mcp` 不在 PATH：改用 venv 的 `python -m sshoc.mcp_server --config <ABS_CONFIG_PATH>` 启动。

---

## 安全提示（强烈建议）

- 不要把云服务器密码明文提交到仓库。优先使用 `password_env`。
- 这个组件等价于“给 AI 一个远程执行入口”，请只在你信任的环境里使用。

---

## License

Apache-2.0（见 `LICENSE`）。

