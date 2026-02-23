# SSHOC

简体中文 | [English](README.en.md)

一个轻量、配置驱动的 SSH 工具集合（CLI + 可选 MCP(stdio) 适配）。

- **CLI**：`sshoc`（`list/run/upload/download/hostkey/...`，以及前缀形式 `sshoc <profile>: <command...>`）
- **MCP(stdio)**：`sshoc-mcp`（按行 JSON 的 JSON-RPC，暴露 `ssh.*` 工具给 MCP 客户端）
- **依赖**：`paramiko`（SSH/SFTP）

> 目标：严格、可预测、易嵌入（尤其适合自动化/AI 场景）。

---

## 快速上手（pip 用户）

1) 安装：

```bash
python -m pip install -U sshoc
```

> Windows 提示：如果安装后 `sshoc` 仍提示“不是内部或外部命令”，通常是脚本目录（包含 `sshoc.exe`）不在 `PATH`。可用下面命令查看脚本目录并加入 `PATH`，然后重新打开终端：
>
> ```bash
> python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
> ```

2) 初始化配置（推荐写入用户配置目录）：

```bash
# 密码认证（推荐用环境变量保存密码）
sshoc init demo --ssh "ssh -p 22 user@host" --password-env SSHOC_DEMO_PASSWORD

# 或：Key 认证
sshoc init demo --ssh "ssh -p 22 user@host" --key-path ~/.ssh/id_ed25519
```

3) 设置密码环境变量（仅 `password_env` 方式需要）：

```powershell
$env:SSHOC_DEMO_PASSWORD="your_password"
```

```bash
export SSHOC_DEMO_PASSWORD="your_password"
```

4) 首次连接（known_hosts）：

默认 `known_hosts_policy=strict`，若本机 `known_hosts` 里没有目标主机的 host key，连接会失败。推荐先写入 host key（可选校验指纹）：

```bash
sshoc hostkey ensure demo
# 如果你能从云厂商/运维渠道拿到可信指纹，强烈建议加这一行：
# sshoc hostkey ensure demo --expected-fingerprint "SHA256:..."
```

5) 执行命令：

```bash
sshoc demo: uname -a
# 或
sshoc run demo --cmd "uname -a"
```

---

## 安装（开发者）

从源码安装（建议在本目录单独建虚拟环境）：

```bash
cd "SSH_Operation_Component (MCP)"
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install -U pip
python -m pip install -e .
```

---

## 配置

### 配置文件在哪里？（以及当前生效的是哪一份？）

```bash
sshoc config path
```

### 工程化建议：用 `SSHOC_CONFIG` 固定配置路径

```powershell
$env:SSHOC_CONFIG="C:\\path\\to\\sshoc.config.json"
```

```bash
export SSHOC_CONFIG="/path/to/sshoc.config.json"
```

### 关键字段速览

- `servers.<profile>`：profile 名称（推荐 `A-Za-z0-9_-`）
- `servers.<profile>.ssh_command`：常见形式 `ssh -p <port> user@host`
- `auth.type`：
  - `password`：`password` 或 `password_env`
  - `key`：`private_key_path`（可选 `private_key_passphrase_env`）
- `known_hosts_policy`：
  - `strict`：默认；未知 host key 直接报错（更安全）
  - `accept_new`：首次连接自动写入 `known_hosts_path`（TOFU）
- `known_hosts_path`：OpenSSH `known_hosts` 路径（模板默认：`~/.ssh/known_hosts`）
- `default_shell`：默认 `bash -lc`（远端无 bash 可设为 `null`）

---

## CLI

### 常用命令

```bash
sshoc list
sshoc demo: "ls -la /root"
sshoc run demo --cmd "python -V"
sshoc upload demo --local ./local.txt --remote /tmp/local.txt --overwrite
sshoc download demo --remote /tmp/local.txt --local ./downloaded.txt --overwrite
```

### host key / known_hosts

这些命令输出 JSON，适合脚本/CI/自动化。

```bash
# 扫描远端 host key（不需要登录）
sshoc hostkey scan demo

# 检查本机 known_hosts 是否已有该 host
sshoc hostkey is-known demo

# 扫描并写入 known_hosts（可选：校验指纹）
sshoc hostkey ensure demo
sshoc hostkey ensure demo --expected-fingerprint "SHA256:..."

# 手动写入（你已拿到 key_type + base64）
sshoc hostkey add demo --key-type ssh-ed25519 --public-key-base64 "<BASE64>"

# 精准删除：只删某个 key_type，或删除该 host 的所有 key types
sshoc hostkey remove demo --key-type ssh-ed25519
sshoc hostkey remove demo --all-types
```

---

## MCP(stdio) server

启动：

```bash
sshoc-mcp
```

提供的工具：

- `ssh.init_config` — 创建 `sshoc.config.json`（无配置时优先调用；AI 可自行完成配置）
- `ssh.list_profiles`
- `ssh.scan_host_key`
- `ssh.is_known_host`
- `ssh.add_known_host`
- `ssh.ensure_known_host`
- `ssh.run`
- `ssh.upload`
- `ssh.download`

> 零配置启动：`sshoc-mcp` 即使没有配置文件也能正常启动。需要配置的工具会返回 `CONFIG_NOT_FOUND` 错误并建议调用 `ssh.init_config`。这样 MCP 客户端（如 AI 助手）可以先发现工具，再按需创建配置。

### 通用 stdio 配置蓝图（供 MCP 客户端参考）

不同 MCP 客户端配置格式可能不同，但核心都离不开：`command` / `args` / `env` / `cwd`。下面给一个“通用蓝图”示例（字段名仅供参考，请按你的客户端实际格式填入）：

```jsonc
{
  "mcpServers": {
    "sshoc": {
      "command": "sshoc-mcp",
      // args/env 可选；AI 可通过 ssh.init_config 自行创建配置。
      // 如需固定配置文件路径：
      // "args": ["--config", "<ABS_CONFIG_PATH>"],
      "env": {
        "SSHOC_DEMO_PASSWORD": "your_password",
        "SSHOC_DEBUG": "0"
      }
    }
  }
}
```

---

## 安全提示（强烈建议）

- 不要把服务器密码明文提交到仓库：优先 `password_env`
- `accept_new` 属于 TOFU（首次信任）；更安全的做法是使用 `--expected-fingerprint` 校验
- 这个组件等价于“给自动化/AI 一个远程执行入口”，请只在你信任的环境里使用

---

## License

Apache-2.0（见 `LICENSE`）
