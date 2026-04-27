# ida mcp in vm

ida mcp in vm 是一个面向“IDA 在虚拟机中运行、Agent 在宿主机中运行”场景的项目。它在 ida-pro-mcp 的基础上做了增强，使宿主机可以通过 MCP 通道把文件上传到虚拟机，在虚拟机中的 IDA 或 idalib 中打开并分析，再按需把产物下载回宿主机，从而不再依赖共享目录。

本项目基于 ida-pro-mcp 修改而来，针对“IDA 在 VM 中、MCP 客户端在宿主机中”的工作流做了补强。

- 上游项目地址：https://github.com/mrexodia/ida-pro-mcp

## 主要功能

- 支持 IDA / idalib 在虚拟机中运行，MCP 客户端在宿主机中运行。
- 支持宿主机通过 MCP 通道上传文件到虚拟机。
- 支持在虚拟机中的 IDA 直接打开上传后的二进制、IDB 或 I64 文件。
- 支持将分析产生的 .i64 等文件再下载回宿主机。
- 避免共享目录带来的路径映射、锁文件、权限和隔离性问题。
- 提供 `idalib_open_from_host`，可一步完成“上传并打开”。

## 工作原理

- 宿主机使用修改后的 ida-pro-mcp。
- 虚拟机中运行 launcher / idalib 服务。
- 虚拟机服务额外挂出 `/vmfs/*` 端点，负责分块上传和下载。
- 宿主机侧 MCP 工具先处理文件传输，再把分析请求转发给虚拟机中的 IDA。

## 仓库结构

- ida-pro-mcp/
  - 修改后的 ida-pro-mcp 源码。
  - 包含 `vm_upload`、`vm_download`、`vm_stat`、`vm_tempdir`。
  - 包含 `idalib_open_from_host`。
- vm-idalib-launcher/
  - 虚拟机侧 launcher 源码。
  - 用于重新打包 exe 的 PyInstaller spec。
  - `dist/` 在源码仓库中默认为空。

## 基本使用方法

### 1. 虚拟机侧

- 本地打包 launcher exe，或从 GitHub Releases 下载 exe。
- 在虚拟机中启动 launcher。
- 监听地址建议绑定 `0.0.0.0`，端口默认使用 `13777`。

### 2. 宿主机侧

- 从 `ida-pro-mcp/` 安装 MCP 包。
- 将 MCP 客户端配置到 `http://<vm-ip>:13777`。
- 可直接调用以下工具：
  - `idalib_open_from_host`
  - `vm_upload`
  - `vm_download`
  - `vm_stat`
  - `vm_tempdir`

#### 安装命令

在 `ida-pro-mcp/` 目录执行：

```powershell
# 推荐：开发模式安装（源码修改可立即生效）
python -m pip install -e .

# 或普通安装
# python -m pip install .
```

安装验证：

```powershell
python -m ida_pro_mcp.server --help
```

#### VS Code MCP 配置片段（可直接复制）

在 MCP 客户端配置文件（mcp.json 或支持 `mcpServers` 的 settings）中添加：

```json
{
  "mcpServers": {
    "ida-pro-mcp-vm": {
      "command": "python",
      "args": [
        "-m",
        "ida_pro_mcp.server",
        "--ida-rpc",
        "http://<vm-ip>:13777"
      ]
    }
  }
}
```

Windows 绝对解释器路径示例：

```json
{
  "mcpServers": {
    "ida-pro-mcp-vm": {
      "command": "D:/path/to/python.exe",
      "args": [
        "-m",
        "ida_pro_mcp.server",
        "--ida-rpc",
        "http://<vm-ip>:13777"
      ]
    }
  }
}
```

### 3. 冒烟测试

在 `ida-pro-mcp/` 目录下执行：

```powershell
python scripts/live_test_vmfs.py --vm-ip <vm-ip> --port 13777
python scripts/live_analyze_i64.py --vm-ip <vm-ip> --port 13777 --file <host-file>
```

## 注意事项

- 不要将虚拟机中的 MCP 端口暴露给不可信网络。
- exe 更适合通过 GitHub Releases 分发，而不是直接提交到源码仓库。
- 如果虚拟机侧服务代码有变更，使用 launcher exe 的场景需要重新打包。
- 主机侧代理（`server.py` 中的 `dispatch_proxy`）在首次转发请求时会自动向虚
  拟机发起 MCP `initialize` 握手，并把返回的 `Mcp-Session-Id` 缓存、附加到
  后续所有转发请求上；如果远端会话失效，会自动重新 initialize 并重试一次。
  MCP 客户端（VS Code、Claude、Cursor 等）无需感知 session id。
