# ida mcp in vm

ida mcp in vm is a VM-oriented workflow for running IDA Pro inside a virtual
machine while keeping the MCP client and coding agent on the host. It removes
the need for shared folders by adding MCP-native file transfer, so binaries can
be uploaded from the host to the VM, opened in IDA, analyzed remotely, and
optionally downloaded back afterward.

This project is based on ida-pro-mcp and extends it for the "IDA in VM, agent
on host" use case.

- Upstream project: https://github.com/mrexodia/ida-pro-mcp

## Main features

- Run IDA or idalib inside a VM while the MCP client stays on the host.
- Upload files from the host to the VM over the MCP HTTP channel.
- Open uploaded binaries or IDB/I64 files directly in IDA.
- Download generated artifacts such as .i64 databases back to the host.
- Avoid shared-folder issues such as path mapping, file locking, and poor
  isolation.
- Support a one-shot workflow with `idalib_open_from_host`.

## How it works

- The host uses a modified ida-pro-mcp package.
- The VM runs the launcher / idalib service.
- The VM service exposes raw `/vmfs/*` endpoints for chunked upload/download.
- Host-side MCP tools call those endpoints and then forward analysis requests
  to IDA.

## Repository layout

- ida-pro-mcp/
  - Modified ida-pro-mcp source code.
  - Includes `vm_upload`, `vm_download`, `vm_stat`, `vm_tempdir`.
  - Includes `idalib_open_from_host` for upload-and-open in one call.
- vm-idalib-launcher/
  - VM-side launcher source.
  - PyInstaller spec for rebuilding the executable.
  - `dist/` is intentionally empty in source control.

## Basic usage

### 1. VM side

- Build the launcher exe locally or download it from GitHub Releases.
- Start the launcher inside the VM.
- Bind to `0.0.0.0` and use port `13777` unless you need a different port.

### 2. Host side

- Install the package from `ida-pro-mcp/`.
- Configure your MCP client to connect to `http://<vm-ip>:13777`.
- Use tools such as:
  - `idalib_open_from_host`
  - `vm_upload`
  - `vm_download`
  - `vm_stat`
  - `vm_tempdir`

#### Install commands

Run in `ida-pro-mcp/`:

```powershell
# Recommended: editable install
python -m pip install -e .

# Or regular install
# python -m pip install .
```

Verify installation:

```powershell
python -m ida_pro_mcp.server --help
```

#### VS Code MCP config snippet (copyable)

Use this in your MCP client config (mcp.json / client settings using `mcpServers`):

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

Windows absolute interpreter path example:

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

### 3. Smoke test

Run from `ida-pro-mcp/`:

```powershell
python scripts/live_test_vmfs.py --vm-ip <vm-ip> --port 13777
python scripts/live_analyze_i64.py --vm-ip <vm-ip> --port 13777 --file <host-file>
```

## Important notes

- Do not expose the VM MCP port to untrusted networks.
- The exe is better distributed through GitHub Releases, not committed to the
  source repository.
- If you use the launcher exe, rebuild it whenever VM-side server code changes.
- The host-side proxy (`dispatch_proxy` in `server.py`) automatically performs
  the MCP `initialize` handshake against the VM on first use and reuses the
  returned `Mcp-Session-Id` for every forwarded call. If the remote session
  expires, it re-initializes once and retries transparently. MCP clients
  (VS Code, Claude, Cursor, ...) do not need to know about session ids.

## Chinese documentation

See README_zh-CN.md for the Chinese version.
