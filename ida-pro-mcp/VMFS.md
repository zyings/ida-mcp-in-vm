# VMFS — MCP-native file transfer between host and VM

This add-on removes the need for a host↔VM shared folder when running IDA
Pro inside a VM and the MCP agent on the host. Files are streamed over the
same HTTP port the IDA MCP plugin already exposes (default `13337`) via
chunked raw endpoints under `/vmfs/*`.

## Deployment

Two VM deployment flavours are supported. Both expose `/vmfs/*` on the same
port as the MCP server.

### A) Headless `.exe` launcher (PyInstaller build)

This is the typical VM setup: `idalib_mcp_launcher.exe` bundles the whole
Python runtime and runs `ida_pro_mcp.idalib_server` under the hood. After
pulling these changes you MUST rebuild the exe so the new `vmfs.py` and
the VMFS-aware HTTP handler are included.

On the build host (where PyInstaller / the source checkout lives):

```powershell
cd idalib_mcp_launcher
pyinstaller idalib_mcp_launcher.spec --clean
# -> dist\idalib_mcp_launcher.exe
```

Copy `dist\idalib_mcp_launcher.exe` into the VM, launch it, pick host
`0.0.0.0`, port `13777` (or whatever you use), and start the server. No
additional dependencies need to be installed in the VM — `ida_pro_mcp`,
`vmfs`, and the VMFS HTTP handler are all frozen into the exe by
`collect_all('ida_pro_mcp')` in the spec file.

Verify endpoint is reachable from host:

```powershell
# on host
curl http://<vm-ip>:13777/vmfs/tempdir
# -> {"base":"...","platform":"win32"}
```

Finally point your host-side MCP client config at the right port
(`--ida-rpc http://<vm-ip>:13777`) and restart the client.

### B) IDA plugin mode (`pip install` + `Edit → Plugins → MCP`)

### 1. Pull the updated code into the VM and host

Same code runs on both sides (host acts as MCP server / agent, VM acts as
IDA plugin). Get this branch onto both:

```powershell
# on host AND in the VM
cd <path>\ida-pro-mcp
git pull    # or copy src/ida_pro_mcp/ contents over
```

### 2. Install the IDA plugin inside the VM

```powershell
# inside the VM
pip install -e .\ida-pro-mcp
ida-pro-mcp --install
```

Start IDA, load any IDB (or a blank one — the plugin loads regardless),
then `Edit → Plugins → MCP` (Ctrl-Alt-M) to start the server. The plugin
listens on `127.0.0.1:13337` by default. Use the in-plugin menu to change
host to `0.0.0.0` so the host can reach it.

### 3. Allow inbound 13337 on the VM firewall (Windows)

```powershell
# inside the VM, one-time, as Administrator
New-NetFirewallRule -DisplayName "IDA MCP" -Direction Inbound `
    -LocalPort 13337 -Protocol TCP -Action Allow
```

### 4. Configure the host MCP server to target the VM

The host MCP server points at `http://<vm-ip>:13337` via `--ida-rpc`.

```powershell
# on host
ida-pro-mcp --install --ida-rpc http://192.168.56.10:13337
```

This generates the MCP client config (Claude / Cursor / VS Code Copilot /
etc.) with the right endpoint baked in. Restart the MCP client.

### 5. End-to-end test with IDA

From your MCP client (e.g. a chat window):

```
Tool call:  idalib_open_from_host
Args:       { "host_path": "D:\\samples\\libApp.so" }
```

The tool uploads the file to the VM temp dir, opens it in IDA Pro via
idalib, and returns `{ upload: {...}, open: {...} }`.

After analysis, pull artifacts back:

```
Tool call:  vm_download
Args:       { "vm_path": "C:\\...\\ida_mcp_vmfs\\<uid>\\libApp.i64",
              "host_dest": "D:\\samples\\libApp.i64" }
```

### Firewall (both flavours)

```powershell
# inside the VM, one-time, as Administrator
New-NetFirewallRule -DisplayName "IDA MCP" -Direction Inbound `
    -LocalPort 13337 -Protocol TCP -Action Allow
# (change port to 13777 for the exe launcher default)
```

## Tool reference

| Tool                       | Side  | Purpose                                     |
|----------------------------|-------|---------------------------------------------|
| `vm_tempdir`               | host  | Get VM upload base dir                      |
| `vm_stat(path)`            | host  | File info + sha256                          |
| `vm_upload(host_path)`     | host  | Stream file host→VM in 4 MB chunks          |
| `vm_download(vm_path,...)` | host  | Stream file VM→host                         |
| `idalib_open_from_host`    | host  | `vm_upload` + remote `idalib_open` combined |

Internal endpoints (you normally don't hit these yourself):

```
GET  /vmfs/tempdir
GET  /vmfs/stat?path=...&sha256=0|1
GET  /vmfs/download?path=...&offset=...&length=...
POST /vmfs/upload/begin     body: {"filename": "...", "gzip": bool}
POST /vmfs/upload/chunk?id=...&final=0|1    body: raw bytes (optional gzip)
POST /vmfs/upload/abort?id=...
```

## Performance notes

Measured on localhost loopback against random data (worst case for gzip):

| File   | `use_gzip=False` up | `use_gzip=True` up | Download |
|--------|---------------------|--------------------|----------|
| 4 MB   | ~120 MB/s           | ~29 MB/s           | ~220 MB/s |
| 12 MB  | ~125 MB/s           | ~28 MB/s           | ~260 MB/s |

For real `.so` / binaries with strings and symbols, gzip saves 30–60 % on
the wire. Rule of thumb:

- LAN / fast tunnel → `use_gzip=False` (default)
- slow / metered link → `use_gzip=True`

Chunk size is 4 MB (`UPLOAD_CHUNK_SIZE` in `server.py`), upload session max
idle TTL is 1 hour (`UPLOAD_TTL` in `vmfs.py`).

## Security model

- `/vmfs/*` has no auth beyond the HTTP CORS / network isolation the plugin
  already relies on. Treat port 13337 as trusted: only expose it across a
  host-only / NAT network, never the public internet.
- Filenames are sanitised (basename only, path separators stripped). Each
  upload lands under a unique `<tempdir>/ida_mcp_vmfs/<uuid>/` subdir.
- `vm_download` reads **arbitrary** paths the IDA process can read. This is
  required to pull `.i64` / reports from anywhere in the VM. Do not expose
  13337 to untrusted networks.
- SHA-256 is verified end-to-end on every upload; mismatches trigger abort.

## Troubleshooting

- `ConnectionRefusedError` from host → plugin not started in IDA
  (`Edit → Plugins → MCP`) or listening on `127.0.0.1` instead of `0.0.0.0`.
- `413 Payload Too Large` → you hit `MAX_CHUNK_BYTES` (64 MB). Lower
  `UPLOAD_CHUNK_SIZE` on the host.
- `sha256 mismatch` → network corruption or, more likely, gzip stream
  desync. Retry with `use_gzip=False`; open an issue with chunk size.
- Upload leaves files behind on crash → cleaned by `UPLOAD_TTL` GC on next
  `/vmfs/upload/begin` call, or delete `%TEMP%\ida_mcp_vmfs` by hand.
