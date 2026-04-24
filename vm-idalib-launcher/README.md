# vm-idalib-launcher

This directory contains VM-side launcher sources.

## Files

- launcher.py
- idalib_mcp_launcher.spec
- dist/ (empty by default)

## Build

```powershell
python -m PyInstaller idalib_mcp_launcher.spec --clean --noconfirm
```

Output:

- dist/idalib_mcp_launcher.exe

## Distribution recommendation

Do not commit exe into source control.
Publish exe as GitHub Release asset instead.
