"""Live end-to-end test against a real VM running idalib_mcp_launcher.exe.

Uploads a generated binary from host to VM, verifies sha256, downloads it
back, verifies sha256 again. Also exercises vm_stat and vm_tempdir.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import random
import sys
import tempfile
import time
import types

# Make the host-side server module importable without idaapi.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

_stub = types.ModuleType("ida_pro_mcp")
_stub.__path__ = [os.path.join(_SRC, "ida_pro_mcp")]  # type: ignore
sys.modules.setdefault("ida_pro_mcp", _stub)

from ida_pro_mcp import server as host_server  # noqa: E402


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _make_random_file(size: int) -> str:
    path = tempfile.mktemp(prefix="liveup_", suffix=".bin")
    rng = random.Random(0xDEADBEEF ^ size)
    with open(path, "wb") as f:
        remaining = size
        while remaining > 0:
            n = min(1024 * 1024, remaining)
            f.write(rng.randbytes(n))
            remaining -= n
    return path


def main(vm_ip: str, port: int) -> None:
    host_server.IDA_HOST = vm_ip
    host_server.IDA_PORT = port
    print(f"[live] target: {vm_ip}:{port}")

    td = host_server.vm_tempdir()
    print(f"[live] vm_tempdir: {td}")

    cases = [
        (128, False),        # tiny raw
        (5 * 1024 * 1024, False),  # crosses 4MB chunk boundary, raw
        (5 * 1024 * 1024, True),   # same, gzip
        (20 * 1024 * 1024, False), # bigger, raw
    ]
    for size, gz in cases:
        src = _make_random_file(size)
        src_sha = _sha256(src)
        try:
            t0 = time.perf_counter()
            up = host_server.vm_upload(src, use_gzip=gz)
            dt_up = time.perf_counter() - t0
            assert up["size"] == size, up
            assert up["sha256"] == src_sha, (up, src_sha)

            dst = tempfile.mktemp(prefix="livedn_", suffix=".bin")
            t0 = time.perf_counter()
            dn = host_server.vm_download(up["path"], dst)
            dt_dn = time.perf_counter() - t0
            assert dn["sha256"] == src_sha, (dn, src_sha)
            assert os.path.getsize(dst) == size

            st = host_server.vm_stat(up["path"])
            assert st["size"] == size and st["sha256"] == src_sha, st

            mbps_up = size / max(dt_up, 1e-9) / 1024 / 1024
            mbps_dn = size / max(dt_dn, 1e-9) / 1024 / 1024
            print(
                f"[live] OK size={size:>10} gzip={str(gz):<5} "
                f"up={mbps_up:7.2f} MB/s ({dt_up*1000:6.0f} ms)  "
                f"dn={mbps_dn:7.2f} MB/s ({dt_dn*1000:6.0f} ms)"
            )
        finally:
            for p in (src, locals().get("dst")):
                if p and os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
    print("[live] all cases passed")


if __name__ == "__main__":
    main("192.168.148.128", 13777)
