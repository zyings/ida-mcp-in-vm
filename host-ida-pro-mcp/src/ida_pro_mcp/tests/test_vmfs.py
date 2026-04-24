"""End-to-end self-test for the VMFS chunked file-transfer pipeline.

Runs entirely on one machine: starts a minimal HTTPServer that mounts the
VmfsHandlerMixin (no IDA required), then exercises vm_upload / vm_download /
vm_stat / vm_tempdir from server.py against it.

Usage
-----
    python -m ida_pro_mcp.tests.test_vmfs
or  python src/ida_pro_mcp/tests/test_vmfs.py
"""

from __future__ import annotations

import importlib.util
import os
import random
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Load vmfs.py directly without triggering ida_mcp/__init__.py (which imports
# idaapi, only available inside IDA).
_VMFS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ida_mcp", "vmfs.py",
)
_spec = importlib.util.spec_from_file_location("_vmfs_testmod", _VMFS_PATH)
assert _spec and _spec.loader
_vmfs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vmfs)
VmfsHandlerMixin = _vmfs.VmfsHandlerMixin

# Load server.py as a standalone module too. It imports from .installer and
# from the ida_mcp zeromcp package, which don't need idaapi.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Neutralise ida_mcp's __init__ before importing server.py by stubbing it.
import types as _types
_stub = _types.ModuleType("ida_pro_mcp")
_stub.__path__ = [os.path.join(_ROOT, "ida_pro_mcp")]  # type: ignore
sys.modules.setdefault("ida_pro_mcp", _stub)

# server.py imports installer with a try/except fallback; give it the package.
from ida_pro_mcp import server as host_server  # noqa: E402


class _Handler(VmfsHandlerMixin, BaseHTTPRequestHandler):
    def log_message(self, *a, **kw):  # silence
        pass

    def do_GET(self):
        if self.vmfs_try_handle_get(self.path.split("?", 1)[0]):
            return
        self.send_error(404)

    def do_POST(self):
        if self.vmfs_try_handle_post(self.path.split("?", 1)[0]):
            return
        self.send_error(404)


def _start_server() -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def _make_random_file(size: int) -> str:
    path = tempfile.mktemp(prefix="vmfs_src_", suffix=".bin")
    rng = random.Random(0xC0FFEE)
    with open(path, "wb") as f:
        remaining = size
        while remaining > 0:
            n = min(1024 * 1024, remaining)
            f.write(rng.randbytes(n))
            remaining -= n
    return path


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def run(sizes=(0, 123, 4 * 1024 * 1024 + 17, 12 * 1024 * 1024 + 5), use_gzip=(True, False)) -> None:
    srv, port = _start_server()
    try:
        host_server.IDA_HOST = "127.0.0.1"
        host_server.IDA_PORT = port
        print(f"[test] VMFS server on 127.0.0.1:{port}")

        td = host_server.vm_tempdir()
        print(f"[test] vm_tempdir: {td}")

        for size in sizes:
            for gz in use_gzip:
                src = _make_random_file(size)
                try:
                    t0 = time.perf_counter()
                    up = host_server.vm_upload(src, use_gzip=gz)
                    dt = time.perf_counter() - t0
                    assert up["size"] == size, up
                    assert up["sha256"] == _sha256(src), up
                    print(
                        f"[test] upload  size={size:>12} gzip={gz} "
                        f"{size / max(dt, 1e-9) / 1024 / 1024:7.1f} MB/s -> {up['path']}"
                    )

                    dst = tempfile.mktemp(prefix="vmfs_dst_", suffix=".bin")
                    t0 = time.perf_counter()
                    dn = host_server.vm_download(up["path"], dst)
                    dt = time.perf_counter() - t0
                    assert dn["sha256"] == up["sha256"], (dn, up)
                    assert os.path.getsize(dst) == size
                    print(
                        f"[test] downld  size={size:>12}           "
                        f"{size / max(dt, 1e-9) / 1024 / 1024:7.1f} MB/s"
                    )

                    st = host_server.vm_stat(up["path"])
                    assert st["size"] == size and st["sha256"] == up["sha256"]
                finally:
                    for p in (src, locals().get("dst")):
                        if p and os.path.exists(p):
                            os.remove(p)
        print("[test] OK")
    finally:
        srv.shutdown()


if __name__ == "__main__":
    run()
