"""Real-world test: push a large .i64 to the VM, open it in idalib,
then invoke a simple analysis tool to confirm the session is live.

Handles MCP session initialization so we can exercise the full path the
agent would go through.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import os
import sys
import tempfile
import time
import types
import http.client

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

_stub = types.ModuleType("ida_pro_mcp")
_stub.__path__ = [os.path.join(_SRC, "ida_pro_mcp")]  # type: ignore
sys.modules.setdefault("ida_pro_mcp", _stub)

from ida_pro_mcp import server as host_server  # noqa: E402


class McpClient:
    """Minimal Streamable-HTTP MCP client: initialize + tools/call."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.session_id: str | None = None
        self._next_id = 0

    def _post(self, payload: dict, extra_headers: dict | None = None) -> tuple[dict, dict[str, str]]:
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if extra_headers:
            headers.update(extra_headers)
        conn = http.client.HTTPConnection(self.host, self.port, timeout=600)
        try:
            conn.request("POST", "/mcp", body, headers)
            resp = conn.getresponse()
            raw = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}: {raw[:400].decode('utf-8', 'replace')}")
            # Some implementations reply with text/event-stream; parse the first data: line.
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                return {}, resp_headers
            if text.startswith("event:") or "\ndata:" in text or text.startswith("data:"):
                for line in text.splitlines():
                    if line.startswith("data:"):
                        text = line[5:].strip()
                        break
            if not text:
                return {}, resp_headers
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                # Notification responses may return non-JSON acks; ignore.
                return {"_raw": text[:200]}, resp_headers
            return data, resp_headers
        finally:
            conn.close()

    def initialize(self) -> dict:
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": False}, "sampling": {}},
                "clientInfo": {"name": "live-ida-test", "version": "0.0.1"},
            },
        }
        data, headers = self._post(payload)
        sid = headers.get("mcp-session-id")
        if sid:
            self.session_id = sid
        # Send initialized notification
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return data

    def tool_call(self, name: str, arguments: dict | None = None, timeout: int = 600) -> dict:
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        data, _h = self._post(payload)
        if "error" in data and data["error"]:
            raise RuntimeError(f"tool {name} error: {data['error']}")
        result = data.get("result") or {}
        if result.get("isError"):
            content = result.get("content") or []
            msg = content[0].get("text") if content else "unknown"
            raise RuntimeError(f"tool {name} failed: {msg}")
        return result


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(4 * 1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def main(vm_ip: str, vm_port: int, host_file: str) -> None:
    assert os.path.isfile(host_file), host_file
    size_mb = os.path.getsize(host_file) / 1024 / 1024
    print(f"[test] file={host_file} size={size_mb:.1f} MB")

    # 1. Configure host-side server module and upload via VMFS.
    host_server.IDA_HOST = vm_ip
    host_server.IDA_PORT = vm_port

    skip_upload = os.environ.get("SKIP_UPLOAD")
    if skip_upload:
        up = {"path": skip_upload, "size": os.path.getsize(host_file)}
        print(f"[test] SKIP_UPLOAD set; reusing VM path {up['path']}")
    else:
        print("[test] computing host sha256 ...")
        t0 = time.perf_counter()
        host_sha = _sha256(host_file)
        print(f"[test]   {host_sha}  ({time.perf_counter()-t0:.2f}s)")

        print("[test] uploading via vm_upload (raw, 4MB chunks) ...")
        t0 = time.perf_counter()
        up = host_server.vm_upload(host_file, use_gzip=False)
        dt = time.perf_counter() - t0
        print(
            f"[test]   uploaded to {up['path']}\n"
            f"[test]   size={up['size']}  sha256={up['sha256']}  "
            f"{size_mb/dt:.1f} MB/s ({dt:.1f}s)"
        )
        assert up["sha256"] == host_sha

    # 2. Open MCP session and call idalib_open on VM.
    client = McpClient(vm_ip, vm_port)
    init = client.initialize()
    print(
        f"[test] MCP initialize: server={init.get('result',{}).get('serverInfo')} "
        f"session={client.session_id}"
    )

    print("[test] calling idalib_open on VM ...")
    t0 = time.perf_counter()
    res = client.tool_call(
        "idalib_open",
        {"input_path": up["path"], "run_auto_analysis": False},
    )
    dt = time.perf_counter() - t0
    structured = res.get("structuredContent") or {}
    print(f"[test]   idalib_open ({dt:.1f}s) -> keys={list(structured.keys())}")
    if structured.get("error"):
        print(f"[test]   ERROR: {structured['error']}")
        return
    sess = structured.get("session", {}) or {}
    print(f"[test]   session_id={sess.get('session_id')}")
    print(f"[test]   input_path={sess.get('input_path')}")

    # 3. Run a cheap analysis tool to confirm the session is alive.
    print("[test] calling server_health ...")
    try:
        res = client.tool_call("server_health")
        health = res.get("structuredContent") or {}
        print(
            f"[test]   module={health.get('module')} "
            f"imagebase={health.get('imagebase')} "
            f"auto_ready={health.get('auto_analysis_ready')} "
            f"hexrays_ready={health.get('hexrays_ready')}"
        )
    except Exception as e:
        print(f"[test]   server_health failed: {e}")

    # 4. Quick survey (metadata only).
    print("[test] calling survey_binary(detail_level='minimal') ...")
    try:
        t0 = time.perf_counter()
        res = client.tool_call(
            "survey_binary", {"detail_level": "minimal"}, timeout=600
        )
        survey = res.get("structuredContent") or {}
        dt = time.perf_counter() - t0
        meta = survey.get("metadata") or {}
        stats = survey.get("statistics") or {}
        print(f"[test]   ({dt:.1f}s) module={meta.get('module')} "
              f"file_type={meta.get('file_type')}")
        print(f"[test]   functions={stats.get('total_functions')} "
              f"strings={stats.get('total_strings')}")
    except Exception as e:
        print(f"[test]   survey_binary failed: {e}")

    print("[test] done")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Open uploaded .i64 in VM IDA and run sanity checks")
    parser.add_argument("--vm-ip", required=True, help="VM IP, e.g. 192.168.56.10")
    parser.add_argument("--port", type=int, default=13777, help="VM MCP port")
    parser.add_argument("--file", required=True, help="Host path to .i64/.so file")
    args = parser.parse_args()
    main(args.vm_ip, args.port, args.file)
