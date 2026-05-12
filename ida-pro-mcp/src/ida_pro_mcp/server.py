import argparse
import gzip
import hashlib
import http.client
import io
import json
import os
import sys
import threading
import traceback
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse, urlencode

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc
except ImportError:
    from installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

# --------------------------------------------------------------------------
# Streamable-HTTP MCP session handshake state for talking to the VM endpoint.
# When the VM launcher runs with --isolated-contexts (or any future build that
# enables session semantics by default), every POST to /mcp must carry a valid
# Mcp-Session-Id obtained from a prior `initialize` call. We perform that
# handshake lazily and cache the session id for subsequent forwarded requests.
# --------------------------------------------------------------------------
_VM_SESSION_ID: Optional[str] = None
_VM_SESSION_LOCK = threading.Lock()
_MCP_PROTOCOL_VERSION = "2025-03-26"


def _read_mcp_response(resp: "http.client.HTTPResponse") -> tuple[int, dict[str, str], bytes, Optional[dict]]:
    """Read an MCP HTTP response.

    Returns (status, headers_lower, raw_body, parsed_json_or_none).
    Handles both `application/json` and `text/event-stream` (SSE) content
    types — the streamable HTTP transport may pick either.
    """
    raw = resp.read()
    headers = {k.lower(): v for k, v in resp.getheaders()}
    ctype = headers.get("content-type", "")
    parsed: Optional[dict] = None
    if "application/json" in ctype:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            parsed = None
    elif "text/event-stream" in ctype:
        # Take the LAST `data: {...}` line — that's the JSON-RPC reply.
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    try:
                        parsed = json.loads(payload)
                    except Exception:
                        pass
    return resp.status, headers, raw, parsed


def _initialize_vm_session() -> Optional[str]:
    """Perform an MCP `initialize` handshake with the VM and return the
    `Mcp-Session-Id` header (or None if the VM doesn't use sessions)."""
    init_req = {
        "jsonrpc": "2.0",
        "id": "_host_init",
        "method": "initialize",
        "params": {
            "protocolVersion": _MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ida-pro-mcp-host-proxy", "version": "2.0.0"},
        },
    }
    body = json.dumps(init_req).encode("utf-8")
    conn = http.client.HTTPConnection(IDA_HOST, IDA_PORT, timeout=30)
    try:
        conn.request(
            "POST", "/mcp", body,
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        resp = conn.getresponse()
        status, headers, raw, _ = _read_mcp_response(resp)
        sid = headers.get("mcp-session-id")
        if status >= 400:
            raise RuntimeError(f"VM initialize failed: HTTP {status} {raw[:200]!r}")
    finally:
        conn.close()

    if sid:
        # Send the required initialized notification with the new session id.
        note = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        body2 = json.dumps(note).encode("utf-8")
        conn = http.client.HTTPConnection(IDA_HOST, IDA_PORT, timeout=30)
        try:
            conn.request(
                "POST", "/mcp", body2,
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": sid,
                },
            )
            conn.getresponse().read()
        finally:
            conn.close()
    return sid


def _get_vm_session_id(force_refresh: bool = False) -> Optional[str]:
    global _VM_SESSION_ID
    if force_refresh:
        with _VM_SESSION_LOCK:
            _VM_SESSION_ID = None
    if _VM_SESSION_ID is None:
        with _VM_SESSION_LOCK:
            if _VM_SESSION_ID is None:
                _VM_SESSION_ID = _initialize_vm_session()
    return _VM_SESSION_ID


def _post_mcp(payload: bytes, *, _retry: bool = True) -> tuple[int, dict[str, str], bytes, Optional[dict]]:
    """POST a JSON-RPC payload to the VM /mcp endpoint, attaching the cached
    session id (auto-handshaking if needed). Retries once on 400/404 by
    re-running initialize, in case the remote session expired."""
    sid = _get_vm_session_id()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if sid:
        headers["Mcp-Session-Id"] = sid

    conn = http.client.HTTPConnection(IDA_HOST, IDA_PORT, timeout=600)
    try:
        conn.request("POST", "/mcp", payload, headers)
        resp = conn.getresponse()
        result = _read_mcp_response(resp)
    finally:
        conn.close()

    status = result[0]
    raw = result[2]
    if _retry and status in (400, 404) and (b"Session" in raw or b"session" in raw):
        # Session expired or never established — refresh and retry once.
        _get_vm_session_id(force_refresh=True)
        return _post_mcp(payload, _retry=False)
    return result


mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


# ============================================================================
# Host-local tools (vm_* file transfer helpers)
# ----------------------------------------------------------------------------
# These tools run ENTIRELY on the host (agent side). They reach into the VM
# only via raw HTTP /vmfs/* endpoints exposed by the IDA plugin. They are NOT
# forwarded through JSON-RPC dispatch_proxy, so the 10MB MCP body limit and
# base64 overhead do not apply.
# ============================================================================

# Upload chunk size. 4MB strikes a good balance between throughput and memory.
UPLOAD_CHUNK_SIZE = 4 * 1024 * 1024

# Names of tools that are handled locally on the host (see dispatch_proxy).
HOST_LOCAL_TOOLS: set[str] = set()


def _host_tool(func):
    """Decorator: register a tool on the host-local McpServer and mark it
    as non-forwarded in HOST_LOCAL_TOOLS."""
    HOST_LOCAL_TOOLS.add(func.__name__)
    return mcp.tool(func)


def _vmfs_http(method: str, path: str, *, body: bytes | None = None,
               headers: dict[str, str] | None = None, timeout: int = 300
               ) -> tuple[int, dict[str, str], bytes]:
    """Issue a raw HTTP request to the IDA plugin. Returns (status, headers, body)."""
    conn = http.client.HTTPConnection(IDA_HOST, IDA_PORT, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, data
    finally:
        conn.close()


def _vmfs_json(method: str, path: str, *, json_body: dict | None = None,
               timeout: int = 60) -> dict:
    body = json.dumps(json_body).encode("utf-8") if json_body is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    status, _h, data = _vmfs_http(method, path, body=body, headers=headers, timeout=timeout)
    try:
        payload = json.loads(data.decode("utf-8")) if data else {}
    except Exception:
        payload = {"raw": data[:256].decode("utf-8", "replace")}
    if status >= 400:
        raise RuntimeError(f"VMFS {method} {path} -> HTTP {status}: {payload}")
    return payload


@_host_tool
def vm_tempdir() -> dict:
    """Return the VM-side base directory used by vm_upload for incoming files.

    Use this before vm_upload if you need to know where the file will land,
    or to construct a custom destination path under the VM's temp area.
    """
    return _vmfs_json("GET", "/vmfs/tempdir")


@_host_tool
def vm_stat(path: str, include_sha256: bool = True) -> dict:
    """Stat a file path inside the VM (size, sha256, mtime, is_dir).

    Useful to verify a prior upload or to check whether an IDA-produced
    artifact (e.g. .i64) already exists before calling vm_download.
    """
    q = urlencode({"path": path, "sha256": "1" if include_sha256 else "0"})
    return _vmfs_json("GET", f"/vmfs/stat?{q}")


@_host_tool
def vm_upload(host_path: str, filename: Optional[str] = None,
              use_gzip: bool = False) -> dict:
    """Upload a file from the host (agent machine) into the VM temp dir.

    The file is streamed in fixed-size chunks over the MCP plugin's raw
    /vmfs/upload endpoint. The LLM sees only this single tool call; chunking
    happens inside the Python server process, so context stays clean.

    Parameters
    ----------
    host_path: absolute path on the host / agent machine.
    filename:  override the target filename on the VM (defaults to basename).
    use_gzip:  gzip-compress each chunk in flight. Off by default (raw is
               2-4x faster on fast links). Turn on for WAN or metered
               networks where the file has real redundancy (text, symbols).

    Returns {path, size, sha256} where `path` is the absolute VM path. Feed
    that path to open_binary / idalib_open for analysis.
    """
    if not os.path.isfile(host_path):
        raise FileNotFoundError(f"Host file not found: {host_path}")
    size = os.path.getsize(host_path)
    target_name = filename or os.path.basename(host_path)

    begin = _vmfs_json("POST", "/vmfs/upload/begin",
                       json_body={"filename": target_name, "gzip": use_gzip})
    upload_id: str = begin["upload_id"]
    vm_path: str = begin["path"]

    host_sha = hashlib.sha256()
    sent = 0
    try:
        with open(host_path, "rb") as f:
            while True:
                raw = f.read(UPLOAD_CHUNK_SIZE)
                if not raw and sent > 0:
                    break
                if raw:
                    host_sha.update(raw)
                    sent += len(raw)
                final = sent >= size
                payload = _gzip_compress(raw) if use_gzip else raw
                q = urlencode({"id": upload_id, "final": "1" if final else "0"})
                status, _h, data = _vmfs_http(
                    "POST", f"/vmfs/upload/chunk?{q}",
                    body=payload,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=600,
                )
                if status >= 400:
                    raise RuntimeError(
                        f"upload/chunk HTTP {status}: "
                        f"{data[:256].decode('utf-8', 'replace')}"
                    )
                if final:
                    result = json.loads(data.decode("utf-8"))
                    if result.get("sha256") != host_sha.hexdigest():
                        raise RuntimeError(
                            f"sha256 mismatch: host={host_sha.hexdigest()} "
                            f"vm={result.get('sha256')}"
                        )
                    return {
                        "path": result["path"],
                        "size": result["size"],
                        "sha256": result["sha256"],
                        "host_path": host_path,
                        "vm_path": vm_path,
                    }
        # Zero-byte file edge case
        q = urlencode({"id": upload_id, "final": "1"})
        status, _h, data = _vmfs_http(
            "POST", f"/vmfs/upload/chunk?{q}",
            body=b"",
            headers={"Content-Type": "application/octet-stream"},
            timeout=60,
        )
        result = json.loads(data.decode("utf-8"))
        return {
            "path": result["path"],
            "size": result["size"],
            "sha256": result["sha256"],
            "host_path": host_path,
            "vm_path": vm_path,
        }
    except Exception:
        # Best-effort abort so the server doesn't leak the half-written file.
        try:
            _vmfs_json("POST", f"/vmfs/upload/abort?{urlencode({'id': upload_id})}")
        except Exception:
            pass
        raise


@_host_tool
def vm_download(vm_path: str, host_dest: str) -> dict:
    """Download a file from the VM to the host. Streams in 4MB chunks.

    Useful for pulling back .i64 databases, analysis reports, or any file
    the agent wrote inside the VM.
    """
    os.makedirs(os.path.dirname(os.path.abspath(host_dest)) or ".", exist_ok=True)
    h = hashlib.sha256()
    written = 0

    # First, stat to get total size (single short HTTP call; cheap).
    info = _vmfs_json("GET", f"/vmfs/stat?{urlencode({'path': vm_path, 'sha256': '0'})}")
    if not info.get("exists") or info.get("is_dir"):
        raise FileNotFoundError(f"VM path not a file: {vm_path}")
    total: int = int(info["size"])

    with open(host_dest, "wb") as out:
        offset = 0
        while offset < total:
            length = min(UPLOAD_CHUNK_SIZE, total - offset)
            q = urlencode({"path": vm_path, "offset": offset, "length": length})
            status, _h, data = _vmfs_http(
                "GET", f"/vmfs/download?{q}", timeout=600
            )
            if status >= 400:
                raise RuntimeError(
                    f"download HTTP {status}: {data[:256].decode('utf-8', 'replace')}"
                )
            out.write(data)
            h.update(data)
            written += len(data)
            offset += length
    return {
        "host_path": os.path.abspath(host_dest),
        "vm_path": vm_path,
        "size": written,
        "sha256": h.hexdigest(),
    }


def _gzip_compress(data: bytes) -> bytes:
    if not data:
        return b""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=5, mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


def _forward_tools_call(name: str, arguments: dict) -> dict:
    """Call a tool that lives on the IDA plugin side via JSON-RPC.

    Returns the structuredContent / parsed result. Raises on transport error.
    """
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    payload = json.dumps(req).encode("utf-8")
    status, _headers, raw, rpc = _post_mcp(payload)
    if status >= 400:
        raise RuntimeError(f"HTTP {status}: {raw[:300]!r}")
    if rpc is None:
        try:
            rpc = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"Could not parse VM response: {e}; body={raw[:200]!r}")
    if "error" in rpc and rpc["error"]:
        raise RuntimeError(f"RPC error: {rpc['error']}")
    result = rpc.get("result") or {}
    if result.get("isError"):
        # Text-only error from the tool itself.
        content = result.get("content") or []
        msg = content[0].get("text") if content else "unknown error"
        raise RuntimeError(f"{name} failed: {msg}")
    # Prefer structured content when present.
    if "structuredContent" in result:
        return result["structuredContent"]
    content = result.get("content") or []
    if content and content[0].get("type") == "text":
        try:
            return json.loads(content[0]["text"])
        except Exception:
            return {"text": content[0]["text"]}
    return result


@_host_tool
def idalib_open_from_host(
    host_path: str,
    run_auto_analysis: bool = True,
    session_id: Optional[str] = None,
    use_gzip: bool = False,
    keep_filename: Optional[str] = None,
) -> dict:
    """One-shot: upload a binary from the host to the VM and open it in idalib.

    Equivalent to calling `vm_upload(host_path)` then `idalib_open(path)` with
    the returned VM path, but saves a round-trip and keeps the agent prompt
    simple.

    Parameters mirror `vm_upload` + `idalib_open`. Returns the idalib_open
    response, augmented with `upload` info (vm path, size, sha256).
    """
    upload = vm_upload(host_path, filename=keep_filename, use_gzip=use_gzip)
    args = {
        "input_path": upload["path"],
        "run_auto_analysis": run_auto_analysis,
    }
    if session_id is not None:
        args["session_id"] = session_id
    opened = _forward_tools_call("idalib_open", args)
    return {"upload": upload, "open": opened}


# ============================================================================
# JSON-RPC dispatch proxy: route host-local tools locally, forward rest.
# ============================================================================


def _is_local_tools_call(method: str, params: Any) -> bool:
    if method != "tools/call":
        return False
    if not isinstance(params, dict):
        return False
    return params.get("name") in HOST_LOCAL_TOOLS


def _merge_local_tools_into_list(remote_response: Any) -> Any:
    """If remote returned a JSON-RPC response for tools/list, append local tools."""
    if not isinstance(remote_response, dict):
        return remote_response
    result = remote_response.get("result")
    if not isinstance(result, dict):
        return remote_response
    tools_list = result.get("tools")
    if not isinstance(tools_list, list):
        return remote_response

    # Ask the local registry for its tools/list; merge non-duplicates.
    local = dispatch_original({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 0,
    })
    if isinstance(local, dict):
        local_result = local.get("result") or {}
        local_tools = local_result.get("tools") or []
        existing = {t.get("name") for t in tools_list if isinstance(t, dict)}
        for t in local_tools:
            if isinstance(t, dict) and t.get("name") in HOST_LOCAL_TOOLS and t.get("name") not in existing:
                tools_list.append(t)
    return remote_response



def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests. Host-local tools run locally; everything
    else is forwarded to the IDA plugin over HTTP."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj.get("method", "")
    params = request_obj.get("params")

    # Protocol / lifecycle methods stay local.
    if method == "initialize":
        return dispatch_original(request)
    if method.startswith("notifications/"):
        return dispatch_original(request)

    # Host-local tool call: run on this process, never hit the VM.
    if _is_local_tools_call(method, params):
        return dispatch_original(request)

    payload: bytes | str | dict = request
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    try:
        status, _hdrs, raw_data, remote = _post_mcp(payload)
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {raw_data[:400]!r}")
        if remote is None:
            try:
                remote = json.loads(raw_data.decode("utf-8"))
            except Exception as e:
                raise RuntimeError(f"Could not parse VM response: {e}; body={raw_data[:200]!r}")

        # For tools/list, append host-local tools to the remote response.
        if method == "tools/list":
            remote = _merge_local_tools_into_list(remote)
        return remote
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=f"http://{IDA_HOST}:{IDA_PORT}",
        help=f"IDA RPC server to use (default: http://{IDA_HOST}:{IDA_PORT})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port
    set_ida_rpc(IDA_HOST, IDA_PORT)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
