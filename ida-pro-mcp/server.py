# author: yszhang
"""将 ida_server HTTP API 适配为可通过 stdio 运行的最小 MCP 服务。"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_SERVER_URL = "http://192.168.148.128:13337"
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ida-http-bridge"
SERVER_VERSION = "0.1.0"


def eprint(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def json_dumps(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def write_message(payload: dict[str, Any]) -> None:
    body = json_dumps(payload)
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def read_message() -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        key, _, value = line.decode("utf-8", errors="replace").partition(":")
        headers[key.strip().lower()] = value.strip()

    content_length = int(headers.get("content-length", "0"))
    if content_length <= 0:
        return None
    body = sys.stdin.buffer.read(content_length)
    return json.loads(body.decode("utf-8"))


def make_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def build_text_result(data: Any, is_error: bool = False) -> dict[str, Any]:
    if isinstance(data, str):
        text = data
    else:
        text = json.dumps(data, ensure_ascii=False, indent=2)
    result = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return result


class IDAHttpClient:
    def __init__(self, server_url: str) -> None:
        self.server_url = server_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        req = urllib.request.Request(
            self.server_url + path,
            data=body,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(response_text)
            except json.JSONDecodeError:
                payload = {"success": False, "error": response_text or str(exc)}
            return payload

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/api/health")

    def check(self, file_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/check/{urllib.parse.quote(file_id)}")

    def upload(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            return {"success": False, "error": f"文件不存在: {path}"}
        body, content_type = build_multipart_form(
            {
                "file": {
                    "filename": path.name,
                    "content_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                    "data": path.read_bytes(),
                }
            }
        )
        return self._request("POST", "/api/upload", body, {"Content-Type": content_type})

    def run(self, file_id: str, script: str, timeout: int = 300) -> dict[str, Any]:
        payload = {"file_id": file_id, "script": script, "timeout": timeout}
        return self._request(
            "POST",
            "/api/run",
            json_dumps(payload),
            {"Content-Type": "application/json; charset=utf-8"},
        )

    def analyze(self, file_path: str, script: str, timeout: int = 300) -> dict[str, Any]:
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            return {"success": False, "error": f"文件不存在: {path}"}
        body, content_type = build_multipart_form(
            {
                "file": {
                    "filename": path.name,
                    "content_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                    "data": path.read_bytes(),
                },
                "script": {"text": script},
                "timeout": {"text": str(timeout)},
            }
        )
        return self._request("POST", "/api/analyze", body, {"Content-Type": content_type})


def build_multipart_form(parts: dict[str, dict[str, Any]]) -> tuple[bytes, str]:
    boundary = "----TraeIDABridgeBoundary7MA4YWxkTrZu0gW"
    chunks: list[bytes] = []
    for field_name, meta in parts.items():
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        if "data" in meta:
            filename = meta["filename"]
            content_type = meta.get("content_type", "application/octet-stream")
            chunks.append(
                (
                    f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
                    f"Content-Type: {content_type}\r\n\r\n"
                ).encode("utf-8")
            )
            chunks.append(meta["data"])
            chunks.append(b"\r\n")
        else:
            chunks.append(
                f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n{meta["text"]}\r\n'.encode("utf-8")
            )
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(chunks)
    return body, f"multipart/form-data; boundary={boundary}"


def md5_file(file_path: str) -> str:
    hasher = hashlib.md5()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "ida_health",
            "description": "检查远程 ida_server 服务与 IDA 可用状态。",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "ida_check_cache",
            "description": "按 file_id 或本地文件路径检查远程缓存和 IDB 状态。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_id": {"type": "string"},
                    "file_path": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "ida_upload_so",
            "description": "上传本地 so 文件到远程 ida_server 缓存。",
            "inputSchema": {
                "type": "object",
                "properties": {"file_path": {"type": "string"}},
                "required": ["file_path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "ida_run_script",
            "description": "对已缓存的文件运行 IDAPython 脚本。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_id": {"type": "string"},
                    "script": {"type": "string"},
                    "timeout": {"type": "integer", "minimum": 1},
                },
                "required": ["file_id", "script"],
                "additionalProperties": False,
            },
        },
        {
            "name": "ida_analyze_so",
            "description": "上传本地 so 并立即运行 IDAPython 脚本。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "script": {"type": "string"},
                    "timeout": {"type": "integer", "minimum": 1},
                },
                "required": ["file_path", "script"],
                "additionalProperties": False,
            },
        },
    ]


def handle_tool_call(client: IDAHttpClient, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "ida_health":
        return build_text_result(client.health())

    if name == "ida_check_cache":
        file_id = arguments.get("file_id")
        file_path = arguments.get("file_path")
        if not file_id:
            if not file_path:
                return build_text_result({"error": "需要 file_id 或 file_path"}, is_error=True)
            file_id = md5_file(file_path)
        return build_text_result(client.check(file_id))

    if name == "ida_upload_so":
        return build_text_result(client.upload(arguments["file_path"]))

    if name == "ida_run_script":
        return build_text_result(
            client.run(
                file_id=arguments["file_id"],
                script=arguments["script"],
                timeout=int(arguments.get("timeout", 300)),
            )
        )

    if name == "ida_analyze_so":
        return build_text_result(
            client.analyze(
                file_path=arguments["file_path"],
                script=arguments["script"],
                timeout=int(arguments.get("timeout", 300)),
            )
        )

    return build_text_result({"error": f"未知工具: {name}"}, is_error=True)


def serve(server_url: str) -> int:
    client = IDAHttpClient(server_url)
    eprint(f"[{SERVER_NAME}] using ida_server={server_url}")

    while True:
        message = read_message()
        if message is None:
            return 0

        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})

        if method == "initialize":
            result = {
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }
            write_message(make_response(request_id, result))
            continue

        if method == "notifications/initialized":
            continue

        if method == "ping":
            write_message(make_response(request_id, {}))
            continue

        if method == "tools/list":
            write_message(make_response(request_id, {"tools": tool_definitions()}))
            continue

        if method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments", {}) or {}
            try:
                result = handle_tool_call(client, name, arguments)
                write_message(make_response(request_id, result))
            except Exception as exc:  # pylint: disable=broad-except
                write_message(make_response(request_id, build_text_result({"error": str(exc)}, is_error=True)))
            continue

        if request_id is not None:
            write_message(make_error(request_id, -32601, f"不支持的方法: {method}"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trae MCP bridge for ida_server HTTP API")
    parser.add_argument(
        "--server-url",
        default=os.environ.get("IDA_SERVER_URL", DEFAULT_SERVER_URL),
        help="ida_server 的 HTTP 根地址，例如 http://192.168.148.128:13337",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return serve(args.server_url)


if __name__ == "__main__":
    raise SystemExit(main())
