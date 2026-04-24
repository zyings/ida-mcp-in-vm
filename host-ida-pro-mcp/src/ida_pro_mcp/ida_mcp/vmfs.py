"""Raw HTTP file-transfer endpoints mounted on the IDA plugin's MCP HTTP server.

Motivation
----------
When the MCP client (agent) runs on a host and IDA runs inside a VM, the
analyst needs to get binaries from host into the VM without relying on a
shared folder. This module exposes chunked upload / download over plain
HTTP on the same port the MCP plugin already listens on (default 13337),
so the only connectivity requirement is the existing MCP channel.

Endpoints (all rooted at /vmfs)
    GET  /vmfs/tempdir                 -> {base, platform}
    GET  /vmfs/stat?path=...           -> {exists,size,sha256,is_dir,mtime}
    POST /vmfs/upload/begin            body JSON {filename, gzip?} -> {upload_id, path}
    POST /vmfs/upload/chunk?id=<uid>&final=<0|1>   body: raw bytes (optionally gzip)
    POST /vmfs/upload/abort?id=<uid>   -> {ok}
    GET  /vmfs/download?path=...&offset=<n>&length=<n>  -> raw bytes

The JSON-RPC body size limit does NOT apply here because we parse the path
before `_read_body()` is called and stream directly from rfile.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
import zlib
from typing import Optional
from urllib.parse import parse_qs, urlparse

# Chunk upload session state. Keyed by upload_id.
# { upload_id: {"path": str, "fh": file, "sha": hasher, "size": int,
#               "gzip": bool, "created": float} }
_uploads: dict[str, dict] = {}
_uploads_lock = threading.Lock()

# Max age of an idle upload before abort (seconds).
UPLOAD_TTL = 3600

# Max per-chunk body size (safety net). 64MB is plenty for any sane chunk.
MAX_CHUNK_BYTES = 64 * 1024 * 1024

# Base directory for uploads. Subdir of tempdir keeps things tidy and easy
# to purge. Created lazily.
_VMFS_SUBDIR = "ida_mcp_vmfs"


# Filename sanitation: strip path separators, drive letters, parent refs.
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._\- +()\[\]]")


def _vmfs_base_dir() -> str:
    base = os.path.join(tempfile.gettempdir(), _VMFS_SUBDIR)
    os.makedirs(base, exist_ok=True)
    return base


def _sanitize_filename(name: str) -> str:
    # Keep just the basename; reject empty / purely dots.
    name = os.path.basename(name.replace("\\", "/"))
    name = _SAFE_NAME_RE.sub("_", name).strip(". ")
    if not name:
        name = "upload.bin"
    return name[:200]


def _gc_stale_uploads() -> None:
    now = time.time()
    stale: list[str] = []
    with _uploads_lock:
        for uid, rec in _uploads.items():
            if now - rec.get("created", now) > UPLOAD_TTL:
                stale.append(uid)
        for uid in stale:
            rec = _uploads.pop(uid, None)
            if rec and rec.get("fh"):
                try:
                    rec["fh"].close()
                except Exception:
                    pass


class VmfsHandlerMixin:
    """Mixin adding /vmfs/* routing.

    Drop this before McpHttpRequestHandler in the MRO. Parent class's
    do_GET/do_POST are still invoked for non-matching paths.
    """

    # -------- dispatch hooks (called from IdaMcpHttpRequestHandler) --------

    def vmfs_try_handle_get(self, path: str) -> bool:
        if path == "/vmfs/tempdir":
            self._vmfs_tempdir()
            return True
        if path == "/vmfs/stat":
            self._vmfs_stat()
            return True
        if path == "/vmfs/download":
            self._vmfs_download()
            return True
        return False

    def vmfs_try_handle_post(self, path: str) -> bool:
        if path == "/vmfs/upload/begin":
            self._vmfs_upload_begin()
            return True
        if path == "/vmfs/upload/chunk":
            self._vmfs_upload_chunk()
            return True
        if path == "/vmfs/upload/abort":
            self._vmfs_upload_abort()
            return True
        return False

    # ------------------------------ helpers ------------------------------

    def _vmfs_send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _vmfs_send_error(self, status: int, message: str) -> None:
        self._vmfs_send_json(status, {"error": message})

    def _vmfs_query(self) -> dict[str, str]:
        qs = parse_qs(urlparse(self.path).query)
        return {k: v[0] for k, v in qs.items() if v}

    # ------------------------------ GET ---------------------------------

    def _vmfs_tempdir(self) -> None:
        import sys as _sys
        self._vmfs_send_json(
            200,
            {"base": _vmfs_base_dir(), "platform": _sys.platform},
        )

    def _vmfs_stat(self) -> None:
        q = self._vmfs_query()
        path = q.get("path", "")
        if not path:
            self._vmfs_send_error(400, "Missing 'path'")
            return
        if not os.path.exists(path):
            self._vmfs_send_json(200, {"exists": False})
            return
        try:
            st = os.stat(path)
            is_dir = os.path.isdir(path)
            info = {
                "exists": True,
                "is_dir": is_dir,
                "size": st.st_size,
                "mtime": st.st_mtime,
            }
            # Hash only when not too large or caller requested.
            want_sha = q.get("sha256", "1") not in ("0", "false", "False")
            if want_sha and not is_dir:
                info["sha256"] = _hash_file(path)
            self._vmfs_send_json(200, info)
        except OSError as e:
            self._vmfs_send_error(500, f"stat failed: {e}")

    def _vmfs_download(self) -> None:
        q = self._vmfs_query()
        path = q.get("path", "")
        if not path or not os.path.isfile(path):
            self._vmfs_send_error(404, "Not a file")
            return
        try:
            offset = int(q.get("offset", "0"))
            length_raw = q.get("length", "")
            length = int(length_raw) if length_raw else -1
        except ValueError:
            self._vmfs_send_error(400, "Bad offset/length")
            return

        total = os.path.getsize(path)
        if offset < 0 or offset > total:
            self._vmfs_send_error(416, "offset out of range")
            return
        remaining = total - offset if length < 0 else min(length, total - offset)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(remaining))
        self.send_header("X-Total-Size", str(total))
        self.end_headers()
        with open(path, "rb") as f:
            f.seek(offset)
            buf_size = 1024 * 1024
            while remaining > 0:
                chunk = f.read(min(buf_size, remaining))
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    return
                remaining -= len(chunk)

    # ------------------------------ POST --------------------------------

    def _read_exact(self, n: int) -> bytes:
        # HTTPBaseHandler's self.rfile is a BufferedReader; read in loops
        # to handle partial reads on huge uploads.
        data = bytearray()
        while len(data) < n:
            chunk = self.rfile.read(n - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def _vmfs_upload_begin(self) -> None:
        _gc_stale_uploads()
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0 or content_length > 8 * 1024:
            self._vmfs_send_error(400, "Invalid begin body size")
            return
        raw = self._read_exact(content_length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._vmfs_send_error(400, f"Bad JSON: {e}")
            return
        filename = _sanitize_filename(str(body.get("filename") or "upload.bin"))
        use_gzip = bool(body.get("gzip", False))

        upload_id = uuid.uuid4().hex
        base = _vmfs_base_dir()
        # Nest uploads under upload_id dir to avoid collisions across concurrent uploads.
        upload_dir = os.path.join(base, upload_id)
        os.makedirs(upload_dir, exist_ok=True)
        path = os.path.join(upload_dir, filename)

        fh = open(path, "wb")
        with _uploads_lock:
            _uploads[upload_id] = {
                "path": path,
                "fh": fh,
                "sha": hashlib.sha256(),
                "size": 0,
                "gzip": use_gzip,
                # Per-upload streaming zlib decompressor (None until first chunk when gzip).
                "inflator": None,
                "created": time.time(),
            }
        self._vmfs_send_json(200, {"upload_id": upload_id, "path": path})

    def _vmfs_upload_chunk(self) -> None:
        q = self._vmfs_query()
        upload_id = q.get("id", "")
        final = q.get("final", "0") in ("1", "true", "True")
        with _uploads_lock:
            rec = _uploads.get(upload_id)
        if rec is None:
            self._vmfs_send_error(404, "Unknown upload_id")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length < 0 or content_length > MAX_CHUNK_BYTES:
            self._vmfs_send_error(413, "Chunk too large")
            return

        data = self._read_exact(content_length) if content_length > 0 else b""

        try:
            if rec["gzip"]:
                # Each chunk is an independent complete gzip stream (matches
                # the host-side _gzip_compress, which compresses per-chunk).
                # Empty chunks are allowed (zero-byte file / final sentinel).
                plain = gzip.decompress(data) if data else b""
            else:
                plain = data

            if plain:
                rec["fh"].write(plain)
                rec["sha"].update(plain)
                rec["size"] += len(plain)
                rec["created"] = time.time()
        except Exception as e:
            self._vmfs_send_error(500, f"chunk write failed: {e}")
            return

        if not final:
            self._vmfs_send_json(200, {"ok": True, "size": rec["size"]})
            return

        # Finalize
        with _uploads_lock:
            _uploads.pop(upload_id, None)
        try:
            rec["fh"].flush()
            rec["fh"].close()
        except Exception:
            pass
        self._vmfs_send_json(
            200,
            {
                "ok": True,
                "path": rec["path"],
                "size": rec["size"],
                "sha256": rec["sha"].hexdigest(),
            },
        )

    def _vmfs_upload_abort(self) -> None:
        q = self._vmfs_query()
        upload_id = q.get("id", "")
        with _uploads_lock:
            rec = _uploads.pop(upload_id, None)
        if rec is None:
            self._vmfs_send_error(404, "Unknown upload_id")
            return
        try:
            rec["fh"].close()
        except Exception:
            pass
        try:
            os.remove(rec["path"])
        except OSError:
            pass
        self._vmfs_send_json(200, {"ok": True})


def _hash_file(path: str, max_bytes: Optional[int] = None) -> str:
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as f:
        while True:
            buf = f.read(1024 * 1024)
            if not buf:
                break
            if max_bytes is not None and read + len(buf) > max_bytes:
                h.update(buf[: max_bytes - read])
                break
            h.update(buf)
            read += len(buf)
    return h.hexdigest()
