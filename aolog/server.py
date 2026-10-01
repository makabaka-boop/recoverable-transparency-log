"""HTTP API for the append-only audit log."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .canonical import canonicalize
from .store import MAX_PAYLOAD, AppendOnlyStore

MAX_BATCH_BODY = MAX_PAYLOAD * 4


def _json_bytes(value: Any) -> bytes:
    return canonicalize(value)


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class LogRequestHandler(BaseHTTPRequestHandler):
    server_version = "AppendOnlyLog/1.0"

    def _send_json(self, status: int, value: Any) -> None:
        body = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("request body is required")
        if length > MAX_BATCH_BODY:
            raise OverflowError("request body is too large")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("truncated request body")
        return json.loads(raw.decode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        parsed = urlsplit(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        query = parse_qs(parsed.query)
        store: AppendOnlyStore = self.server.store  # type: ignore[attr-defined]
        try:
            if parts == ["v1", "head"]:
                self._send_json(HTTPStatus.OK, store.current_head())
            elif len(parts) == 3 and parts[:2] == ["v1", "records"]:
                index = int(parts[2])
                payload = store.get_record(index)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            elif parts == ["v1", "proof"]:
                head = store.current_head()
                index = int(query["index"][0])
                size = int(query.get("size", [head["tree_size"]])[0])
                self._send_json(
                    HTTPStatus.OK,
                    store.inclusion_proof(index, size),
                )
            elif parts == ["v1", "consistency"]:
                head = store.current_head()
                old_size = int(query["old_size"][0])
                new_size = int(query.get("new_size", [head["tree_size"]])[0])
                self._send_json(
                    HTTPStatus.OK,
                    store.consistency_proof(old_size, new_size),
                )
            else:
                self._send_error(HTTPStatus.NOT_FOUND, "unknown endpoint")
        except (IndexError, ValueError, KeyError) as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))

    def do_POST(self) -> None:  # noqa: N802 - stdlib API
        parsed = urlsplit(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        store: AppendOnlyStore = self.server.store  # type: ignore[attr-defined]
        try:
            if parts != ["v1", "append"]:
                self._send_error(HTTPStatus.NOT_FOUND, "unknown endpoint")
                return
            body = self._read_json()
            if isinstance(body, dict) and "records" in body:
                values = body["records"]
            else:
                values = body
            if not isinstance(values, list) or not values:
                raise ValueError("records must be a non-empty JSON array")
            normalized = [canonicalize(value) for value in values]
            sequence_numbers = store.append_batch(normalized)
            self._send_json(HTTPStatus.OK, {
                "sequence_numbers": sequence_numbers,
                "tree_head": store.current_head(),
            })
        except OverflowError as exc:
            self._send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, str(exc))
        except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))

    def log_message(self, fmt: str, *args: object) -> None:
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)


def build_server(directory: str, host: str = "127.0.0.1", port: int = 0,
                 *, crash_at: str | None = None, verbose: bool = False) -> ThreadingHTTPServer:
    server = ReusableThreadingHTTPServer((host, port), LogRequestHandler)
    server.store = AppendOnlyStore(directory, crash_at=crash_at)  # type: ignore[attr-defined]
    server.verbose = verbose
    return server
