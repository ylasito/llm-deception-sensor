"""Passive LLM API emulation: no real LLM, tools, credential validation or outbound calls."""
from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from typing import Any
import hmac as secure_hmac
import http.client
import socket
from urllib.parse import urlsplit
import uuid

from .config import Settings
from .detection import analyze, redact
from .storage import JsonlSink
from .canary import CanaryRegistry
from .mcp import dispatch as mcp_dispatch, PROTOCOL_VERSION as MCP_PROTOCOL
from .proxy import LocalUpstream, POST_PATHS, GET_PATHS, is_safe_mime
from .fidelity import openai_response, ollama_response, fingerprint


FAKE_MODELS = ("llama3.2:latest", "qwen2.5:7b")
MODEL_TEXT = "Ready."


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Throttle:
    """Small in-process rate limiter; use a reverse proxy for robust DoS controls."""
    def __init__(self, quota: int):
        self.quota = quota
        self.calls: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self.lock:
            if len(self.calls) > 10000:
                self.calls = defaultdict(deque, {k: v for k, v in self.calls.items() if v and v[-1] > now - 60})
            q = self.calls[client]
            while q and q[0] < now - 60:
                q.popleft()
            if len(q) >= self.quota:
                return False
            q.append(now)
            return True


class SensorServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], settings: Settings):
        super().__init__(address, SensorHandler)
        self.settings = settings
        self.sink = JsonlSink(settings.log_dir, settings.rotate_bytes, settings.retention_files)
        self.throttle = Throttle(settings.requests_per_minute)
        self.registry = CanaryRegistry.load(settings.canary_registry)
        if settings.proxy_upstream:
            LocalUpstream.parse(settings.proxy_upstream)
            if len(settings.proxy_client_token) < 24 or settings.capture_mode != "metadata":
                raise ValueError("Local proxy requires a >=24 character client token and metadata capture")


class SensorHandler(BaseHTTPRequestHandler):
    server: SensorServer
    server_version = "Ollama/0.6"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)  # Bound inactive / slow client connections.

    def log_message(self, fmt: str, *args: Any) -> None:
        # Avoid leaking request paths, auth tokens or unredacted payloads to stdout.
        return

    def _client_key(self) -> str:
        return self.client_address[0]

    def _hash(self, value: str) -> str:
        return hmac.new(self.server.settings.secret.encode(), value.encode(), hashlib.sha256).hexdigest()[:24]

    def _session_key(self) -> str:
        sid = self.headers.get("X-Session-ID", "")[:256]
        auth = self.headers.get("Authorization", "")[:256]
        fallback = self._client_key() + ":" + self.headers.get("User-Agent", "")[:256]
        value = "session:" + sid if sid else "auth:" + auth if auth else "peer:" + fallback
        return self._hash(value)

    def _send(self, status: int, result: Any, content_type: str = "application/json") -> None:
        body = (json.dumps(result, separators=(",", ":")) if content_type == "application/json" else str(result)).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _stream(self, payloads: list[dict[str, Any]], kind: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if kind == "sse" else "application/x-ndjson")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for payload in payloads:
                data = json.dumps(payload, separators=(",", ":"))
                line = f"data: {data}\n\n" if kind == "sse" else data + "\n"
                self.wfile.write(line.encode())
            if kind == "sse":
                self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def _stream_events(self, events: list[dict]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for event in events:
                line = f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
                self.wfile.write(line.encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def _capture(self, route: str, payload: Any, byte_count: int, method: str, extra: str = "") -> str:
        findings = analyze(payload, route)
        model = payload.get("model", "") if isinstance(payload, dict) else ""
        messages = payload.get("messages", []) if isinstance(payload, dict) else []
        if not isinstance(model, str):
            model = ""
        if not isinstance(messages, list):
            messages = []
        accepted_roles = {"system", "developer", "user", "assistant", "tool", "function"}
        roles = [m.get("role") if isinstance(m.get("role"), str) and m.get("role") in accepted_roles else "other"
                 for m in messages[:100] if isinstance(m, dict)]
        registry_hits = self.server.registry.hits(payload)
        mcp_method = ""
        mcp_tool = ""
        if route == "/mcp" and isinstance(payload, dict):
            candidate = payload.get("method")
            mcp_method = candidate if isinstance(candidate, str) and candidate in (
                "initialize", "ping", "tools/list", "tools/call", "resources/list", "resources/read",
                "prompts/list", "prompts/get", "notifications/initialized") else "other"
            if mcp_method == "tools/call" and isinstance(payload.get("params"), dict):
                candidate = payload["params"].get("name")
                mcp_tool = candidate if isinstance(candidate, str) and candidate in (
                    "research_catalog", "read_sample_note", "lookup_agent_status") else "other"
        record = {
            "schema_version": "0.3.0", "event_kind": "request", "sensor_id": self.server.settings.sensor_id,
            "ts": timestamp(), "event_id": uuid.uuid4().hex,
            "client_id": self._hash("client:" + self._client_key()),
            "session_id": self._session_key(), "method": method, "route": redact(route[:120]),
            "request_bytes": byte_count, "model": redact(model[:100]),
            "message_count": len(messages), "roles": [str(v)[:32] for v in roles],
            "indicators": findings["tags"], "risk_score": findings["risk_score"],
            "severity": findings["severity"], "capture_mode": self.server.settings.capture_mode,
            "endpoint_family": ("mcp" if route == "/mcp" else "ollama" if route.startswith("/api/")
                                else "openai" if route.startswith("/v1/") else "other"),
            "mcp_method": mcp_method, "mcp_tool": mcp_tool,
            "canary_hits": registry_hits,
            "confirmed_synthetic_exposure": bool(registry_hits),
            "fidelity": fingerprint(payload) if route in ("/v1/chat/completions", "/chat/completions", "/api/chat") else {},
        }
        lab_case = self.server.registry.case(self.headers.get("X-Lab-Case-ID", ""))
        if lab_case:
            record["lab_case_id"] = lab_case
        if extra:
            record["detail"] = extra
        if self.server.settings.capture_mode == "redacted":
            record["request_redacted"] = redact(payload)
        elif self.server.settings.capture_mode == "raw":
            record["request_raw"] = payload
        self.server.sink.emit(record)
        return record["event_id"]

    def _precheck(self, path: str, method: str) -> bool:
        if not self.server.throttle.allow(self._client_key()):
            self._capture(path, {}, 0, method, "rate_limited")
            self._send(429, {"error": {"message": "Too many requests", "type": "rate_limit_error"}})
            return False
        return True

    def _proxy_auth(self) -> bool:
        supplied = self.headers.get("X-Proxy-Token", "")
        expected = self.server.settings.proxy_client_token
        if not supplied or len(supplied) > 256 or not secure_hmac.compare_digest(supplied, expected):
            # Never log supplied token or value of Authorization.
            self._send(401, {"error": {"message": "Proxy client token required"}})
            self.close_connection = True
            return False
        return True

    def _proxy_outcome(self, route: str, parent: str, status: int | None, error: str = "") -> None:
        event = {
            "schema_version": "0.3.0", "event_kind": "proxy_outcome",
            "sensor_id": self.server.settings.sensor_id, "ts": timestamp(),
            "event_id": uuid.uuid4().hex, "parent_event_id": parent,
            "session_id": self._session_key(), "client_id": self._hash("client:" + self._client_key()),
            "route": route, "capture_mode": "metadata", "endpoint_family":
            "ollama" if route.startswith("/api/") else "openai",
        }
        if status is not None:
            event["proxy_upstream_status"] = status
        if error:
            event["proxy_error"] = error
        self.server.sink.emit(event)

    def _relay(self, method: str, route: str, parent: str, body: bytes | None = None) -> None:
        """Forward only fixed API paths to explicitly configured 127.0.0.1 endpoint.

        Never forward the caller's Authorization, X-Proxy-Token, cookies, or
        headers that contain request context. SSE/NDJSON bytes pass through
        incrementally without ever being stored in telemetry.
        """
        upstream = LocalUpstream.parse(self.server.settings.proxy_upstream)
        if upstream.port == self.server.server_address[1] and self.server.server_address[0] in ("127.0.0.1", "0.0.0.0", "localhost"):
            self._proxy_outcome(route, parent, None, "upstream_self_loop")
            self._send(502, {"error": {"message": "Upstream cannot point to sensor itself"}})
            return
        conn = upstream.connect()
        headers_sent = False
        try:
            outgoing = {"Accept": "application/json, text/event-stream, application/x-ndjson",
                        "User-Agent": "LLM-Deception-Sensor/0.3", "Content-Type": "application/json"}
            if self.server.settings.proxy_upstream_api_key:
                outgoing["Authorization"] = "Bearer " + self.server.settings.proxy_upstream_api_key
            conn.request(method, route, body=body, headers=outgoing)
            resp = conn.getresponse()
            mime = resp.getheader("Content-Type", "application/json")
            if not is_safe_mime(mime):
                self._proxy_outcome(route, parent, None, "upstream_bad_mime")
                self._send(502, {"error": {"message": "Unsupported upstream response format"}})
                return
            length = resp.getheader("Content-Length", "")
            if length.isdigit() and int(length) > self.server.settings.proxy_max_response_bytes:
                self._proxy_outcome(route, parent, None, "upstream_response_too_large")
                self._send(502, {"error": {"message": "Upstream response too large"}})
                return
            self.send_response(resp.status)
            self.send_header("Content-Type", mime.split(";", 1)[0].strip().lower())
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            headers_sent = True
            total = 0
            error = ""
            try:
                while True:
                    part = resp.read1(8192)
                    if not part:
                        break
                    total += len(part)
                    if total > self.server.settings.proxy_max_response_bytes:
                        error = "upstream_response_too_large"
                        break
                    self.wfile.write(part)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                error = "client_disconnected"
            except (OSError, http.client.HTTPException):
                error = "upstream_read_error"
            self._proxy_outcome(route, parent, resp.status, error)
            self.close_connection = True
        except (OSError, socket.timeout, http.client.HTTPException):
            self._proxy_outcome(route, parent, None, "upstream_connection_failed")
            if not headers_sent and not self.wfile.closed:
                try:
                    self._send(502, {"error": {"message": "Local inference upstream unavailable"}})
                except (BrokenPipeError, ConnectionResetError):
                    pass
            self.close_connection = True
        finally:
            conn.close()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if not self._precheck(path, "GET"):
            return
        if self.server.settings.proxy_upstream and path in GET_PATHS:
            if not self._proxy_auth():
                return
            parent = self._capture(path, {}, 0, "GET", "local_proxy")
            self._relay("GET", path, parent)
            return
        self._capture(path, {}, 0, "GET")
        if path == "/healthz":
            self._send(200, {"status": "ok"})
        elif path == "/":
            self._send(200, "Ollama is running", content_type="text/plain")
        elif path == "/api/version":
            self._send(200, {"version": "0.6.0"})
        elif path == "/api/tags":
            self._send(200, {"models": [{"name": name, "model": name, "modified_at": "2026-01-01T00:00:00Z", "size": 4000000000, "digest": "sha256:" + ("0" * 64), "details": {"format": "gguf", "family": "llama"}} for name in FAKE_MODELS]})
        elif path in ("/v1/models", "/models"):
            self._send(200, {"object": "list", "data": [{"id": m, "object": "model", "created": 1700000000, "owned_by": "local"} for m in FAKE_MODELS]})
        else:
            self._send(404, {"error": {"message": "Not found", "type": "invalid_request_error"}})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if not self._precheck(path, "POST"):
            self.close_connection = True
            return
        if self.server.settings.proxy_upstream and path in POST_PATHS and not self._proxy_auth():
            return
        if self.headers.get("Transfer-Encoding"):
            self._capture(path, {}, 0, "POST", "unsupported_transfer_encoding")
            self._send(400, {"error": {"message": "Transfer encoding not supported"}})
            self.close_connection = True
            return
        length = self.headers.get("Content-Length", "")
        if not length.isdigit():
            self._capture(path, {}, 0, "POST", "missing_content_length")
            self._send(411, {"error": {"message": "Content-Length required"}})
            self.close_connection = True
            return
        n = int(length)
        if n > self.server.settings.max_request_bytes:
            self._capture(path, {}, n, "POST", "request_too_large")
            self._send(413, {"error": {"message": "Request too large"}})
            self.close_connection = True
            return
        raw = self.rfile.read(n)
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("Object expected")
        except (ValueError, UnicodeDecodeError):
            self._capture(path, {}, n, "POST", "invalid_json")
            self._send(400, {"error": {"message": "Invalid JSON object", "type": "invalid_request_error"}})
            return
        # MCP Streamable HTTP browser-origin validation (all other routes also reject foreign origins).
        origin = self.headers.get("Origin", "")
        if origin:
            parsed_origin = urlsplit(origin)
            if (parsed_origin.scheme not in ("http", "https") or
                parsed_origin.hostname not in ("localhost", "127.0.0.1", "::1") or
                parsed_origin.username is not None or parsed_origin.password is not None or
                parsed_origin.path not in ("", "/") or parsed_origin.query):
                self._capture(path, {}, n, "POST", "rejected_origin")
                self._send(403, {"error": {"message": "Origin not allowed"}})
                return
        canonical = "/mcp" if path in ("/mcp", "/mcp/") else path
        parent = self._capture(canonical, payload, n, "POST", "local_proxy" if self.server.settings.proxy_upstream and canonical in POST_PATHS else "")
        if self.server.settings.proxy_upstream and canonical in POST_PATHS:
            self._relay("POST", canonical, parent, raw)
            return
        if canonical == "/mcp":
            version = self.headers.get("MCP-Protocol-Version", "")
            if version and version != MCP_PROTOCOL:
                self._send(400, {"jsonrpc": "2.0", "id": payload.get("id"),
                                 "error": {"code": -32600, "message": "Unsupported MCP version: supports 2025-03-26 subset"}})
                return
            status, result = mcp_dispatch(payload)
            if result is None:
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            else:
                self._send(status, result)
            return
        model = payload.get("model", FAKE_MODELS[0])
        if not isinstance(model, str):
            model = FAKE_MODELS[0]
        model = model[:100]
        created = int(time.time())
        if path in ("/v1/chat/completions", "/chat/completions"):
            cid = "chatcmpl-" + uuid.uuid4().hex[:18]
            result, chunks = openai_response(payload, cid, model, created)
            if payload.get("stream") is True:
                self._stream(chunks, "sse")
            else:
                self._send(200, result)
        elif path in ("/api/chat", "/api/generate"):
            chat = path == "/api/chat"
            result = ollama_response(payload, model, timestamp(), chat)
            if payload.get("stream", True) is False:
                self._send(200, result)
            else:
                self._stream([result], "ndjson")
        elif path == "/v1/embeddings":
            items = payload.get("input", "")
            inputs = items if isinstance(items, list) else [items]
            if len(inputs) > 100:
                self._send(400, {"error": {"message": "Too many inputs"}})
                return
            self._send(200, {"object": "list", "data": [{"object": "embedding", "index": i, "embedding": [0.0] * 8} for i in range(len(inputs))], "model": model, "usage": {"prompt_tokens": 0, "total_tokens": 0}})
        elif path == "/v1/responses":
            msg_id = "msg_" + uuid.uuid4().hex[:12]
            response = {"id": "resp_" + uuid.uuid4().hex, "object": "response", "created_at": created,
                        "status": "completed", "model": model,
                        "output": [{"id": msg_id, "type": "message", "status": "completed", "role": "assistant",
                                    "content": [{"type": "output_text", "text": MODEL_TEXT, "annotations": []}]}],
                        "usage": {"input_tokens": 0, "output_tokens": 1, "total_tokens": 1}}
            if payload.get("stream") is True:
                events = [
                    {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}, "sequence_number": 0},
                    {"type": "response.output_text.delta", "item_id": msg_id, "output_index": 0,
                     "content_index": 0, "delta": MODEL_TEXT, "sequence_number": 1},
                    {"type": "response.output_text.done", "item_id": msg_id, "output_index": 0,
                     "content_index": 0, "text": MODEL_TEXT, "sequence_number": 2},
                    {"type": "response.completed", "response": response, "sequence_number": 3},
                ]
                self._stream_events(events)
            else:
                self._send(200, response)
        else:
            self._send(404, {"error": {"message": "Not found", "type": "invalid_request_error"}})


def serve(settings: Settings) -> None:
    with SensorServer((settings.host, settings.port), settings) as server:
        print(f"LLM deception sensor on {settings.host}:{settings.port}; capture={settings.capture_mode}; " + ("local model proxy enabled" if settings.proxy_upstream else "decoy-only, no outbound inference"), flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
