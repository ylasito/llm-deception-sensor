"""Central multi-sensor collector: authenticated, deduplicated, metadata-only.

HMAC covers exact wire bytes. SQLite is the authoritative event store. TLS is
mandatory for non-loopback binds; no remote configuration or command endpoint.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import ssl
import threading
import time
from typing import Any

SENSOR_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
HEX_ID = re.compile(r"[a-f0-9]{32}\Z")
HASH_ID = re.compile(r"[a-f0-9]{24}\Z")
SAFE_WORD = re.compile(r"[a-z_]{1,48}\Z")
CANARY_KIND = {"system", "tool", "memory", "knowledge_graph"}
MAX_BATCH_BYTES = 512_000
MAX_BATCH_EVENTS = 100
SKEW_SECONDS = 300


def validate_event(event: Any, expected_sensor: str) -> dict | None:
    """Only a strict safe allowlist; refuse raw/redacted capture."""
    if not isinstance(event, dict) or event.get("capture_mode") != "metadata":
        return None
    if event.get("sensor_id") != expected_sensor or event.get("schema_version") not in ("0.2.0", "0.3.0"):
        return None
    eid = event.get("event_id")
    if not isinstance(eid, str) or not HEX_ID.fullmatch(eid):
        return None
    ts = event.get("ts", "")
    if not isinstance(ts, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ts):
        return None
    try:
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    out: dict[str, Any] = {
        "schema_version": "0.3.0", "sensor_id": expected_sensor, "ts": ts, "event_id": eid,
        "capture_mode": "metadata", "event_kind": event.get("event_kind") if event.get("event_kind") in ("request", "proxy_outcome") else "request",
    }
    for k in ("client_id", "session_id"):
        val = event.get(k)
        if isinstance(val, str) and HASH_ID.fullmatch(val):
            out[k] = val
    route = event.get("route", "")
    # Whitelisted routes only; unknown probes mapped to a category, not stored verbatim.
    routes = {"/", "/healthz", "/mcp", "/api/chat", "/api/generate", "/api/tags", "/api/version",
              "/v1/chat/completions", "/chat/completions", "/v1/responses", "/v1/models", "/models", "/v1/embeddings"}
    out["route"] = route if isinstance(route, str) and route in routes else "/other"
    for k in ("risk_score", "request_bytes", "message_count"):
        val = event.get(k)
        if type(val) is int and 0 <= val <= 1048576:
            out[k] = val
    severity = event.get("severity")
    if severity in ("informational", "low", "medium", "high"):
        out["severity"] = severity
    method = event.get("method")
    if method in ("GET", "POST"):
        out["method"] = method
    family = event.get("endpoint_family")
    if family in ("openai", "ollama", "mcp", "other"):
        out["endpoint_family"] = family
    for k in ("mcp_method", "mcp_tool", "lab_case_id", "proxy_error"):
        val = event.get(k)
        if isinstance(val, str) and re.fullmatch(r"[a-z0-9/_-]{1,64}", val):
            out[k] = val
    for k in ("indicators", "roles"):
        val = event.get(k)
        if isinstance(val, list):
            out[k] = [x for x in val[:32] if isinstance(x, str) and SAFE_WORD.fullmatch(x)]
    hits = event.get("canary_hits", [])
    if isinstance(hits, list):
        out["canary_hits"] = [
            {"id": x["id"], "kind": x["kind"]}
            for x in hits[:16] if isinstance(x, dict) and isinstance(x.get("id"), str)
            and re.fullmatch(r"[a-z0-9-]{1,64}", x["id"]) and x.get("kind") in CANARY_KIND
        ]
    out["confirmed_synthetic_exposure"] = bool(out.get("canary_hits"))
    status = event.get("proxy_upstream_status")
    if type(status) is int and 100 <= status <= 599:
        out["proxy_upstream_status"] = status
    parent = event.get("parent_event_id")
    if isinstance(parent, str) and HEX_ID.fullmatch(parent):
        out["parent_event_id"] = parent
    # Omit all unknown fields (especially request_raw, request_redacted, auth, prompt).
    return out


class EventDatabase:
    def __init__(self, path: Path, max_events: int = 100_000):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.lock = threading.Lock()
        self.max_events = max_events
        with self.lock:
            self.conn.execute("CREATE TABLE IF NOT EXISTS events (row_id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL, event_id TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(sensor_id,event_id))")
            self.conn.execute("CREATE INDEX IF NOT EXISTS events_sensor ON events(sensor_id)")
            self.conn.commit()
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def insert(self, sensor_id: str, events: list[dict]) -> int:
        inserted = 0
        with self.lock:
            for event in events:
                cursor = self.conn.execute("INSERT OR IGNORE INTO events(sensor_id,event_id,payload) VALUES(?,?,?)",
                                           (sensor_id, event["event_id"], json.dumps(event, separators=(",", ":"))))
                inserted += cursor.rowcount
            self.conn.execute("DELETE FROM events WHERE row_id IN (SELECT row_id FROM events ORDER BY row_id ASC LIMIT max(0,(SELECT COUNT(*) FROM events)-?))", (self.max_events,))
            self.conn.commit()
        return inserted

    def export(self, path: Path) -> dict:
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock, path.open("w", encoding="utf-8") as file:
            cursor = self.conn.execute("SELECT payload FROM events ORDER BY row_id")
            count = 0
            by_sensor = Counter()
            for (payload,) in cursor:
                data = json.loads(payload)
                file.write(json.dumps(data, separators=(",", ":")) + "\n")
                count += 1
                by_sensor[data["sensor_id"]] += 1
        path.chmod(0o600)
        return {"events": count, "by_sensor": dict(by_sensor), "output": str(path)}

    def close(self) -> None:
        with self.lock:
            self.conn.close()


@dataclass(frozen=True)
class CollectorSettings:
    host: str
    port: int
    database: Path
    keys: dict[str, str]
    max_events: int = 100_000
    tls_cert: Path | None = None
    tls_key: Path | None = None

    @classmethod
    def from_file(cls, keys_file: Path, host: str, port: int, db: Path, tls_cert: Path | None = None,
                  tls_key: Path | None = None, max_events: int = 100_000) -> "CollectorSettings":
        raw = json.loads(keys_file.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not raw or not all(
            isinstance(k, str) and SENSOR_PATTERN.fullmatch(k) and isinstance(v, str) and len(v) >= 32
            for k, v in raw.items()
        ):
            raise ValueError("Keys JSON must map sensor IDs to unique, random >=32-character secrets")
        if len(set(raw.values())) != len(raw):
            raise ValueError("Each sensor requires a different collector signing key")
        if not 1 <= port <= 65535 or not 100 <= max_events <= 10_000_000:
            raise ValueError("Invalid port or max-events")
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback and not (tls_cert and tls_key):
            raise ValueError("Non-loopback collector bind requires a TLS certificate and key")
        if bool(tls_cert) != bool(tls_key):
            raise ValueError("TLS requires both certificate and private key")
        return cls(host, port, db, raw, max_events, tls_cert, tls_key)


class CollectorServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, settings: CollectorSettings):
        super().__init__((settings.host, settings.port), CollectorHandler)
        self.settings = settings
        self.database = EventDatabase(settings.database, settings.max_events)
        if settings.tls_cert and settings.tls_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(str(settings.tls_cert), str(settings.tls_key))
            self.socket = ctx.wrap_socket(self.socket, server_side=True)

    def server_close(self) -> None:
        self.database.close()
        super().server_close()


class CollectorHandler(BaseHTTPRequestHandler):
    server: CollectorServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args) -> None:
        return

    def respond(self, status: int, data: dict) -> None:
        raw = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.respond(200, {"status": "ok", "service": "collector"})
        else:
            self.respond(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/v1/events":
            self.respond(404, {"error": "not_found"})
            self.close_connection = True
            return
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or self.headers.get("Transfer-Encoding") or not 1 <= int(length) <= MAX_BATCH_BYTES:
            self.respond(413, {"error": "invalid_body_length"})
            self.close_connection = True
            return
        raw = self.rfile.read(int(length))
        sensor = self.headers.get("X-Sensor-ID", "")
        timestamp = self.headers.get("X-Timestamp", "")
        signature = self.headers.get("X-Signature", "")
        secret = self.server.settings.keys.get(sensor)
        if not secret or not timestamp.isdigit() or len(timestamp) > 12 or not re.fullmatch(r"[0-9a-f]{64}", signature):
            self.respond(401, {"error": "unauthorized"})
            return
        if abs(time.time() - int(timestamp)) > SKEW_SECONDS:
            self.respond(401, {"error": "expired_signature"})
            return
        signed = (timestamp + "\n" + sensor + "\n").encode() + raw
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            self.respond(401, {"error": "unauthorized"})
            return
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self.respond(400, {"error": "invalid_json"})
            return
        if (not isinstance(payload, dict) or not isinstance(payload.get("events"), list)
                or not 1 <= len(payload["events"]) <= MAX_BATCH_EVENTS):
            self.respond(400, {"error": "invalid_batch"})
            return
        clean = [validate_event(e, sensor) for e in payload["events"]]
        if any(e is None for e in clean):
            self.respond(400, {"error": "invalid_event"})
            return
        inserted = self.server.database.insert(sensor, clean)
        self.respond(202, {"accepted": len(clean), "inserted": inserted, "duplicates": len(clean) - inserted})


def serve_collector(config: CollectorSettings) -> None:
    with CollectorServer(config) as server:
        print(f"Central metadata collector listening on {config.host}:{config.port}; TLS={bool(config.tls_cert)}", flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
