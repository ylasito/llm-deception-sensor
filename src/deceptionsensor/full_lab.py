"""Docker Full Lab: isolated, reproducible synthetic workload and local dashboard.

No real model, arbitrary tool execution, external API calls, or real secrets.
The lab bootstrap is intended for an operator-owned Docker environment only.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import time
import uuid

from .canary import CanaryRegistry
from .config import Settings
from .lab import init_lab
from .server import serve

LAB_USER_ID = 10001
SENSOR_ID = "local-sensor"


def _private_file(path: Path, content: str) -> None:
    """Create a new private file without overwriting existing credentials."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    if os.geteuid() == 0:
        os.chown(path, LAB_USER_ID, LAB_USER_ID)


def _volume_dir(path: Path, *, private: bool = False) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(path, LAB_USER_ID, LAB_USER_ID)
    path.chmod(0o700 if private else 0o750)


def init(secrets_dir: Path, shared_dir: Path, sensor_dir: Path, fleet_dir: Path) -> dict:
    """Generate only synthetic canaries and persistent local signing keys.

    Uses a restricted, one-shot bootstrap container to assign UID ownership of
    fresh named volumes. Never outputs key values. Fails on inconsistent state.
    """
    os.umask(0o077)
    for p, private in ((secrets_dir, True), (shared_dir, False), (sensor_dir, False), (fleet_dir, False)):
        _volume_dir(p, private=private)
    sensor_secret = secrets_dir / "sensor-secret.txt"
    collector_keys = secrets_dir / "collector-keys.json"
    shipper_key = secrets_dir / "shipper-key.txt"
    registry = shared_dir / "registry.json"
    if not sensor_secret.exists():
        _private_file(sensor_secret, secrets.token_hex(32) + "\n")
    if not collector_keys.exists():
        if shipper_key.exists():
            raise RuntimeError("Incomplete fleet key state; do not generate mismatched signing keys")
        key = secrets.token_hex(32)
        _private_file(collector_keys, json.dumps({SENSOR_ID: key}) + "\n")
        _private_file(shipper_key, key + "\n")
    else:
        data = json.loads(collector_keys.read_text(encoding="utf-8"))
        key = data.get(SENSOR_ID, "")
        if not isinstance(key, str) or len(key) < 32:
            raise ValueError("Invalid pre-existing fleet key")
        if not shipper_key.exists():
            _private_file(shipper_key, key + "\n")
        if shipper_key.read_text(encoding="utf-8").strip() != key:
            raise ValueError("Collector and shipper keys mismatch")
    if not registry.exists():
        init_lab(registry)
    CanaryRegistry.load(registry)
    for file in (sensor_secret, collector_keys, shipper_key, registry):
        file.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(file, LAB_USER_ID, LAB_USER_ID)
    return {"status": "initialized", "registry": "synthetic", "secrets": "persisted_in_private_docker_volume"}


def serve_sensor(secrets_dir: Path, shared_dir: Path) -> None:
    secret = (secrets_dir / "sensor-secret.txt").read_text(encoding="utf-8").strip()
    if len(secret) < 32:
        raise ValueError("Missing strong sensor secret")
    # Explicitly fail closed: Full Lab never proxies to any other inference host.
    if os.environ.get("PROXY_UPSTREAM_URL") or os.environ.get("ALLOW_RAW_CAPTURE"):
        raise ValueError("Docker Full Lab forbids upstream proxy and raw capture")
    os.environ.update({"SENSOR_SECRET": secret, "CANARY_REGISTRY": str(shared_dir / "registry.json"),
                       "CAPTURE_MODE": "metadata", "SENSOR_ID": SENSOR_ID})
    serve(Settings.from_env())


def synthetic_cases(registry_path: Path) -> list[tuple[str, str, dict]]:
    reg = CanaryRegistry.load(registry_path)
    expected = {"baseline", "system", "tool", "memory", "knowledge", "mcp", "keyword"}
    if set(reg.cases) != expected:
        raise ValueError("Full Lab requires standard seven-case synthetic registry")
    markers = {c.kind: c.marker for c in reg.canaries}
    return [
        ("baseline", "/v1/chat/completions", {"model": "fictional-lab", "messages": [{"role": "user", "content": "Hello lab"}]}),
        ("system", "/v1/chat/completions", {"model": "fictional-lab", "messages": [{"role": "system", "content": "Synthetic only: " + markers["system"]}, {"role": "user", "content": "Hello"}]}),
        ("tool", "/api/chat", {"model": "fictional-lab", "stream": False, "messages": [{"role": "tool", "content": "Synthetic tool output " + markers["tool"]}]}),
        ("memory", "/v1/responses", {"model": "fictional-lab", "input": [{"role": "developer", "content": "Synthetic memory " + markers["memory"]}]}),
        ("knowledge", "/v1/chat/completions", {"model": "fictional-lab", "messages": [{"role": "user", "content": "Synthetic graph " + markers["knowledge_graph"]}]}),
        ("mcp", "/mcp", {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "read_sample_note", "arguments": {"note_id": markers["memory"]}}}),
        ("keyword", "/v1/chat/completions", {"model": "fictional-lab", "messages": [{"role": "user", "content": "Describe imaginary agent memory and system prompts."}]}),
        ("tool-call", "/v1/chat/completions", {"model": "fictional-lab", "messages": [{"role": "user", "content": "Invoke synthetic research catalog"}], "tools": [{"type": "function", "function": {"name": "research_catalog", "parameters": {"type": "object", "properties": {}}}}], "tool_choice": "required", "stream": True}),
    ]


def run_test_agent(registry: Path, *, host: str = "sensor", port: int = 8080) -> dict:
    """Single bounded synthetic batch against an explicitly allowlisted lab service."""
    if host not in ("sensor", "127.0.0.1", "localhost") or not 1 <= port <= 65535:
        raise ValueError("Test agent target must be internal sensor or loopback")
    batch_id = "full-lab-" + uuid.uuid4().hex[:12]
    statuses: list[int] = []
    for name, route, body in synthetic_cases(registry):
        conn = http.client.HTTPConnection(host, port, timeout=8)
        try:
            conn.request("POST", route, body=json.dumps(body).encode("utf-8"), headers={
                "Content-Type": "application/json", "X-Lab-Case-ID": name if name != "tool-call" else "baseline",
                "X-Session-ID": batch_id + "-" + name,
            })
            response = conn.getresponse()
            response.read(262144)
            statuses.append(response.status)
        finally:
            conn.close()
    return {"type": "synthetic_calibration_not_a_real_agent", "requests": len(statuses),
            "http_successes": sum(s == 200 for s in statuses), "all_ok": all(s == 200 for s in statuses)}


def agent_loop(registry: Path, interval: int = 45) -> None:
    if not 15 <= interval <= 3600:
        raise ValueError("Interval must be 15-3600 seconds")
    while True:
        try:
            print(json.dumps(run_test_agent(registry)), flush=True)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            # Never log request data or generated synthetic marker values.
            print(json.dumps({"test_agent_status": "retrying", "error_type": type(exc).__name__}), flush=True)
        time.sleep(interval)


def summary(db_path: Path, limit: int = 2000) -> dict:
    """Read a bounded, metadata-only view of collector SQLite without writes."""
    result: dict = {"status": "waiting_for_collector", "total_events": 0, "recent_events": 0,
                    "recent_sessions": 0, "synthetic_exposure_events": 0,
                    "by_route": {}, "by_sensor": {}, "by_severity": {}, "last_event_at": None}
    if not db_path.is_file():
        return result
    uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        records = db.execute("SELECT payload FROM events ORDER BY row_id DESC LIMIT ?", (limit,)).fetchall()
    routes: Counter[str] = Counter()
    sensors: Counter[str] = Counter()
    severity: Counter[str] = Counter()
    sessions: set[tuple[str, str]] = set()
    hits = 0
    last_ts = None
    for (item,) in records:
        try:
            event = json.loads(item)
        except (json.JSONDecodeError, TypeError):
            continue
        if last_ts is None:
            last_ts = event.get("ts") if isinstance(event.get("ts"), str) else None
        if event.get("event_kind") != "request":
            continue
        route = event.get("route", "/other")
        routes[route if route in {"/mcp", "/v1/chat/completions", "/api/chat", "/v1/responses", "/other"} else "other"] += 1
        sensor = event.get("sensor_id", "unknown")
        sensors[sensor if sensor == SENSOR_ID else "other"] += 1
        level = event.get("severity", "informational")
        severity[level if level in ("informational", "low", "medium", "high") else "other"] += 1
        sid = event.get("session_id", "")
        if isinstance(sid, str) and sid:
            sessions.add((sensor, sid))
        hits += bool(event.get("canary_hits"))
    result.update({"status": "ok", "total_events": total, "recent_events": len(records),
                   "recent_sessions": len(sessions), "synthetic_exposure_events": hits,
                   "by_route": dict(routes), "by_sensor": dict(sensors), "by_severity": dict(severity),
                   "last_event_at": last_ts,
                   "interpretation": "Synthetic context intentionally sent by calibration agent; not proof of compromise."})
    return result


def _list_rows(items: dict) -> str:
    if not items:
        return "<tr><td colspan='2'>No observed requests yet</td></tr>"
    return "".join(f"<tr><td>{escape(str(k))}</td><td class='num'>{int(v)}</td></tr>"
                   for k, v in sorted(items.items(), key=lambda x: (-x[1], x[0])))


def render_html(data: dict) -> str:
    def num(key: str) -> str:
        return str(int(data.get(key, 0)))
    routes = _list_rows(data.get("by_route", {}))
    levels = _list_rows(data.get("by_severity", {}))
    stamp = escape(str(data.get("last_event_at") or "No events yet"))
    state = escape(str(data.get("status", "unknown")))
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta http-equiv='refresh' content='10'><title>LLM Deception — Local Full Lab</title>
<style>body{{font:15px system-ui,sans-serif;background:#0b1220;color:#f0f4fa;margin:0;padding:32px}}
main{{max-width:1060px;margin:auto}}h1{{font-size:27px}}p{{color:#b0bfd3;line-height:1.6}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:24px 0}}
.card,.table{{background:#152138;border:1px solid #30405a;border-radius:12px;padding:18px}}
.card strong{{display:block;font-size:30px;color:#95f2d4}}table{{width:100%;border-collapse:collapse}}
td,th{{text-align:left;padding:9px;border-bottom:1px solid #30405a}}.num{{text-align:right}}
.columns{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}@media(max-width:640px){{.columns{{grid-template-columns:1fr}}}}
small{{color:#b0bfd3}}</style></head><body><main>
<h1>LLM Deception Sensor — Full Lab</h1>
<p>Local synthetic experiment only · Auto-refresh every 10 seconds · Collector status: {state}</p>
<div class='cards'><div class='card'><small>Total collector events</small><strong>{num('total_events')}</strong></div>
<div class='card'><small>Recent events analyzed</small><strong>{num('recent_events')}</strong></div>
<div class='card'><small>Recent pseudonymous sessions</small><strong>{num('recent_sessions')}</strong></div>
<div class='card'><small>Recent synthetic canary observations</small><strong>{num('synthetic_exposure_events')}</strong></div></div>
<div class='columns'><section class='table'><h2>Endpoint requests</h2><table>{routes}</table></section>
<section class='table'><h2>Severity labels</h2><table>{levels}</table></section></div>
<p>Latest event (UTC): {stamp}</p><p><strong>Interpretation:</strong> The test-agent intentionally transmits
fictional markers. Observed canary transport is calibration, not evidence of an unauthorized agent leak.
No actual prompt, credentials or canary strings are displayed.</p>
<small>Read-only metadata dashboard · 2,000 latest events max · Not intended for public exposure</small></main></body></html>"""


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: tuple[str, int], database: Path):
        super().__init__(addr, DashboardHandler)
        self.database = database


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        return

    def respond(self, status: int, payload: bytes, mimetype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mimetype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.respond(200, b'{"status":"ok"}', "application/json")
            return
        if self.path not in ("/", "/api/summary"):
            self.respond(404, b'{"error":"not_found"}', "application/json")
            return
        try:
            data = summary(self.server.database)
        except (sqlite3.DatabaseError, OSError):
            self.respond(503, b'{"error":"collector_unavailable"}', "application/json")
            return
        if self.path == "/api/summary":
            payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
            self.respond(200, payload, "application/json")
        else:
            self.respond(200, render_html(data).encode("utf-8"), "text/html; charset=utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Docker Full Lab: synthetic sensors, shipper, collector and local web dashboard")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("sensor")
    agent = commands.add_parser("test-agent")
    agent.add_argument("--once", action="store_true")
    agent.add_argument("--interval", type=int, default=45)
    dashboard = commands.add_parser("dashboard")
    dashboard.add_argument("--host", default="0.0.0.0")
    dashboard.add_argument("--port", type=int, default=8081)
    opts = parser.parse_args()
    secrets_path = Path(os.getenv("LAB_SECRETS_DIR", "/run/lab-secrets"))
    shared = Path(os.getenv("LAB_SHARED_DIR", "/lab"))
    if opts.command == "init":
        print(json.dumps(init(secrets_path, shared, Path("/data"), Path("/fleet"))), flush=True)
    elif opts.command == "sensor":
        serve_sensor(secrets_path, shared)
    elif opts.command == "test-agent":
        if opts.once:
            result = run_test_agent(shared / "registry.json")
            print(json.dumps(result), flush=True)
            if not result["all_ok"]:
                raise SystemExit(1)
        else:
            agent_loop(shared / "registry.json", interval=opts.interval)
    else:
        httpd = DashboardServer((opts.host, opts.port), Path("/fleet/events.sqlite3"))
        try:
            httpd.serve_forever(poll_interval=0.3)
        finally:
            httpd.server_close()


if __name__ == "__main__":
    main()
