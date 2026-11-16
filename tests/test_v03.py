"""v0.3 local-only integration suite for proxy, signed collector and fleet reporting."""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from deceptionsensor.agent_lab import create_agent_experiment, evaluate_agents
from deceptionsensor.analytics import report
from deceptionsensor.collector import CollectorSettings, CollectorServer, validate_event
from deceptionsensor.config import Settings
from deceptionsensor.proxy import LocalUpstream
from deceptionsensor.server import SensorServer
from deceptionsensor.shipper import collector_target, send_batch, ship_logs
from deceptionsensor.storage import iter_events
from deceptionsensor.__main__ import fleet_action

TOKEN = "local-agent-token-12345678901234567890"
KEY1 = "collector-key-sensor-alpha-12345678901234567890"
KEY2 = "collector-key-sensor-bravo-12345678901234567890"


@contextmanager
def serve(server):
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


class FakeUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.reply({"object": "list", "data": [{"id": "local-lab-model"}]})

    def reply(self, data):
        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        content = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        self.server.observed.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                                     "proxy_token": self.headers.get("X-Proxy-Token"), "data": json.loads(content)})
        if self.server.response_type == "sse":
            raw = b'data: {"choices":[{"delta":{"content":"lab reply"}}]}\n\ndata: [DONE]\n\n'
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif self.server.response_type == "html":
            raw = b"<html>not expected</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        else:
            self.reply({"object": "chat.completion", "choices": [{"message": {"content": "real-local-model-response"}}]})


@contextmanager
def fake_upstream(response_type="json"):
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstreamHandler)
    server.observed = []
    server.response_type = response_type
    with serve(server):
        yield server


@contextmanager
def proxy_sensor(folder: Path, port: int, registry: Path | None = None, sensor_id="sensor-alpha"):
    config = Settings(host="127.0.0.1", port=0, log_dir=folder, capture_mode="metadata",
                      secret="s" * 32, max_request_bytes=65536, requests_per_minute=200,
                      rotate_bytes=250000, retention_files=2, sensor_id=sensor_id,
                      canary_registry=registry, proxy_upstream=f"http://127.0.0.1:{port}",
                      proxy_client_token=TOKEN, proxy_max_response_bytes=65536)
    with serve(SensorServer(("127.0.0.1", 0), config)) as srv:
        yield srv


@contextmanager
def collector(folder: Path):
    cfg = CollectorSettings(host="127.0.0.1", port=0, database=folder / "fleet.sqlite3",
                            keys={"sensor-alpha": KEY1, "sensor-bravo": KEY2})
    with serve(CollectorServer(cfg)) as srv:
        yield srv


def req(port, method, path, data=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    body = json.dumps(data).encode() if data is not None else None
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    status, result = resp.status, resp.read().decode()
    conn.close()
    return status, result


class ProxyTests(unittest.TestCase):
    def test_restricted_upstream(self):
        for url in ("https://api.example.org", "http://169.254.169.254:80", "http://10.0.0.1:80",
                    "http://localhost:8090/path", "http://localhost:99999", "http://localhost:8090?to=evil",
                    "http://user:pass@localhost:8090", "file:///etc/passwd"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                LocalUpstream.parse(url)
        self.assertEqual(LocalUpstream.parse("http://localhost:1234").port, 1234)

    def test_proxy_requires_token_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            with fake_upstream() as upstream:
                with proxy_sensor(Path(tmp), upstream.server_address[1]) as sensor:
                    port = sensor.server_address[1]
                    self.assertEqual(req(port, "POST", "/v1/chat/completions", {"messages": []})[0], 401)
                    self.assertEqual(req(port, "GET", "/v1/models")[0], 401)
                    self.assertEqual(len(upstream.observed), 0)
            env = {"PROXY_UPSTREAM_URL": "http://127.0.0.1:11434", "PROXY_CLIENT_TOKEN": "short"}
            with patch.dict(os.environ, env):
                with self.assertRaises(ValueError):
                    Settings.from_env()

    def test_real_local_model_response_and_no_header_forward(self):
        with tempfile.TemporaryDirectory() as tmp, fake_upstream() as up:
            with proxy_sensor(Path(tmp), up.server_address[1]) as sensor:
                payload = {"messages": [{"role": "system", "content": "PRIVATE LOCAL LAB MESSAGE"}]}
                status, content = req(sensor.server_address[1], "POST", "/v1/chat/completions", payload,
                                       {"X-Proxy-Token": TOKEN, "Authorization": "Bearer third-party-client-token"})
            self.assertEqual(status, 200)
            self.assertIn("real-local-model-response", content)
            self.assertEqual(len(up.observed), 1)
            self.assertIsNone(up.observed[0]["authorization"])
            self.assertIsNone(up.observed[0]["proxy_token"])
            logs = (Path(tmp) / "events.jsonl").read_text()
            self.assertNotIn("PRIVATE LOCAL LAB", logs)
            self.assertNotIn("third-party-client-token", logs)
            self.assertNotIn(TOKEN, logs)
            self.assertEqual(report(Path(tmp))["proxy_outcomes"], 1)

    def test_sse_stream_is_relayed(self):
        with tempfile.TemporaryDirectory() as tmp, fake_upstream("sse") as up:
            with proxy_sensor(Path(tmp), up.server_address[1]) as sensor:
                status, content = req(sensor.server_address[1], "POST", "/v1/chat/completions",
                                      {"stream": True, "messages": []}, {"X-Proxy-Token": TOKEN})
            self.assertEqual(status, 200)
            self.assertIn("data: [DONE]", content)
            self.assertIn("lab reply", content)

    def test_bad_upstream_mime_blocked(self):
        with tempfile.TemporaryDirectory() as tmp, fake_upstream("html") as up:
            with proxy_sensor(Path(tmp), up.server_address[1]) as sensor:
                status, content = req(sensor.server_address[1], "POST", "/v1/chat/completions",
                                      {"messages": []}, {"X-Proxy-Token": TOKEN})
            self.assertEqual(status, 502)
            self.assertNotIn("<html>", content)

    def test_real_agent_canary_via_proxy(self):
        with tempfile.TemporaryDirectory() as tmp, fake_upstream() as up:
            folder = Path(tmp)
            registry = folder / "agent-registry.json"
            create_agent_experiment(registry)
            marker = next(c["marker"] for c in json.loads(registry.read_text())["canaries"] if c["kind"] == "memory")
            with proxy_sensor(folder / "logs", up.server_address[1], registry) as sensor:
                port = sensor.server_address[1]
                for i in range(2):
                    status, response = req(port, "POST", "/v1/chat/completions", {
                        "messages": [{"role": "system", "content": "Synthetic agent memory " + marker},
                                     {"role": "user", "content": f"Authorized step {i}"}]},
                        {"X-Proxy-Token": TOKEN, "X-Lab-Case-ID": "agent-memory", "X-Session-ID": "safe-lab-001"})
                    self.assertEqual(status, 200)
                    self.assertIn("real-local-model-response", response)
            result = evaluate_agents(folder / "logs", registry)
            self.assertEqual(result["observed_seeded_cases"], 1)
            self.assertEqual(result["exposed_observed_seeded_cases"], 1)
            self.assertEqual(result["context_exposure_rate_observed"], 1.0)
            self.assertEqual(result["cases"][2]["status"], "observed")  # memory case
            self.assertNotIn(marker, (folder / "logs" / "events.jsonl").read_text())


class CollectorTests(unittest.TestCase):
    def test_insecure_remote_collector_forbidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"sensor-alpha": KEY1}))
            with self.assertRaises(ValueError):
                CollectorSettings.from_file(keys, "0.0.0.0", 18888, Path(tmp) / "db")
        for url in ("http://example.com:18888", "http://10.0.0.2:18888", "http://evil.com@127.0.0.1:8"):
            with self.assertRaises(ValueError):
                collector_target(url)

    def test_schema_allowlist_drops_unknown_and_raw(self):
        event = {"event_id": "a" * 32, "sensor_id": "sensor-alpha", "ts": "2026-11-17T00:00:00Z",
                 "schema_version": "0.3.0", "capture_mode": "metadata", "route": "/hidden-secret-path",
                 "request_raw": "SECRET_SHOULD_NOT_BE_PRESENT", "detail": "P4SSW0RD", "model": "PRIVATE", "indicators": ["agent_memory_reference"]}
        clean = validate_event(event, "sensor-alpha")
        self.assertIsNotNone(clean)
        self.assertEqual(clean["route"], "/other")
        self.assertNotIn("SECRET", json.dumps(clean))
        self.assertNotIn("PRIVATE", json.dumps(clean))
        event["capture_mode"] = "raw"
        self.assertIsNone(validate_event(event, "sensor-alpha"))

    def test_ship_ingest_replay_dedupe_and_fleet(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with fake_upstream() as up:
                with proxy_sensor(folder / "alpha", up.server_address[1]) as sensor:
                    self.assertEqual(req(sensor.server_address[1], "POST", "/v1/chat/completions",
                                        {"messages": [{"role": "system", "content": "my private text"}]},
                                        {"X-Proxy-Token": TOKEN})[0], 200)
            alpha = list(iter_events(folder / "alpha"))
            self.assertEqual(len(alpha), 2)
            beta = dict(alpha[0], sensor_id="sensor-bravo", event_id="b" * 32)
            with collector(folder) as fleet:
                port = fleet.server_address[1]
                url = f"http://127.0.0.1:{port}"
                r1 = ship_logs(folder / "alpha", url, "sensor-alpha", KEY1)
                r2 = send_batch(url, "sensor-alpha", KEY1, alpha)
                r3 = send_batch(url, "sensor-bravo", KEY2, [beta])
                self.assertEqual(r1["sent"], 2)
                self.assertEqual(r2["duplicates"], 2)
                self.assertEqual(r3["inserted"], 1)
                with self.assertRaises(ConnectionError):
                    send_batch(url, "sensor-alpha", "incorrect-secret-of-sufficient-length-abcdef", alpha)
            exported = fleet_action(folder / "fleet.sqlite3", "fleet-export", folder / "out" / "events.jsonl")
            self.assertEqual(exported["events"], 3)
            data = (folder / "out" / "events.jsonl").read_text()
            self.assertNotIn("my private text", data)
            self.assertEqual(exported["by_sensor"], {"sensor-alpha": 2, "sensor-bravo": 1})
            stats = fleet_action(folder / "fleet.sqlite3", "fleet-report")
            self.assertEqual(stats["report"]["events"], 2)  # upstream outcome excluded
            self.assertEqual(stats["report"]["proxy_outcomes"], 1)
            self.assertEqual(stats["report"]["unique_session_hashes"], 2)
            dash = fleet_action(folder / "fleet.sqlite3", "fleet-dashboard", folder / "fleet.html")
            self.assertTrue(Path(dash["output"]).is_file())
            self.assertIn("sensor-bravo", Path(dash["output"]).read_text())


    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI unavailable")
    def test_verified_https_transport(self):
        """Self-signed SAN=localhost is trusted only via the explicit lab CA file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            cert, key = path / "collector.crt", path / "collector.key"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            cfg = CollectorSettings(host="127.0.0.1", port=0, database=path / "fleet.sqlite3",
                                    keys={"sensor-alpha": KEY1}, tls_cert=cert, tls_key=key)
            event = {"event_id": "d" * 32, "sensor_id": "sensor-alpha", "ts": "2026-11-17T00:00:00Z",
                     "schema_version": "0.3.0", "capture_mode": "metadata"}
            with serve(CollectorServer(cfg)) as srv:
                dest = "https://localhost:" + str(srv.server_address[1])
                with self.assertRaises(Exception):
                    send_batch(dest, "sensor-alpha", KEY1, [event])  # untrusted self-signed cert
                response = send_batch(dest, "sensor-alpha", KEY1, [event], ca_file=str(cert))
                self.assertEqual(response["inserted"], 1)
                self.assertEqual(send_batch(dest, "sensor-alpha", KEY1, [event], ca_file=str(cert))["duplicates"], 1)

    def test_bad_timestamp_and_signature_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, collector(Path(tmp)) as srv:
            port = srv.server_address[1]
            event = {"event_id": "c" * 32, "sensor_id": "sensor-alpha", "ts": "2026-11-17T00:00:00Z",
                     "schema_version": "0.3.0", "capture_mode": "metadata"}
            raw = json.dumps({"events": [event]}).encode()
            old = str(int(time.time()) - 600)
            signed = (old + "\n" + "sensor-alpha" + "\n").encode() + raw
            signature = hmac.new(KEY1.encode(), signed, hashlib.sha256).hexdigest()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("POST", "/v1/events", body=raw,
                         headers={"X-Sensor-ID": "sensor-alpha", "X-Timestamp": old, "X-Signature": signature})
            response = conn.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            conn.close()


if __name__ == "__main__":
    unittest.main()
