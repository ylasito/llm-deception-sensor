"""Full Lab bootstrap, synthetic agent, telemetry collection and read-only UI tests."""
from __future__ import annotations
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from deceptionsensor.collector import CollectorSettings, CollectorServer
from deceptionsensor.config import Settings
from deceptionsensor.full_lab import init, run_test_agent, summary, render_html, DashboardServer, serve_sensor
from deceptionsensor.server import SensorServer
from deceptionsensor.shipper import ship_logs


@contextmanager
def running(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        t.join(3)


class FullLabTests(unittest.TestCase):
    def test_bootstrap_idempotent_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [root / x for x in ("secrets", "shared", "sensor", "fleet")]
            a = init(*paths)
            self.assertEqual(a["status"], "initialized")
            sensor_secret = (paths[0] / "sensor-secret.txt").read_text()
            collector_key = json.loads((paths[0] / "collector-keys.json").read_text())["local-sensor"]
            registry = json.loads((paths[1] / "registry.json").read_text())
            self.assertEqual(len(registry["cases"]), 7)
            self.assertEqual(init(*paths), a)
            self.assertEqual(sensor_secret, (paths[0] / "sensor-secret.txt").read_text())
            self.assertEqual(collector_key, (paths[0] / "shipper-key.txt").read_text().strip())
            self.assertEqual((paths[0] / "sensor-secret.txt").stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(collector_key, sensor_secret.strip())

    def test_bootstrap_fails_closed_on_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = [root / x for x in ("secrets", "shared", "sensor", "fleet")]
            init(*p)
            (p[0] / "shipper-key.txt").write_text("x" * 64)
            with self.assertRaises(ValueError):
                init(*p)

    def test_agent_forbids_external_network_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                run_test_agent(Path(tmp), host="attacker.example.com")
            with self.assertRaises(ValueError):
                run_test_agent(Path(tmp), host="169.254.169.254")

    def test_integrated_synthetic_end_to_end_and_dashboard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = [root / x for x in ("secrets", "shared", "sensor", "fleet")]
            init(*p)
            config = Settings(host="127.0.0.1", port=0, log_dir=p[2], capture_mode="metadata",
                              secret=(p[0] / "sensor-secret.txt").read_text().strip(), max_request_bytes=65536,
                              requests_per_minute=200, rotate_bytes=5_000_000, retention_files=2,
                              sensor_id="local-sensor", canary_registry=p[1] / "registry.json")
            server = SensorServer(("127.0.0.1", 0), config)
            with running(server):
                status = run_test_agent(p[1] / "registry.json", host="127.0.0.1", port=server.server_address[1])
                self.assertTrue(status["all_ok"], status)
                self.assertEqual(status["requests"], 8)
            key = (p[0] / "shipper-key.txt").read_text().strip()
            ccfg = CollectorSettings(host="127.0.0.1", port=0, database=p[3] / "events.sqlite3",
                                     keys={"local-sensor": key})
            collector = CollectorServer(ccfg)
            with running(collector):
                result = ship_logs(p[2], f"http://127.0.0.1:{collector.server_address[1]}", "local-sensor", key)
            self.assertGreaterEqual(result["sent"], 8, result)
            view = summary(p[3] / "events.sqlite3")
            self.assertEqual(view["status"], "ok")
            self.assertEqual(view["total_events"], 8)
            self.assertEqual(view["recent_sessions"], 8)
            self.assertGreaterEqual(view["synthetic_exposure_events"], 4)
            html = render_html(view)
            self.assertIn("not evidence of an unauthorized agent leak", html)
            self.assertNotIn("LABCANARY_", html)
            dashboard = DashboardServer(("127.0.0.1", 0), p[3] / "events.sqlite3")
            with running(dashboard):
                conn = http.client.HTTPConnection("127.0.0.1", dashboard.server_address[1], timeout=3)
                conn.request("GET", "/api/summary")
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                self.assertEqual(json.loads(response.read())["total_events"], 8)
                conn.close()
            raw = (p[2] / "events.jsonl").read_text()
            self.assertNotIn("LABCANARY_", raw)
            self.assertNotIn(key, raw)

    def test_dashboard_waiting_and_escaping(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = summary(Path(tmp) / "missing.db")
            self.assertEqual(data["status"], "waiting_for_collector")
            html = render_html({**data, "last_event_at": '<script>alert("x")</script>',
                                "by_route": {"<script>": 12}})
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)

    def test_compose_configuration_includes_safe_ports(self):
        compose = (Path(__file__).resolve().parents[1] / "compose.full-lab.yaml").read_text()
        self.assertIn('127.0.0.1:18080:8080', compose)
        self.assertIn('127.0.0.1:18081:8081', compose)
        self.assertIn('internal: true', compose)
        self.assertIn('network_mode: service:collector', compose)
        for service in ('sensor:', 'collector:', 'shipper:', 'dashboard:', 'test-agent:'):
            self.assertIn(service, compose)


if __name__ == "__main__":
    unittest.main()
