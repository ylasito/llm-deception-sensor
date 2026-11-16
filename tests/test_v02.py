"""v0.2 contract tests; local-only and synthetic markers, no external network."""
from __future__ import annotations
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from deceptionsensor.analytics import report
from deceptionsensor.agent_lab import create_agent_experiment, evaluate_agents
from deceptionsensor.canary import CanaryRegistry
from deceptionsensor.config import Settings
from deceptionsensor.dashboard import generate
from deceptionsensor.lab import evaluate_lab, init_lab, run_lab
from deceptionsensor.server import SensorServer
from deceptionsensor.storage import iter_events, JsonlSink


@contextmanager
def sensor(log_dir: Path, registry: Path | None = None):
    settings = Settings(host="127.0.0.1", port=0, log_dir=log_dir, capture_mode="metadata",
                        secret="s" * 32, max_request_bytes=65536, requests_per_minute=400,
                        rotate_bytes=300000, retention_files=2,
                        sensor_id="test-node", canary_registry=registry)
    server = SensorServer((settings.host, settings.port), settings)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(port: int, path: str, payload: dict, headers: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("POST", path, json.dumps(payload).encode(),
                 headers={"Content-Type": "application/json", **(headers or {})})
    response = conn.getresponse()
    status, content_type, body = response.status, response.getheader("Content-Type"), response.read().decode()
    conn.close()
    return status, content_type, body


class MCPTests(unittest.TestCase):
    def test_initialize_and_tools(self):
        with tempfile.TemporaryDirectory() as tmp, sensor(Path(tmp)) as s:
            port = s.server_address[1]
            status, _, raw = request(port, "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                                     {"MCP-Protocol-Version": "2025-03-26"})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw)["result"]["protocolVersion"], "2025-03-26")
            status, _, raw = request(port, "/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            self.assertEqual(status, 200)
            self.assertEqual(len(json.loads(raw)["result"]["tools"]), 3)
            status, _, raw = request(port, "/mcp", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                                    "params": {"name": "read_sample_note", "arguments": {"note_id": "../../etc/passwd"}}})
            self.assertEqual(status, 200)
            self.assertIn("Synthetic note", raw)
            self.assertNotIn("/etc/passwd", raw)
            events = list(iter_events(Path(tmp)))
            self.assertEqual(events[-1]["mcp_method"], "tools/call")
            self.assertEqual(events[-1]["mcp_tool"], "read_sample_note")

    def test_notifications_and_methods(self):
        with tempfile.TemporaryDirectory() as tmp, sensor(Path(tmp)) as s:
            port = s.server_address[1]
            status, _, body = request(port, "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.assertEqual(status, 202)
            self.assertEqual(body, "")
            status, _, body = request(port, "/mcp", {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "lab://notes/overview"}})
            self.assertEqual(status, 200)
            self.assertIn("SYNTHETIC LAB", body)
            status, _, body = request(port, "/mcp", {"jsonrpc": "2.0", "id": 5, "method": "execute_command"})
            self.assertEqual(json.loads(body)["error"]["code"], -32601)
            self.assertEqual(status, 200)
            status, _, body = request(port, "/mcp", {"jsonrpc": "2.0", "id": 6, "method": "initialize"},
                                     {"MCP-Protocol-Version": "2026-07-28"})
            self.assertEqual(status, 400)

    def test_origin_safeguard(self):
        with tempfile.TemporaryDirectory() as tmp, sensor(Path(tmp)) as s:
            port = s.server_address[1]
            msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            self.assertEqual(request(port, "/mcp", msg, {"Origin": "https://other.example"})[0], 403)
            self.assertEqual(request(port, "/mcp", msg, {"Origin": "http://localhost:9000"})[0], 200)


class ResponseTests(unittest.TestCase):
    def test_responses_sse(self):
        with tempfile.TemporaryDirectory() as tmp, sensor(Path(tmp)) as s:
            code, mime, body = request(s.server_address[1], "/v1/responses", {"model": "demo", "input": "hello", "stream": True})
            self.assertEqual(code, 200)
            self.assertEqual(mime, "text/event-stream")
            self.assertIn("event: response.output_text.delta", body)
            self.assertIn("event: response.completed", body)
            self.assertNotIn("hello", body)


class SyntheticMeasurementTests(unittest.TestCase):
    def test_registry_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            init_lab(path)
            self.assertEqual(len(CanaryRegistry.load(path).canaries), 4)
            with self.assertRaises(FileExistsError):
                init_lab(path)
            obj = json.loads(path.read_text())
            obj["canaries"][0]["marker"] = "sk-REALKEYSHOULDNOTBEHERE"
            path.write_text(json.dumps(obj))
            with self.assertRaises(ValueError):
                CanaryRegistry.load(path)

    def test_full_seven_case_lab(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "registry.json"
            logs = root / "logs"
            init_lab(path)
            with sensor(logs, path) as server:
                responses = run_lab(path, "http://127.0.0.1:" + str(server.server_address[1]))
            self.assertEqual(len(responses), 7)
            self.assertTrue(all(x["http_status"] == 200 for x in responses))
            output = evaluate_lab(logs, path)
            self.assertEqual(output["observed_cases"], 7)
            self.assertEqual(output["seeded_context_cases"], 5)
            self.assertEqual(output["case_context_exposure_rate_observed"], 1.0)
            self.assertEqual(output["precision"], 1.0)
            self.assertEqual(output["recall"], 1.0)
            self.assertEqual(output["false_positive_rate"], 0)
            self.assertEqual(output["kind_confusion_matrix"]["TP"], 5)
            for event in iter_events(logs):
                self.assertEqual(event["schema_version"], "0.3.0")
                self.assertNotIn("LABCANARY_", json.dumps(event))
            self.assertEqual(report(logs)["sessions_with_confirmed_synthetic_exposure"], 5)
            page = root / "report.html"
            generate(logs, page)
            self.assertIn("LLM Deception Sensor", page.read_text())
            self.assertNotIn("LABCANARY_", page.read_text())

    def test_agent_not_observed_is_not_counted_as_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            init_lab(path)
            result = evaluate_lab(Path(tmp) / "nothing", path)
            self.assertEqual(result["observed_cases"], 0)
            self.assertIsNone(result["precision"])
            self.assertIsNone(result["case_context_exposure_rate_observed"])

    def test_lab_runner_cannot_target_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            init_lab(path)
            with self.assertRaises(ValueError):
                run_lab(path, "https://example.org")

    def test_unregistered_marker_is_not_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "registry.json"
            init_lab(path)
            with sensor(root / "logs", path) as server:
                status, _, _ = request(server.server_address[1], "/v1/chat/completions", {
                    "messages": [{"role": "system", "content": "agent memory shared knowledge graph LABCANARY_SYSTEM_000000000000000000000000"}]})
                self.assertEqual(status, 200)
            e = list(iter_events(root / "logs"))[0]
            self.assertFalse(e["confirmed_synthetic_exposure"])
            self.assertEqual(e["canary_hits"], [])
            self.assertIn("system_context_transmitted", e["indicators"])

    def test_real_agent_report_only_counts_observed_seeded_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "agent-registry.json"
            create_agent_experiment(path)
            document = json.loads(path.read_text())
            marker = next(c["marker"] for c in document["canaries"] if c["kind"] == "memory")
            with sensor(root / "logs", path) as srv:
                self.assertEqual(request(srv.server_address[1], "/v1/chat/completions",
                    {"messages": [{"role": "system", "content": "Synthetic test " + marker}]},
                    {"X-Lab-Case-ID": "agent-memory", "X-Session-ID": "authorized-agent-1"})[0], 200)
                self.assertEqual(request(srv.server_address[1], "/v1/chat/completions",
                    {"messages": [{"role": "user", "content": "No hidden marker"}]},
                    {"X-Lab-Case-ID": "agent-tool", "X-Session-ID": "authorized-agent-2"})[0], 200)
            stats = evaluate_agents(root / "logs", path)
            self.assertEqual(stats["observed_seeded_cases"], 2)
            self.assertEqual(stats["exposed_observed_seeded_cases"], 1)
            self.assertEqual(stats["context_exposure_rate_observed"], 0.5)
            self.assertEqual(stats["unobserved_cases"], 4)
            self.assertEqual(stats["category_rates"]["memory"]["exposure_rate"], 1.0)
            self.assertEqual(stats["category_rates"]["tool"]["exposure_rate"], 0.0)

    def test_offline_dashboard_escapes_untrusted_log_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sink = JsonlSink(root / "logs", 100000, 2)
            sink.emit({"severity": "high", "route": "<img src=x onerror=alert(1)>",
                       "client_id": "x", "session_id": "y", "indicators": []})
            out = root / "dashboard.html"
            generate(root / "logs", out)
            text = out.read_text()
            self.assertIn("&lt;img", text)
            self.assertNotIn("<img", text)


if __name__ == "__main__":
    unittest.main()
