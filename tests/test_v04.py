"""v0.4 controlled synthetic research and privacy-preserving cluster regression."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest

from deceptionsensor.behavior import cluster_sessions
from deceptionsensor.research import (
    research_init, research_report, research_run, wilson_ci, _local_port,
)
from deceptionsensor.storage import JsonlSink
from test_v03 import fake_upstream, proxy_sensor

TOKEN = "local-agent-token-12345678901234567890"


class ResearchTests(unittest.TestCase):
    def _design(self, root):
        registry, manifest = root / "registry.json", root / "manifest.json"
        result = research_init(registry, manifest)
        self.assertEqual(result["cases"], 8)
        self.assertEqual(registry.stat().st_mode & 0o777, 0o600)
        return registry, manifest

    def test_registry_private_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry, manifest = self._design(root)
            self.assertNotEqual(registry.read_text(), manifest.read_text())
            with self.assertRaises(FileExistsError):
                research_init(registry, manifest)

    def test_loopback_only_enforced(self):
        self.assertEqual(_local_port("http://127.0.0.1:18080"), 18080)
        for url in ("https://127.0.0.1:8080", "http://localhost:8080", "http://10.0.0.1:8080",
                    "http://127.0.0.1:8080/secret", "http://127.0.0.1:8080?url=evil",
                    "http://user:pass@127.0.0.1:8080", "http://127.0.0.1:8080#frag"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                _local_port(url)

    def test_empty_report_unknown_is_not_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry, manifest = self._design(root)
            output = research_report(root, registry, manifest)
            self.assertIsNone(output["approved_transport_rate"])
            self.assertIsNone(output["unexpected_canary_session_rate"])
            self.assertEqual(output["observed_sessions"], 0)
            self.assertIsNone(output["requested_sessions"])

    def test_wilson_edge_cases(self):
        self.assertIsNone(wilson_ci(0, 0))
        self.assertIsNone(wilson_ci(2, 1))
        self.assertEqual(wilson_ci(0, 3)[0], 0)
        self.assertEqual(wilson_ci(3, 3)[1], 1)

    def test_scripted_research_e2e_with_mock_local_model(self):
        with tempfile.TemporaryDirectory() as tmp, fake_upstream() as upstream:
            root = Path(tmp)
            registry, manifest = self._design(root)
            with proxy_sensor(root / "logs", upstream.server_address[1], registry) as sensor:
                ledger_path = root / "ledger.json"
                ledger = research_run(registry, manifest,
                                      f"http://127.0.0.1:{sensor.server_address[1]}",
                                      mode="scripted", repeats=1, turns=2,
                                      token=TOKEN, output=ledger_path)
                self.assertEqual(ledger["sessions_planned"], 8)
                self.assertEqual(ledger["sessions_completed"], 8)
                self.assertEqual(ledger["execution_type"], "controlled_scripted_calibration")
                self.assertGreaterEqual(len(upstream.observed), 16)
            result = research_report(root / "logs", registry, manifest, ledger_path)
            self.assertEqual(result["observed_sessions"], 8)
            self.assertEqual(result["unknown_or_missing_sessions_lower_bound"], 0)
            self.assertEqual(result["negative_control_canary_rate"], 0)
            self.assertEqual(result["unexpected_canary_session_rate"], 0)
            self.assertEqual(result["approved_transport_rate"], 1)
            self.assertNotIn("LABCANARY_", json.dumps(result))
            with self.assertRaises(FileExistsError):
                research_run(registry, manifest, "http://127.0.0.1:8080",
                             token=TOKEN, repeats=1, turns=2, output=ledger_path)


class BehavioralClusteringTests(unittest.TestCase):
    def test_insufficient_and_clustering_without_secret_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sink = JsonlSink(root, rotate_bytes=1000000, retention_files=2)
            self.assertEqual(cluster_sessions(root)["status"], "insufficient_sessions")
            for i in range(6):
                sink.emit({"event_kind": "request", "capture_mode": "metadata",
                           "session_id": f"sid-{i}", "sensor_id": "research-sensor",
                           "endpoint_family": "openai", "route": "/v1/chat/completions",
                           "roles": ["system", "user"] if i % 2 else ["user", "tool"],
                           "request_bytes": 100 + i * 200, "message_count": 2 + i,
                           "canary_hits": [{"kind": "memory"}], "lab_case_id": "withheld-memory",
                           "raw_content": "SYNTHETIC-DO-NOT-EXPORT"})
            result = cluster_sessions(root, k=2)
            self.assertEqual(result["status"], "exploratory_only")
            self.assertEqual(result["sessions"], 6)
            self.assertEqual(sum(c["sessions"] for c in result["clusters"]), 6)
            self.assertNotIn("SYNTHETIC-DO-NOT-EXPORT", json.dumps(result))
            self.assertIn("canary_hits", result["exclusions"])

    def test_clustering_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                cluster_sessions(root, k=1)
            with self.assertRaises(ValueError):
                cluster_sessions(root, max_events=10)


if __name__ == "__main__":
    unittest.main()
