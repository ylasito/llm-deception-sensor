"""Offline intelligence tests with entirely synthetic data and no outbound traffic."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from deceptionsensor.intelligence import (
    _event, _jensen_shannon, _dataset, drift_report, intelligence_report,
    render_intelligence_dashboard, write_report,
)
from deceptionsensor.storage import JsonlSink


def fake(sid="a" * 24, *, minute=0, route="/v1/models", indicators=None,
         family="openai", roles=None, sensor="research-sensor", raw=None):
    moment = datetime(2026, 11, 15, tzinfo=timezone.utc) + timedelta(minutes=minute)
    result = {"event_kind": "request", "capture_mode": "metadata", "schema_version": "0.3.0",
              "sensor_id": sensor, "session_id": sid, "ts": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "route": route, "endpoint_family": family, "method": "POST", "indicators": indicators or [],
              "roles": roles or ["user"], "lab_case_id": "sensitive-test-label"}
    if raw:
        result.update(raw)
    return result


def write_events(path: Path, records: list[dict]) -> None:
    sink = JsonlSink(path, rotate_bytes=1000000, retention_files=2)
    for r in records:
        sink.emit(r)


class IntelligenceTests(unittest.TestCase):
    def test_sequence_signals_are_within_single_session_and_chronological(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            events = [fake(minute=0, indicators=["model_listing_request"]),
                      fake(minute=1, indicators=["prompt_override"]),
                      fake("b" * 24, minute=0, indicators=["model_listing_request"]),
                      fake("c" * 24, minute=1, indicators=["prompt_override"]),
                      fake("d" * 24, minute=0, route="/mcp", family="mcp", indicators=["mcp_discovery"], raw={"mcp_method": "tools/list"}),
                      fake("d" * 24, minute=1, route="/mcp", family="mcp", indicators=["mcp_tool_invocation"], raw={"mcp_method": "tools/call"})]
            write_events(root, list(reversed(events)))
            r = intelligence_report(root)
            self.assertEqual(r["sessions"], 4)
            self.assertEqual(r["pattern_session_counts"]["discovery_then_prompt_probe"], 1)
            self.assertEqual(r["pattern_session_counts"]["discovery_then_mcp_call"], 1)
            self.assertEqual(r["pattern_session_counts"]["mcp_tool_interaction"], 1)
            self.assertEqual(r["findings"][0]["triage_score"], 5)
            self.assertNotIn("sensitive-test-label", json.dumps(r))

    def test_expected_context_not_treated_as_attack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_events(root, [fake(indicators=["system_context_transmitted", "tool_history_transmitted"])])
            r = intelligence_report(root)
            self.assertEqual(r["pattern_session_counts"], {"context_bearing_request": 1})
            self.assertEqual(r["findings"], [])
            self.assertEqual(r["sessions_with_patterns"], 1)

    def test_synthetic_secret_and_untrusted_fields_never_exported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = "SECRET_MARKER_SHOULD_NOT_BE_EXPORTED"
            write_events(root, [fake(indicators=["credential_hunting",payload], raw={
                "request_raw": payload, "canary_hits": [{"marker":payload}],
                "roles": ["user", payload], "mcp_method": {"malicious":payload},
                "route": "/private/" + payload, "endpoint_family": payload,
            })])
            report = intelligence_report(root)
            self.assertIn("credential_related_request", report["pattern_session_counts"])
            self.assertNotIn(payload, json.dumps(report))
            self.assertNotIn("request_raw", json.dumps(report))
            self.assertIn("canary_hits", report["exclusions"])

    def test_invalid_metadata_and_no_hash_session_not_analyzed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_events(root, [fake(), fake(raw={"capture_mode": "raw"}),
                                fake(raw={"session_id": "x"}), fake(raw={"ts": "2026-11-35T01:00:00Z"}),
                                fake(raw={"event_kind": "proxy_outcome"})])
            result = intelligence_report(root)
            self.assertEqual(result["quality"]["records_scanned"], 5)
            self.assertEqual(result["quality"]["valid_metadata_requests"], 1)
            self.assertEqual(result["quality"]["excluded_records"], 4)

    def test_same_data_order_invariant_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp)/"one", Path(tmp)/"two"
            records = [fake("a"*24, minute=1), fake("a"*24, minute=0), fake("b"*24, minute=2)]
            write_events(a, records)
            write_events(b, records[::-1])
            self.assertEqual(intelligence_report(a)["quality"]["sanitized_dataset_sha256"],
                             intelligence_report(b)["quality"]["sanitized_dataset_sha256"])

    def test_burst_rule_fires_only_with_six_in_minute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = [fake(minute=0) for _ in range(6)]
            write_events(root, records)
            self.assertIn("request_burst", intelligence_report(root)["pattern_session_counts"])

    def test_event_limit_and_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_events(root, [fake() for _ in range(101)])
            with self.assertRaises(ValueError):
                intelligence_report(root, max_events=100)
            with self.assertRaises(ValueError):
                intelligence_report(root, top=0)
            with self.assertRaises(ValueError):
                drift_report(root, root, minimum_requests=1)
            self.assertIsNone(_event({"capture_mode": "metadata", "event_kind": "request"}))

    def test_drift_identical_and_changed_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, current = Path(tmp)/"base", Path(tmp)/"current"
            records = [fake(f"{i:024x}", minute=i, route="/v1/models") for i in range(35)]
            write_events(base, records)
            write_events(current, [fake(f"{i:024x}", minute=i, route="/mcp", family="mcp") for i in range(35)])
            report = drift_report(base, current)
            self.assertEqual(report["status"], "descriptive_only")
            d = {x["dimension"]: x for x in report["dimensions"]}
            self.assertAlmostEqual(d["endpoint_family"]["jensen_shannon_bits"], 1.0)
            self.assertTrue(d["route"]["heuristic_shift"])
            self.assertEqual(d["role"]["jensen_shannon_bits"], 0.0)
            self.assertIsNone(d["indicator"]["jensen_shannon_bits"])
            self.assertIn("NOT", report["interpretation"])

    def test_drift_small_sample_cannot_claim_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, current = Path(tmp)/"base", Path(tmp)/"current"
            write_events(base, [fake()])
            write_events(current, [fake(route="/mcp")])
            report = drift_report(base,current)
            self.assertEqual(report["status"], "insufficient_sample")
            self.assertTrue(all(x["heuristic_shift"] is None for x in report["dimensions"]))

    def test_html_dashboard_and_report_are_non_overwriting_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            write_events(root/"logs", [fake(indicators=["prompt_override"])])
            report=intelligence_report(root/"logs")
            json_path=root/"report.json"
            html_path=root/"dashboard.html"
            write_report(report, json_path)
            render_intelligence_dashboard(report, html_path)
            self.assertEqual(json_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(html_path.stat().st_mode & 0o777, 0o600)
            self.assertIn("Content-Security-Policy", html_path.read_text())
            self.assertNotIn("sensitive-test-label", html_path.read_text())
            with self.assertRaises(FileExistsError):
                write_report(report, json_path)
            with self.assertRaises(FileExistsError):
                render_intelligence_dashboard(report, html_path)

    def test_empty_data_handling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.assertEqual(intelligence_report(root)["sessions"], 0)
            self.assertEqual(drift_report(root,root)["status"], "insufficient_sample")
            self.assertGreaterEqual(_jensen_shannon({"a":1},{"b":1}),0)


if __name__ == "__main__":
    unittest.main()
