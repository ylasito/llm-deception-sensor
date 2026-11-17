"""Offline v0.7 threat-intel tests; no real credentials or network services."""
import json
from pathlib import Path
import tempfile
import unittest
from deceptionsensor.storage import JsonlSink
from deceptionsensor.threatintel import (
    campaign_report, mapping_report, ioc_report, evaluation_report, normalize_ioc)

class ThreatIntelTests(unittest.TestCase):
    def test_iocs_reject_private_and_dedupe(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"indicators.jsonl"
            path.write_text("\n".join(json.dumps(x) for x in [
                {"type":"ipv4","value":"8.8.8.8"},
                {"type":"ipv4","value":"127.0.0.1"},
                {"type":"ipv4","value":"8.8.8.8"},
                {"type":"domain","value":"example.org"},
                {"type":"url","value":"http://example.org/"}
            ])+"\n")
            report=ioc_report(path)
            self.assertEqual(report["rejected"],2)
            self.assertEqual(len(report["indicators"]),2)
            self.assertTrue(all(x["verification"]=="analyst_supplied_unverified" for x in report["indicators"]))

    def test_url_validation(self):
        for value in ["https://person:pass@example.org/", "http://example.org/",
                      "https://127.0.0.1/", "https://example.org:444/", "https://example.org/#frag"]:
            self.assertIsNone(normalize_ioc(value,"url"))

    def test_grouped_metadata_not_actor_attribution(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            sink=JsonlSink(root,rotate_bytes=1000000,retention_files=2)
            for letter in "ab":
                for minute, indicator in [(0,"model_listing_request"),(1,"prompt_override")]:
                    sink.emit({"capture_mode":"metadata","event_kind":"request",
                        "sensor_id":"sensor-1","session_id":letter*24,
                        "ts":f"2026-11-15T10:{minute:02}:00Z",
                        "route":"/v1/chat/completions","endpoint_family":"openai","method":"POST",
                        "indicators":[indicator],"roles":["user"],"raw_content":"secret-never-export"})
            report=campaign_report(root)
            self.assertEqual(len(report["groups"]),1)
            self.assertEqual(report["groups"][0]["session_count"],2)
            self.assertNotIn("secret-never-export",json.dumps(report))
            mapping=mapping_report(root)
            self.assertTrue(any(row["technique_id"]=="T1595" for row in mapping["candidate_mappings"]))

    def test_blinded_pairing_metrics(self):
        with tempfile.TemporaryDirectory() as d:
            p,t=Path(d)/"pred.json",Path(d)/"truth.json"
            p.write_text(json.dumps([{"id":"a","positive":True},{"id":"b","positive":True},
                                     {"id":"c","positive":False},{"id":"extra","positive":False}]))
            t.write_text(json.dumps([{"id":"a","positive":True},{"id":"b","positive":False},
                                     {"id":"c","positive":True},{"id":"missing","positive":False}]))
            r=evaluation_report(p,t)
            self.assertEqual(r["confusion_matrix"],{"tp":1,"fp":1,"fn":1,"tn":0})
            self.assertEqual(r["precision"],.5)
            self.assertEqual(r["recall"],.5)
            self.assertEqual(r["missing_predictions"],1)
            self.assertEqual(r["extra_predictions"],1)

    def test_duplicate_labels_fail(self):
        with tempfile.TemporaryDirectory() as d:
            p,t=Path(d)/"pred",Path(d)/"truth"
            p.write_text('[{"id":"x","positive":true}]')
            t.write_text('[{"id":"x","positive":true},{"id":"x","positive":false}]')
            with self.assertRaises(ValueError):
                evaluation_report(p,t)

if __name__=="__main__":
    unittest.main()
