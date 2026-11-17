"""Offline metadata-only hypotheses, analyst-supplied IOC review and blinded evaluation.
No internet enrichment, automated blocking or actor attribution.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import json
import re
from .intelligence import _dataset, _patterns

DOMAIN = re.compile(r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z", re.I)
HEX256 = re.compile(r"[0-9a-f]{64}\Z", re.I)
CANDIDATES = {
    "credential_related_request": ("T1552", "Unsecured Credentials"),
    "discovery_then_prompt_probe": ("T1595", "Active Scanning (analogy only)"),
    "request_burst": ("T1595", "Active Scanning (analogy only)"),
}

def normalize_ioc(value, kind):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    value = value.strip().lower()
    if kind == "ipv4":
        try:
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_global:
                return None
        except ValueError:
            return None
    elif kind == "domain":
        if not DOMAIN.fullmatch(value):
            return None
    elif kind == "sha256":
        if not HEX256.fullmatch(value):
            return None
    elif kind == "url":
        try:
            u = urlsplit(value)
            if (u.scheme != "https" or not u.hostname or u.username or u.password
                    or u.port not in (None, 443) or u.fragment or len(value) > 1024
                    or not DOMAIN.fullmatch(u.hostname)):
                return None
        except ValueError:
            return None
    else:
        return None
    return {"type": kind, "value": value, "verification": "analyst_supplied_unverified"}

def ioc_report(source: Path, *, max_records=1000):
    if not 1 <= max_records <= 10000:
        raise ValueError("Invalid record cap")
    found = {}
    rejected = total = 0
    with source.open(encoding="utf-8") as stream:
        for line in stream:
            total += 1
            if total > max_records:
                raise ValueError("IOC input exceeds cap")
            try:
                item = json.loads(line)
                record = normalize_ioc(item.get("value"), item.get("type")) if isinstance(item, dict) else None
            except (ValueError, TypeError):
                record = None
            if record:
                found[(record["type"], record["value"])] = record
            else:
                rejected += 1
    return {"schema": "ioc-review-v1", "input_rows": total, "rejected": rejected,
            "indicators": [found[k] for k in sorted(found)],
            "warning": "Indicators are unverified; do not automatically block or attribute."}

def _sessions(records):
    grouped = defaultdict(list)
    for event in records:
        grouped[(event["sensor_id"], event["session_id"])].append(event)
    return grouped

def campaign_report(log_dir: Path, *, max_events=10000, bucket_minutes=60, minimum_sessions=2):
    if not 5 <= bucket_minutes <= 1440 or not 2 <= minimum_sessions <= 1000:
        raise ValueError("Invalid grouping arguments")
    events, quality = _dataset(log_dir, max_events)
    groups = defaultdict(list)
    for (sensor, session), entries in _sessions(events).items():
        entries.sort(key=lambda e: (e["epoch"], e["route"]))
        labels = sorted({r["rule"] for r in _patterns(entries) if r["weight"] > 0})
        if not labels:
            continue
        bucket = entries[0]["epoch"] // (bucket_minutes * 60)
        fingerprint = sha256(json.dumps(labels, separators=(",", ":")).encode()).hexdigest()[:16]
        groups[(bucket, fingerprint)].append((sensor, session[:12], labels))
    output = []
    for (bucket, fingerprint), members in sorted(groups.items()):
        if len(members) < minimum_sessions:
            continue
        output.append({"bucket_start_utc": datetime.fromtimestamp(bucket * bucket_minutes * 60, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "fingerprint": fingerprint, "session_count": len(members),
                       "sensor_count": len({m[0] for m in members}),
                       "rule_ids": members[0][2],
                       "session_hash_prefixes": sorted({m[1] for m in members})[:50],
                       "interpretation": "Shared metadata signature, NOT common-actor attribution"})
    return {"schema": "campaign-hypotheses-v1", "quality": quality, "groups": output,
            "limitations": "Cannot identify people, campaigns or common actors from pseudonymous session metadata."}

def mapping_report(log_dir: Path, *, max_events=10000):
    events, quality = _dataset(log_dir, max_events)
    counts = Counter()
    for records in _sessions(events).values():
        records.sort(key=lambda e: (e["epoch"], e["route"]))
        counts.update({p["rule"] for p in _patterns(records)})
    mappings = [{"observed_rule": key, "technique_id": CANDIDATES[key][0],
                 "technique_name": CANDIDATES[key][1], "session_count": counts[key],
                 "confidence": "low", "status": "analyst_review_required"}
                for key in sorted(counts) if key in CANDIDATES]
    return {"schema": "technique-candidates-v1", "quality": quality,
            "candidate_mappings": mappings,
            "warning": "ATT&CK candidates are analogies, not proven TTPs. No unverified ATLAS IDs asserted."}

def evaluation_report(predictions: Path, truth: Path):
    def load(path):
        rows = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(rows, list) or len(rows) > 100000:
            raise ValueError("Expected bounded JSON array")
        output = {}
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                    or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", row["id"])
                    or type(row.get("positive")) is not bool or row["id"] in output):
                raise ValueError("Invalid or duplicate labeled row")
            output[row["id"]] = row["positive"]
        return output
    p, t = load(predictions), load(truth)
    if not t:
        raise ValueError("Empty ground truth")
    shared = sorted(p.keys() & t.keys())
    tp = sum(p[k] and t[k] for k in shared)
    fp = sum(p[k] and not t[k] for k in shared)
    fn = sum(not p[k] and t[k] for k in shared)
    tn = sum(not p[k] and not t[k] for k in shared)
    return {"schema": "blinded-evaluation-v1", "truth_count": len(t), "evaluated": len(shared),
            "missing_predictions": len(t.keys() - p.keys()), "extra_predictions": len(p.keys() - t.keys()),
            "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "warning": "Only paired, independently labeled cases scored; missing cases are not counted as safe."}
