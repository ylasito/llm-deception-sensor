"""Local-only defensive behavior analytics on strictly allowlisted request metadata.

This module does NOT learn attacker identity or determine intent. A statistical
baseline can show distribution shift, and rule sequences provide triage leads.
Neither proves compromise, maliciousness, or unauthorized data exposure.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
import math
from pathlib import Path
import re
from typing import Any
from .storage import iter_events

SESSION = re.compile(r"[0-9a-f]{24}\Z")
SENSOR = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
ROUTES = {"/", "/healthz", "/mcp", "/api/chat", "/api/generate", "/api/tags",
          "/api/version", "/v1/chat/completions", "/chat/completions", "/v1/responses",
          "/v1/models", "/models", "/v1/embeddings", "/other"}
FAMILIES = {"openai", "ollama", "mcp", "other"}
METHODS = {"GET", "POST"}
INDICATORS = {"prompt_override", "system_prompt_request", "agent_memory_reference",
              "credential_hunting", "endpoint_recon", "credential_like_content",
              "model_listing_request", "sensitive_path_probe", "system_context_transmitted",
              "tool_history_transmitted", "tool_schemas_transmitted", "mcp_tool_invocation", "mcp_discovery"}
ROLES = {"system", "developer", "user", "assistant", "tool", "function"}
MAX_EVENTS = 100_000


def _event(raw: dict) -> dict | None:
    """Discard all untrusted free text and non-metadata captures, including content."""
    if raw.get("capture_mode") != "metadata" or raw.get("event_kind") != "request":
        return None
    sensor, session = raw.get("sensor_id"), raw.get("session_id")
    if not (isinstance(sensor, str) and SENSOR.fullmatch(sensor)
            and isinstance(session, str) and SESSION.fullmatch(session)):
        return None
    ts = raw.get("ts")
    if not isinstance(ts, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ts):
        return None
    try:
        moment = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    route = raw.get("route")
    family = raw.get("endpoint_family")
    method = raw.get("method")
    indicators = raw.get("indicators")
    roles = raw.get("roles")
    return {
        "sensor_id": sensor, "session_id": session, "ts": ts, "epoch": int(moment.timestamp()),
        "route": route if isinstance(route, str) and route in ROUTES else "/other",
        "family": family if isinstance(family, str) and family in FAMILIES else "other",
        "method": method if isinstance(method, str) and method in METHODS else "other",
        "indicators": sorted({s for s in indicators[:32] if isinstance(s, str) and s in INDICATORS}) if isinstance(indicators, list) else [],
        "roles": sorted({s for s in roles[:32] if isinstance(s, str) and s in ROLES}) if isinstance(roles, list) else [],
        "mcp_method": raw.get("mcp_method") if isinstance(raw.get("mcp_method"), str) and raw.get("mcp_method") in {"tools/list", "tools/call", "resources/list", "resources/read", "initialize"} else "other",
    }


def _dataset(log_dir: Path, max_events: int) -> tuple[list[dict], dict]:
    if not 100 <= max_events <= MAX_EVENTS:
        raise ValueError("max_events must be 100..100000")
    seen = 0
    dropped = 0
    data = []
    for item in iter_events(log_dir):
        seen += 1
        if seen > max_events:
            raise ValueError("Telemetry exceeds explicit event cap; partition by retention window")
        rec = _event(item)
        if rec is None:
            dropped += 1
        else:
            data.append(rec)
    # Hash only sanitized, canonical metadata; never hash or echo raw content.
    canonical = json.dumps(sorted(data, key=lambda e: (e["sensor_id"], e["session_id"], e["ts"], e["route"], e["method"])),
                           sort_keys=True, separators=(",", ":"))
    quality = {"records_scanned": seen, "valid_metadata_requests": len(data),
               "excluded_records": dropped, "sanitized_dataset_sha256": sha256(canonical.encode()).hexdigest()}
    return data, quality


def _patterns(events: list[dict]) -> list[dict]:
    tags = {tag for e in events for tag in e["indicators"]}
    methods = {e["mcp_method"] for e in events}
    out = []
    if "credential_hunting" in tags or "credential_like_content" in tags:
        out.append({"rule": "credential_related_request", "weight": 3})
    if "prompt_override" in tags or "system_prompt_request" in tags:
        out.append({"rule": "prompt_probe", "weight": 2})
    if "mcp_tool_invocation" in tags or "tools/call" in methods:
        out.append({"rule": "mcp_tool_interaction", "weight": 1})
    if "system_context_transmitted" in tags or "tool_history_transmitted" in tags:
        out.append({"rule": "context_bearing_request", "weight": 0})
    if len(events) >= 6:
        for idx in range(len(events) - 5):
            if events[idx + 5]["epoch"] - events[idx]["epoch"] <= 60:
                out.append({"rule": "request_burst", "weight": 2})
                break
    discovery = lambda e: bool({"model_listing_request", "mcp_discovery", "endpoint_recon"} & set(e["indicators"])) or e["mcp_method"] in ("tools/list", "resources/list")
    probing = lambda e: bool({"prompt_override", "system_prompt_request"} & set(e["indicators"]))
    # Chronological order within one pseudonymous session, never across sensors.
    prior_discovery = False
    saw_probe_after_discovery = False
    saw_call_after_discovery = False
    for event in events:
        if prior_discovery and probing(event):
            saw_probe_after_discovery = True
        if prior_discovery and event["mcp_method"] == "tools/call":
            saw_call_after_discovery = True
        prior_discovery = prior_discovery or discovery(event)
    if saw_probe_after_discovery:
        out.append({"rule": "discovery_then_prompt_probe", "weight": 3})
    if saw_call_after_discovery:
        out.append({"rule": "discovery_then_mcp_call", "weight": 2})
    return out


def intelligence_report(log_dir: Path, *, max_events: int = 10000, top: int = 20) -> dict:
    if not 1 <= top <= 100:
        raise ValueError("top must be 1..100")
    events, quality = _dataset(log_dir, max_events)
    groups = defaultdict(list)
    for event in events:
        groups[(event["sensor_id"], event["session_id"])].append(event)
    findings = []
    labels = Counter()
    for (sensor, session), group in sorted(groups.items()):
        group.sort(key=lambda e: (e["epoch"], e["route"]))
        rules = _patterns(group)
        labels.update(rule["rule"] for rule in rules)
        weight = min(10, sum(rule["weight"] for rule in rules))
        if not rules or (len(rules) == 1 and weight == 0):
            continue
        findings.append({"sensor_id": sensor, "session_hash_prefix": session[:12],
                         "first_seen": group[0]["ts"], "last_seen": group[-1]["ts"],
                         "request_count": len(group), "triage_score": weight,
                         "rule_ids": [rule["rule"] for rule in rules],
                         "triage_band": "review" if weight >= 5 else "observe"})
    findings.sort(key=lambda x: (-x["triage_score"], -x["request_count"], x["sensor_id"], x["session_hash_prefix"]))
    return {"schema_version": "intelligence-v1", "analysis_type": "rule_based_metadata_session_triage",
            "quality": quality, "sensors": len({e["sensor_id"] for e in events}), "sessions": len(groups),
            "sessions_with_patterns": sum(1 for v in groups.values() if _patterns(sorted(v, key=lambda e: (e["epoch"], e["route"])))),
            "pattern_session_counts": dict(sorted(labels.items())), "findings": findings[:top],
            "findings_truncated": max(0, len(findings) - top),
            "exclusions": ["raw_prompt", "system_prompt_text", "canary_hits", "credentials", "model_output", "lab_case_id"],
            "interpretation": "Rules detect observable request patterns, not malicious intent. Context normally sent to an approved LLM endpoint is not exfiltration. False-positive rate and attribution are unvalidated."}


def _distributions(events: list[dict]) -> dict[str, Counter]:
    counters = {dim: Counter() for dim in ("endpoint_family", "route", "indicator", "role")}
    for event in events:
        counters["endpoint_family"][event["family"]] += 1
        counters["route"][event["route"]] += 1
        for i in set(event["indicators"]):
            counters["indicator"][i] += 1
        for role in set(event["roles"]):
            counters["role"][role] += 1
    return counters


def _jensen_shannon(a: Counter, b: Counter) -> float:
    """Jensen-Shannon divergence in bits, [0,1]; not a p-value."""
    labels = set(a) | set(b)
    n1, n2 = sum(a.values()), sum(b.values())
    if not n1 or not n2:
        return 0.0
    score = 0.0
    for label in labels:
        p, q = a.get(label, 0) / n1, b.get(label, 0) / n2
        mean = (p + q) / 2
        if p:
            score += p * math.log2(p / mean) / 2
        if q:
            score += q * math.log2(q / mean) / 2
    return score


def drift_report(baseline_dir: Path, observed_dir: Path, *, max_events: int = 10000,
                 minimum_requests: int = 30, threshold: float = 0.15) -> dict:
    if not 10 <= minimum_requests <= 10000 or not 0 < threshold <= 1:
        raise ValueError("minimum_requests must be 10..10000 and threshold (0,1]")
    baseline, base_quality = _dataset(baseline_dir, max_events)
    observed, obs_quality = _dataset(observed_dir, max_events)
    ready = len(baseline) >= minimum_requests and len(observed) >= minimum_requests
    first, second = _distributions(baseline), _distributions(observed)
    dimensions = []
    for name in first:
        n1, n2 = sum(first[name].values()), sum(second[name].values())
        js = _jensen_shannon(first[name], second[name]) if ready and n1 and n2 else None
        dimensions.append({"dimension": name, "jensen_shannon_bits": round(js, 5) if js is not None else None,
                           "heuristic_shift": js >= threshold if js is not None else None,
                           "baseline_observations": n1, "current_observations": n2})
    return {"schema_version": "drift-v1", "status": "descriptive_only" if ready else "insufficient_sample",
            "baseline": base_quality, "current": obs_quality, "minimum_requests_per_window": minimum_requests,
            "js_threshold_heuristic": threshold, "dimensions": dimensions,
            "interpretation": "Jensen-Shannon divergence measures metadata distribution shift, NOT attacker detection, model learning, statistical significance or proof of compromise. Use matched windows and review changes manually."}


def write_report(result: dict, output: Path) -> None:
    if output.exists():
        raise FileExistsError("Refusing to overwrite existing report")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)


def render_intelligence_dashboard(report: dict, output: Path) -> dict:
    if report.get("schema_version") != "intelligence-v1":
        raise ValueError("Only intelligence-v1 reports supported")
    cards = "".join(f"<tr><td>{escape(str(r['sensor_id']))}</td>"
                    f"<td>{escape(str(r['session_hash_prefix']))}</td>"
                    f"<td>{int(r['request_count'])}</td><td>{int(r['triage_score'])}</td>"
                    f"<td>{escape(', '.join(r['rule_ids']))}</td></tr>" for r in report.get("findings", []))
    rules = "".join(f"<tr><td>{escape(k)}</td><td>{int(v)}</td></tr>" for k, v in report.get("pattern_session_counts", {}).items())
    html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>AI Deception Intelligence — Local Offline Dashboard</title>"
            "<style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#202a35}"
            "table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{text-align:left;border-bottom:1px solid #ddd;padding:.65rem}"
            "h1{margin-bottom:0}small{color:#555}section{margin:2rem 0}code{word-wrap:break-word}</style></head><body>"
            "<h1>AI Deception — Behavioral Intelligence</h1><small>Offline synthetic/research telemetry • triage is not attribution</small>"
            f"<p><b>{int(report.get('sessions',0))}</b> sessions • <b>{int(report.get('sensors',0))}</b> sensors • "
            f"<b>{int(report.get('quality',{}).get('valid_metadata_requests',0))}</b> validated requests</p>"
            "<section><h2>Observed patterns</h2><table><tr><th>Rule</th><th>Sessions</th></tr>" + rules + "</table></section>"
            "<section><h2>Review queue</h2><table><tr><th>Sensor</th><th>Session hash prefix</th>"
            "<th>Requests</th><th>Triage score</th><th>Indicators</th></tr>" + cards + "</table></section>"
            "<p><small>Not proof of compromise. Raw prompts, credentials, canary values and user content are excluded.</small></p>"
            "</body></html>")
    if output.exists():
        raise FileExistsError("Refusing to overwrite dashboard")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    output.chmod(0o600)
    return {"output": str(output), "sessions": report.get("sessions", 0), "findings": len(report.get("findings", []))}
