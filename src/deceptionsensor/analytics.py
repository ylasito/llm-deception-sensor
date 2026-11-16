"""Privacy-preserving offline aggregate reporting over sensor JSONL."""
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
from .storage import iter_events


def report(root: Path) -> dict:
    all_events = list(iter_events(root))
    outcomes = [e for e in all_events if e.get("event_kind") == "proxy_outcome"]
    events = [e for e in all_events if e.get("event_kind") != "proxy_outcome"]
    sensor_counts = Counter(e.get("sensor_id", "unknown") for e in events)
    upstream_status = Counter(str(e.get("proxy_upstream_status", "unknown")) for e in outcomes)
    upstream_errors = Counter(e["proxy_error"] for e in outcomes if e.get("proxy_error"))
    severity = Counter(e.get("severity", "unknown") for e in events)
    routes = Counter(e.get("route", "unknown") for e in events)
    indicators = Counter(tag for e in events for tag in e.get("indicators", []))
    methods = Counter(e.get("mcp_method", "") for e in events if e.get("mcp_method"))
    contexts = Counter(hit.get("kind", "unknown") for e in events for hit in e.get("canary_hits", [])
                       if isinstance(hit, dict))
    clients = {(e.get("sensor_id", ""), e["client_id"]) for e in events if e.get("client_id")}
    sessions = {(e.get("sensor_id", ""), e["session_id"]) for e in events if e.get("session_id")}
    exposed = {(e.get("sensor_id", ""), e["session_id"]) for e in events if e.get("confirmed_synthetic_exposure") and e.get("session_id")}
    sessions_map = defaultdict(lambda: {"events": 0, "canary_hits": 0, "routes": set(), "route_sequence": [],
                                       "indicators": set(), "mcp_methods": set(), "first": "", "last": ""})
    for e in events:
        sid = (e.get("sensor_id", ""), e.get("session_id", ""))
        if not sid[1]:
            continue
        item = sessions_map[sid]
        item["events"] += 1
        item["canary_hits"] += len(e.get("canary_hits", []))
        item["routes"].add(e.get("route", ""))
        if len(item["route_sequence"]) < 100:
            item["route_sequence"].append(e.get("route", ""))
        if e.get("mcp_method"):
            item["mcp_methods"].add(e["mcp_method"])
        item["indicators"].update(e.get("indicators", []))
        ts = e.get("ts", "")
        item["first"] = min(item["first"], ts) if item["first"] else ts
        item["last"] = max(item["last"], ts)
    transition_counts = Counter()
    behavior_counts = Counter()
    for sid, v in sessions_map.items():
        for left, right in zip(v["route_sequence"], v["route_sequence"][1:]):
            transition_counts[(left, right)] += 1
        tags = v["indicators"]
        if v["canary_hits"]:
            behavior_counts["confirmed_synthetic_canary_exposure"] += 1
        if v["mcp_methods"]:
            behavior_counts["mcp_interaction"] += 1
        if "prompt_override" in tags or "system_prompt_request" in tags:
            behavior_counts["instruction_override_or_prompt_probe"] += 1
        if "model_listing_request" in tags or "sensitive_path_probe" in tags or "mcp_discovery" in tags:
            behavior_counts["endpoint_discovery"] += 1
        if "system_context_transmitted" in tags or "tool_history_transmitted" in tags:
            behavior_counts["context_bearing_request"] += 1
    timeline = [{"sensor_id": sid[0], "session_id": sid[1], "events": v["events"], "synthetic_canary_hits": v["canary_hits"],
                 "routes": sorted(v["routes"]), "route_sequence": v["route_sequence"][:20],
                 "indicators": sorted(v["indicators"]),
                 "first_seen": v["first"], "last_seen": v["last"]} for sid, v in sessions_map.items()]
    timeline.sort(key=lambda x: (-x["synthetic_canary_hits"], -x["events"], x["session_id"]))
    return {"schema_version": "0.3.0", "events": len(events), "total_records": len(all_events), "fleet_sensor_counts": dict(sensor_counts), "proxy_outcomes": len(outcomes), "proxy_upstream_status": dict(upstream_status), "proxy_errors": dict(upstream_errors), "unique_client_hashes": len(clients),
            "unique_session_hashes": len(sessions), "sessions_with_confirmed_synthetic_exposure": len(exposed),
            "severity": dict(severity), "top_routes": routes.most_common(10),
            "indicators": indicators.most_common(20), "mcp_methods": methods.most_common(10),
            "synthetic_exposure_by_kind": dict(contexts),
            "session_behavior_patterns": dict(behavior_counts),
            "top_endpoint_transitions": [{"from": a, "to": b, "count": n}
                                         for (a, b), n in transition_counts.most_common(20)],
            "session_timeline": timeline[:100],
            "notice": "Synthetic canary hits are verified only against the locally supplied lab registry. Heuristic indicator scores are not proof of exploitation."}
