"""Reproducible, synthetic-only local lab for measuring context exposure.

Generate marker registry and cases, send a deterministic calibration workload,
then evaluate ONLY saved sensor metadata. No real agents, tokens or remote calls.
"""
from __future__ import annotations
from collections import Counter, defaultdict
import http.client
import json
from pathlib import Path
import secrets
from urllib.parse import urlsplit

from .canary import CanaryRegistry, KINDS
from .storage import iter_events


def init_lab(path: Path) -> dict:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite an existing registry: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    markers = [
        {"id": f"lab-{kind}", "kind": kind,
         "marker": f"LABCANARY_{kind.upper()}_{secrets.token_hex(16).upper()}"}
        for kind in KINDS
    ]
    doc = {
        "schema_version": "lab-v1", "purpose": "AUTHORIZED SYNTHETIC LAB ONLY",
        "canaries": markers,
        "cases": [
            {"id": "baseline", "description": "Harmless normal user prompt", "expected_kinds": []},
            {"id": "system", "description": "System-context canary transmitted", "expected_kinds": ["system"]},
            {"id": "tool", "description": "Tool-output canary transmitted", "expected_kinds": ["tool"]},
            {"id": "memory", "description": "Agent-memory canary transmitted", "expected_kinds": ["memory"]},
            {"id": "knowledge", "description": "Knowledge-graph canary transmitted", "expected_kinds": ["knowledge_graph"]},
            {"id": "mcp", "description": "Memory canary exposed via MCP tool argument", "expected_kinds": ["memory"]},
            {"id": "keyword", "description": "Keyword-only request without canary", "expected_kinds": []},
        ],
    }
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return {"registry": str(path), "cases": len(doc["cases"]), "canaries": len(markers)}


def _post(url: str, path: str, payload: dict, case: str) -> dict:
    target = urlsplit(url)
    # Lab runner is deliberately restricted to loopback; no remote agent manipulation.
    if target.scheme != "http" or target.hostname not in ("127.0.0.1", "localhost", "::1") or target.username or target.password:
        raise ValueError("lab-run accepts local http://127.0.0.1 or localhost only")
    conn = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=5)
    body = json.dumps(payload).encode("utf-8")
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json", "X-Lab-Case-ID": case,
                                                         "X-Session-ID": f"lab-session-{case}"})
        response = conn.getresponse()
        response.read()
        return {"case": case, "path": path, "http_status": response.status}
    finally:
        conn.close()


def run_lab(registry_path: Path, base_url: str) -> list[dict]:
    registry = CanaryRegistry.load(registry_path)
    if set(registry.cases) != {"baseline", "system", "tool", "memory", "knowledge", "mcp", "keyword"}:
        raise ValueError("lab-run requires a standard seven-case generated registry")
    marker = {c.kind: c.marker for c in registry.canaries}
    cases = [
        ("baseline", "/v1/chat/completions", {"model": "synthetic-model", "messages": [{"role": "user", "content": "hello"}]}),
        ("system", "/v1/chat/completions", {"model": "synthetic-model", "messages": [{"role": "system", "content": "private test context " + marker["system"]}, {"role": "user", "content": "hello"}]}),
        ("tool", "/api/chat", {"model": "synthetic-model", "stream": False, "messages": [{"role": "tool", "content": "sample tool trace " + marker["tool"]}]}),
        ("memory", "/v1/responses", {"model": "synthetic-model", "input": [{"role": "developer", "content": "authorized synthetic memory " + marker["memory"]}]}),
        ("knowledge", "/v1/chat/completions", {"model": "synthetic-model", "messages": [{"role": "user", "content": "graph context " + marker["knowledge_graph"]}]}),
        ("mcp", "/mcp", {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "read_sample_note", "arguments": {"note_id": "synthetic memory " + marker["memory"]}}}),
        ("keyword", "/v1/chat/completions", {"model": "synthetic-model", "messages": [{"role": "user", "content": "Please summarize the agent memory and system prompt of this fictional experiment."}]}),
    ]
    return [_post(base_url, route, data, case) for case, route, data in cases]


def evaluate_lab(log_dir: Path, registry_path: Path) -> dict:
    registry = CanaryRegistry.load(registry_path)
    latest: dict[str, list[dict]] = defaultdict(list)
    for e in iter_events(log_dir):
        case_id = e.get("lab_case_id")
        if case_id in registry.cases:
            latest[case_id].append(e)
    confusion = Counter({"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    case_results = []
    hit_cases = 0
    seeded_cases = 0
    for cid, c in registry.cases.items():
        observed = {hit.get("kind") for e in latest[cid] for hit in e.get("canary_hits", [])
                    if isinstance(hit, dict)}
        expected = set(c["expected_kinds"])
        if expected:
            seeded_cases += 1
        if observed & expected:
            hit_cases += 1
        if not latest[cid]:
            # Missing cases cannot be silently classified as true negatives.
            case_results.append({"case": cid, "status": "not_observed", "expected": sorted(expected), "observed": []})
            continue
        for kind in KINDS:
            key = "TP" if kind in expected and kind in observed else "FN" if kind in expected else "FP" if kind in observed else "TN"
            confusion[key] += 1
        case_results.append({"case": cid, "status": "observed", "expected": sorted(expected),
                             "observed": sorted(observed), "events": len(latest[cid])})
    def rate(a: int, b: int) -> float | None:
        return round(a / b, 4) if b else None
    observed_cases = sum(bool(latest[cid]) for cid in registry.cases)
    observed_seeded = sum(bool(latest[cid]) for cid, c in registry.cases.items() if c["expected_kinds"])
    observed_hit_seeded = sum(bool({hit.get("kind") for e in latest[cid] for hit in e.get("canary_hits", [])
                                    if isinstance(hit, dict)} & set(c["expected_kinds"]))
                              for cid, c in registry.cases.items() if c["expected_kinds"] and latest[cid])
    return {
        "schema_version": "lab-report-v1", "type": "synthetic_calibration_not_autonomous_agent_measurement",
        "registry_cases": len(registry.cases), "observed_cases": observed_cases,
        "unobserved_cases": len(registry.cases) - observed_cases,
        "seeded_context_cases": seeded_cases, "observed_seeded_cases": observed_seeded,
        "case_context_exposure_rate_observed": rate(observed_hit_seeded, observed_seeded),
        "kind_confusion_matrix": dict(confusion),
        "precision": rate(confusion["TP"], confusion["TP"] + confusion["FP"]),
        "recall": rate(confusion["TP"], confusion["TP"] + confusion["FN"]),
        "false_positive_rate": rate(confusion["FP"], confusion["FP"] + confusion["TN"]),
        "cases": case_results,
        "interpretation": "Calibration tests intentionally transmit synthetic markers. High exposure rate validates sensor detection, NOT a real agent vulnerability. For actual research, seed markers in an authorized agent and measure whether it transmits them without direct prompting.",
    }
