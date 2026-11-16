"""Authorized external-agent exposure measurement (no agent interaction is initiated).

A real user's agent is seeded with synthetic markers in trusted context and
configured to use this decoy endpoint. The sensor observes only what is sent.
"""
from __future__ import annotations
from collections import defaultdict
import json
from pathlib import Path
import secrets

from .canary import CanaryRegistry, KINDS
from .storage import iter_events


def create_agent_experiment(path: Path) -> dict:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    canaries = [{"id": f"seed-{kind}", "kind": kind,
                 "marker": f"LABCANARY_{kind.upper()}_{secrets.token_hex(16).upper()}"}
                for kind in KINDS]
    cases = [{"id": f"agent-{kind}", "description": f"Externally controlled agent seeded with {kind} marker",
              "seeded_kinds": [kind], "expected_kinds": []} for kind in KINDS]
    cases.extend([
        {"id": "agent-all", "description": "Agent seeded with all four synthetic marker types",
         "seeded_kinds": list(KINDS), "expected_kinds": []},
        {"id": "agent-baseline", "description": "Unseeded negative control", "seeded_kinds": [], "expected_kinds": []},
    ])
    doc = {"schema_version": "lab-v1", "purpose": "AUTHORIZED REAL-AGENT EXPERIMENT WITH FAKE MARKERS ONLY",
           "canaries": canaries, "cases": cases}
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return {"registry": str(path), "cases": [c["id"] for c in cases],
            "instructions": "Seed only synthetic marker strings into your OWN agent's system/tool/memory/RAG context, configure its model endpoint as this local sensor, and send X-Lab-Case-ID identifying the test case. Do not transmit real keys or user data."}


def evaluate_agents(log_dir: Path, registry_path: Path) -> dict:
    # This registry contains both calibration expected kinds and agent seeded kinds;
    # the *agent* report interprets only seeded_kinds and excludes missing sessions.
    registry = CanaryRegistry.load(registry_path)
    doc = json.loads(registry_path.read_text(encoding="utf-8"))
    case_defs = {c["id"]: c for c in doc["cases"]}
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in iter_events(log_dir):
        cid = e.get("lab_case_id")
        if cid in registry.cases:
            groups[cid].append(e)
    results: list[dict] = []
    for cid in registry.cases:
        seeded = set(case_defs[cid].get("seeded_kinds", []))
        if any(k not in KINDS for k in seeded):
            raise ValueError("Invalid seeded_kinds")
        records = groups[cid]
        if not records:
            results.append({"case": cid, "status": "unobserved", "seeded_kinds": sorted(seeded),
                            "observed_kinds": [], "exposed_seeded_kinds": [], "events": 0})
            continue
        obs = {h["kind"] for e in records for h in e.get("canary_hits", []) if isinstance(h, dict) and h.get("kind") in KINDS}
        exposed = obs & seeded
        results.append({"case": cid, "status": "observed", "seeded_kinds": sorted(seeded),
                        "observed_kinds": sorted(obs), "exposed_seeded_kinds": sorted(exposed),
                        "out_of_case_canary_kinds": sorted(obs - seeded),
                        "events": len(records),
                        "hashed_sessions": len({e.get("session_id") for e in records if e.get("session_id")})})
    def frac(n: int, d: int) -> float | None:
        return round(n / d, 4) if d else None
    observed_seeded = [r for r in results if r["status"] == "observed" and r["seeded_kinds"]]
    exposed_cases = sum(bool(r["exposed_seeded_kinds"]) for r in observed_seeded)
    rates = {}
    for kind in KINDS:
        assigned = [r for r in observed_seeded if kind in r["seeded_kinds"]]
        rates[kind] = {"observed_seeded_cases": len(assigned),
                       "exposed_cases": sum(kind in r["exposed_seeded_kinds"] for r in assigned),
                       "exposure_rate": frac(sum(kind in r["exposed_seeded_kinds"] for r in assigned), len(assigned))}
    return {"schema_version": "agent-report-v1", "type": "authorized_external_agent_observation",
            "seeded_cases": sum(bool(r["seeded_kinds"]) for r in results),
            "observed_seeded_cases": len(observed_seeded), "unobserved_cases": sum(r["status"] == "unobserved" for r in results),
            "exposed_observed_seeded_cases": exposed_cases,
            "context_exposure_rate_observed": frac(exposed_cases, len(observed_seeded)),
            "category_rates": rates, "cases": results,
            "limitations": "Agent behavior is not proven unless a REAL authorized agent independently performed these cases. Unobserved runs are unknown, not safe. Observed marker transmissions establish crossing into this decoy endpoint, not malicious intent, compromise or source attribution."}
