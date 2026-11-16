"""Strict, synthetic-only canary registry for authorized lab exposure measurement.

No real credentials or externally harvested strings belong in this registry.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any

KINDS = ("system", "tool", "memory", "knowledge_graph")
MARKER_RE = re.compile(r"^LABCANARY_(SYSTEM|TOOL|MEMORY|KNOWLEDGE_GRAPH)_[A-F0-9]{20,40}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@dataclass(frozen=True)
class Canary:
    id: str
    marker: str
    kind: str


class CanaryRegistry:
    def __init__(self, canaries: list[Canary], cases: dict[str, dict]):
        self.canaries = canaries
        self.cases = cases

    @classmethod
    def load(cls, path: Path | None) -> "CanaryRegistry":
        if path is None:
            return cls([], {})
        if path.stat().st_size > 131072:
            raise ValueError("Canary registry exceeds 128 KiB")
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schema_version") != "lab-v1":
            raise ValueError("Invalid lab registry version")
        raw = document.get("canaries", [])
        cases = document.get("cases", [])
        if not isinstance(raw, list) or len(raw) > 256 or not isinstance(cases, list) or len(cases) > 256:
            raise ValueError("Registry arrays must be bounded lists")
        canaries: list[Canary] = []
        ids: set[str] = set()
        markers: set[str] = set()
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("Invalid canary")
            c = Canary(str(item.get("id", "")), str(item.get("marker", "")), str(item.get("kind", "")))
            if not ID_RE.fullmatch(c.id) or not MARKER_RE.fullmatch(c.marker) or c.kind not in KINDS:
                raise ValueError("Only properly formatted synthetic LABCANARY markers are allowed")
            if not c.marker.startswith("LABCANARY_" + c.kind.upper() + "_"):
                raise ValueError("Canary marker/kind mismatch")
            if c.id in ids or c.marker in markers:
                raise ValueError("Duplicate canary")
            ids.add(c.id); markers.add(c.marker); canaries.append(c)
        case_map: dict[str, dict] = {}
        for c in cases:
            if not isinstance(c, dict) or not ID_RE.fullmatch(str(c.get("id", ""))):
                raise ValueError("Invalid case ID")
            expected = c.get("expected_kinds", [])
            if not isinstance(expected, list) or any(k not in KINDS for k in expected):
                raise ValueError("Invalid expected kinds")
            if c["id"] in case_map:
                raise ValueError("Duplicate case ID")
            case_map[c["id"]] = {"id": c["id"], "expected_kinds": sorted(set(expected)),
                                 "description": str(c.get("description", ""))[:120]}
        return cls(canaries, case_map)

    def hits(self, payload: Any) -> list[dict[str, str]]:
        if not self.canaries:
            return []
        # Data is only inspected in memory; never emit matched marker strings to telemetry.
        text = json.dumps(payload, ensure_ascii=True)
        return [{"id": c.id, "kind": c.kind} for c in self.canaries if c.marker in text]

    def case(self, case_header: str) -> str | None:
        return case_header if case_header in self.cases else None
