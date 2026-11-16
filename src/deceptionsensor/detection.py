"""Defensive indicators. These are heuristic telemetry tags, not proof of compromise."""
from __future__ import annotations
import re
from typing import Any

# Keep patterns targeted. Never echo or store matched secret values in findings.
SECRET_PATTERNS = (
    re.compile(r"\bsk-[a-zA-Z0-9_-]{12,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]\s*['\"]?[^\s'\",;]{7,}"),
    re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9._~+/-]{10,}"),
)

RULES = (
    ("prompt_override", 3, re.compile(r"(?i)ignore (?:all )?(?:previous|prior|system) instructions|bypass (?:your )?(?:safety|guardrails)|disregard your instructions")),
    ("system_prompt_request", 2, re.compile(r"(?i)(?:reveal|print|dump|expose|leak|show) (?:your |the )?(?:hidden |internal )?(?:system|developer) (?:prompt|instructions)")),
    ("agent_memory_reference", 2, re.compile(r"(?i)shared knowledge graph|agent memory|campaign memory|conversation history|scratchpad|tool execution history")),
    ("credential_hunting", 3, re.compile(r"(?i)(?:extract|dump|steal|harvest|retrieve) (?:the |all )?(?:api keys?|tokens?|credentials?|secrets?)")),
    ("endpoint_recon", 1, re.compile(r"(?i)(?:enumerate|list) (?:all )?(?:models?|endpoints?)|/v1/models|/api/tags")),
)

SENSITIVE_KEYS = re.compile(r"(?i)(?:^|[_-])(authorization|api[_-]?key|token|password|secret|credential|cookie|private[_-]?key|image|images|base64|data_uri)(?:$|[_-])")


def _extract(obj: Any, depth: int = 0) -> str:
    """Bounded text extraction for rules; no image or file payload extraction."""
    if depth >= 8:
        return ""
    if isinstance(obj, str):
        return obj[:16384]
    if isinstance(obj, list):
        return " ".join(_extract(x, depth + 1) for x in obj[:100])[:32768]
    if isinstance(obj, dict):
        return " ".join(_extract(v, depth + 1) for k, v in list(obj.items())[:100]
                        if not SENSITIVE_KEYS.search(str(k)))[:32768]
    return ""


def analyze(payload: Any, route: str) -> dict[str, Any]:
    haystack = _extract(payload)
    matches: dict[str, int] = {}
    for code, score, pattern in RULES:
        if pattern.search(haystack):
            matches[code] = score
    if any(p.search(haystack) for p in SECRET_PATTERNS):
        matches["credential_like_content"] = 4
    if route in ("/v1/models", "/models", "/api/tags"):
        matches["model_listing_request"] = 1
    if re.search(r"(?i)(?:^|/)(?:\.env|admin|config\.json|actuator|secrets)(?:/|$)", route):
        matches["sensitive_path_probe"] = 2
    if isinstance(payload, dict):
        messages = payload.get("messages", payload.get("input", []))
        if isinstance(messages, list):
            roles = {m.get("role") for m in messages[:100] if isinstance(m, dict) and isinstance(m.get("role"), str)}
            if "system" in roles or "developer" in roles:
                matches["system_context_transmitted"] = 1
            if "tool" in roles or "function" in roles:
                matches["tool_history_transmitted"] = 2
        if "tools" in payload:
            matches["tool_schemas_transmitted"] = 1
        if route == "/mcp":
            method = payload.get("method", "")
            if method == "tools/call":
                matches["mcp_tool_invocation"] = 1
            if method in ("resources/list", "resources/read", "tools/list"):
                matches["mcp_discovery"] = 1
    score = min(10, sum(matches.values()))
    severity = "high" if score >= 7 else "medium" if score >= 3 else "low" if score else "informational"
    return {"tags": sorted(matches), "risk_score": score, "severity": severity}


def redact(obj: Any, depth: int = 0) -> Any:
    """Best-effort content redaction. Not a guarantee of PII elimination."""
    if depth >= 8:
        return "[TRUNCATED_DEPTH]"
    if isinstance(obj, dict):
        return {str(k)[:100]: ("[REDACTED_FIELD]" if SENSITIVE_KEYS.search(str(k)) else redact(v, depth + 1))
                for k, v in list(obj.items())[:100]}
    if isinstance(obj, list):
        return [redact(v, depth + 1) for v in obj[:100]]
    if isinstance(obj, str):
        result = obj[:4096]
        for pattern in SECRET_PATTERNS:
            result = pattern.sub("[REDACTED_SECRET]", result)
        return result
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    return "[UNSUPPORTED_TYPE]"
