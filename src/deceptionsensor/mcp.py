"""Safe synthetic MCP 2025-03-26 JSON-RPC endpoint subset. Never executes tools."""
from __future__ import annotations
from typing import Any

PROTOCOL_VERSION = "2025-03-26"
TOOLS = [
    {"name": "research_catalog", "description": "Read the synthetic laboratory research catalog (decoy; no network access)",
     "inputSchema": {"type": "object", "properties": {"topic": {"type": "string"}}, "additionalProperties": False}},
    {"name": "read_sample_note", "description": "Read an entirely fictional lab note (no files are accessed)",
     "inputSchema": {"type": "object", "properties": {"note_id": {"type": "string"}}, "additionalProperties": False}},
    {"name": "lookup_agent_status", "description": "Return a fixed synthetic agent status", "inputSchema": {"type": "object", "properties": {}}},
]
RESOURCES = [{"uri": "lab://notes/overview", "name": "Fictional laboratory overview", "mimeType": "text/plain"}]
PROMPTS = [{"name": "lab_summary", "description": "Produce a harmless test summary", "arguments": []}]


def _result(rid: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def dispatch(payload: dict) -> tuple[int, dict | None]:
    rid = payload.get("id")
    method = payload.get("method")
    params = payload.get("params", {})
    if payload.get("jsonrpc") != "2.0" or not isinstance(method, str) or not isinstance(params, dict):
        return 400, _error(rid, -32600, "Invalid JSON-RPC request")
    # Notifications do not receive JSON-RPC response bodies.
    if "id" not in payload:
        return 202, None
    if not isinstance(rid, (str, int)) or isinstance(rid, bool):
        return 400, _error(None, -32600, "Invalid id")
    if method == "initialize":
        return 200, _result(rid, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                                  "serverInfo": {"name": "lab-deception-sensor", "version": "0.2.0"},
                                  "instructions": "This is a synthetic laboratory service. All data is fictional."})
    if method == "ping":
        return 200, _result(rid, {})
    if method == "tools/list":
        return 200, _result(rid, {"tools": TOOLS})
    if method == "resources/list":
        return 200, _result(rid, {"resources": RESOURCES})
    if method == "resources/read":
        if params.get("uri") != "lab://notes/overview":
            return 200, _error(rid, -32002, "Resource not found")
        return 200, _result(rid, {"contents": [{"uri": "lab://notes/overview", "mimeType": "text/plain", "text": "SYNTHETIC LAB: no real data or external systems."}]})
    if method == "prompts/list":
        return 200, _result(rid, {"prompts": PROMPTS})
    if method == "prompts/get":
        if params.get("name") != "lab_summary":
            return 200, _error(rid, -32602, "Unknown prompt")
        return 200, _result(rid, {"description": "Fictional laboratory prompt", "messages": [
            {"role": "user", "content": {"type": "text", "text": "Summarize synthetic laboratory findings only."}}]})
    if method == "tools/call":
        name = params.get("name")
        if name not in {tool["name"] for tool in TOOLS}:
            return 200, _result(rid, {"isError": True, "content": [{"type": "text", "text": "Unknown synthetic tool"}]})
        text = {
            "research_catalog": "Synthetic research catalog: three fictional entries; no external access.",
            "read_sample_note": "Synthetic note: this data is generated for testing only.",
            "lookup_agent_status": "Synthetic agent status: idle, no actual tasks or tools executed.",
        }[name]
        return 200, _result(rid, {"isError": False, "content": [{"type": "text", "text": text}]})
    return 200, _error(rid, -32601, "Method not found")
