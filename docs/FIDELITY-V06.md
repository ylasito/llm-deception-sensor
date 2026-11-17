# v0.6 — Bounded high-fidelity LLM endpoint research

## Implemented

- OpenAI-compatible `POST /v1/chat/completions` generates a synthetic function `tool_calls` response when `tool_choice=required` or explicitly selects a declared function. The SSE stream sends the tool-call ID/name and a separate arguments chunk, then `finish_reason=tool_calls` and `[DONE]`.
- Ollama `POST /api/chat` returns a compatible fictional `tool_calls` object, for both JSON and NDJSON modes.
- `auto` mode remains a safe static response, not an autonomous decision. Declared tool names are bounded, ASCII validated and limited to 16 entries. Arguments are always `{}`; no tool is invoked.
- Default metadata capture includes requested tool-emulation status, bounded turn count and tool schema count. No prompt, tool arguments or actual marker strings are included.
- `evidence-report` creates a deterministic SHA-256 chain of *sanitized* metadata events sorted by timestamp, sensor and event ID. Optional HMAC signature identifies accidental alteration relative to a **privately held key**. `evidence-verify` checks current logs against the report.

## Example: test fictional tool call

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2:latest","messages":[{"role":"user","content":"Use the fictional tool"}],"tools":[{"type":"function","function":{"name":"research_catalog","parameters":{"type":"object","properties":{}}}}],"tool_choice":"required"}'
```

## Example: derive and check evidence report

```bash
export EVIDENCE_HMAC_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
PYTHONPATH=src python3 -m deceptionsensor evidence-report --log-dir data --output report/evidence-v06.json
PYTHONPATH=src python3 -m deceptionsensor evidence-verify --log-dir data --report report/evidence-v06.json
```

Preserve the HMAC key privately for subsequent verification, and save the report separately from the logs; never commit either to Git. A report may fail verification when source logs rotate or acquire new events. The digest is **not cryptographic proof** of historical collection integrity because original JSONL logs are mutable, no external timestamping is used, and an attacker with access to source and HMAC key can recreate evidence. This is an *experiment reproducibility aid*, not legal chain-of-custody.

## Explicitly not implemented

- Stateful LLM planning, arbitrary tool execution, model-level behavioral fidelity, full model fingerprints, model accuracy simulation, official OpenAI/Ollama conformance certification, or live agent SDK validation.
- Internet honeynet scale, passive interception, raw prompt interception in proxy mode, nonconsensual secret harvesting, or threat-actor attribution.
- Determination that an observed system prompt or synthetic canary transmission is unauthorized. Such a conclusion requires a **separately defined endpoint trust policy** and independent ground truth.

Tests use only synthetic traffic against local test servers. Public-facing honeynet operation requires independent security testing and controls absent from this prototype.
