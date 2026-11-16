# v0.5: Privacy-first autonomous-agent behavior intelligence (offline)

**Maturity:** local-only research prototype. This release adds descriptive analytics and review queues, **not autonomous threat attribution, an adaptive attacker classifier, or proof of compromise**.

## Why this exists

Our authorized LLM/MCP decoy records requests. A session may query model lists, make MCP tool calls, or submit instructions and synthetic canaries. The v0.5 layer looks for *observable sequences* in strictly allowlisted request metadata and compares aggregate behavior against a different window. It never sends user content to an external service.

## Features

1. `intel-report`: groups by **sensor ID + HMAC session ID**, chronologically, detects predefined behavioral patterns, and produces a bounded review queue. Any **known** system context legitimately submitted to an approved model is informational (zero triage weight), not exploitation.
2. `intel-drift`: compares two *operator-selected* metadata windows. Jensen–Shannon divergence (bits, 0–1) is calculated for endpoint families, routes, indicator types and role presence. A divergence >= 0.15 sets a **heuristic shift** flag. That is not a p-value or a claim of maliciousness. Default minimum is 30 valid requests in each window; missing data yields `insufficient_sample`.
3. `intel-dashboard`: static offline HTML. No JavaScript, external scripts, network requests or active UI; CSP denies network resources.
4. Output is non-overwriting, `0600` by default. The report includes a SHA-256 digest over **sanitized metadata**, not source file bytes (use a separate chain of custody mechanism for originals).

## Demo from scratch (does not call a model or network)

From the repository root:

```sh
export PYTHONPATH=src
python3 examples/generate_intel_demo.py --output-dir lab/intel-demo
python3 -m deceptionsensor intel-report --log-dir lab/intel-demo/current --output report/intel.json
python3 -m deceptionsensor intel-dashboard --log-dir lab/intel-demo/current --output report/intel.html
python3 -m deceptionsensor intel-drift --baseline lab/intel-demo/baseline --current lab/intel-demo/current --output report/drift.json
```

Open `report/intel.html` locally. The whole demo is synthetic calibration metadata, not evidence of actual attacker activity. Output files refuse overwrites so repeated experiments need unique paths or operator-controlled cleanup.

To analyze your **authorized** local agent sessions instead, point `--log-dir` to the sensor's metadata directory. It does not inspect the agent itself and cannot see anything not submitted through that sensor. The proxy remains loopback-only, authenticated, and tied to an operator-owned inference endpoint.

## Triage semantics

| Rule ID | Trigger | Weight | What it does *not* prove |
|---|---|---:|---|
| `credential_related_request` | Sensor's bounded credential-related indicator | 3 | Successful credential access |
| `prompt_probe` | Prompt-override/system-instruction request indicator | 2 | Prompt injection success |
| `mcp_tool_interaction` | MCP tool call method or sensor indicator | 1 | Harmful tool execution |
| `context_bearing_request` | Normal context-bearing request | **0** | Unauthorized data disclosure |
| `request_burst` | Six requests in <=60 seconds within one session | 2 | Attack automation |
| `discovery_then_prompt_probe` | Model/resource discovery before prompt probing | 3 | Malicious actor intent |
| `discovery_then_mcp_call` | Model/resource discovery before tool invocation | 2 | Compromised tool or agent |

Scores are capped at 10 and used **only to sort manual review**. They are not calibrated probabilities, CVSS scores or production alert severities. Only 20 findings per report are displayed by default; truncation is explicit. No real credential validation, live remote scanning, or automated retaliation is performed.

## Experimental limitations

- **Data minimization:** raw text, hidden instructions, key values, full user prompts, canary values, case IDs, and model responses are excluded from v0.5 input features and output. Only enumerated classes and truncated HMAC IDs are displayed. HMAC identifiers are pseudonymous, not anonymous.
- **Telemetry scope:** only `capture_mode=metadata`, `event_kind=request`, valid timestamp, session digest, and sensor identifier are eligible. Unknown categories collapse to `other`; invalid records are counted as excluded.
- **Coverage:** suspicious-looking sequences can be legitimate workflows; honest-looking sequences can be attacks. External false positives/negatives are unknown. The v0.4 canary report remains the correct way to describe *observed synthetic context transmission*. Neither report can prove that an endpoint was substituted without authorization.
- **Data hygiene:** use bounded retention and avoid publishing telemetry. Original local JSONL might contain richer fields under other capture modes; v0.5 refuses those events and does not create or persist new raw request bodies.
- **Temporal drift:** select equal-length, comparable baseline/current periods. Differences may arise from population, workload, routing, upgrades, and instrumentation. No confidence interval or significance is implied by a JS divergence.
- **Training status:** this release is not a trained machine learning model. Distribution comparison is a baseline-driven descriptive monitor. v0.4 k-medoids remains exploratory, not learned attacker identification.
- **Chain of custody:** SHA-256 in v0.5 fingerprints canonical *sanitized event content*, not immutable logs; originals require independent integrity logs, signed ingestion, and proper forensic preservation.

## Future validation gates

1. Run the existing model adapter against your **owned** LM Studio/Ollama model and record model/version/quantization and trial seed.
2. Use distinct trials for scripted calibration vs real agent runs; run the negative controls. Do not reuse an old log folder for claimed per-run metrics.
3. Calibrate manual triage precision/recall on independently labeled, consented test sessions before any production alerts.
4. Test multi-agent orchestration, drift under ordinary workloads, retention/rotation, and collector resilience. Maintain no-internet-by-default, permissions, and legal review.
