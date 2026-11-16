# v0.4 Research Protocol — Authorized Agent Behavior

## Scope and safeguards

This implementation is a **local research harness**, not a public MadPot implementation. It does not require or collect real account credentials. Synthetic canaries are randomly generated and stored under `lab/` (gitignored, chmod 0600). The runner permits only `http://127.0.0.1:PORT`, forbids redirects by using a fixed connection, caps request/response sizes, and offers bounded numbers of turns/repeats. The only simulated tool reads a **fabricated** note, without filesystem, shell, network or production access.

Default modes:
- `scripted`: deterministic mock tool calls and repeatable prompt flows. **Calibration only; not autonomous behavior.**
- `model`: calls an owned OpenAI-compatible localhost LLM through the sensor. The LLM may choose a single synthetic tool, and execution is bounded. **This is not validated as a third-party autonomous agent.**

Inference endpoint routing is controlled by the sensor's fixed local upstream. The sensor does not forward client Authorization headers to the upstream. Only metadata telemetry should be kept in proxy mode; do not enable raw prompt capture.

## Experimental design

Eight labeled scenarios: baseline, keyword-only negative control, allowed system, allowed tool, allowed memory, withheld memory, allowed knowledge graph, and withheld knowledge graph. The allowed cases deliberately transmit an experiment canary to the **authorized** model endpoint; such transport is normal operation and **must not** be described as unauthorized exfiltration. Withheld cases validate that the harness itself does not forward restricted synthetic context.

For each scenario, shuffle order using a known seed, run 1–50 repeats of 2–8 turns, then associate observations through HMAC session identifiers. The run ledger records **no raw canary values**, just case identifiers, status and bounded call counts. Keep the raw registry and manifest out of public repositories.

## Setup

```bash
export PYTHONPATH=src
python3 -m deceptionsensor research-init --registry lab/research-registry.json --manifest lab/research-manifest.json
# Configure CAPTURE_MODE=metadata, PROXY_UPSTREAM_URL=http://127.0.0.1:1234,
# PROXY_CLIENT_TOKEN (24+ chars), SENSOR_SECRET (32+ chars),
# CANARY_REGISTRY=lab/research-registry.json; start an OWNED local model and sensor
python3 -m deceptionsensor research-run --mode scripted --repeats 3 --turns 3 --seed 42
python3 -m deceptionsensor research-report --log-dir data --ledger lab/research-run.json --output lab/research-report.json
python3 -m deceptionsensor behavior-cluster --log-dir data --clusters 3 --output lab/behavior-clusters.json
```

For `--mode model`, choose an OpenAI-compatible locally hosted model (the optional example is not certified against specific models). Do not point an agent at a third-party API or production proxy.

## Metrics and interpretation

- **Approved transport rate:** fraction of observed approved scenario sessions with the expected synthetic marker; this measures visibility and authorized prompt transport, not attack success.
- **Unexpected canary session rate:** fraction of observed sessions with a marker inconsistent with the scenario's policy. In this controlled harness an anomaly requires investigation before calling it a breach.
- **Negative-control canary rate:** fraction of observed `withheld` and `control` sessions with any marker.
- **Unknown/missing sessions:** planned sessions for which no telemetry can be correlated. Unknown is **not** counted as safe.
- **Wilson 95% CI:** descriptive binomial interval on observed rates; small-sample effects and non-independence of repeated turns limit inference.
- **Metadata behavior clusters:** deterministic k-medoids over request counts, size, role counts and route/endpoint diversity. Excludes case IDs, marker hits, prompts, credentials and raw text to avoid target leakage. Clusters are anonymous and **not** cyber-actor classification.

Research results must state execution mode (`controlled_scripted_calibration` versus `local_model_tool_loop`), number of cases and observed requests, missing observations, approved vs unexpected marker delivery, and any experimental limitations. This PoC does not measure true adversarial attack success, transferability to other models, or causality of a third-party agent's decision.

## Reliability and security limits

- In-memory clustering uses a quadratic distance matrix. Keep data small and local (`--max-events` defaults to 10,000); clustering large fleets requires scalable offline processing.
- Endpoint transport is HTTP on loopback; internet deployment, secure service identity and boundary-level proxy controls require more work.
- JSONL telemetry rotation can affect analysis window and completeness; use the collector and archival procedures for longitudinal experiments.
- Docker and real-model interoperability are not covered by the automated test suite yet.
