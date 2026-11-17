# LLM Deception Sensor v0.7.0

**MIT-licensed, local-first AI deception and authorized-agent context-exposure research platform.** Independent research prototype. **Not AWS MadPot** or an AWS product. No internet deployment is implied or recommended.

**Previously in v0.6:** bounded fictional OpenAI/Ollama `tool_calls` emulation (including OpenAI SSE chunks), privacy-filtered turn/tool counts, and optional HMAC-signed derived evidence reports for reproducible local experiments. No real tools execute, and *auto* mode does not autonomously plan. See [v0.6 guide](docs/FIDELITY-V06.md). These are **partial protocol emulations**, not verified fidelity against third-party agents or AWS MadPot.

**New in v0.5:** privacy-filtered metadata-only agent-session sequence triage, deterministic behavioral rules, baseline Jensen–Shannon distribution shift monitoring, and offline intelligence dashboard. No adaptive ML classifier or attack attribution is claimed. See [v0.5 guide](docs/INTELLIGENCE-V05.md).

**Previously in v0.4:** bounded, repeatable **multi-turn research runs**, a controlled local-model tool loop, negative/withheld controls, Wilson 95% intervals, separation of approved vs unexpected marker delivery, and exploratory **metadata-only k-medoids clustering**. These features do not establish that an autonomous attacker was compromised. See [v0.4 research guide](docs/RESEARCH-V04.md).

**Inherited from v0.3:** authenticated **local-only inference relay** for a real model server; safe synthetic canary measurement; HMAC-signed, per-sensor **fleet telemetry collection**; SQLite deduplication; central offline reporting and HTML dashboard; collector-side optional TLS; isolated Docker Compose fleet overlay. It retains the v0.2 decoy OpenAI/Ollama/MCP API and calibration features.

Python 3.11+, **standard library only** for sensor and collector. Optional `openai` SDK for the external authorized agent adapter. No external inference or online service required in default decoy mode.

## New: Docker Compose Full Lab (v0.7.1 pilot PR)

**One command** to start a local research stack with synthetic test-agent, fake OpenAI/Ollama/MCP sensor, signed telemetry shipper, SQLite collector, and a read-only web dashboard:

```bash
docker compose -f compose.full-lab.yaml up --build -d
```

Dashboard: <http://127.0.0.1:18081> · Sensor health: <http://127.0.0.1:18080/healthz>.
All secrets and synthetic markers are initialized automatically into private Docker volumes. No model, external API, real agent or production secret is required. A scripted test-client runs eight synthetic requests every 45 seconds; **it is not an autonomous agent**. See [full setup guide](docs/FULL-LAB.md). Docker deployment still needs validation on a Docker-equipped host; local Python integration tests alone do not prove Compose networking.

## New in v0.7 — offline threat intelligence research

- `ti-campaigns`: groups **metadata-only** sessions into reproducible behavior-pattern hypotheses in bounded time buckets. **No actor attribution**.
- `ti-mappings`: lists limited **ATT&CK analogy candidates** for analyst review. No MITRE ATLAS technique IDs are asserted without independent verification.
- `ti-iocs`: validates and deduplicates **analyst-supplied** IPv4/domain/SHA-256/HTTPS URL indicators (not scraped from request bodies); all are unverified, never automatically blocked.
- `ti-evaluate`: independently supplied positive/negative truth and prediction JSON arrays, with TP/FP/FN/TN, precision, recall, false-positive rate, and explicit missing-prediction counts.

See [v0.7 threat intelligence guide](docs/THREAT-INTELLIGENCE-V07.md). This is a defensive offline research engine and does not perform network enrichment, threat attribution or automatic disruption.

## Capability matrix

| Capability | State as of v0.5 |
|---|---|
| Static OpenAI-compatible and Ollama decoys | Working; inherited v0.2 |
| v0.6 fictional tool calls + streaming | Implemented for selected OpenAI/Ollama routes, not full conformance |
| Derived experiment evidence hash/HMAC | Implemented; NOT tamper-proof acquisition or forensic chain-of-custody |
| Synthetic MCP tools/resources | Working; **selected** 2025-03-26 JSON-RPC subset, not full MCP |
| Fixed-route local model relay with JSON / SSE / NDJSON | Working; only 127.0.0.1 upstream permitted |
| Client proxy authentication | Required for proxied routes (`X-Proxy-Token`) |
| No onward forwarding of client credentials | Working; independent upstream key is optional |
| Metadata-only traffic telemetry / synthetic canaries | Working; proxy mode rejects raw/redacted capture |
| HMAC-authenticated fleet collector | Working; up to 100 events per signed batch |
| Durable deduplication, bounded records | SQLite `UNIQUE(sensor_id,event_id)` and max-record cap |
| Central fleet reporting and HTML dashboard | Working offline (not a live web UI) |
| TLS collector | Supported using operator-provided certificate/key; unverified externally |
| Authenticated real agent workflow | Optional example using OpenAI SDK and your own local model; not tested against third-party agents |
| v0.4 controlled multi-turn scripted/model experiments | Implemented locally, subject to validation against an owned real model |
| v0.4 negative controls / Wilson CI / unknown cases | Implemented and tested |
| v0.4 deterministic metadata-only session clustering | Implemented; descriptive only, not model learning or attribution |
| Internet-facing honeynet, adaptive ML, Kubernetes | **Not implemented** |

### Quick start A — safe decoy / synthetic calibration (no model)

Open two terminals:

```sh
PYTHONPATH=src python3 -m deceptionsensor lab-init --output lab/registry.json
export SENSOR_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
CANARY_REGISTRY=lab/registry.json PYTHONPATH=src python3 -m deceptionsensor
```

In terminal B:

```sh
PYTHONPATH=src python3 -m deceptionsensor lab-run --registry lab/registry.json
PYTHONPATH=src python3 -m deceptionsensor lab-report --registry lab/registry.json --log-dir data
PYTHONPATH=src python3 -m deceptionsensor dashboard --log-dir data --output report/dashboard.html
```

These synthetic calibration cases deliberately send fake markers; they do **not** establish that a third-party agent leaked any secrets.

### Quick start B — actual model relay + owned agent

Start your **own** local OpenAI-compatible inference server (e.g. LM Studio configured for `127.0.0.1:1234`) and ensure its API is reachable from the same network namespace as the native Python sensor. Then in terminal A:

```sh
PYTHONPATH=src python3 -m deceptionsensor agent-init --output lab/agent-registry.json
export SENSOR_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export PROXY_CLIENT_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
export PROXY_UPSTREAM_URL=http://127.0.0.1:1234
export CAPTURE_MODE=metadata
export CANARY_REGISTRY=lab/agent-registry.json
PYTHONPATH=src python3 -m deceptionsensor
```

**Terminal B** (optional SDK; installs to your own environment):

```sh
python3 -m pip install openai
export PROXY_CLIENT_TOKEN="<SAME TOKEN AS TERMINAL A>"
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export LAB_MODEL_ID="<MODEL ID OFFERED BY YOUR LOCAL SERVER>"
python3 examples/agent_sdk_tools.py
PYTHONPATH=src python3 -m deceptionsensor agent-report \
  --registry lab/agent-registry.json --log-dir data --output report/agent.json
```

Or send a controlled request with `X-Proxy-Token` and `X-Lab-Case-ID` headers using curl. Proxy **never** forwards client `Authorization`, cookies, `X-Proxy-Token`, or `X-Lab-Case-ID` to your model. The response body is passed to the client but **not** written to sensor telemetry. All experiments should use synthetic context and owned resources only.

> **Interpretation warning:** model request bodies normally carry system messages; detecting them in an explicitly configured inference endpoint is expected, **not** evidence of a vulnerability. A trust-boundary failure needs an experiment proving unapproved endpoint substitution or an equivalent policy breach.

### Quick start C — central collection (native loopback)

Generate one independent signing key per sensor. Demo generator makes a key for `local-sensor`:

```sh
python3 examples/create_fleet_keys.py
PYTHONPATH=src python3 -m deceptionsensor collector \
  --keys lab/collector-keys.json --database fleet/events.sqlite3 \
  --host 127.0.0.1 --port 18888
```

From another terminal, after sensor has created telemetry:

```sh
PYTHONPATH=src python3 -m deceptionsensor ship \
  --sensor-id local-sensor --key-file lab/shipper-key.txt \
  --log-dir data --url http://127.0.0.1:18888

PYTHONPATH=src python3 -m deceptionsensor fleet-report --database fleet/events.sqlite3
PYTHONPATH=src python3 -m deceptionsensor fleet-dashboard \
  --database fleet/events.sqlite3 --output report/fleet.html
PYTHONPATH=src python3 -m deceptionsensor fleet-export \
  --database fleet/events.sqlite3 --output report/fleet.jsonl
```

For multiple sensors add unique entries to `collector-keys.json` and configure each sender's `SENSOR_ID`, signing key, and log directory. **Different sensors must not share signing keys.** Fleet collection is one-way telemetry, not a remote-control interface. The collector discards all non-allowlisted fields and refuses non-metadata capture records. All central outputs are offline artifacts, not an authenticated browser dashboard.

A long-lived `ship --follow` retries at-least-once on a fixed interval and deduplicates in the collector. Its in-memory seen cache is not persisted across restart; the receiver's event ledger handles resends. File rotation or outages can drop events when old local logs are deleted before being shipped; for stronger guarantees use a durable queue in a future version.

### Docker

Default decoy service (host port bound to loopback):

```sh
cp .env.example .env
python3 -c "import secrets; p='.env'; s=open(p).read(); open(p,'w').write(s.replace('SENSOR_SECRET=', 'SENSOR_SECRET='+secrets.token_hex(32),1))"
docker compose up --build -d
```

Fleet overlay (collector + shipper share a private loopback network namespace, collector has **no published port**):

```sh
python3 examples/create_fleet_keys.py
docker compose -f compose.yaml -f compose.fleet.yaml up --build -d
docker compose -f compose.yaml -f compose.fleet.yaml exec collector \
  python -m deceptionsensor fleet-report --database /fleet/events.sqlite3
```

`compose.fleet.yaml` sends decoy telemetry. For **real local model proxy mode**, prefer running the sensor natively, because `127.0.0.1` in Docker refers to the **container**, not your Mac host. No Docker build or fleet overlay was executed in the test environment; these are included as reviewed deployment examples, not operational validation.

### TLS and network egress

The collector accepts plaintext only when its bind is a loopback interface. A non-loopback bind fails closed without an operator-provided TLS certificate and key:

```sh
PYTHONPATH=src python3 -m deceptionsensor collector \
  --keys lab/collector-keys.json --database fleet/events.sqlite3 \
  --host 0.0.0.0 --port 18888 \
  --tls-cert tls/collector.crt --tls-key tls/collector.key
```

Remote shipper uses `https://trusted-collector-host:18888` with certificate verification (optionally `--ca-file tls/ca.crt`). Use a VPN or firewall allowlist, trusted PKI and independent ingress/egress controls before ANY non-loopback deployment. The relay allows only `http://127.0.0.1:PORT` as upstream and a fixed set of LLM API paths; it cannot contact arbitrary remote addresses or internal metadata endpoints. The shipper can connect to an explicitly chosen HTTPS collector but it sends only verified metadata.

### Security limitations

- **No external internet publishing by default.** Public-facing honeypots require operator authorization, hardened ingress, retention policies, DDoS protection, isolation, and privacy/legal review.
- No real secrets in experiments. Metadata includes HMAC client/session hashes; they are *pseudonymous*, not anonymous.
- The central collector is not a full management plane; no remote commands, centralized policy deployment, RBAC dashboard, or push alerts.
- Inference relay does not send content to an external provider. If your local model gateway itself uses a remote provider, that gateway's privacy/egress controls are your responsibility.
- The collector's TLS support needs proper certificates, key protection and operational validation in your environment. The local transport tests do not prove production-grade TLS security.
- The v0.3 tests use a deterministic **fake upstream** (not a real local LLM) to validate relay behavior; an optional real-model adapter is supplied but has not been executed with an installed model.

Read [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/SECURITY.md), [Research Protocol](docs/RESEARCH-PROTOCOL.md), [Deployment](docs/DEPLOYMENT-V03.md), and [Roadmap](docs/ROADMAP.md).

### Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

All integration tests are loopback-only, require no network access, and use fake data. MIT license. Use only on infrastructure you own or are explicitly authorized to test.

### Python package installation (optional)

```sh
python3 -m pip install -e .
llm-deception-sensor --help
```

Installing from source with `PYTHONPATH=src` remains dependency-free. Optional SDK adapter only: `python3 -m pip install -e '.[agent]'`.


## v0.4 controlled behavioral experiments

Run an **authorized, local-only** LLM sensor. The commands below start with an intentionally fake model server in the automated tests; for actual model-loop experiments provide your own compatible local inference endpoint as described in [RESEARCH-V04.md](docs/RESEARCH-V04.md). Never send real credentials or real confidential prompts as research canaries.

```bash
export PYTHONPATH=src
python3 -m deceptionsensor research-init --registry lab/research-registry.json --manifest lab/research-manifest.json
# Start sensor and approved local inference server separately; see docs/RESEARCH-V04.md
python3 -m deceptionsensor research-run --registry lab/research-registry.json --manifest lab/research-manifest.json --url http://127.0.0.1:8080 --mode scripted --repeats 3 --turns 3 --output lab/research-run.json
python3 -m deceptionsensor research-report --registry lab/research-registry.json --manifest lab/research-manifest.json --ledger lab/research-run.json --log-dir data --output lab/research-report.json
python3 -m deceptionsensor behavior-cluster --log-dir data --clusters 3 --output lab/behavior-clusters.json
```

**Note:** Inference proxy mode requires `PROXY_UPSTREAM_URL` pointing to `http://127.0.0.1:<port>`, `PROXY_CLIENT_TOKEN` (minimum 24 characters), and `CAPTURE_MODE=metadata`; the token must be available to `research-run` through the env variable `PROXY_CLIENT_TOKEN`. `research-run` cannot be run unattended as a real-model test without provisioning an owned local model. `--mode scripted` is a calibration, not an autonomous agent.

Full regression suite: `PYTHONPATH=src python3 -m unittest discover -s tests -v`. All real network traffic in automated tests is loopback only.


## v0.5 — offline agent behavioral intelligence

This is **descriptive telemetry analytics** only. v0.5 does not automatically learn attack intent or establish unauthorized exfiltration. Run a no-network demonstration:

```sh
export PYTHONPATH=src
python3 examples/generate_intel_demo.py --output-dir lab/intel-demo
python3 -m deceptionsensor intel-report --log-dir lab/intel-demo/current --output report/intel.json
python3 -m deceptionsensor intel-dashboard --log-dir lab/intel-demo/current --output report/intel.html
python3 -m deceptionsensor intel-drift --baseline lab/intel-demo/baseline --current lab/intel-demo/current --output report/drift.json
```

The 120 baseline and 120 current requests are **synthetically generated**, not collected from real agent clients. The v0.4 `research-report` is the separate mechanism for measuring known synthetic marker transport, and must never be presented as proof of a real trust-boundary breach. Read [Intelligence & validation protocol](docs/INTELLIGENCE-V05.md).
