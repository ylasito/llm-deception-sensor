# v0.3 Deployment & Research Operations

## A. Local testing prerequisites

- Python 3.11+ (no runtime dependencies), two terminals, dedicated non-production account, isolated lab VM or Mac.
- For proxy trials: a local model server that implements selected compatible `/v1/*` or `/api/*` paths and is listening on **127.0.0.1**, and separately controlled synthetic prompts/documents.
- For optional SDK example: `python3 -m pip install openai` in a virtual environment; not part of core install.

Use different folders for calibration versus *authorized external-agent* tests to prevent mixing the denominator. Example v0.2 `lab-init` is calibration; `agent-init` is independent agent experiment.

## B. Sensor network and trust test

1. Start a local inference backend on `127.0.0.1:1234` (set `PROXY_UPSTREAM_URL` to the exact port). Avoid remote bridge/gateway unless you independently validate its data use.
2. Generate random `SENSOR_SECRET` and `PROXY_CLIENT_TOKEN`, set `CAPTURE_MODE=metadata`, and keep the sensor listener on `127.0.0.1:8080`.
3. Request `/v1/models` without `X-Proxy-Token` → expect HTTP 401; retry with it → expect upstream model listing.
4. Generate `agent-registry.json`, seed only its `LABCANARY_*` strings into the owned agent, set an `X-Lab-Case-ID` associated with the chosen synthetic case. Use a unique `X-Session-ID` for each trial.
5. Use optional `examples/agent_sdk_tools.py` to send a bounded, fully fictional task via the sensor. Compare against a baseline where the model is directly contacted (no decoy) or where endpoint substitution is prevented by policy.
6. Run `agent-report`, inspect records and report case exposure **only among observed seeded cases**. Never claim system compromise from ordinary system-prompt transmission.

## C. Central ingest

`python3 examples/create_fleet_keys.py` generates a demonstration key for `local-sensor`. For a second sensor, manually generate an independent random 32-byte key, append it to `lab/collector-keys.json`, and provide it to its shipper as a separate mode-0600 secret file. Start collector on local `127.0.0.1:18888`, then run `ship` or `ship --follow` from each sensor's host.

To deploy collector outside localhost, use a trusted TLS certificate and enforce VPN/firewall restrictions. Supply `--tls-cert` and `--tls-key` to collector and use `https://...` and optional `--ca-file` on shipper. Never use `http://remote-IP`. Do not disable TLS verification. HMAC keys protect message authenticity, **not** traffic confidentiality; they require TLS for remote links.

Docker co-located lab: `compose.fleet.yaml` makes collector and shipper share an isolated loopback namespace, avoiding plaintext network traffic between containers. Neither the collector's port nor the database is published. Compose overlay and Docker image should be built and reviewed locally before reliance; they were not executed in the original CI environment.

## D. Basic operational checks

- `GET http://127.0.0.1:8080/healthz` returns sensor status.
- `GET http://127.0.0.1:18888/healthz` returns collector status (in its namespace).
- CLI `fleet-report` provides counts per sensor, request statuses, pseudonymous sessions, endpoint transitions, marker hits and heuristic indicator counts.
- Report generated with `fleet-dashboard` is a static HTML file with no live API. Keep database and report under access control. Collector rejects raw and redacted telemetry.

## E. What not to do

Do not place a real company gateway, API keys, unauthorized documents, actual model conversations or production RAG memory behind a public decoy. Do not infer that an exposed synthetic system marker is an exploit without an independently defined endpoint access policy. Do not expose an unauthenticated HTTP collector or proxy on a public address. Do not use metadata findings to attribute a real-world actor without additional evidence.
