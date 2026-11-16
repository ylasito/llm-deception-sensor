# v0.3 Threat Model & Security Boundaries

This is a **research prototype**, not a hardened internet honeynet or production LLM gateway. Do not deceive unaffiliated people into submitting confidential content, and do not test third-party AI systems without explicit authorization.

## Implemented safeguards

- Decoy mode (default) sends no outbound inference requests. Local relay requires `PROXY_UPSTREAM_URL` and a high-entropy `PROXY_CLIENT_TOKEN`. Its only permitted destination is `http://127.0.0.1:PORT`; caller-provided URLs, redirects, remote IP addresses, and non-allowlisted routes cannot redirect traffic elsewhere.
- All inbound request bodies have byte limits; object-only JSON is required. Chunked inbound requests are rejected rather than ambiguously parsed. Basic rate limits and read timeouts are enforced.
- In relay mode, `CAPTURE_MODE=metadata` is mandatory. No raw prompts, tool inputs, returned model content, caller credentials, or live network IP addresses are written by the relay to its telemetry. The independent collector applies a **second** metadata-only allowlist even to signed events.
- Canary matching is exact and restricted to operator-generated `LABCANARY_*` registry values. The output contains **marker IDs + category only**.
- Relay client `Authorization`, cookies, proxy access token, original HTTP headers, and source identity are never forwarded to the model. An optional *independent local upstream* key may be injected by configuration.
- Central collector requires a distinct >=32-character HMAC key for each sensor, checks timestamp freshness (five minutes), validates event schema/size/count, and deduplicates by `(sensor_id,event_id)`. Loss/reordering can still occur; this is not a signed forensic chain-of-custody system.
- Central non-loopback bind is rejected without a TLS certificate and private key. Shipper refuses HTTP to remote destinations, and HTTPS uses certificate verification. Protect collector private keys and signing secrets independently.
- No inbound endpoint supports arbitrary command execution, arbitrary file reads, or arbitrary outbound callbacks. MCP decoy tools return fixed fictional content only.
- Docker image uses a non-root user and Compose sets read-only filesystem and drops capabilities. Docker containers are **not** claimed to have no network egress solely from these flags.

## Known limitations to address before production

1. Proxy application-layer client auth is a single static shared token; no mTLS, revocation/role management, token rotation protocol, per-agent identity, or RBAC. Only bind sensor locally and use separate network segmentation for remote clients.
2. No OS-level egress enforcement, sandboxing, packet inspection, or independent attack-surface review. Local relay can access the configured localhost service; any proxy or local gateway elsewhere may itself make outbound network requests.
3. In-memory sensor rate limiter is approximate and per-process, not distributed DDoS protection. Request-body patterns, Unicode encodings, and oversized complex objects are not exhaustively analyzed.
4. Even pseudoidentifiers and model metadata can be sensitive. Local `redacted` capture mode outside relay mode is **best effort**, not a guarantee against PII leakage; `raw` capture is explicitly unsafe for unaffiliated traffic.
5. SQLite event-count retention is not a GDPR/organization time-based lifecycle program; the SQLite file can keep free pages containing previous event data, and filesystem backups need independent governance. No encryption at rest or data lifecycle scheduler.
6. Shipper is at-least-once and rescans rotated JSONL in follow mode. Offline queue and rotation gaps can lose events. Outgoing TLS supports CA validation but does not establish client identities; authenticity uses HMAC.
7. MCP supports only a selected older protocol subset. The static response simulator and local proxy do not emulate all features such as realtime audio, WebSockets, sessions, full tool calling or current client negotiation.
8. Any observed non-secret canary reflects only **transmission** to the selected endpoint. It is not proof of illegitimate exfiltration, exploit success, adversarial actor identity, or defensive-control bypass.
9. No human-in-the-loop approval, policy engine, forensic chain-of-custody, tenant isolation, compliance certification or uptime SLA.
10. TLS configuration and Docker Compose deployment must be validated in the operator's environment; no current claim of production readiness.

## Deployment checklist

Obtain written permission, isolate host/VPC, keep `HOST=127.0.0.1` by default, use generated random secrets, ensure `CAPTURE_MODE=metadata`, restrict listener and allowlisted egress at the firewall/VPC layer, terminate trusted HTTPS where needed, protect logs and registry files with least privilege, back up or rotate SQLite under policy, keep NTP time synchronized for signed message timestamps, test recovery, run independent security assessment before external exposure.

Do not share authentic credentials, private agent memories, real customer data or sensitive prompts in public datasets or honeypot responses. All demos contain fictional synthetic values.
