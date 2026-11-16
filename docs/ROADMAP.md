# Roadmap & actual maturity

## v0.1 completed — local honeypot

OpenAI/Ollama API emulation, JSONL recording, rate limiting, basic heuristic tags, container packaging.

## v0.2 completed — synthetic exposure measurement

MCP 2025-03-26 subset, synthetic canary lab, authorized-agent exposure report, local offline dashboard, session telemetry and privacy controls.

## v0.3 completed in local automated Python tests

- Fixed-route **application-level** proxy to an owned **localhost** inference endpoint, JSON/SSE/NDJSON relay, client token, no caller header forwarding, metadata-only capture.
- Multi-sensor HMAC-authenticated collection, validation and allowlisted metadata export; durable SQLite dedupe/record cap; fleet report and static dashboard.
- Optional collector TLS with local certificates, HTTPS sender with CA validation, and Docker Compose examples for co-located sensor/collector/shipper.
- SDK-based owned agent example and fake-inference integration tests. **The SDK example has not been run against a real local model.** Docker builds and public-facing deployments remain unvalidated.

This is *not* full central management, high-fidelity deception, a complete MCP server, or internet-grade security. It supports controlled trials, not attribution of real attackers.

## v0.3 hardening backlog (NOT completed)

1. Durable and resumable shipper queue with rotation/ack checkpoint; health metrics and monitoring.
2. mTLS/service identities; secret rotation and revocation, central RBAC, collector rate/size limits per sensor, secure UI.
3. Independently validated Docker/TLS deployments with container scanning and egress firewall verification.
4. Observability metrics for time-to-detection, event loss, uptime, and safe export/retention.
5. Test interoperability with specific versions of OpenAI SDK, Ollama, LM Studio, LangGraph, AutoGen, CrewAI, and MCP clients.

## v0.4 implemented locally — controlled behavior research

- Bounded scripted calibration and local-model tool-loop experiments with standardized baselines and negative controls, loopback-only endpoint restriction, and repeatable seeded ordering. Actual external autonomous agent integration is not yet validated.
- Synthetic context transport metrics by system/tool/memory/knowledge graph; Wilson 95% confidence intervals and observed/unknown separation. False-positive and false-negative estimates on external agents have not yet been validated.
- Deterministic offline k-medoids grouping of *pseudonymous metadata-only behavior features*; no automatic retaliation or threat attribution.
- Threat-intelligence technique mapping with independently verified labels remains backlog, along with calibration against independent agents and live local LLMs.
