# Event Schema v0.3.0

## Local sensor

Common request fields include `schema_version`, `event_kind=request`, `event_id`, `sensor_id`, `ts` (UTC), `client_id`, `session_id`, `method`, `route`, `request_bytes`, `message_count`, `roles`, `indicators`, `risk_score`, `severity`, `endpoint_family`, `mcp_method`, `mcp_tool`, `canary_hits`, `confirmed_synthetic_exposure`, and optionally `lab_case_id`.

Relay emits an additional metadata-only event with `event_kind=proxy_outcome`, a new `event_id`, a `parent_event_id` that matches the earlier request event, and `proxy_upstream_status` or a small enumerated `proxy_error`. **No model response bytes are logged.** Latency and token usage are not reliably measured in this version.

`canary_hits` example:

```json
[{"id": "seed-memory", "kind": "memory"}]
```

This is a marker ID, not the synthetic marker value. The only qualified exposure is exact matching against the separately owned registered synthetic canary value in the observed request body. `indicators` are heuristic rules, not confirmed exploitation.

## Central collector allowlist

The shipper runs local `validate_event`, and the collector runs it again after verifying the body HMAC signature. Allowed fields are listed below. All other keys—including `model`, `detail`, `request_redacted`, `request_raw`, client Authorization and supplied raw HTTP headers—are **dropped** rather than stored in the central database.

- Identity/timing: `schema_version`, `sensor_id`, `event_id`, `ts`, `client_id`, `session_id`, `event_kind`, `parent_event_id`
- Bounded request metadata: `route` (known path or `/other`), `method`, `request_bytes`, `message_count`, `roles`, `endpoint_family`, `risk_score`, `severity`, `indicators`
- Research fields: `canary_hits` (limited IDs + kinds), `confirmed_synthetic_exposure`, `lab_case_id`, `mcp_method`, `mcp_tool`
- Relay outcomes: `proxy_upstream_status`, `proxy_error`

Every sensor has its own signing secret in the receiver. A batch is HMAC-SHA256 signed over UTF-8 `timestamp + '\n' + sensor_id + '\n' + exact_json_body`, supplied as `X-Timestamp`, `X-Sensor-ID` and `X-Signature`. Clock drift greater than five minutes is refused. Replays inside that window cannot duplicate the same `(sensor_id,event_id)` row while its record remains retained.

**No** claim is made that metadata means anonymized, that HMAC is end-to-end encryption, or that SQLite is an immutable forensic evidence store.
