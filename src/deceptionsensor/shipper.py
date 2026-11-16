"""One-way, metadata-only HMAC-signed event shipper. Never ships raw requests."""
from __future__ import annotations
from collections import deque
import hashlib
import hmac
import http.client
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit

from .collector import validate_event, MAX_BATCH_EVENTS
from .storage import iter_events


def collector_target(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("Collector URL must be a scheme://host:port origin with no userinfo, path or query")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Plaintext collector transport allowed only for loopback")
    if parsed.scheme == "https" and parsed.hostname in ("127.0.0.1", "localhost", "::1"):
        # Local TLS allowed; certificate must match hostname or be trusted via CA file.
        pass
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def send_batch(url: str, sensor_id: str, secret: str, records: list[dict], ca_file: str | None = None) -> dict:
    scheme, host, port = collector_target(url)
    if len(secret) < 32:
        raise ValueError("Signing secret must be at least 32 characters")
    safe = [validate_event(record, sensor_id) for record in records]
    if not records or len(records) > MAX_BATCH_EVENTS or any(e is None for e in safe):
        raise ValueError("Only 1-100 validated metadata events can be shipped")
    raw = json.dumps({"events": safe}, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(secret.encode(), (timestamp + "\n" + sensor_id + "\n").encode() + raw, hashlib.sha256).hexdigest()
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=8, context=ssl.create_default_context(cafile=ca_file))
    else:
        conn = http.client.HTTPConnection("127.0.0.1" if host == "localhost" else host, port, timeout=8)
    try:
        conn.request("POST", "/v1/events", body=raw, headers={
            "Content-Type": "application/json", "X-Sensor-ID": sensor_id,
            "X-Timestamp": timestamp, "X-Signature": signature,
        })
        r = conn.getresponse()
        body = r.read(8192)
        if r.status != 202:
            raise ConnectionError(f"Collector rejected batch (HTTP {r.status})")
        result = json.loads(body)
        if result.get("accepted") != len(safe):
            raise ConnectionError("Collector acknowledged a different batch size")
        return result
    finally:
        conn.close()


def ship_logs(log_dir: Path, url: str, sensor_id: str, secret: str, *, ca_file: str | None = None,
              follow: bool = False, interval: int = 10) -> dict:
    """At-least-once sender. Receiver provides durable event-ID deduplication.

    The follow implementation scans bounded rotated logs; receiver ID ledger
    makes retries idempotent, though files lost before shipping cannot be recovered.
    """
    seen: set[str] = set()
    queue: deque[str] = deque()
    result = {"sent": 0, "duplicates": 0, "skipped": 0, "batches": 0}
    while True:
        pending = []
        for record in iter_events(log_dir):
            if record.get("sensor_id") != sensor_id:
                continue
            safe = validate_event(record, sensor_id)
            if safe is None:
                result["skipped"] += 1
                continue
            eid = safe["event_id"]
            if eid in seen:
                continue
            pending.append(safe)
            if len(pending) == MAX_BATCH_EVENTS:
                ack = send_batch(url, sensor_id, secret, pending, ca_file)
                result["sent"] += ack["inserted"]
                result["duplicates"] += ack["duplicates"]
                result["batches"] += 1
                for item in pending:
                    seen.add(item["event_id"])
                    queue.append(item["event_id"])
                pending = []
        if pending:
            ack = send_batch(url, sensor_id, secret, pending, ca_file)
            result["sent"] += ack["inserted"]
            result["duplicates"] += ack["duplicates"]
            result["batches"] += 1
            for item in pending:
                seen.add(item["event_id"])
                queue.append(item["event_id"])
        while len(queue) > 100000:
            seen.discard(queue.popleft())
        if not follow:
            return result
        time.sleep(max(1, interval))
