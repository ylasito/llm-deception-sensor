"""Reproducible metadata-only evidence digest for an owned research experiment.

This is a *derived*, optionally HMAC-signed report, NOT a tamper-proof source log
or forensic chain of custody. Never includes raw request data or canary strings.
"""
from __future__ import annotations
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from .storage import iter_events

HEX_ID = re.compile(r'^[a-f0-9]{24}$')
SAFE_CASE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')
KINDS = {'system', 'tool', 'memory', 'knowledge_graph'}


def _normalized(event: dict) -> dict | None:
    if event.get('capture_mode') != 'metadata' or event.get('event_kind') != 'request':
        return None
    sid = event.get('session_id')
    sensor = event.get('sensor_id')
    date = event.get('ts')
    if not isinstance(sid, str) or not HEX_ID.fullmatch(sid):
        return None
    if not isinstance(sensor, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', sensor):
        return None
    if not isinstance(date, str):
        return None
    try:
        datetime.fromisoformat(date.replace('Z', '+00:00'))
    except ValueError:
        return None
    raw_hits = event.get('canary_hits', [])
    hits = []
    if isinstance(raw_hits, list):
        for hit in raw_hits[:256]:
            if isinstance(hit, dict) and hit.get('kind') in KINDS and isinstance(hit.get('id'), str) and SAFE_CASE.fullmatch(hit['id']):
                hits.append({'id': hit['id'], 'kind': hit['kind']})
    case = event.get('lab_case_id')
    return {'sensor_id': sensor, 'session_id': sid, 'ts': date,
            'event_id': event.get('event_id') if isinstance(event.get('event_id'), str) and re.fullmatch(r'[a-f0-9]{32}', event['event_id']) else '',
            'route_family': event.get('endpoint_family') if event.get('endpoint_family') in ('openai', 'ollama', 'mcp', 'other') else 'other',
            'case_id': case if isinstance(case, str) and SAFE_CASE.fullmatch(case) else None,
            'synthetic_hits': sorted(hits, key=lambda v: (v['kind'], v['id']))}


def _canonical(x: object) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def create_report(log_dir: Path, max_events: int = 10000, signing_key: str = '') -> dict:
    if not 1 <= max_events <= 100000:
        raise ValueError('max_events out of bounds')
    if signing_key and len(signing_key) < 32:
        raise ValueError('signing_key must be at least 32 characters')
    raw = list(iter_events(log_dir))
    if len(raw) > max_events:
        raise ValueError('too many events; select a smaller log window')
    events = [x for row in raw if (x := _normalized(row)) is not None]
    events.sort(key=lambda e: (e['ts'], e['sensor_id'], e['session_id'], e['event_id']))
    chain = bytes(32)
    for event in events:
        chain = hashlib.sha256(chain + _canonical(event)).digest()
    sessions = {(e['sensor_id'], e['session_id']) for e in events}
    observed_marker_events = 0
    # Canary transport alone is never a policy violation; assessment requires ground truth.
    for e in events:
        if e['synthetic_hits']:
            observed_marker_events += 1
    report = {
        'schema_version': 'evidence-v06', 'status': 'metadata_only_descriptive',
        'events_scanned': len(raw), 'accepted_metadata_events': len(events),
        'excluded_events': len(raw) - len(events), 'sessions': len(sessions),
        'synthetic_marker_events': observed_marker_events,
        'transport_interpretation': 'Synthetic marker observed at sensor endpoint; trust boundary breach NOT established.',
        'order': 'ts,sensor_id,session_id,event_id',
        'digest_algorithm': 'sha256-chained-canonical-allowlisted-events',
        'digest': chain.hex(),
        'limitations': ['Derived from mutable source JSONL', 'No raw request or model response retention',
                        'No independent timestamp attestation', 'No unauthorized exfiltration conclusion'],
    }
    if signing_key:
        report['hmac_sha256'] = hmac.new(signing_key.encode(), _canonical(report), hashlib.sha256).hexdigest()
    return report


def verify_report(report: dict, log_dir: Path, signing_key: str = '') -> bool:
    if report.get('schema_version') != 'evidence-v06':
        return False
    signature = report.get('hmac_sha256')
    if signature is not None:
        if not signing_key:
            return False
        unsigned = {k: v for k, v in report.items() if k != 'hmac_sha256'}
        if not hmac.compare_digest(str(signature), hmac.new(signing_key.encode(), _canonical(unsigned), hashlib.sha256).hexdigest()):
            return False
    regenerated = create_report(log_dir, signing_key=signing_key if signature else '')
    return hmac.compare_digest(_canonical(regenerated), _canonical(report))


def write_private(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        json.dump(report, out, indent=2)
        out.write('\n')
