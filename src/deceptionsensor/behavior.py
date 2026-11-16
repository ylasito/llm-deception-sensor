"""Privacy-preserving exploratory session grouping from request metadata only.

Unsupervised descriptive grouping, not threat attribution or proof of leakage.
Canary matches, experiment case IDs, and raw prompt content are excluded.
"""
from __future__ import annotations
from collections import defaultdict
import math
from pathlib import Path
from .storage import iter_events

FIELDS = ("request_count", "avg_request_bytes", "avg_message_count", "system_roles",
          "user_roles", "tool_roles", "endpoint_count", "route_count")


def _features(events: list[dict]) -> list[float]:
    count = len(events)
    roles = [r for e in events for r in (e.get("roles") or []) if isinstance(r, str)]
    def nonneg(value, cap):
        return min(cap, max(0, float(value))) if isinstance(value, (float, int)) else 0.0
    return [float(count), sum(nonneg(e.get("request_bytes"), 65536) for e in events) / count,
            sum(nonneg(e.get("message_count"), 100) for e in events) / count,
            float(roles.count("system")), float(roles.count("user")), float(roles.count("tool")),
            float(len({e.get("endpoint_family") for e in events})),
            float(len({e.get("route") for e in events}))]


def _distance(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x-y)**2 for x, y in zip(a, b)))


def cluster_sessions(log_dir: Path, k: int = 3, max_events: int = 10000) -> dict:
    """Simple deterministic k-medoids on standardised metadata-only features.

    Reject overflowing datasets instead of silently sampling or declaring unsampled
    sessions safe. No dependencies or network calls; all cluster labels are arbitrary.
    """
    if not 2 <= k <= 8 or not 100 <= max_events <= 100000:
        raise ValueError("k must be 2..8 and max_events must be 100..100000")
    sessions = defaultdict(list)
    count = 0
    for event in iter_events(log_dir):
        if event.get("event_kind") != "request" or event.get("capture_mode") != "metadata":
            continue
        count += 1
        if count > max_events:
            raise ValueError("Dataset exceeds safety cap; partition telemetry before clustering")
        sid = event.get("session_id")
        sensor = event.get("sensor_id")
        if not isinstance(sid, str) or len(sid) > 128 or not sid or not isinstance(sensor, str):
            continue
        sessions[(sensor, sid)].append(event)
    keys = sorted(sessions)
    raw = [_features(sessions[key]) for key in keys]
    n = len(raw)
    if n < k:
        return {"schema_version": "behavior-v1", "status": "insufficient_sessions",
                "sessions": n, "requested_clusters": k, "features": list(FIELDS),
                "interpretation": "No clusters produced: fewer sessions than clusters"}
    means = [sum(a[j] for a in raw) / n for j in range(len(FIELDS))]
    stds = [math.sqrt(sum((a[j] - means[j]) ** 2 for a in raw) / n) or 1 for j in range(len(FIELDS))]
    z = [[(a[j] - means[j]) / stds[j] for j in range(len(FIELDS))] for a in raw]
    dist = [[_distance(z[i], z[j]) for j in range(n)] for i in range(n)]
    # Farthest-first deterministic initial medoids; no random / canary input.
    medoids = [0]
    while len(medoids) < k:
        medoids.append(max((j for j in range(n) if j not in medoids),
                           key=lambda j: (min(dist[j][m] for m in medoids), -j)))
    for _ in range(25):
        labels = [min(range(k), key=lambda c: (dist[i][medoids[c]], c)) for i in range(n)]
        new = []
        used = set()
        for c in range(k):
            members = [i for i, label in enumerate(labels) if label == c]
            candidates = members if members else [i for i in range(n) if i not in used]
            best = min(candidates, key=lambda i: (sum(dist[i][j] for j in members), i))
            if best in used:
                best = next(i for i in range(n) if i not in used)
            new.append(best); used.add(best)
        if new == medoids:
            break
        medoids = new
    labels = [min(range(k), key=lambda c: (dist[i][medoids[c]], c)) for i in range(n)]
    clusters = []
    sil = []
    for c in range(k):
        members = [i for i in range(n) if labels[i] == c]
        if not members:
            continue
        summary = {FIELDS[j]: round(sum(raw[i][j] for i in members) / len(members), 2)
                   for j in range(len(FIELDS))}
        clusters.append({"cluster": c, "sessions": len(members), "mean_features": summary})
    for i in range(n):
        mine = [j for j in range(n) if labels[j] == labels[i] and i != j]
        if not mine or len(clusters) < 2:
            sil.append(0.0)
            continue
        a = sum(dist[i][j] for j in mine) / len(mine)
        b = min(sum(dist[i][j] for j in range(n) if labels[j] == c) /
                sum(labels[j] == c for j in range(n)) for c in range(k) if c != labels[i] and any(label == c for label in labels))
        sil.append((b - a) / max(a, b) if max(a, b) > 0 else 0.0)
    return {"schema_version": "behavior-v1", "status": "exploratory_only", "sessions": n,
            "events": count, "clusters_requested": k, "clusters_nonempty": len(clusters),
            "mean_silhouette": round(sum(sil) / n, 4), "features": list(FIELDS), "clusters": clusters,
            "exclusions": ["prompt_content", "canary_hits", "lab_case_id", "experiment_labels", "credentials"],
            "interpretation": "Descriptive groupings of request metadata; not attacker classification, model understanding, or evidence of unauthorized context exfiltration"}
