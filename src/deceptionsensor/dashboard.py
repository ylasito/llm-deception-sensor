"""Produce an offline, self-contained, escaped HTML SOC-style report."""
from __future__ import annotations
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from .analytics import report

STYLE = """body{font:15px system-ui,sans-serif;background:#0b1220;color:#e6eefb;margin:0;padding:26px}
main{max-width:1100px;margin:auto}header{display:flex;align-items:center;justify-content:space-between;gap:16px}
h1{font-size:27px;margin:0}h2{font-size:18px;margin-top:34px}p,.muted{color:#a9b7ca}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:24px 0}
.card{background:#162237;border:1px solid #29394e;border-radius:10px;padding:19px}
.big{font-size:31px;font-weight:700;margin-top:7px}table{width:100%;border-collapse:collapse;margin:12px 0}
th,td{padding:12px;text-align:left;border-bottom:1px solid #29394e;font-size:14px;vertical-align:top}
th{color:#bed0e6}td{overflow-wrap:anywhere}.mono{font:12px ui-monospace,monospace}
.bar{height:8px;background:#26364b;border-radius:5px;margin-top:6px;overflow:hidden}.bar span{display:block;background:#63afdf;height:100%}
small{color:#a9b7ca}.warning{border-left:3px solid #e2ac57;padding:10px 15px;background:#1c293b}
"""


def generate(log_dir: Path, output: Path) -> dict:
    stats = report(log_dir)
    def text(val: object) -> str:
        return escape(str(val), quote=True)
    def table(pairs: list[tuple[object, object]]) -> str:
        ceiling = max((n for _, n in pairs), default=1) or 1
        return "<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>" + "".join(
            f"<tr><td>{text(label)}<div class='bar'><span style='width:{int(100*count/ceiling)}%'></span></div></td><td>{int(count)}</td></tr>"
            for label, count in pairs) + "</tbody></table>"
    stats_cards = [("Requests", stats["events"]), ("Pseudonymous sessions", stats["unique_session_hashes"]),
                   ("Canary-exposed sessions", stats["sessions_with_confirmed_synthetic_exposure"]),
                   ("Client hashes", stats["unique_client_hashes"]),
                   ("Fleet sensors", len(stats["fleet_sensor_counts"])), ("Relay outcomes", stats["proxy_outcomes"])]
    cards = "".join(f"<div class='card'><div class='muted'>{text(label)}</div><div class='big'>{val}</div></div>" for label, val in stats_cards)
    sessions = "".join(
        "<tr><td>" + text(e.get("sensor_id", "")) + "</td><td class='mono'>" + text(e["session_id"]) + "</td><td>" + text(e["events"]) + "</td><td>" +
        text(e["synthetic_canary_hits"]) + "</td><td>" + text(", ".join(e["routes"])) + "</td><td>" +
        text(e["first_seen"]) + "</td></tr>" for e in stats["session_timeline"])
    document = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<meta http-equiv='Content-Security-Policy' content="default-src 'none'; style-src 'unsafe-inline'">
<title>LLM Deception Sensor | SOC Research Dashboard</title><style>{STYLE}</style></head><body><main>
<header><div><h1>LLM Deception Sensor</h1><p>Offline research dashboard · v0.3.0</p></div><small>{text(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}</small></header>
<section class='cards'>{cards}</section>
<div class='warning'><b>Research-only telemetry.</b> Synthetic marker detection is not proof of actual attacker exfiltration. No live data or credentials required.</div>
<h2>Fleet sensor distribution</h2>{table(list(stats['fleet_sensor_counts'].items()))}
<h2>Proxy upstream response status</h2>{table(list(stats['proxy_upstream_status'].items()))}
<h2>Proxy errors</h2>{table(list(stats['proxy_errors'].items()))}
<h2>Severity indicators</h2>{table(list(stats['severity'].items()))}
<h2>Most observed endpoints</h2>{table(stats['top_routes'])}
<h2>Heuristic indicators</h2>{table(stats['indicators'])}
<h2>Confirmed synthetic exposure by category</h2>{table(list(stats['synthetic_exposure_by_kind'].items()))}
<h2>MCP method distribution</h2>{table(stats['mcp_methods'])}
<h2>Observed session behavior (descriptive, not ML)</h2>{table(list(stats['session_behavior_patterns'].items()))}
<h2>Frequently observed endpoint transitions</h2>{table([(p['from'] + ' → ' + p['to'], p['count']) for p in stats['top_endpoint_transitions']])}
<h2>Session summary (100 max)</h2><table><thead><tr><th>Sensor</th><th>Hashed session</th><th>Events</th><th>Canary hits</th><th>Routes</th><th>First seen</th></tr></thead><tbody>{sessions}</tbody></table>
<p class='muted'>Offline report; no external requests, script execution or raw prompt contents. Session IDs are pseudonymous, not anonymous.</p>
</main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    output.chmod(0o600)
    return {"output": str(output), "events": stats["events"], "sessions": stats["unique_session_hashes"]}
