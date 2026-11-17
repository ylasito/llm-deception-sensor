"""Local deception sensor and independently authenticated fleet collector CLI."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import tempfile

from .analytics import report
from .config import Settings
from .collector import CollectorSettings, EventDatabase, serve_collector
from .dashboard import generate
from .lab import init_lab, run_lab, evaluate_lab
from .agent_lab import create_agent_experiment, evaluate_agents
from .server import serve
from .shipper import ship_logs
from .research import research_init, research_run, research_report
from .behavior import cluster_sessions
from .intelligence import intelligence_report, drift_report, write_report, render_intelligence_dashboard
from .evidence import create_report, verify_report, write_private
from .threatintel import campaign_report, mapping_report, ioc_report, evaluation_report


def fleet_action(db: Path, command: str, output: Path | None = None) -> dict:
    database = EventDatabase(db)
    try:
        with tempfile.TemporaryDirectory(prefix="fleet-report-") as tmp:
            folder = Path(tmp)
            exported = database.export(folder / "events.jsonl")
            if command == "fleet-export":
                if output is None:
                    raise ValueError("Export output path required")
                exported = database.export(output)
                return exported
            if command == "fleet-report":
                return {"fleet": exported["by_sensor"], "report": report(folder)}
            if command == "fleet-dashboard":
                if output is None:
                    raise ValueError("Dashboard output required")
                res = generate(folder, output)
                return {**res, "fleet": exported["by_sensor"]}
    finally:
        database.close()
    raise ValueError("Unknown fleet command")


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM Deception Sensor v0.7.0 (authorized research)")
    sub = parser.add_subparsers(dest="command")
    summary = sub.add_parser("summary", help="Offline aggregated telemetry")
    summary.add_argument("--log-dir", default="./data")
    dash = sub.add_parser("dashboard", help="Render offline HTML dashboard")
    dash.add_argument("--log-dir", default="./data")
    dash.add_argument("--output", default="./report/dashboard.html")
    init = sub.add_parser("lab-init", help="Create synthetic calibration registry")
    init.add_argument("--output", default="./lab/registry.json")
    run = sub.add_parser("lab-run", help="Send seven synthetic calibration cases to LOCAL sensor")
    run.add_argument("--registry", default="./lab/registry.json")
    run.add_argument("--url", default="http://127.0.0.1:8080")
    evaluate = sub.add_parser("lab-report", help="Evaluate synthetic markers")
    evaluate.add_argument("--registry", default="./lab/registry.json")
    evaluate.add_argument("--log-dir", default="./data")
    evaluate.add_argument("--output")
    agent_init = sub.add_parser("agent-init", help="Create synthetic marker registry for real authorized agent")
    agent_init.add_argument("--output", default="./lab/agent-registry.json")
    agent_report = sub.add_parser("agent-report", help="Measure synthetic context exposure in agent requests")
    agent_report.add_argument("--registry", default="./lab/agent-registry.json")
    agent_report.add_argument("--log-dir", default="./data")
    agent_report.add_argument("--output")

    research_i = sub.add_parser("research-init", help="Create private synthetic case registry and manifest")
    research_i.add_argument("--registry", default="./lab/research-registry.json")
    research_i.add_argument("--manifest", default="./lab/research-manifest.json")
    research_r = sub.add_parser("research-run", help="Repeat bounded local multi-turn experiments")
    research_r.add_argument("--registry", default="./lab/research-registry.json")
    research_r.add_argument("--manifest", default="./lab/research-manifest.json")
    research_r.add_argument("--url", default="http://127.0.0.1:8080")
    research_r.add_argument("--mode", choices=["scripted", "model"], default="scripted")
    research_r.add_argument("--model", default="local-lab-model")
    research_r.add_argument("--repeats", type=int, default=3)
    research_r.add_argument("--turns", type=int, default=3)
    research_r.add_argument("--seed", type=int, default=42)
    research_r.add_argument("--token-env", default="PROXY_CLIENT_TOKEN")
    research_r.add_argument("--output", default="./lab/research-run.json")
    research_e = sub.add_parser("research-report", help="Summarize approved transport, unexpected canaries and missing sessions")
    research_e.add_argument("--registry", default="./lab/research-registry.json")
    research_e.add_argument("--manifest", default="./lab/research-manifest.json")
    research_e.add_argument("--ledger", default="./lab/research-run.json")
    research_e.add_argument("--log-dir", default="./data")
    research_e.add_argument("--output")
    cluster = sub.add_parser("behavior-cluster", help="Explore metadata-only session clusters; not threat attribution")
    cluster.add_argument("--log-dir", default="./data")
    cluster.add_argument("--clusters", type=int, default=3)
    cluster.add_argument("--max-events", type=int, default=10000)
    cluster.add_argument("--output")

    intel = sub.add_parser("intel-report", help="Generate privacy-filtered offline session triage report")
    intel.add_argument("--log-dir", default="./data")
    intel.add_argument("--max-events", type=int, default=10000)
    intel.add_argument("--top", type=int, default=20)
    intel.add_argument("--output")
    intel_dash = sub.add_parser("intel-dashboard", help="Generate local HTML triage dashboard")
    intel_dash.add_argument("--log-dir", default="./data")
    intel_dash.add_argument("--max-events", type=int, default=10000)
    intel_dash.add_argument("--top", type=int, default=20)
    intel_dash.add_argument("--output", default="./report/intelligence.html")
    drift = sub.add_parser("intel-drift", help="Compare two metadata-only windows (descriptive JS drift)")
    drift.add_argument("--baseline", required=True)
    drift.add_argument("--current", required=True)
    drift.add_argument("--max-events", type=int, default=10000)
    drift.add_argument("--minimum-requests", type=int, default=30)
    drift.add_argument("--threshold", type=float, default=0.15)
    drift.add_argument("--output")
    evidence = sub.add_parser("evidence-report", help="Create privacy-filtered chain digest report for authorized lab")
    evidence.add_argument("--log-dir", default="./data")
    evidence.add_argument("--output", required=True)
    evidence.add_argument("--key-env", default="EVIDENCE_HMAC_KEY")
    ev_check = sub.add_parser("evidence-verify", help="Compare existing evidence report against current logs")
    ev_check.add_argument("--log-dir", default="./data")
    ev_check.add_argument("--report", required=True)
    ev_check.add_argument("--key-env", default="EVIDENCE_HMAC_KEY")
    collector = sub.add_parser("collector", help="Start authenticated fleet collector")
    collector.add_argument("--keys", required=True, help="JSON map of sensor IDs to 32+ char shared HMAC keys")
    collector.add_argument("--database", default="./fleet/events.sqlite3")
    collector.add_argument("--host", default="127.0.0.1")
    collector.add_argument("--port", type=int, default=18888)
    collector.add_argument("--tls-cert")
    collector.add_argument("--tls-key")
    collector.add_argument("--max-events", type=int, default=100000)
    ship = sub.add_parser("ship", help="Send only validated metadata to collector")
    ship.add_argument("--log-dir", default="./data")
    ship.add_argument("--url", default="http://127.0.0.1:18888")
    ship.add_argument("--sensor-id", required=True)
    ship.add_argument("--key-file", help="Read private HMAC key from this file (recommended)")
    ship.add_argument("--key-env", default="COLLECTOR_SIGNING_KEY", help="Environment variable containing signing key")
    ship.add_argument("--ca-file", help="Trusted CA certificate for HTTPS collector")
    ship.add_argument("--follow", action="store_true")
    ship.add_argument("--interval", type=int, default=10)
    for cmd in ("fleet-export", "fleet-report", "fleet-dashboard"):
        cli = sub.add_parser(cmd, help="Offline fleet exports/analytics from SQLite")
        cli.add_argument("--database", default="./fleet/events.sqlite3")
        if cmd != "fleet-report":
            cli.add_argument("--output", required=True)

    ti1 = sub.add_parser("ti-campaigns", help="Offline metadata pattern groups, not actor attribution")
    ti1.add_argument("--log-dir", default="./data")
    ti1.add_argument("--bucket-minutes", type=int, default=60)
    ti1.add_argument("--minimum-sessions", type=int, default=2)
    ti2 = sub.add_parser("ti-mappings", help="Candidate ATT&CK analogies for analyst review")
    ti2.add_argument("--log-dir", default="./data")
    ti3 = sub.add_parser("ti-iocs", help="Review only analyst-supplied indicators")
    ti3.add_argument("--input", required=True)
    ti4 = sub.add_parser("ti-evaluate", help="Evaluate independent positive/negative label files")
    ti4.add_argument("--predictions", required=True)
    ti4.add_argument("--truth", required=True)
    args = parser.parse_args()
    if args.command == "ti-campaigns":
        result = campaign_report(Path(args.log_dir), bucket_minutes=args.bucket_minutes,
                                 minimum_sessions=args.minimum_sessions)
    elif args.command == "ti-mappings":
        result = mapping_report(Path(args.log_dir))
    elif args.command == "ti-iocs":
        result = ioc_report(Path(args.input))
    elif args.command == "ti-evaluate":
        result = evaluation_report(Path(args.predictions), Path(args.truth))
    elif args.command == "summary":
        result = report(Path(args.log_dir))
    elif args.command == "dashboard":
        result = generate(Path(args.log_dir), Path(args.output))
    elif args.command == "lab-init":
        result = init_lab(Path(args.output))
    elif args.command == "lab-run":
        result = run_lab(Path(args.registry), args.url)
    elif args.command == "lab-report":
        result = evaluate_lab(Path(args.log_dir), Path(args.registry))
        if args.output:
            dest = Path(args.output)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    elif args.command == "agent-init":
        result = create_agent_experiment(Path(args.output))
    elif args.command == "agent-report":
        result = evaluate_agents(Path(args.log_dir), Path(args.registry))
        if args.output:
            dest = Path(args.output)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    elif args.command == "evidence-report":
        result = create_report(Path(args.log_dir), signing_key=os.getenv(args.key_env, ""))
        write_private(result, Path(args.output))
    elif args.command == "evidence-verify":
        verified = verify_report(json.loads(Path(args.report).read_text(encoding="utf-8")),
                                 Path(args.log_dir), os.getenv(args.key_env, ""))
        result = {"verified": verified, "interpretation": "Derived metadata integrity comparison only"}
    elif args.command == "research-init":
        result = research_init(Path(args.registry), Path(args.manifest))
    elif args.command == "research-run":
        result = research_run(Path(args.registry), Path(args.manifest), args.url, mode=args.mode,
                              model_id=args.model, repeats=args.repeats, turns=args.turns,
                              seed=args.seed, token=os.getenv(args.token_env, ""), output=Path(args.output))
    elif args.command == "research-report":
        result = research_report(Path(args.log_dir), Path(args.registry), Path(args.manifest),
                                 Path(args.ledger) if args.ledger else None)
        if args.output:
            path = Path(args.output); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    elif args.command == "behavior-cluster":
        result = cluster_sessions(Path(args.log_dir), k=args.clusters, max_events=args.max_events)
        if args.output:
            path = Path(args.output); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    elif args.command == "intel-report":
        result = intelligence_report(Path(args.log_dir), max_events=args.max_events, top=args.top)
        if args.output:
            write_report(result, Path(args.output))
    elif args.command == "intel-dashboard":
        intelligence = intelligence_report(Path(args.log_dir), max_events=args.max_events, top=args.top)
        result = render_intelligence_dashboard(intelligence, Path(args.output))
    elif args.command == "intel-drift":
        result = drift_report(Path(args.baseline), Path(args.current), max_events=args.max_events,
                              minimum_requests=args.minimum_requests, threshold=args.threshold)
        if args.output:
            write_report(result, Path(args.output))
    elif args.command == "collector":
        settings = CollectorSettings.from_file(Path(args.keys), args.host, args.port,
                    Path(args.database), Path(args.tls_cert) if args.tls_cert else None,
                    Path(args.tls_key) if args.tls_key else None, args.max_events)
        serve_collector(settings)
        return
    elif args.command == "ship":
        secret = Path(args.key_file).read_text(encoding="utf-8").strip() if args.key_file else os.environ.get(args.key_env, "")
        result = ship_logs(Path(args.log_dir), args.url, args.sensor_id, secret,
                           ca_file=args.ca_file, follow=args.follow, interval=args.interval)
    elif args.command in ("fleet-export", "fleet-report", "fleet-dashboard"):
        result = fleet_action(Path(args.database), args.command, Path(args.output) if args.command != "fleet-report" else None)
    else:
        serve(Settings.from_env())
        return
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
