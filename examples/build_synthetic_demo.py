"""Generate an OFFLINE fleet dashboard from fake-upstream fixtures; no real LLM.

Intentionally reuses regression-suite fixtures so demo and integration tests
follow the same network and privacy boundaries. No internet connections.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "tests"))
from test_v03 import fake_upstream, proxy_sensor, collector, req, TOKEN, KEY1, KEY2  # noqa: E402
from deceptionsensor.agent_lab import create_agent_experiment, evaluate_agents  # noqa: E402
from deceptionsensor.shipper import ship_logs  # noqa: E402
from deceptionsensor.__main__ import fleet_action  # noqa: E402


def run(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    registry = out / "agent-registry-internal.json"
    create_agent_experiment(registry)
    doc = json.loads(registry.read_text())
    memory = next(x["marker"] for x in doc["canaries"] if x["kind"] == "memory")
    with fake_upstream() as upstream:
        with proxy_sensor(out / "alpha-logs", upstream.server_address[1], registry) as alpha:
            port = alpha.server_address[1]
            status, _ = req(port, "POST", "/v1/chat/completions", {
                "model": "synthetic-lab-model", "messages": [{"role": "system", "content": memory},
                 {"role": "user", "content": "Test fictional alert"}]},
                {"X-Proxy-Token": TOKEN, "X-Lab-Case-ID": "agent-memory", "X-Session-ID": "synthetic-run-001"})
            assert status == 200
            status, _ = req(port, "POST", "/v1/chat/completions", {
                "model": "synthetic-lab-model", "messages": [{"role": "user", "content": "No marker in this baseline"}]},
                {"X-Proxy-Token": TOKEN, "X-Lab-Case-ID": "agent-baseline", "X-Session-ID": "synthetic-run-002"})
            assert status == 200
        with proxy_sensor(out / "bravo-logs", upstream.server_address[1], sensor_id="sensor-bravo") as bravo:
            status, _ = req(bravo.server_address[1], "POST", "/v1/chat/completions", {
                "model": "synthetic-lab-model", "messages": [{"role": "user", "content": "Simulated neutral event"}]},
                {"X-Proxy-Token": TOKEN, "X-Session-ID": "synthetic-run-003"})
            assert status == 200
    with collector(out) as fleet:
        url = f"http://127.0.0.1:{fleet.server_address[1]}"
        a = ship_logs(out / "alpha-logs", url, "sensor-alpha", KEY1)
        b = ship_logs(out / "bravo-logs", url, "sensor-bravo", KEY2)
        assert a["sent"] == 4 and b["sent"] == 2
    stats = fleet_action(out / "fleet.sqlite3", "fleet-report")
    dashboard = fleet_action(out / "fleet.sqlite3", "fleet-dashboard", out / "fleet-dashboard.html")
    exposure = evaluate_agents(out / "alpha-logs", registry)
    (out / "fleet-report.json").write_text(json.dumps(stats, indent=2) + "\n")
    (out / "agent-exposure-report.json").write_text(json.dumps(exposure, indent=2) + "\n")
    (out / "RUN-NOTES.txt").write_text(
        "This sample was produced entirely in a loopback test harness with a fake inference upstream, "
        "two local sensors and a signed collector. Synthetic markers only. "
        "No third-party AI agent, actual attacker, cloud model, real secret, or real exfiltration was involved.\n")
    registry.unlink()  # Do not distribute full marker strings.
    print(json.dumps({"dashboard": dashboard, "fleet_sensors": stats["fleet"],
                      "requests": stats["report"]["events"], "proxy_outcomes": stats["report"]["proxy_outcomes"],
                      "synthetic_exposure_cases": exposure["exposed_observed_seeded_cases"]}, indent=2))


if __name__ == "__main__":
    run(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./demo-v03"))
