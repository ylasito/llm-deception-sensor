"""Generate harmless synthetic metadata-only telemetry for the v0.5 intelligence CLI.

Does NOT call or probe any network endpoint, agent or provider.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
import argparse
from deceptionsensor.storage import JsonlSink


def generate(root: Path) -> dict:
    if (root / "baseline").exists() or (root / "current").exists():
        raise FileExistsError("Refusing to overwrite existing lab windows")
    stamp = datetime(2026, 11, 15, tzinfo=timezone.utc)
    outputs = {}
    for period in ("baseline", "current"):
        sink = JsonlSink(root / period, 1000000, 3)
        request_count = 0
        for i in range(40):
            session = f"{i+1:024x}"
            for step in range(3):
                if period == "baseline":
                    route, indicator, family = "/v1/chat/completions", [], "openai"
                elif i % 3 == 0 and step == 0:
                    route, indicator, family = "/v1/models", ["model_listing_request"], "openai"
                elif i % 3 == 0 and step == 1:
                    route, indicator, family = "/v1/chat/completions", ["system_prompt_request"], "openai"
                elif i % 3 == 1 and step == 0:
                    route, indicator, family = "/mcp", ["mcp_discovery"], "mcp"
                elif i % 3 == 1 and step == 1:
                    route, indicator, family = "/mcp", ["mcp_tool_invocation"], "mcp"
                else:
                    route, indicator, family = "/v1/chat/completions", [], "openai"
                mcp_method = ("tools/list" if route == "/mcp" and step == 0 else
                              "tools/call" if route == "/mcp" else "other")
                event = {"schema_version":"0.3.0", "event_kind":"request", "capture_mode":"metadata",
                         "sensor_id":"lab-sensor-01", "session_id":session,
                         "ts":(stamp + timedelta(hours=int(period=="current"), seconds=i*60+step*5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "route":route, "endpoint_family":family, "method":"POST", "mcp_method":mcp_method,
                         "indicators":indicator, "roles":["user"], "request_bytes":245,
                         "message_count":1, "canary_hits": []}
                sink.emit(event)
                request_count += 1
        outputs[period] = {"path":str(root / period), "request_count":request_count}
    return {"output":outputs, "synthetic_only":True, "has_real_agent_interactions":False}


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Generate offline synthetic AI sensor telemetry")
    parser.add_argument("--output-dir", default="./lab/intel-demo")
    args=parser.parse_args()
    print(generate(Path(args.output_dir)))
