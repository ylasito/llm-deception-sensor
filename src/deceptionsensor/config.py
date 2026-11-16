"""Configuration. Safe defaults: local decoy; proxy mode requires explicit opt-in."""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import sys
from .proxy import LocalUpstream


def _integer(name: str, default: int, lo: int, hi: int) -> int:
    value = int(os.getenv(name, str(default)))
    if not lo <= value <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return value


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    log_dir: Path
    capture_mode: str
    secret: str
    max_request_bytes: int
    requests_per_minute: int
    rotate_bytes: int
    retention_files: int
    sensor_id: str = "local-sensor"
    canary_registry: Path | None = None
    proxy_upstream: str = ""
    proxy_client_token: str = ""
    proxy_upstream_api_key: str = ""
    proxy_max_response_bytes: int = 4194304

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.getenv("CAPTURE_MODE", "metadata").lower()
        if mode not in ("metadata", "redacted", "raw"):
            raise ValueError("CAPTURE_MODE must be metadata, redacted, or raw")
        secret = os.getenv("SENSOR_SECRET", "")
        if not secret:
            secret = secrets.token_hex(32)
            print("WARNING: SENSOR_SECRET is ephemeral; correlation IDs change after restart.", file=sys.stderr)
        elif len(secret) < 32:
            raise ValueError("SENSOR_SECRET must be at least 32 characters")
        if mode == "raw" and os.getenv("ALLOW_RAW_CAPTURE", "") != "I_UNDERSTAND_THE_RISK":
            raise ValueError("Raw capture requires ALLOW_RAW_CAPTURE=I_UNDERSTAND_THE_RISK")
        sensor_id = os.getenv("SENSOR_ID", "local-sensor")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", sensor_id):
            raise ValueError("SENSOR_ID must contain lowercase letters, numbers and dashes (max 64)")
        upstream = os.getenv("PROXY_UPSTREAM_URL", "").strip()
        token = os.getenv("PROXY_CLIENT_TOKEN", "")
        if upstream:
            LocalUpstream.parse(upstream)
            if len(token) < 24:
                raise ValueError("PROXY_CLIENT_TOKEN must be at least 24 characters in proxy mode")
            if mode != "metadata":
                raise ValueError("Proxy mode requires CAPTURE_MODE=metadata")
        return cls(
            host=os.getenv("HOST", "127.0.0.1"),
            port=_integer("PORT", 8080, 1, 65535),
            log_dir=Path(os.getenv("LOG_DIR", "./data")),
            capture_mode=mode,
            secret=secret,
            max_request_bytes=_integer("MAX_REQUEST_BYTES", 65536, 1024, 1048576),
            requests_per_minute=_integer("REQUESTS_PER_MINUTE", 120, 1, 10000),
            rotate_bytes=_integer("ROTATE_BYTES", 5242880, 4096, 1073741824),
            retention_files=_integer("RETENTION_FILES", 4, 1, 40),
            sensor_id=sensor_id,
            canary_registry=Path(os.environ["CANARY_REGISTRY"]) if os.getenv("CANARY_REGISTRY") else None,
            proxy_upstream=upstream,
            proxy_client_token=token,
            proxy_upstream_api_key=os.getenv("PROXY_UPSTREAM_API_KEY", ""),
            proxy_max_response_bytes=_integer("PROXY_MAX_RESPONSE_BYTES", 4194304, 4096, 33554432),
        )
