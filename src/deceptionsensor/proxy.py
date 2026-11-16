"""Strict local inference relay. No arbitrary destinations, redirects, or client credentials.

This is a LAB ONLY forwarder to a separately operated local model server.
The built-in relay deliberately supports only TCP IPv4 loopback upstreams;
remote inference is out of scope and requires an independently secured gateway.
"""
from __future__ import annotations
from dataclasses import dataclass
import http.client
import re
from urllib.parse import urlsplit

ALLOWED_PATHS = frozenset({
    "/v1/models", "/models", "/v1/chat/completions", "/chat/completions",
    "/v1/responses", "/v1/embeddings", "/api/chat", "/api/generate",
    "/api/tags", "/api/version",
})
POST_PATHS = frozenset({"/v1/chat/completions", "/chat/completions", "/v1/responses",
                        "/v1/embeddings", "/api/chat", "/api/generate"})
GET_PATHS = ALLOWED_PATHS - POST_PATHS
MIMES = ("application/json", "application/x-ndjson", "text/event-stream")


@dataclass(frozen=True)
class LocalUpstream:
    port: int

    @classmethod
    def parse(cls, url: str) -> "LocalUpstream":
        parsed = urlsplit(url)
        # Never pass a user-controlled URL to an HTTP client. Only a strict local host:port.
        if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost")
                or parsed.username or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or not parsed.port
                or parsed.netloc.count("@") or not re.fullmatch(r"(?:127\.0\.0\.1|localhost):[0-9]{1,5}", parsed.netloc)):
            raise ValueError("PROXY_UPSTREAM_URL must be http://127.0.0.1:PORT (no path, userinfo, or query)")
        return cls(port=parsed.port)

    def connect(self, timeout: float = 8.0) -> http.client.HTTPConnection:
        # Bypasses DNS entirely. No SSH metadata services, RFC1918 hosts or internet egress.
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)


def is_safe_mime(value: str) -> bool:
    return value.split(";", 1)[0].strip().lower() in MIMES
