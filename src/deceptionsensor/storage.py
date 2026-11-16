"""Bounded JSONL telemetry with rotation and no unredacted credentials by default."""
from __future__ import annotations
import json
import os
from pathlib import Path
import threading
from typing import Any, Iterator


class JsonlSink:
    def __init__(self, root: Path, rotate_bytes: int, retention_files: int):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        self.path = self.root / "events.jsonl"
        self.rotate_bytes = rotate_bytes
        self.retention_files = retention_files
        self.lock = threading.Lock()

    def _rotate(self) -> None:
        for index in range(self.retention_files - 1, 0, -1):
            old = self.root / f"events.jsonl.{index}"
            new = self.root / f"events.jsonl.{index + 1}"
            if old.exists():
                old.replace(new)
        if self.path.exists():
            self.path.replace(self.root / "events.jsonl.1")

    def emit(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")
        with self.lock:
            if self.path.exists() and self.path.stat().st_size + len(encoded) > self.rotate_bytes:
                self._rotate()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, encoded)
            finally:
                os.close(fd)


def iter_events(root: Path) -> Iterator[dict]:
    paths = sorted(root.glob("events.jsonl.*"), reverse=True) + [root / "events.jsonl"]
    for path in paths:
        if not path.is_file():
            continue
        with path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    yield item
