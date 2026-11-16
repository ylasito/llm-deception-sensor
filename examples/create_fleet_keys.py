"""Generate demo fleet signing keys locally; refuses to overwrite existing secrets."""
import json
import os
from pathlib import Path
import secrets
import sys


def main():
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("lab")
    folder.mkdir(parents=True, exist_ok=True)
    key_file = folder / "collector-keys.json"
    sender_file = folder / "shipper-key.txt"
    if key_file.exists() or sender_file.exists():
        raise SystemExit("Refusing to overwrite existing secrets")
    key = secrets.token_hex(32)
    for dest, content in ((key_file, json.dumps({"local-sensor": key}, indent=2) + "\n"),
                          (sender_file, key + "\n")):
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(content)
    print("Created local fleet secrets; do not commit these files")


if __name__ == "__main__":
    main()
