#!/bin/sh
set -eu
BASE="${BASE:-http://127.0.0.1:8080}"
curl --fail-with-body -sS "$BASE/mcp" \
  -H 'Content-Type: application/json' -H 'MCP-Protocol-Version: 2025-03-26' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
printf '\n'
curl --fail-with-body -sS "$BASE/mcp" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
printf '\n'
