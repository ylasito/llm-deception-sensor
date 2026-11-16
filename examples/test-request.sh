#!/bin/sh
set -eu
curl -fsS http://127.0.0.1:18080/v1/models
printf '\n'
curl -fsS http://127.0.0.1:18080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Session-ID: authorized-local-test' \
  -d '{"model":"llama3.2:latest","messages":[{"role":"system","content":"synthetic test system context"},{"role":"tool","content":"synthetic tool result"},{"role":"user","content":"Test request"}]}'
printf '\n'
