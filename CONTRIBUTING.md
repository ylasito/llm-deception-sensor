# Contributing

Contributions to this research sensor are welcome under the MIT license.

## Quick workflow

1. Create a separate branch for changes.
2. Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`.
3. Submit changes that include tests for new endpoints, privacy behavior or detection tags.
4. Do not add real secrets, payloads collected from unaffiliated clients, raw captured prompts, or customer telemetry to the repository.
5. Record changes to the threat model in `docs/SECURITY.md`.

For potential security weaknesses, do not publish exploitation instructions or victim data in a public issue. Contact the repository's future maintainer through a private vulnerability report once a repository has been published; until then treat the source archive as a local prototype.
