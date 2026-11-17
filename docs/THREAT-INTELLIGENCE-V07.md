# v0.7 — Offline Threat Intelligence Research

This is **not AWS MadPot**, a threat-actor attribution service, or an automated security control. No external threat feed or network enrichment is used.

## Commands

```bash
export PYTHONPATH=src
python3 -m deceptionsensor ti-campaigns --log-dir data --bucket-minutes 60 --minimum-sessions 2
python3 -m deceptionsensor ti-mappings --log-dir data
python3 -m deceptionsensor ti-iocs --input lab/analyst-iocs.jsonl
python3 -m deceptionsensor ti-evaluate --predictions lab/predictions.json --truth lab/ground-truth.json
python3 -m unittest discover -s tests -q
```

**IOC schema:** one JSON object per line with `type` = `ipv4`, `domain`, `sha256` or `url` and a matching `value`. Indicators must come from an authorized analyst; they are not extracted from private agent prompts. All are *unverified*, deduplicated and never automatically blocked.

**Evaluation schema:** JSON arrays of `{"id":"case-01","positive":true}` in independently prepared predictions and truth. Only matching IDs are scored. Missing predictions and extras are reported separately; zero denominators produce `null`.

**Campaign hypotheses:** Only sanitized metadata events are used. Positive-weight rule signatures matching within a time bucket are grouped by pseudonymous session IDs. Similar behavior does not prove shared actors, malicious intent or a single attack campaign.

**Technique candidates:** Selected ATT&CK IDs are low-confidence analogies, requiring independent analyst review and verification against current MITRE documentation. No unverified MITRE ATLAS technique identifiers are asserted.

**Publication controls:** Do not publish sensitive logs, real credentials, private context, real customer data or private experimental labels. Results are research hypotheses; never automatically block based on these outputs. No real autonomous external adversary has been tested.
