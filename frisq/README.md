# FRISQ v0.3 — Butler & AI

Evidence-first security **AUDIT → authorised FIX → VERIFY → GATE** skill and offline starter engine.

## Commands
```bash
python3 scripts/frisq.py scan /path/to/authorised/repo --output frisq-report.json
python3 scripts/frisq.py gate examples/evidence.sample.json --output frisq-decision.json
python3 -m unittest discover -s tests -v
```

## Installation
Copy this folder into your private repository. For Claude Code, make the `SKILL.md` and references available as a project skill according to your Claude Code version. Use only authorised targets. No cloud credentials are needed for the offline scanner.

## What actually works today
- Offline read-only indicator scan; does not execute target code or print matching secret lines.
- Evidence policy gate (fails closed on missing mandatory evidence, missing proof or high/critical failures). v0.3 adds product profiles (`--profile`), commit-match checks, unknown-control and expired-exception checks, and a named reviewer for N/A on required controls.
- 15 static indicator rules (secrets, RLS, CI triggers, unpinned actions, open redirects).
- Unit tests, CI self-tests, control catalogue, product profiles and authorised fix workflow instructions.

## What is NOT built yet
- Autonomous safe patch generator, external scanner orchestration, actual cloud API checks, real RLS/browser/AI attack tests, secrets/dependency scanner integration, verified evidence signing, production CI integration, dashboard, and automatic deployment blocking in other repos.
- `gate` trusts submitted evidence fields and cannot authenticate them. Use human review and protected CI artifacts; never treat sample evidence as real.
- A clean scan is **NOT_VERIFIED**, never a release approval. Do not merge/deploy automatically.

## Safety
Do not put secrets, client data or production backups in this repository. Keep repository private. Review and pin third-party GitHub Actions before production use.
