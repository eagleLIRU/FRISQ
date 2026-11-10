# FRISQ

**Evidence-first security audit, authorised fix, verification and release gating for web, cloud, AI and messaging products.**

**In plain words:** FRISQ helps an AI assistant (Claude Code) review a software project for security problems carefully and honestly. It can scan code for risky patterns, and it can decide whether a release is `APPROVE`, `REVIEW` or `BLOCK` based on test evidence you give it. It will not say something is safe unless there is a recorded test to prove it.

FRISQ (v0.3.0) is a Claude Code skill plus a small offline engine. The skill tells an AI assistant *how* to run a security review safely; the engine provides a read-only source scanner and a conservative evidence gate. Its core principle: **inspect everything, verify everything, trust nothing without evidence.**

**It is a working starter skill, not a complete automated security auditing platform.** It does not run penetration tests or check your cloud settings for you.

> **Status: early starter, not a finished security product.** See [Current limitations](#current-limitations) before relying on it. FRISQ is not a certification and does not guarantee that anything is secure.

## What it does today

| Capability | Status |
|---|---|
| Skill instructions for the AUDIT, FIX, VERIFY and GATE workflows (`frisq/SKILL.md`) | Working (guidance for the assistant) |
| Control catalogue (20 controls), test playbook, provider baselines, product profiles, release policy (`frisq/references/`) | Working (reference documents) |
| `scan`: offline, read-only static indicator scan (15 regex rules: private keys, AWS key IDs, hard-coded tokens, `service_role` references, RLS disabled, `pull_request_target`, unpinned Actions, open-redirect and HTML-injection sinks, etc.). Does not execute target code, does not follow symlinks, and does not print matched secret values | Working, heuristic only |
| `gate`: evaluates a JSON evidence file and returns `APPROVE`, `REVIEW` or `BLOCK` (exit code 2 on BLOCK) | Working, trusts the evidence it is given |
| Product profiles for `gate` (`pattio`, `vault`, `replio`, `lytics`, `ctma`, `client-site`) that add mandatory controls | Working (defaults are adjustable in `PROFILES`) |
| Unit tests and CI self-test | Working |

How the gate decides:

- `PASS` is only accepted with a method, tool version, UTC timestamp and evidence reference, and only for the commit under review.
- A clean scan is `NOT_VERIFIED`, never `PASS`.
- `BLOCK`: any critical/high `FAIL`, any required control missing or `NOT_VERIFIED`, or any validation error (unknown control, duplicate, expired exception, wrong commit, `NOT_APPLICABLE` on a required control without a named reviewer).
- `REVIEW`: medium/low failures or `NOT_APPLICABLE` controls remain.
- `APPROVE`: every required control has valid `PASS` evidence. It applies to one commit and environment only and is not a security guarantee.

## Installation

Requires Python 3 (tested on 3.12 and 3.14; standard library only; no dependencies, no cloud credentials).

As a Claude Code skill, copy the `frisq/` folder into your skills directory:

```bash
git clone https://github.com/eagleLIRU/FRISQ.git
cp -r FRISQ/frisq ~/.claude/skills/frisq
```

On Windows PowerShell:

```powershell
git clone https://github.com/eagleLIRU/FRISQ.git
Copy-Item -Recurse FRISQ\frisq $HOME\.claude\skills\frisq
```

The CLI also works standalone without Claude.

## Usage

Run from the `frisq/` folder.

Scan an **authorised** repository (read-only):

```bash
python3 scripts/frisq.py scan /path/to/authorised/repo --output frisq-report.json
```

Evaluate externally gathered test evidence for a release:

```bash
python3 scripts/frisq.py gate evidence.json --profile ctma --output frisq-decision.json
```

`examples/evidence.sample.json` shows the format. It is a placeholder (every control is `NOT_VERIFIED`) and must never be treated as real evidence.

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

Inside Claude Code, ask for a security audit, pre-deployment check or release gate and the skill will load. By default it is read-only: fixes require an explicit request, a dedicated branch, a plan, a diff, and retesting, and anything touching production, secrets, auth, RLS, schema, DNS, IAM or deployments needs separate approval.

## Repository layout

```
frisq/                    the skill (install this folder)
  SKILL.md                skill instructions
  README.md               original skill README
  references/             control catalogue, playbook, baselines, profiles, release policy
  scripts/frisq.py        scan and gate engine
  tests/                  unit tests
  examples/               sample (placeholder) evidence
  .github/workflows/      the skill's original self-test workflow
.github/workflows/ci.yml  repository CI (runs the tests and self-scan from frisq/)
CONTRIBUTING.md  SECURITY.md
```

## Current limitations

These are **not built yet**; do not assume they work:

- Autonomous safe patch generation.
- Orchestration of external scanners (dependency, secrets, SAST) and real cloud API checks (AWS, Cloudflare, Supabase, Vercel, GitHub settings).
- Real RLS, browser, tenant-isolation, API or AI/prompt-injection attack tests. The playbook describes what to test; it does not run the tests.
- Evidence signing or authentication. `gate` trusts submitted evidence fields, so use human review and protected CI artifacts.
- A dashboard, and automatic deployment blocking in other repositories.
- The scanner is a small set of heuristics. It will miss issues and produce false positives; a finding is a lead, not a proven exploit.
- The test file `frisq/tests/test_frisq.py` contains a dummy AWS-key-shaped string used only to test the scanner; it is not a real credential.
- Third-party GitHub Actions in the workflows use version tags, not commit SHAs; pin them before production use.
- The original skill workflow at `frisq/.github/workflows/` is preserved as shipped but only runs if the `frisq/` folder is used as its own repository root; the root `ci.yml` is what runs here.

Only use FRISQ on systems you own or are explicitly authorised to test. Never put secrets, client data or production backups in this repository.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). The software is provided as is, with no warranty; using it does not make a system secure.
