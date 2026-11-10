# Contributing to FRISQ

Thanks for helping. The one rule: **never report PASS without executed-test evidence.** Changes that weaken it will not be accepted.

## Layout

- `frisq/` is the skill: `SKILL.md`, `references/`, `scripts/frisq.py`, `tests/`, `examples/`. This folder is what gets installed as a Claude Code skill.
- `.github/workflows/ci.yml` runs the tests and the self-scan on every push and pull request.

## Workflow

1. Fork, then branch from `main`.
2. Make a focused change. Add or update tests in `frisq/tests/` for any change to `scan` or `gate`.
3. Run the checks (Python 3, standard library only):

   ```bash
   cd frisq
   python3 -m unittest discover -s tests -v
   python3 scripts/frisq.py scan . --output /tmp/frisq-report.json
   ```

4. Open a pull request describing what changed and why. Be explicit about what is tested and what is not.

## Ground rules

- Keep the scanner non-executing and read-only; never run target code.
- Never echo matched secret values into reports or logs.
- Do not commit credentials, customer data or real evidence files. `examples/evidence.sample.json` is a placeholder only.
- Do not claim a capability works unless it is implemented and tested. Update the README limitations when that changes.
- Pin third-party GitHub Actions by commit SHA before relying on them in production.
