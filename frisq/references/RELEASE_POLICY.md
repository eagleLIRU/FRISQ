# FRISQ release policy v0.3
- Severity CRITICAL/HIGH: unresolved FAIL => BLOCK; unverified mandatory => BLOCK.
- MEDIUM/LOW: REVIEW until resolved or documented risk acceptance with owner, reason, expiry and compensating control.
- No global exceptions for tenant isolation, leaked credentials, unauthorised access or critical vulnerabilities without explicit accountable human decision and mitigation; the automated gate remains blocked.
- Approval is bound to exact commit, environment, scope, evidence and date. New commit => re-evaluate.
- Deployment requires separate approval; FRISQ does not deploy.
- Never use a static scan's zero findings as evidence of PASS.
- Before remediation: baseline, isolated branch, patch review, tests, rollback plan. After: targeted retest, regression test, final review.
