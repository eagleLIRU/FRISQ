# FRISQ verification playbook
Use isolated test tenants, synthetic data and authorised environments. Evidence is required for each PASS.

## Identity, sessions and authorisation
- Test MFA enrollment, enforcement, recovery and revocation; login and reset throttling; expired/replayed reset tokens.
- Verify cookie Secure/HttpOnly/SameSite, session rotation, expiry, logout and account disable.
- Test BOLA/IDOR across users and tenants on every read, write, search, export and attachment route.
- Verify privilege changes, admin routes, default-deny, role escalation and staff removal.

## Database, storage and privacy
- Verify RLS on each exposed table; deny cross-tenant SELECT/INSERT/UPDATE/DELETE, including joins and RPCs.
- Check service-role secrets are server-only; validate storage bucket policies, signed URL TTL and revocation.
- Review migration rollback/forward safety, schema drift, backups and tested restore with synthetic data.
- Check consent, minimisation, retention, deletion/export, redaction and logging of sensitive fields.

## App and API
- Validate injection, XSS, CSRF, SSRF, file/path traversal, open redirect, request limits, schema enforcement and security headers.
- Verify CORS is not treated as authentication; test API access separately.
- Test uploads for type/content/size, malware scanning, private storage and download authorisation.
- Verify webhook signatures, timestamp/replay, deduplication, idempotency and rate limits.

## AI and messaging
- Test untrusted prompt injection in retrieved docs, chats and tool output; confirm tool allowlists and human approval for high-impact actions.
- Verify sensitive output filtering, data boundaries, tenant isolation, retention and safe fallback on unknowns.
- Test chat membership on read/send/edit/delete, attachments, webhook authenticity and delivery retries.

## Infrastructure and release
- Review DNS/TLS, origin bypass, WAF policies, DDoS/rate controls, IAM least privilege, network exposure and audit logs.
- Review lockfiles, dependency and secret scanners, CI token permissions, pinned actions and build artifacts.
- Test alert delivery, incident runbook, health checks, rollback and restoration; check staging vs production separation.
- Run critical UI journeys and mobile/accessibility checks; collect evidence with timestamps and commit IDs.

## Evidence record
For every control include: control_id, status, severity, method, tool_version, timestamp_utc, evidence_ref, environment, commit, reviewer, redaction status. For NOT_APPLICABLE include reason.
