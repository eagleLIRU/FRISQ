# Butler & AI product overlays
Gate profiles (`gate --profile X`) add these mandatory controls to the base 14. Defaults, owner to adjust in `PROFILES` in scripts/frisq.py: pattio EDGE-01 CLOUD-01 UX-01; vault EDGE-01 CHAT-01 UX-01; replio EDGE-01 CHAT-01; lytics EDGE-01 UX-01; ctma AI-01 EDGE-01; client-site UX-01.

- **PATTIO** (critical): principal-only data, household and staff isolation, staff revoke/restore, MFA, incident logs, secure uploads, privacy and cross-household data tests.
- **Vault** (critical): client/project access, invitation lifecycle, guest review boundaries, attachments, download token expiry, email bundling without exposing unrelated files.
- **REPLIO** (high): Meta signature verification, workspace isolation, OAuth token storage, keyword automation limits, deduplication, retries, send authorisation.
- **LYTICS** (high): site/path tenant separation, tracking consent, replay privacy, API key scoping, retention, dashboards and export permissions.
- **CTMA/Centra** (critical): read-only TradingView capture, no broker order execution, append-only ledger, partial exit arithmetic, AI unverified status fail-closed, model/tool injection boundaries and API key handling.
- **Client websites** (risk-based): forms/spam, privacy, SEO/public content, admin access, domain/email DNS, backup and rollback, accessibility and responsive testing.
