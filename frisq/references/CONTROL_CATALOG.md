# FRISQ Control Catalog v0.1
Every applicable control needs a test method and evidence, not a checkbox.

| ID | Domain | Verification required |
|---|---|---|
| ID-01 | Identity | MFA, recovery, session expiration, brute-force limits |
| AUTHZ-01 | Authorisation | IDOR/BOLA negative tests; least privilege on every endpoint |
| TENANT-01 | Isolation | Cross-tenant reads/writes/files/messages denied by test |
| DATA-01 | Database | RLS coverage, migration safety, access roles, query limits |
| SECRETS-01 | Secrets | Secret scanning, CI exposure, rotation and scoped credentials |
| WEB-01 | Web | TLS, CSP, security headers, CSRF, XSS, injection and redirects |
| API-01 | API | Schema validation, auth, quotas, CORS and replay protection |
| EDGE-01 | Cloudflare | WAF rules, DDoS controls, bot policy, origin lockdown and alerts |
| CLOUD-01 | AWS/cloud | IAM least privilege, encryption, network exposure, audit trails |
| FILE-01 | Files | Type/size checks, malware controls, private buckets, signed URL TTL |
| CHAT-01 | Messaging | Conversation membership, attachment ACL, deletion and retention |
| AI-01 | Agents | Prompt injection, tool permission limits, output checks, data leakage |
| SUPPLY-01 | Supply chain | Dependency vulnerabilities, lockfiles, build provenance, CI permissions |
| LOG-01 | Monitoring | Redacted logs, anomaly alerts, audit events, incident ownership |
| BACKUP-01 | Recovery | Encrypted backups, restore test, rollback rehearsal, RPO/RTO |
| DEPLOY-01 | Deployment | CI tests, environment separation, approval, rollback, health check |
| PRIV-01 | Privacy | Data minimisation, consent, retention, export/deletion workflows |
| UX-01 | Functionality | Critical user journeys, mobile/accessibility, errors and dead buttons |
| PAY-01 | Payments | Webhook signatures, idempotency, no stored card data without controls |
| OPS-01 | Governance | Asset inventory, risk exceptions, owners, incident response plan |

Evidence must include: control ID, target, environment, commit SHA, method, tool/version, timestamp, result, redacted artifact reference and reviewer.
