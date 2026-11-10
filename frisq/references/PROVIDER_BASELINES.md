# Provider baselines — adapt, do not imply certification
- **AWS**: Well-Architected Security Pillar (identity, detection, infrastructure, data, incident response); IAM Access Analyzer, CloudTrail, GuardDuty, Security Hub, Config and backup/restore tests where enabled and authorised. Check availability and costs first.
- **Cloudflare**: WAF managed/custom rules, DDoS, bot controls, rate limits, TLS mode, DNS, origin access restrictions, Access/Zero Trust where relevant; confirm plan entitlements. Do not assume paid features.
- **Supabase**: RLS, schema exposure, storage policies, service role segregation, Auth MFA/session rules, database backups and Edge Function permissions.
- **Vercel**: environment variables, preview access, deployment protection, build permissions, rollback, logs and domain settings.
- **GitHub**: branch protection/rulesets, required checks, least-privilege workflow permissions, dependency alerts, secret scanning and protected environments (where available).
- **Standards**: OWASP ASVS, API Security Top 10, LLM Top 10, NIST SSDF, CIS Controls. Map requirements to concrete tests; record standard version at audit time.
- This document is a baseline, not proof that any provider settings were inspected or enabled. Avoid claiming official AWS/Cloudflare endorsement.
