# Case Studies

The actual disclosure reports and proof-of-concept scripts this pipeline produced
for three vulnerabilities that have completed coordinated disclosure and been
assigned a public CVE. They are here so you can see what the tool really generates:
the write-up, the root-cause analysis, and a working PoC, not a marketing summary.

Only findings whose CVE is public (verified PUBLISHED on the CVE registry) appear
here. Anything still in the Wordfence pipeline, and any CVE that is assigned but not
yet published, stays out until the record is public. See `AUTHORIZATION.md`.

## Published

| CVE | Plugin | Class | Auth | Notes |
|---|---|---|---|---|
| [CVE-2026-14433](https://www.cve.org/CVERecord?id=CVE-2026-14433) | Online Booking & Scheduling Calendar by vcita | Stored XSS (CWE-79) | Unauthenticated | 70k+ installs, CVSS 7.2 |
| [CVE-2026-13454](https://www.cve.org/CVERecord?id=CVE-2026-13454) | MotoPress Appointment Booking | SQL Injection (CWE-89) | Staff role | 10k+ installs, CVSS 8.8 |
| [CVE-2026-15066](https://www.cve.org/CVERecord?id=CVE-2026-15066) | Loco Translate | Stored XSS (CWE-79) | Translator role | 1M+ installs. CVE assigned, but classified out of scope for a bounty |

Each folder holds:
- `disclosure-report.md`, the report as the pipeline wrote it (lightly sanitized: a
  local test-environment IP was genericized; the Loco Translate report's internal
  triage banner was removed)
- `poc.py`, the proof-of-concept script

The PoC scripts target `target.local`, a local test install. Do not run them against
sites you do not own.
