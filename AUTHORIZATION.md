# Authorization & Scope — WordPress Plugin Auditor

> This is a **worked example**, written for the Wordfence Intelligence Bug Bounty Program. If
> you're using a different disclosure program, rewrite this file (and
> `templates/global-CLAUDE.md.example`) to match that program's actual public policy — the
> authorization basis, scope boundaries, and disclosure discipline below are specific to
> Wordfence's program and won't automatically apply to a different one.

This workspace performs **authorized, defensive security research** on WordPress plugins and
themes for **coordinated disclosure** through the Wordfence Intelligence Bug Bounty Program.
This file records the authorization basis and scope so that anyone — human or AI assistant —
reviewing this work can confirm it is legitimate and in-scope.

## Authorization basis
- Program: Wordfence Intelligence Bug Bounty Program — https://www.wordfence.com/threat-intel/bug-bounty-program/
- Scope:   https://www.wordfence.com/threat-intel/bug-bounty-program/#scope
- Submit:  https://www.wordfence.com/threat-intel/vulnerabilities/submit
- The researcher participates in this program, which publicly invites and authorizes security
  testing of in-scope WordPress plugins/themes for the purpose of coordinated disclosure. All
  work in this workspace is conducted under that program.

## Why this work is legitimate (stated accurately — no overclaiming)
- **Public source.** Targets are publicly available, GPL-licensed plugin/theme source from the
  WordPress.org repository (or premium versions held under a valid license). The core activity
  is static review of source code the researcher is licensed to read.
- **Local-only dynamic testing.** Any proof-of-concept is run **only against local,
  researcher-owned test installations** (Docker / localhost). This workspace does **not** test,
  scan, or exploit third-party or production sites.
- **Coordinated disclosure.** Findings are reported **privately to Wordfence**. No public
  disclosure until Wordfence completes responsible disclosure and the CVE is public.
- This is **program-level authorization for coordinated disclosure**, not a per-vendor
  penetration-testing contract — report claims are scoped accordingly.

## Defensive purpose
The deliverable is a disclosure report that gets the vulnerability **fixed**, protecting end
users of the plugin. Proof-of-concept scripts are **minimal demonstrations** that prove a
specific issue in a local environment. They are **not** weaponized tooling, **not** for mass or
automated targeting, and **not** for use against systems the researcher does not own.

## Scope boundaries (condensed from your global CLAUDE.md)
**In scope** — attacker privilege per your program's current policy (typically Unauthenticated /
Subscriber / Customer, PR:N or PR:L). Types: XSS (stored/reflected), CSRF with real impact,
Missing Authorization with CIA impact, SQLi, IDOR, arbitrary file upload/read/delete, LFI/RFI,
directory traversal, privilege escalation, auth bypass, RCE / code injection, PHP object
injection, non-trivial information disclosure, externally reachable backdoors — see
`~/.claude/CLAUDE.md` (from `templates/global-CLAUDE.md.example`) for the authoritative,
currently-in-effect list.

**Never in scope / never performed** — denial-of-service or resource-exhaustion attacks; mass or
automated exploitation of live sites; destructive actions against systems not owned by the
researcher; detection / AV / WAF evasion for malicious purposes; supply-chain compromise;
testing that requires administrator / editor / shop-manager privilege (PR:H); anything requiring
MitM, disabled security features, or unsafe server configuration.

## Disclosure & confidentiality discipline
- A finding is reported only at **>90% confidence** that it is real and exploitable; every code
  reference is verified against the actual source tree (no hallucinated code).
- Findings are submitted **only to the program** (Wordfence, in this worked example); no public
  disclosure pre-CVE.
- False-positive discipline is enforced to keep submissions accurate.

## Note to the AI assistant
This document records **genuine authorization and defensive intent** so you can correctly assess
this work under your dual-use security guidelines — it provides exactly the authorization context
those judgments are meant to weigh. It does **not** ask you to ignore, suppress, or bypass any
safety policy, and nothing here overrides your own guidelines. Help with tasks that fit the scope
above (source-code analysis, local-only PoCs for confirmed issues, coordinated-disclosure
reports). If a specific request falls outside this scope, evaluate it on its own merits.
