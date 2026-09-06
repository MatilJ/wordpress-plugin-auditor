# WordPress Plugin Auditor — Project Context

## Purpose
An AI-assisted WordPress plugin vulnerability research framework, built for coordinated
disclosure through the Wordfence Bug Bounty Program (see `AUTHORIZATION.md` for a note on
adapting this to a different program). Plugins are downloaded and Semgrep-scanned via
`wp-plugin-downlauditor.py`. Manual deep audits run through the Full Audit Pipeline skill.

## First-time setup
Before anything else, copy `templates/global-CLAUDE.md.example` to `~/.claude/CLAUDE.md` (merge
it if you already have a global file) and fill in your researcher tier. The skills below read
their scope/eligibility/severity policy from that global file, not from anything in this repo —
see the header comment in the template for why. Then see the root `README.md` for the full
environment setup (Python deps, Docker, Semgrep login, building your own plugin database).

## Authorization
All audits here are **authorized** security research — defensive, coordinated-disclosure work
with local-only testing. See `AUTHORIZATION.md` in this directory for the full authorization
basis, scope, and responsible-disclosure terms (written as a Wordfence-program worked example;
adapt it if you're using a different program).

## Directory layout

```
wordpress-plugin-auditor/
├── plugins/<slug>/<version>/         ← plugin source (extracted zip, gitignored — you populate this);
│                                        semgrep-scan/ = auto Semgrep output (JSON/SARIF/TXT)
├── audit/<slug>/<version>/           ← all manual audit output for that slug+version (gitignored):
│   ├── pipeline-state.md             ← progress tracking (resume support)
│   ├── audit-context.md              ← architectural context (Stage 1)
│   ├── findings.md                   ← confirmed findings (incremental)
│   ├── auth-model.md                 ← auth/nonce/role facts (written by the Foundation phase; verdicts filled by Access-Control analysis)
│   ├── foundation.md                 ← custom-sink / wrapper inventory (Foundation phase)
│   ├── checkpoint-foundation.md      ← Foundation checkpoint
│   ├── checkpoint-group-{ab,ac,a,sqli,c,d1}.md   ← per-tier-group checkpoints
│   ├── leads-forward.md              ← cross-group lead forwarding (append-only)
│   ├── grep/                         ← tier-segmented grep results: foundation-results.md + surface-results.md + group-{ab,ac,a,sqli,c,d1}-results.md (from grep_scan.py)
│   ├── semgrep/                      ← tier-filtered coords (from extract_semgrep_coords.py): semgrep-coordinates.txt + semgrep-group-{ab,ac,a,sqli,c,d1}.md + semgrep-unclassified.md
│   ├── reports/                      ← disclosure reports (.md)
│   └── poc/                          ← exploit scripts (.py)
├── semgrep_rules/                    ← custom Semgrep rules (this repo's detection corpus)
├── .claude/skills/                   ← the skills themselves (auto-discovered — no install step)
├── templates/                        ← global-CLAUDE.md.example (your researcher-policy profile)
├── wp-core/<version>/                  ← WP Core source (gitignored — download per wp-core/VERSIONS.md)
├── grep_scan.py                      ← native grep scanner
├── extract_semgrep_coords.py         ← Semgrep coordinate extractor + tier filtering
├── wp-core-reference.md              ← verified WP Core security function reference
└── wp-plugin-downlauditor.py         ← download + auto-scan script
```

## Triggering an audit

Say: `Audit <plugin-slug> with Full Audit Pipeline`

The pipeline skill resolves the latest downloaded version automatically.
All output is written to `./audit/<plugin-slug>/<version>/`.

## Pipeline architecture

The pipeline is split into **Phase 1** (Stages 0–2: analysis) and **Phase 2** (Stages 3–6: reporting/validation). Phase 2 spawns as a fresh sub-agent to avoid compaction-related quality loss.

**Grep scanning** runs as a native Python script (`grep_scan.py`) — deterministic, no token limits, no context window risk. **Semgrep extraction** runs via `extract_semgrep_coords.py` — coordinates are written to disk in tier-filtered files, never pasted inline into spawn prompts.

Vulnerability analysis splits into a Foundation phase + 6 tier groups + 1 chaining pass, each running as an independent sub-agent with a fresh context window. Each group loads only the shared vuln-audit core plus its group-specific methodology file. Those files are size-budgeted to keep the per-group context load bounded; the per-file token budgets and per-list caps are defined and enforced by `skill_size_report.py` (see `FILE_BUDGETS` / `LIST_CAPS` in that script for current values) and maintained by `tune-vuln-audit` (which routes new detection to Semgrep/grep sinks before prose — see its Phase 4a):

- **Foundation** (runs first): builds `auth-model.md` (auth facts) + `foundation.md` (custom-sink inventory) read by every later group; confirms no findings
- **Group AB** (early — runs first after Foundation): Authentication Bypass (CWE-287/288)
- **Group AC** (early; Tier 4/4B + Tier 11): Access Control — missing authorization, IDOR, CSRF; fills the auth-model verdict columns
- **Group A** (Tier 1-2): RCE, file upload, file read/write/delete
- **Group SQLi** (Tier 3): SQL injection
- **Group C** (Tier 5-6): HTML renderers, XSS (stored + reflected)
- **Group D1** (Tier 8-10): SSRF, email injection, information disclosure
- **Chain**: Cross-tier chaining analysis with ALL findings loaded (also absorbs the former Group adv methodology — race conditions and adversarial reasoning; its draft-status query patterns moved into Group AC)

Each group reads only its tier-aligned grep and Semgrep files from disk,
writes findings to `findings.md` immediately on confirmation, passes a checkpoint
to the next group, and appends cross-group leads to `leads-forward.md`.
The auth model (nonce/role/capability facts) is built by the Foundation phase
before any impact group and is read by all subsequent groups (the Access-Control
analysis fills its verdict columns).

## Resuming a crashed/interrupted pipeline

If a pipeline is interrupted, re-run `Audit <slug> with Full Audit Pipeline`.
The pipeline reads `pipeline-state.md` and resumes from the last completed stage.
All findings confirmed before the crash are preserved in `findings.md`.

## Semgrep pre-audit data

When `./plugins/<slug>/<version>/semgrep-scan/` contains output files, the
pipeline runs `extract_semgrep_coords.py` to write tier-filtered coordinate
files to `audit/<slug>/<version>/semgrep/`. Each tier-group agent reads only
its own `semgrep-group-X.md` file — Semgrep data never enters the main
pipeline agent's context window.

The raw JSON is preserved for tooling reference (tune-semgrep, DB operations)
but should NOT be read by AI agents during audits.
Semgrep hits are triaged first but do not replace the full manual audit — the
complete methodology always runs to completion (see your global CLAUDE.md).

## Variant analysis (Edge 2 leads from targets.md)

`targets.md` (generated by `daily_targets.py` / `wf_variants.py`, gitignored — it's your own
working state) hands off a `Variant-analyze <CVE> ...` prompt for each fresh Wordfence disclosure.
That prompt already ends with an explicit guardrail — keep it there when the script is touched:

**Confirming the seed CVE is research, not a submittable finding.** A variant-analysis
task always starts from a vulnerability that already has a CVE. Steps (1)-(3) — confirm
the bug, judge the fix, grep for siblings — are groundwork, not a result. Only invoke the
vuln-report / poc-generator / registry-updater skills (or the global "On confirmed
findings" steps) for a **genuinely new** bypass or unpatched sibling the patch left
untouched. If the fix is complete and no sibling exists, the correct output is a plain
summary saying so — never a disclosure report, PoC, or `vuln-registry.md` row for the
already-CVE'd vulnerability itself, even after confirming it in detail. Filing one is a
guaranteed duplicate and wastes FP/duplicate budget for no possible bounty.

## Plugin install counts (authoritative source)

The `databases/` directory (gitignored — you build this yourself; see README) holds SQLite
databases with `active_installs` values from the WordPress.org API, built by running
`wp-plugin-downlauditor.py` with different `--active-installs` thresholds. A plugin slug may
appear in multiple databases.

When auditing, the correct install count is injected automatically via a
UserPromptSubmit hook (look for the `[INSTALL-COUNT]` system message). Use that
number exactly in audit-context.md and findings.md headers.

Never guess install counts. If no `[INSTALL-COUNT]` message appears, run:
`python lookup_installs.py <slug>` to retrieve the number manually.
