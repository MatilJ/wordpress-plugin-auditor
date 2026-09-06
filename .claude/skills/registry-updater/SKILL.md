# Skill: Registry Updater (Sub-agent)

## Purpose
Append one row per finding to the global vulnerability registry. No analysis — read, append, write only.

Invoked as sub-agent (model: haiku) after all reports and PoCs written.

## Input (provided in spawn prompt)

One block per finding. Repeat for multiple.

```
REGISTRY_PATH: ${CLAUDE_PROJECT_DIR}/vuln-registry.md

FINDING_1:
  DATE:        [YYYY-MM-DD]
  PROJECT:     [Project folder name]
  SLUG:        [WordPress.org slug]
  INSTALLS:    [e.g. 50,000+]
  AUTH:        [Unauthenticated / Subscriber / Customer / Contributor / Author]
  VULN_TYPE:   [e.g. Stored Cross-Site Scripting]
  CWE:         [e.g. CWE-79]
  CVSS:        [e.g. 7.2]
  SUMMARY:     [One-line description]
  EST_BOUNTY:  [e.g. $120 - $480]
  STATUS:      [Ready to submit]
```

## Task

1. Read `REGISTRY_PATH`
2. For each FINDING, check for duplicates: scan existing rows for matching SLUG + CWE (case-insensitive). If a match exists with the same SUMMARY (substring match):
   - SKIP that row. Print: `[registry-updater] SKIP: duplicate for [SLUG] [CWE] — already in registry`
   - If existing row has a DIFFERENT status, also print: `[registry-updater] WARN: [SLUG] [CWE] exists with status "[STATUS]"`
3. For non-duplicate findings, construct row: `| DATE | PROJECT | SLUG | INSTALLS | AUTH | VULN_TYPE | CWE | CVSS | SUMMARY | EST_BOUNTY | STATUS |`
4. Find last `|`-delimited row. Append new row(s) after it.
   - If no table exists, prepend header:
     ```
     | Date | Project | Plugin Slug | Installs | Auth Required | Vuln Type | CWE | CVSS | Summary | Estimated Bounty | Status |
     |---|---|---|---|---|---|---|---|---|---|---|
     ```
5. Write updated file
6. Print: `[registry-updater] Appended N row(s), skipped M duplicate(s)`

## Rules

- Do not modify existing rows
- Do not reformat table
- If file doesn't exist, create with header + new rows
- Convert date to `YYYY-MM-DD` if different format provided
