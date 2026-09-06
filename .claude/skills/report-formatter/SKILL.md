# Skill: Report Formatter (Sub-agent)

## Purpose
Write a Wordfence disclosure report Markdown file by filling caller-provided values into template. No analysis — formatting and file writing only.

Invoked as sub-agent (model: haiku) after main agent finalizes finding details.

## Input (provided in spawn prompt)

All required. If omitted, write `[MISSING — DO NOT SUBMIT]`.

```
OUTPUT_PATH:          [AUDIT_DIR]/reports/[slug]-[vuln-type]-disclosure.md
SOFTWARE_TYPE:        [WordPress Plugin / WordPress Theme / WordPress Core]
SOFTWARE_NAME:        [Full display name]
SOFTWARE_SLUG:        [e.g. contact-form-7]
AFFECTED_VERSIONS:    [e.g. <= 5.8.7]
VULN_DESCRIPTION:     [1-2 sentence factual description]
VULN_TYPE:            [e.g. Stored Cross-Site Scripting (XSS)]
IMPACT_STATEMENT:     [One sentence, max 200 chars, e.g. "Unauthenticated users can upload image files."]
CWE:                  [e.g. CWE-79]
AUTH_LEVEL:           [Unauthenticated / Subscriber / Customer / Contributor]
AFFECTED_CODE_REFS:   [One Trac URL per line]
POC_TYPE:             [Python / PHP / JavaScript / HTML / Other / Text instructions]
POC_CONTENT:          [GUI-first step-by-step working concept — install/activate, exact Settings menu-path config, required content creation, account setup, then trigger + confirm (raw HTTP as secondary). No live-validation/Docker narrative.]
MITIGATION_CONTENT:   [vendor patch guide — what/why/where prose + a before→after corrected-code block referencing the vulnerable file:line; no update/defense-in-depth/WAF/interim-patch/site-operator advice, no boilerplate]
ENVIRONMENT_DETAILS:  [WP, PHP, MySQL versions (incl. versions verified against) + settings — accurate plain values, no Docker/localhost narrative]
CVSS_SCORE:           [e.g. 7.2]
CVSS_VECTOR:          [e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N]
ACTIVE_INSTALLS:      [e.g. 10,000+]
```

**Passthrough discipline:** substitute values verbatim — do not add analysis or wording. The main body (through `## All environment, setting, and configuration details`) must carry no live-validation / Docker narrative; any validation stamp belongs only in the `## Internal Metadata (not submitted)` table, which the live-validation stage may later extend with extra rows.

## Task

1. Read all input fields from spawn prompt
2. Substitute into template below
3. Write to `OUTPUT_PATH` (create parent dirs if needed)
4. Print: `[report-formatter] Written: OUTPUT_PATH`

## Template

```markdown
# Vulnerability Disclosure — {{SOFTWARE_NAME}}

## Type Of Software
{{SOFTWARE_TYPE}}

## Software Name
{{SOFTWARE_NAME}}

## Software Slug
{{SOFTWARE_SLUG}}

## Affected Version(s)
{{AFFECTED_VERSIONS}}

## Description of Vulnerability
{{VULN_DESCRIPTION}}

## Vulnerability Type
{{VULN_TYPE}}

## Impact Statement
{{IMPACT_STATEMENT}}

## Common Weakness (CWE) Type
{{CWE}}

## Authentication Level Required
{{AUTH_LEVEL}}

## References to Affected Code
{{AFFECTED_CODE_REFS}}

## What is your Proof of Concept?
{{POC_TYPE}}

## Provide a working concept
{{POC_CONTENT}}

## Recommended Mitigation
{{MITIGATION_CONTENT}}

## All environment, setting, and configuration details
{{ENVIRONMENT_DETAILS}}

---

## Internal Metadata (not submitted to Wordfence)

| Field | Value |
|---|---|
| CVSS Score | {{CVSS_SCORE}} |
| CVSS Vector | {{CVSS_VECTOR}} |
| Active Installations | {{ACTIVE_INSTALLS}} |
| CVSS Calculator | https://www.first.org/cvss/calculator/3.1 |
```
