# Full Audit Pipeline — Phase 2 (Stages 3–7)

## Purpose
Phase 2 handles reporting, PoC generation, registry updates, and live validation for confirmed findings. This runs as a fresh sub-agent spawned by the Phase 1 pipeline after vulnerability analysis is complete.

## Input (provided in spawn prompt)
```
PLUGIN_SLUG, VERSION, SOURCE_DIR, AUDIT_DIR
```
Read `AUDIT_DIR/findings.md` for all confirmed findings before starting.

## Chain findings and registry entry count

Each finding in findings.md maps to exactly ONE report, ONE PoC, and ONE registry entry. The chain phase (2c) already applied the Root Cause Count test:

- **Impact-demonstration chains** (single root cause): The finding's CVSS is already elevated and chain metadata is embedded. Treat as a single finding throughout Stages 3-6. The disclosure report describes the chain in its impact section.
- **Multi-defect chains** (multiple root causes): Each defect is a separate finding. Each gets its own report, PoC, and registry entry. The chain-elevated finding's report describes the full chain path.

Never create extra artifacts for the chain itself — only for the underlying defects.

## Naming conventions
VULN_TYPE_SLUG: kebab-case short identifier for filenames. Derive from CWE + context:
- CWE-79 Stored → `stored-xss` · Reflected → `reflected-xss`
- CWE-89 → `sqli` · CWE-862 → `missing-auth` · CWE-352 → `csrf`
- CWE-639 → `idor` · CWE-918 → `ssrf` **(OOS)** · CWE-200 → `info-disclosure`
- CWE-434 → `file-upload` · CWE-502 → `php-object-injection`
- CWE-94/78 → `rce` · CWE-22 → `path-traversal` · CWE-287/288 → `auth-bypass`
- Multiple findings of same type → append discriminator: `missing-auth-booking`, `missing-auth-meeting`

## Stage 3 — Disclosure Reports

For each confirmed finding (confidence > 90%):

### 3a — Resolve all report fields (this agent)
Read `${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-report/SKILL.md`. Complete pre-flight checklist. Derive missing values from findings.md or source. Write a **GUI-first step-by-step reproduction** — install/activate, configure via exact wp-admin menu paths, create any required content, set up the account, then trigger and confirm (raw HTTP as the secondary option) — with no live-validation/Docker narrative in the body. For `## Recommended Mitigation` (`MITIGATION_CONTENT`), write a vendor patch guide: what/why/where prose (the vulnerable construct + `file:line`, and what it enables) followed by a before→after corrected-code block (the exact capability check, escaper/sanitizer, prepared statement, or ownership/nonce check to add). Do NOT leave any field unresolved.

### 3b — Write report file (Haiku sub-agent)

```
Spawn Agent:
  description: "Report formatter — [slug]-[vuln-type]"
  model: haiku
  subagent_type: general-purpose
  prompt: |
    Read and follow exactly:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/report-formatter/SKILL.md

    OUTPUT_PATH: [AUDIT_DIR]/reports/[plugin-slug]-[vuln-type]-disclosure.md

    SOFTWARE_TYPE:        [WordPress Plugin / WordPress Theme]
    SOFTWARE_NAME:        [full display name]
    SOFTWARE_SLUG:        [wordpress.org slug]
    AFFECTED_VERSIONS:    [e.g. <= 2.4.1]
    VULN_DESCRIPTION:     [1-2 sentence description]
    VULN_TYPE:            [e.g. Stored Cross-Site Scripting (XSS)]
    CWE:                  [e.g. CWE-79]
    AUTH_LEVEL:           [Unauthenticated / Subscriber / Customer]
    AFFECTED_CODE_REFS:   [SVN/Trac URLs to vulnerable files and lines]
    POC_TYPE:             [Python / PHP / JavaScript / HTML / Other / Text]
    POC_CONTENT:          [GUI-first step-by-step — install/activate, exact Settings menu-path config, required content creation, account setup — THEN raw HTTP trigger + exact payloads. No live-validation/Docker narrative.]
    ENVIRONMENT_DETAILS:  [WP, PHP, MySQL, plugin version (incl. versions verified against), settings — accurate plain values, no Docker narrative]
    CVSS_SCORE:           [e.g. 7.2]
    CVSS_VECTOR:          [e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N]
    ACTIVE_INSTALLS:      [e.g. 10,000+]
    MITIGATION_CONTENT:   [vendor patch guide — what/why/where prose + before→after corrected-code block referencing vulnerable file:line; no update/WAF/site-operator advice]
```

Multiple findings → spawn sub-agents in parallel (max 3 concurrent; if more than 3 findings, batch in groups of 3 and wait for each batch to complete).
Update `AUDIT_DIR/pipeline-state.md`: `Stage 3: COMPLETE (<timestamp>) — N report(s)`
`[PIPELINE] Stage 3 complete — N report(s) written to AUDIT_DIR/reports/`

## Stage 4 — PoC Scripts

For each report from Stage 3:

### 4a — Write exploit logic (this agent)
Read `${CLAUDE_PROJECT_DIR}/.claude/skills/poc-generator/SKILL.md`. Determine: endpoint, auth requirements, nonce acquisition, `detect()` body, `exploit()` body, extra CLI flags, usage examples.

### 4b — Write PoC file (Haiku sub-agent)

```
Spawn Agent:
  description: "PoC writer — [slug]-[vuln-type]"
  model: haiku
  subagent_type: general-purpose
  prompt: |
    Read and follow exactly:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/poc-writer/SKILL.md

    OUTPUT_PATH:     [AUDIT_DIR]/poc/[plugin-slug]-[vuln-type]-poc.py
    PLUGIN_NAME:     [full display name]
    PLUGIN_VERSION:  [e.g. <= 2.4.1]
    CVE:             [CVE-ID or "Pending"]
    CVSS_SCORE:      [score]
    CVSS_VECTOR:     [vector string]
    VULN_TYPE:       [type]
    AFFECTED_FILE:   [file.php, line N]
    AUTH_REQUIRED:   [Unauthenticated / Subscriber / Customer]
    VULN_DESCRIPTION: [one paragraph]
    IMPACT:          [one sentence]
    USAGE_DETECT:    python poc.py --url https://target.local --detect --insecure
    USAGE_EXPLOIT:   python poc.py --url https://target.local [--username sub --password pass] --insecure
    EXTRA_CLI_FLAGS: [argparse add_argument lines, or "none"]
    DETECT_FUNCTION: [complete Python function body, 4-space indent]
    EXPLOIT_FUNCTION: [complete Python function body, 4-space indent]
    AUTH_BLOCK:      [UNAUTHENTICATED or AUTHENTICATED]
```

Multiple PoCs → spawn sub-agents in parallel (max 3 concurrent; batch if more).
Update `AUDIT_DIR/pipeline-state.md`: `Stage 4: COMPLETE (<timestamp>) — N PoC(s)`
`[PIPELINE] Stage 4 complete — N PoC script(s) written to AUDIT_DIR/poc/`

## Stage 5 — Registry Update

### 5a — Compute Vuln Type and Estimated Bounty

Before spawning the registry-updater, compute VULN_TYPE and EST_BOUNTY for each confirmed finding.

Read `${CLAUDE_PROJECT_DIR}/bounty_calculator_config.json`.

**VULN_TYPE** — Map each finding's CWE + summary context to the matching `vulnerability_types[key].description`:

| CWE | Context | Config key |
|---|---|---|
| CWE-79 + "Stored" | | `stored_xss` |
| CWE-79 + "Reflected" | | `reflected_xss` |
| CWE-352 | | `csrf` |
| CWE-862 (general) | | `missing_authorization` |
| CWE-862 + arbitrary options | | `arbitrary_options_update` |
| CWE-89 | | `sql_injection` |
| CWE-639 | | `insecure_direct_object_reference` |
| CWE-918 | | `ssrf` **(OOS — current program policy)** |
| CWE-200 (sensitive) | | `information_disclosure` |
| CWE-200 (basic) | | `basic_information_disclosure` |
| CWE-434 | | `arbitrary_file_upload` |
| CWE-915 | arbitrary settings | `arbitrary_options_update` |
| CWE-345 | webhook/verification | `missing_authorization` |
| CWE-502 | | `php_object_injection` |
| CWE-94/CWE-78 | | `rce` |
| CWE-22 | | `directory_traversal` |
| CWE-269 + admin | | `privilege_escalation_admin` |
| CWE-269 + non-admin | | `privilege_escalation_non_admin` |

Use the config's `description` field as the VULN_TYPE value (e.g., "Stored Cross-Site Scripting").

**EST_BOUNTY** — Compute bounty range (impact unknown → show low-to-critical range):

Auth mapping: Unauthenticated→`none`, Subscriber/Subscriber+/Customer→`low`, Contributor/Author→`mid` (OOS — maps to null/ineligible, same as high), Editor/Admin→`high`

```
base      = vulnerability_types[key].value
divisor   = authentication_levels[auth_key].divisor
inst_mult = install_count_tiers[matching_tier].multiplier

If divisor is null (high): EST_BOUNTY = "Ineligible"
If inst_mult is 0 (< 25 installs): EST_BOUNTY = "$0"

low_est  = floor(base / divisor * inst_mult * 0.25)
high_est = floor(base / divisor * inst_mult * 1.0)

Each estimate: max(estimate, 5) if estimate > 0
Format: "$X - $Y"
If low_est == high_est: "$X"
```

### 5b — Spawn Registry Updater

Spawn a single Haiku sub-agent:

```
Spawn Agent:
  description: "Registry update — [PLUGIN_SLUG]"
  model: haiku
  subagent_type: general-purpose
  prompt: |
    Read and follow exactly:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/registry-updater/SKILL.md

    REGISTRY_PATH: ${CLAUDE_PROJECT_DIR}/vuln-registry.md

    One FINDING block per finding in findings.md (1:1 mapping).
    Chain-elevated findings use their elevated CVSS and chain-aware SUMMARY.
    Do not create separate chain entries beyond the underlying findings.

    FINDING_1:
      DATE:       [YYYY-MM-DD]
      PROJECT:    [PLUGIN_SLUG/VERSION]
      SLUG:       [wordpress.org slug]
      INSTALLS:   [active install count]
      AUTH:       [Unauthenticated / Subscriber / Customer]
      VULN_TYPE:  [e.g. Stored Cross-Site Scripting]
      CWE:        [e.g. CWE-79]
      CVSS:       [e.g. 7.2]
      SUMMARY:    [one-line description]
      EST_BOUNTY: [e.g. $120 - $480]
      STATUS:     Ready to submit - Pending validation
    [FINDING_2, etc.]
```

Update `AUDIT_DIR/pipeline-state.md`: `Stage 5: COMPLETE (<timestamp>)`
`[PIPELINE] Stage 5 complete — registry updated.`

**MANDATORY CONTINUATION:** Proceed immediately to Stage 6.

## Stage 6 — Live Validation

Validate all confirmed findings by spinning up a Docker WordPress environment, executing PoC scripts, and updating artifacts with live test results.

### 6a — Gate check and lock acquisition

**Pre-conditions (all must pass):**
- `AUDIT_DIR/findings.md` has at least one CONFIRMED finding
- `AUDIT_DIR/poc/` contains at least one `.py` file
- `AUDIT_DIR/reports/` contains at least one `.md` file
- Docker daemon is running (see below)

**Docker daemon check and auto-start (Windows):**
1. Run `docker compose version` to test if Docker is available.
2. If it fails (Docker daemon not running), attempt to start Docker Desktop:
   ```powershell
   Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
   ```
   If that path doesn't exist, try:
   ```powershell
   Start-Process "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
   ```
3. After starting, poll `docker info` every 15 seconds, up to 120 seconds:
   ```powershell
   $timeout = 120; $elapsed = 0
   while ($elapsed -lt $timeout) { docker info 2>$null; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep 15; $elapsed += 15 }
   ```
4. If Docker is responsive → continue. If still not responsive after 120s → `[PIPELINE] Stage 6 skipped — Docker Desktop failed to start within 120s. Pipeline complete without validation.` and stop.

Any other pre-condition failure → `[PIPELINE] Stage 6 skipped — <reason>. Pipeline complete without validation.` and stop.

**Proprietary/paid dependency check (distinct from lock-timeout/Docker-unavailable):**
If the plugin under test hard-requires a proprietary, paid, or otherwise non-obtainable
companion plugin to initialize at all (e.g. a free "Extended"/"Addon" plugin whose bootstrap
gate checks for a constant/class only the PAID base plugin defines — confirmed by an actual
fatal-error stack trace during setup, not assumed from a readme), and no licensed copy is
available in this environment or from the researcher:
1. Do NOT attempt to fabricate the dependency's classes/constants to force a pass — this
   would validate against code that doesn't represent genuine plugin behavior.
2. Tear down Docker and release the lock as normal (6f).
3. Set `vuln-registry.md` status to `Blocked - requires <dependency name> (proprietary,
   unavailable; cannot reproduce/record for Wordfence submission)` for every affected
   finding — **NOT** `Ready to submit - Pending validation`. The distinction matters:
   "Pending validation" implies routine follow-up (just re-run live-validation later);
   a paid-dependency block may never resolve on its own, and Wordfence submission requires
   the researcher to personally reproduce and record the vulnerability — static-analysis
   confidence alone, however high, does not substitute for that. A finding stuck behind an
   unobtainable paid dependency is not currently submittable and should not be labeled as if
   it's simply next in queue.
4. Note in `findings.md` under the finding(s): what dependency is missing, how the gate was
   confirmed (exact error/stack trace), and that the block is a reproduction/tooling
   limitation, not a confidence problem with the finding itself.
5. Print `[PIPELINE] Stage 6 blocked — <dependency> unavailable. N finding(s) marked Blocked in registry (not Pending validation).` and stop.

**Lock acquisition (via lock_manager.py):**
Lock file: `.\live-validation.lock` (project root). Managed by `lock_manager.py` — do NOT manipulate the lock file directly.

1. Try to acquire the lock:
   ```powershell
   python lock_manager.py acquire <PLUGIN_SLUG>
   ```

2. **Exit code 0** → lock acquired. Parse JSON output and save `SESSION_ID`:
   ```powershell
   $lockResult = python lock_manager.py acquire <PLUGIN_SLUG> | ConvertFrom-Json
   $SESSION_ID = $lockResult.session_id
   ```
   Print: `[PIPELINE] Stage 6a complete — lock acquired (session: <SESSION_ID>).`

3. **Exit code 1** → lock is held by another session. Wait with timeout:
   ```powershell
   $lockResult = python lock_manager.py wait <PLUGIN_SLUG> --timeout 3600 --interval 90
   ```
   The script prints periodic JSON status lines while waiting. Parse the LAST line for the result.
   - If final status is `"acquired"` → save `SESSION_ID` from that line. Proceed.
   - If final status is `"timeout"` → skip validation, update findings.md with `**Validation:** Skipped (lock timeout)`. Do NOT update vuln-registry.md status — leave as `Ready to submit - Pending validation`. Print `[PIPELINE] Pipeline complete without live validation (lock timeout). Registry status left as "Pending validation" — run live-validation standalone to complete.` and stop.

**Heartbeat during validation (mandatory):**
After acquiring the lock and before each major operation (Docker up, each PoC execution, cleanup start), run:
```powershell
python lock_manager.py heartbeat <SESSION_ID>
```
If exit code 1 → lock was broken by another session that detected this session as stale. **STOP validation immediately.** Do NOT continue modifying the Docker environment. Print: `[PIPELINE] Stage 6 aborted — lock lost (detected as stale by another session).` and stop.

`[PIPELINE] Stage 6a complete — lock acquired (session: <SESSION_ID>).`

### 6b–6d — Environment setup, plugin configuration, PoC execution

**Follow the live-validation skill for these stages.** Read:
`${CLAUDE_PROJECT_DIR}/.claude/skills/live-validation/skill.md`.

Execute live-validation Stages 2–4 with these pipeline-specific overrides:
- **Skip user prompts:** Pipeline mode — tear down existing containers without asking (`docker compose down -v` first).
- **Skip source verification (Stage 1):** Pipeline already verified code in Stages 2–5.
- **Templates already deployed** if reusing environment; if fresh setup, deploy in Stage 2d per live-validation instructions.
- **Credentials:** admin/admin123, editor/editor123, author/author123, contributor/contributor123, subscriber/subscriber123.
- **Compose file:** `compose.yaml` in project root.
- **MANDATORY:** Execute `AUDIT_DIR/poc/*.py` scripts (both `--detect` and exploit modes). Never use ad-hoc scripts. If PoC fails, fix it in-place and re-run. Finding is PASS only when its deliverable PoC succeeds.
- **PoC success criteria:** `--detect` mode: exit code 0 AND stdout contains `VULNERABLE` or `DETECTED`. Exploit mode: exit code 0 AND stdout contains `SUCCESS` or `EXPLOITED`. Any non-zero exit code or `NOT VULNERABLE`/`FAILED` in stdout = FAIL. These strings are standardized by the poc-writer template.
- **GUI Setup Verification (live-validation Stage 3h):** best-effort only in pipeline mode — if claude-in-chrome / a connected browser is unavailable, skip silently. Never prompt, never block Stage 4.

For each finding, the live-validation skill covers: Docker setup → template deployment → plugin copy + activation → environment verification → plugin configuration → smoke test → contract reconciliation → GUI setup verification → PoC execution (detect then exploit) → database verification → diagnosis on failure (reference `live-validation-reference.md` Section 4).

After PoC execution completes for all findings:
```
[PIPELINE] Stage 6d complete.
  Finding 1: <PASS/FAIL> — <brief result>
```

### 6e — Artifact updates

Update only validation-specific fields (pipeline already wrote full artifacts in Stages 2–5).

**For each PASSED finding:**
1. **findings.md** — change `CONFIRMED` → `CONFIRMED — LIVE VALIDATED`. Insert: `**Live Test:** <YYYY-MM-DD> — WordPress <ver>, PHP <ver>, MariaDB (Docker). <1-line result>.`
2. **vuln-registry.md** — `Ready to submit - Pending validation` → `Ready to submit - Validated: live-validation`
3. **PoC scripts** — edit only if execution revealed bugs. Syntax check after edits:
   ```powershell
   python -c "import ast; ast.parse(open(r'AUDIT_DIR/poc/<script>.py').read()); print('Syntax OK')"
   ```
4. **Reports** — edit the body only for factual corrections (auth level, environment versions incl. versions verified against, reproduction steps, line numbers, and any GUI Setup menu path/tab/field/button label corrected during live-validation Stage 3h). Any live-validation or GUI-verification stamp goes into the report's `## Internal Metadata (not submitted)` table (e.g. a `Live Validation` or `GUI Setup Verified (claude-in-chrome)` row) and into findings.md — NEVER into the main body. The `**Live Test:** … (Docker)` line stays in findings.md only.

**For each FAILED finding:**
1. **findings.md** — `CONFIRMED` → `REJECTED (live test)`. Add failure explanation.
2. **vuln-registry.md** — `Ready to submit - Pending validation` → `Rejected - live-validation`.
3. Do NOT delete report/PoC files — mark as rejected in-place.

**Correction scope during validation:**
- **Auth level:** update if live testing proves a different minimum role (e.g., finding says Subscriber but Subscriber gets 403, Contributor succeeds → correct to Contributor). Update findings.md, reports, vuln-registry.md, and recalculate CVSS.
- **CWE/CVSS:** update ONLY if the live test demonstrates a factual error (e.g., finding says CWE-862 but live test proves it's CWE-639 because ownership check exists but is bypassable). Do NOT change CVSS based on subjective reassessment.
- **Reproduction steps:** update if additional required steps are found — write them as neutral prerequisites in the report body (e.g., "the X setting must be enabled first"), not as "live testing revealed…".

### 6f — Release lock and cleanup

1. **Release lock (mandatory, even on failure):**
   ```powershell
   python lock_manager.py release <SESSION_ID>
   ```

2. **Tear down Docker environment:**
   ```powershell
   docker compose down -v
   ```

3. Update `AUDIT_DIR/pipeline-state.md`: `Stage 6: COMPLETE (<timestamp>) — N validated, M rejected`

Print:
```
[PIPELINE] Pipeline complete.
  Findings: N confirmed
  Validated: M passed, K rejected
  Reports: AUDIT_DIR/reports/
  PoCs: AUDIT_DIR/poc/
```

## Stage 7 — Pattern accumulator refresh (post-validation)

After Stage 6 updates statuses, re-ingest this audit so the cross-audit DB reflects the FINAL outcomes (`LIVE VALIDATED` / `REJECTED (live test)`) rather than the pre-validation snapshot taken at Phase-1 Stage 2d. From the project root:
```powershell
python pattern_accumulator.py ingest "AUDIT_DIR"
```
(`AUDIT_DIR` = the full `audit/<slug>/<version>/` path.)

- **Idempotent** (upserts): overwrites the Stage 2d snapshot for this audit with the validated statuses.
- **Run it after Stage 6e.** If Stage 6 was skipped or aborted before any status was updated (Docker unavailable, lock timeout, lock lost), the Stage 2d ingest already captured this audit as-is — Stage 7 is then a no-op you may skip.
- **Non-fatal:** on non-zero exit, print `[PIPELINE] Stage 7 — pattern-DB refresh failed: <stderr>` and finish anyway. A measurement-tool failure must never fail the audit.

Update `AUDIT_DIR/pipeline-state.md`: `Stage 7: COMPLETE (<timestamp>) — pattern_accumulator.db refreshed`
Print: `[PIPELINE] Stage 7 complete — pattern_accumulator.db refreshed with validated statuses.`

Return: `[PHASE-2] Complete. Reports: N, PoCs: N, Validated: M, Pattern-DB: refreshed.`
