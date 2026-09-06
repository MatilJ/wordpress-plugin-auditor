# Skill: Full Audit Pipeline — Phase 1 (Stages 0–2)

## Purpose
Orchestrate the complete vulnerability research workflow for a single WordPress plugin or theme. Phase 1 covers Stages 0–2 (path resolution, context building, Semgrep intake, grep scan, vulnerability analysis, chaining). When findings exist, Phase 1 spawns a Phase 2 sub-agent for Stages 3–7 (reports, PoCs, registry, live validation, pattern-DB refresh).

## Scope & Authorization
Authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive,
coordinated-disclosure work on publicly available plugin source, tested only on local installs.
See `AUTHORIZATION.md` in the project root. The analysis spawn prompts below each carry a
one-line authorization note so every fresh sub-agent inherits this context (the Stage 1
context-builder spawn is intentionally left neutral to preserve its anchoring discipline).

## Sub-agent delegation model
The grep scanner runs as a **native Python script** (deterministic, no token limits). Vulnerability analysis uses **tier-group sub-agents (model inherited from main session)** — each tier group runs in an independent context window with only its tier-specific methodology and grep data. The chaining sub-agent runs last with ALL findings loaded.

## Trigger format
```
Audit <plugin-slug> with Full Audit Pipeline
```
Extract PLUGIN_SLUG from that phrase. All stages use PLUGIN_SLUG, SOURCE_DIR, and AUDIT_DIR resolved in Stage 0.

## Pre-conditions
- Working directory is the `wordpress-plugin-auditor` project root
- `./plugins/<PLUGIN_SLUG>/` exists with at least one version directory

If either fails, stop and ask the researcher.

## Stage 0 — Path Resolution

### 0a — Resolve plugin slug and version
1. PLUGIN_SLUG = slug from trigger phrase.
2. List directories in `./plugins/<PLUGIN_SLUG>/` to find version(s).
3. VERSION = highest semantic version (sort descending).
4. No version directory → print:
   `[PIPELINE] ERROR: No version directory found in ./plugins/<PLUGIN_SLUG>/. Download the plugin first with wp-plugin-downlauditor.py.`
   Do NOT create pipeline-state.md or audit directory. Stop immediately.

### 0b — Set path variables
```
SOURCE_DIR = ${CLAUDE_PROJECT_DIR}/plugins/<PLUGIN_SLUG>/<VERSION>
AUDIT_DIR  = ${CLAUDE_PROJECT_DIR}/audit/<PLUGIN_SLUG>/<VERSION>
```
When constructing sub-agent spawn prompts, convert SOURCE_DIR and AUDIT_DIR to forward-slash format (replace all `\` with `/`). The paths above use Windows backslashes for PowerShell commands run by the main agent; sub-agents receive forward-slash paths only.

### 0c — Create audit directory structure
```bash
mkdir -p "$AUDIT_DIR/poc" "$AUDIT_DIR/reports" "$AUDIT_DIR/grep" "$AUDIT_DIR/semgrep"
```

### 0c2 — Check for resume (pipeline state tracking)
Check if `AUDIT_DIR/pipeline-state.md` exists:
- **Exists:** Read it. Identify last completed stage/group. Print: `[PIPELINE] Resuming from <last completed stage>. Skipping completed stages.` Skip to the next incomplete stage. Re-read relevant checkpoint files and audit-context.md. If `Phase 1: COMPLETE` is present, skip directly to Phase 2 spawn.
- **Does not exist:** Fresh run. Create the file:
  ```markdown
  ## Pipeline State — <PLUGIN_SLUG> v<VERSION>
  Started: <ISO timestamp>
  Stage 0: IN_PROGRESS
  ```

### 0d — Note Semgrep data availability (DO NOT READ YET)
Use `Glob(pattern: "*.md", path: SOURCE_DIR/semgrep-scan)` to check for semgrep output.
If that returns no results, try `Glob(pattern: "*.json", path: SOURCE_DIR/semgrep-scan)` as fallback.

- Any files found → `SEMGREP_AVAILABLE = yes`
- No files found (or directory does not exist) → `SEMGREP_AVAILABLE = no`

Do NOT use PowerShell Test-Path, Bash ls, or any shell command for this check — Glob is the only reliable method on Windows. If multiple JSON files found, prefer the file named `<PLUGIN_SLUG>.<VERSION>.json` (the standard output from wp-plugin-downlauditor.py). If no exact match, use the most recently modified file. Log: `[PIPELINE] Semgrep data: <filename>`.

Semgrep data is read in Stage 2a after unbiased context building. Reading it before Stage 1 causes anchoring bias.

### 0e — Print Stage 0 summary and update state
Update `AUDIT_DIR/pipeline-state.md`: `Stage 0: COMPLETE (<timestamp>)`
```
[PIPELINE] Stage 0 complete.
  Slug:        <PLUGIN_SLUG>
  Version:     <VERSION>
  Source dir:  <SOURCE_DIR>
  Audit dir:   <AUDIT_DIR>
  Semgrep:     <available / not present> (will be read in Stage 2a)
```

## Stage 1 — Audit Context Builder (sub-agent)

Stage 1 runs as an isolated sub-agent so its 30K–80K+ token output does not pollute the main pipeline context window. The main agent spawns it, waits for the completion signal, then reads only the compact Structural Summary (~500 tokens) from the output file.

```
Spawn Agent:
  description: "Audit context builder — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    You are building a pure architectural context document for a WordPress plugin.
    You are a software architect studying how the codebase works — NOT a vulnerability researcher.

    SOURCE_DIR: [SOURCE_DIR — absolute path, forward slashes]
    AUDIT_DIR:  [AUDIT_DIR — absolute path, forward slashes]

    **BEHAVIORAL CONSTRAINT — STRICTLY ENFORCED:**

    **FORBIDDEN (violations invalidate the context document):**
    - Security-loaded language: vulnerability, exploit, critical, dangerous, attack surface,
      injection, bypass, insecure, CVE, CWE, XSS, SQLi, CSRF, SSRF, RCE
    - Auth sufficiency judgments: "no capability check", "properly gated",
      "missing authorization", "nonce-only"
    - Threat framing: "accessible to attackers", "controllable by", "user-controlled",
      "exploitable"
    - Security assessments: "safe", "unsafe", "vulnerable", "secure", "protected",
      "unprotected"
    - Nonce exposure analysis (who can obtain nonces — this is threat modeling, not
      architecture)

    **REQUIRED framing — neutral structural observations only:**
    - "Handler X registers on hook Y"
      (not "Handler X is exposed to unauthenticated users")
    - "Function checks capability Z before proceeding"
      (not "properly gated with manage_options")
    - "Nonce action string A is localized via script B on hook C"
      (not "nonce exposed to Contributors")
    - "Data flows from $_POST through sanitize_text_field() into update_option()"
      (not "user-controlled input reaches option write")
    - Section headers: "AJAX Handlers", "Hook Registrations", "Data Flow Paths"
      (not "Attack Surface")

    Self-check before writing audit-context.md: Re-read every sentence. If it implies
    a security judgment, rewrite it as a structural fact. The document must read like
    an API reference, not a penetration test report.

    **Step 1 — Run the context-building skill:**
    Use the Skill tool:
      skill: "audit-context-building:audit-context-building"
      args: "[SOURCE_DIR]"

    Do NOT use skill "audit-context-building:audit-context" — it causes incorrect
    Agent spawning. Wait for all sub-agents spawned by the skill to finish.

    **Step 2 — Save context document:**
    Write or move the context document to: [AUDIT_DIR]/audit-context.md

    **Step 3 — Append Structural Summary and Entry Point Map:**
    Count from the audit-context analysis and append at the END of
    [AUDIT_DIR]/audit-context.md:

    ## Structural Summary (machine-readable)
    AJAX_HANDLERS: [N] ([M] nopriv, [K] priv)
    REST_ROUTES: [N] ([M] with __return_true, [K] with capability checks)
    CUSTOM_ROLES: [N] ([list names, note if self-registerable])
    CUSTOM_TABLES: [N] ([list names])
    FILE_OPS: [N] functions with upload/write handling
    DB_DIRECT: [N] $wpdb->query calls ([M] with prepare, [K] without)
    NONCE_ACTIONS: [N] unique actions, [M] localized on public pages
    ENTRY_POINTS_UNAUTHENTICATED: nopriv AJAX ([N]), REST __return_true ([M]),
      init hooks ([K])
    BUNDLED_LIBRARIES: [list with versions if found]

    ## Entry Point Map (compact)
    AJAX_NOPRIV: [action] → [handler] @ [file:line] | NONCE: [action_string/"none"] | CAP: [cap/"none"]
    AJAX_PRIV: [same format]
    REST: [route] → [callback] @ [file:line] | PERM_CB: [function] | CAP: [cap/"__return_true"]
    SHORTCODES: [tag] → [callback] @ [file:line]
    INIT_HOOKS: [function] @ [file:line] | READS_SUPERGLOBALS: [yes/no]
    ADMIN_INIT: [function] @ [file:line] | CAP: [cap/"none"]

    **Step 4 — Update state file:**
    Append to [AUDIT_DIR]/pipeline-state.md:
      Stage 1: COMPLETE (<ISO timestamp>)

    **Return this exact string (fill in N):**
    [STAGE-1] Complete. audit-context.md written. Structural summary appended.
    N functions analyzed.
```

Wait for the sub-agent to return the `[STAGE-1] Complete` signal. Discard the sub-agent's full response — retain only the completion signal line. All output is on disk.

**Read Structural Summary only:**
Read ONLY the `## Structural Summary (machine-readable)` section from `AUDIT_DIR/audit-context.md` (~15 lines, ~500 tokens). Do NOT read the full context document — tier-group analysis agents read it with fresh context windows.

Update `AUDIT_DIR/pipeline-state.md`: confirm `Stage 1: COMPLETE` is present (sub-agent writes it; verify it exists, add if missing).

Print: `[PIPELINE] Stage 1 complete — context built.`

**MANDATORY CONTINUATION:** Stage 1 is 1 of 6 stages. Immediately proceed to Stage 2. Do NOT stop, summarize, or wait for user input.

## Stage 2 — Vulnerability Audit

### 2a — Semgrep Lead Intake (script-based)

**Step 1: Extract Semgrep coordinates via script.**

Check for Semgrep JSON:
```powershell
python extract_semgrep_coords.py "[SOURCE_DIR]/semgrep-scan/<PLUGIN_SLUG>.<VERSION>.json" "[SOURCE_DIR]" "[AUDIT_DIR]/semgrep"
```

If no Semgrep JSON exists at that path, try `Glob(pattern: "*.json", path: SOURCE_DIR/semgrep-scan)` and use the first result. If no JSON at all, create empty placeholder files in `AUDIT_DIR/semgrep/`.

Verify output: check that `AUDIT_DIR/semgrep/semgrep-coordinates.txt` and the 7 group files exist. Do NOT read the group files into the main agent's context — each tier-group agent reads only its own.

If the script output contains `WARNING:` followed by `CRITICAL/HIGH severity unclassified`, print: `[PIPELINE] High-severity Semgrep findings could not be classified to a tier group — review AUDIT_DIR/semgrep/semgrep-unclassified.md after pipeline completes.`

Update `AUDIT_DIR/pipeline-state.md`: `Stage 2a: COMPLETE (<timestamp>)`

Per global CLAUDE.md: Semgrep hits are leads only. The full audit methodology runs to completion regardless. Findings discovered independently are equally valid.

**Step 2: Orientation.** Read plugin entry points from SOURCE_DIR:
- Main plugin `.php` file (has `Plugin Name:` header)
- `includes/`, `src/`, `classes/` directories
- `readme.txt` — confirms latest stable version

Determine: plugin name/version, PHP entry points/autoloader, bundled libraries, custom DB tables. Do not run grep commands in this step.

### 2b — Grep Scan (native script)

Run the grep scanner script:

```powershell
python grep_scan.py "[SOURCE_DIR]" "[AUDIT_DIR]/grep" --semgrep-coords "[AUDIT_DIR]/semgrep/semgrep-coordinates.txt"
```

Verify output: check that all 7 group files exist in `AUDIT_DIR/grep/` and the `GREP_SCAN_COMPLETE` summary shows expected section counts. Do not read the full grep files into context — each tier-group agent reads only its own.

Update `AUDIT_DIR/pipeline-state.md`: `Stage 2b: COMPLETE (<timestamp>)`

### 2c — Vulnerability Analysis (tier-group sub-agents, model inherited from main session)

Analysis is split into a Foundation phase + 6 tier groups + 1 chaining pass. The Foundation runs FIRST and writes `auth-model.md` + `foundation.md` (auth + custom-sink facts) read by every later group; it confirms no findings. Each runs as an independent sub-agent (model inherited from main session) with a fresh context window, loading only the shared core methodology + its group-specific methodology file + its grep data. Findings are written to `AUDIT_DIR/findings.md` incrementally by each agent.

**MANDATORY: Sequential execution.** Groups MUST run one at a time in order: Foundation → AB → AC → A → SQLi → C → D1 → Chain. Each group depends on checkpoints and leads from prior groups. NEVER spawn two groups in parallel — GroupAC reads checkpoint-group-ab.md and leads-forward.md entries written by GroupAB. Wait for each group's completion signal before spawning the next. (Group adv collapsed — its race/adversarial methodology folded into the Chain pass and its draft-status patterns into GroupAC.)

**CONTEXT PRESSURE MITIGATION — TWO RULES:**

**Rule 1 — Discard sub-agent verbosity.** After each sub-agent returns, retain ONLY its one-line completion signal (e.g. `[GROUP-A] Complete. Findings: 0 confirmed, 2 leads forwarded.`). The sub-agent's internal reasoning, tool call logs, and intermediate analysis are irrelevant to the orchestrator — all durable output is already on disk (findings.md, checkpoint files, leads-forward.md). Do NOT summarize, reflect on, or reference the sub-agent's response beyond the completion signal.

**Rule 2 — Continuation guard (compaction-safe).** After EVERY group completion + pipeline-state.md update, execute this sequence before doing anything else:
1. Write the group's completion entry to `AUDIT_DIR/pipeline-state.md`. If the write fails (tool error), retry once. If the retry also fails, print `[PIPELINE] CRITICAL: Cannot update pipeline-state.md — stopping to prevent duplicate execution. Last completed: <group>.` and STOP.
2. Re-read `AUDIT_DIR/pipeline-state.md`
3. Determine the next required step from this fixed sequence:
   `Foundation → GroupAB → GroupAC → GroupA → GroupSQLi → GroupC → GroupD1 → Chain → Stage 2d`
   Find the last `Stage 2c-Foundation: COMPLETE`, `Stage 2c-Group*: COMPLETE`, or `Stage 2c-Chain:` line. The next step in the sequence above is what you spawn next.
4. Print: `[PIPELINE] Continuation check — last completed: <X>, next: <Y>`
5. Immediately spawn/execute the next step. Do NOT summarize progress, reflect, or wait for user input.

If pipeline-state.md shows all groups + chain done, proceed to Stage 2d.

**Before spawning:** Initialize `AUDIT_DIR/findings.md` with header if it doesn't exist:
```markdown
# Vulnerability Findings — <PLUGIN_SLUG> <VERSION>
Active installs: <from [INSTALL-COUNT] message or lookup_installs.py>
Audit date: <YYYY-MM-DD>
OOS (per current program policy): Contributor/Author auth floor and SSRF (CWE-918) are out of scope.
```

Initialize `AUDIT_DIR/leads-forward.md` if it doesn't exist (the Foundation phase then seeds
the SINK LEDGER). It is the single deduplicated cross-group ledger — two sections only; see
`vuln-audit/SKILL.md` §5/§6 for the read/write/dedup rules and the `Consumed-by` contract:
```markdown
# Cross-Group Ledger — <PLUGIN_SLUG> <VERSION>

## SINK LEDGER
<!-- One deduped row per custom sink, keyed by fn@file:line. Update in place (never duplicate);
     append your group code to Consumed-by when you evaluate a sink. The Chain pass analyses
     every row whose Consumed-by is (none). Type ∈ sqli|xss|file-op|rce|ssrf|poi|other. -->
| Sink | Type | Wraps | Missing | Auth-floor | Callers | Consumed-by |
|------|------|-------|---------|-----------|---------|-------------|

## LEADS
<!-- Deduped cross-references. Read only rows tagged Relevant-to your group / Any / Chain.
### From Group [X] — [timestamp]
- LEAD: [file:line] — [description] — Relevant-to: [Group Y / Chain / Any]
-->
```

#### 2c-Foundation — Auth Model & Custom-Sink Facts

Runs FIRST, before any impact group. Writes `auth-model.md` (auth facts) and `foundation.md` (custom-sink inventory) read by every later group. Confirms NO findings.

```
Spawn Agent:
  description: "Foundation: auth model + sink facts — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are building the authorization + custom-sink FACTS for a WordPress plugin audit.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-foundation.md

    Execute Phases F1–F5. Produce FACTS only — do NOT confirm vulnerabilities, assign CVSS, or write to findings.md.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read: AUDIT_DIR/audit-context.md (Entry Point Map + Structural Summary first, then deeper as needed)
    Read: AUDIT_DIR/grep/foundation-results.md
    Read: AUDIT_DIR/grep/surface-results.md

    Write: AUDIT_DIR/auth-model.md (facts; leave the CIA Impact + Verdict columns blank for the Access-Control analysis)
    Write: AUDIT_DIR/foundation.md (custom-sink / wrapper inventory)
    Init: AUDIT_DIR/leads-forward.md as the cross-group ledger — write the "## SINK LEDGER" table header and "## LEADS" header (core SKILL.md §5), then seed the SINK LEDGER with one row per inventory sink (Consumed-by = (none))
    Write: AUDIT_DIR/checkpoint-foundation.md

    Return: "[FOUNDATION] Complete. Auth model + sink inventory written. Roles: N, nopriv entry points: M, custom sinks: K."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-Foundation: COMPLETE (<timestamp>)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=GroupAB, spawn it.**

#### 2c-GroupAB — Authentication Bypass (CWE-287/288)

Runs FIRST among the impact groups (early access-control band, right after Foundation). Auth bypass = credential-validation logic is flawed (CWE-287/288), distinct from Missing Authorization (Group AC).

```
Spawn Agent:
  description: "Auth bypass analysis — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are analyzing a WordPress plugin for security vulnerabilities.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-ab.md

    SCOPE GATE: Contributor/Author auth floor findings are OOS (current program policy). SSRF (CWE-918) is OOS. Do NOT write OOS findings to findings.md — log as OOS leads in checkpoint/leads-forward only.

    Execute: Authentication Bypass analysis (OAuth/Social Login, Token Comparison,
    JWT Validation, Password Reset, Auto-Login, Domain Validation, Multi-Step Auth Gaps,
    Workflow-Step / One-Time-Replay).
    For EACH confirmed finding, also run Phase 2B and Phase 2D from the core skill.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read: AUDIT_DIR/audit-context.md (Entry Point Map + Structural Summary first, then deeper as needed)
    Read: AUDIT_DIR/grep/surface-results.md
    Read: AUDIT_DIR/auth-model.md and AUDIT_DIR/foundation.md (Foundation facts; append auth-model addendum if auth-relevant discoveries — see methodology)
    Read: AUDIT_DIR/grep/group-ab-results.md
    Read: AUDIT_DIR/checkpoint-foundation.md
    Read: AUDIT_DIR/leads-forward.md
    Read: AUDIT_DIR/semgrep/semgrep-group-ab.md

    For each confirmed finding, IMMEDIATELY append to AUDIT_DIR/findings.md.
    After analysis, write AUDIT_DIR/checkpoint-group-ab.md.
    Update AUDIT_DIR/leads-forward.md per the ledger protocol (core SKILL.md §5/§6): append LEADS (tag each Relevant-to) and, for every custom sink you evaluated, add/refresh its SINK LEDGER row with your group code in Consumed-by (dedup by fn@file:line; leave (none) only for sinks deferred to a later group or the Chain pass).

    Return: "[GROUP-AB] Complete. Findings: N confirmed, M leads forwarded."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-GroupAB: COMPLETE (<timestamp>) — N finding(s)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=GroupAC, spawn it.**

#### 2c-GroupAC — Access Control: Missing Authorization, IDOR, CSRF

Runs SECOND (early access-control band, after Auth-Bypass). This group FILLS the CIA Impact + Verdict columns of the auth-model Handler Auth Summary that the impact groups then consume.

```
Spawn Agent:
  description: "Access-control analysis (missing-auth/IDOR/CSRF) — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are analyzing a WordPress plugin for security vulnerabilities.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-ac.md

    SCOPE GATE: Contributor/Author auth floor findings are OOS (current program policy). SSRF (CWE-918) is OOS. Do NOT write OOS findings to findings.md — log as OOS leads in checkpoint/leads-forward only.

    Execute: Tier 4 (Broken Access Control/Privilege Escalation), Tier 4B (CSRF),
    Tier 11 (IDOR — all sub-patterns), the adversarial draft-status WP_Query / parse_args
    patterns (see the "Adversarial draft-status / parse_args patterns" section of
    vuln-audit-group-ac.md; grep sections WP_QUERY_DRAFT_STATUS_AJAX / WP_PARSE_ARGS_WRONG_ORDER
    now ship in group-ac-results.md), and the Auth Model Verdicts checkpoint.
    For EACH confirmed finding, also run Phase 2B and Phase 2D from the core skill.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read: AUDIT_DIR/audit-context.md (Entry Point Map + Structural Summary first, then deeper as needed)
    Read: AUDIT_DIR/grep/surface-results.md
    Read: AUDIT_DIR/auth-model.md and AUDIT_DIR/foundation.md (Foundation facts — auth floor + custom-sink index; re-verify gates in source before confirming)
    Read: AUDIT_DIR/grep/group-ac-results.md
    Read: AUDIT_DIR/checkpoint-foundation.md and AUDIT_DIR/checkpoint-group-ab.md
    Read: AUDIT_DIR/leads-forward.md
    Read: AUDIT_DIR/semgrep/semgrep-group-ac.md

    For each confirmed finding, IMMEDIATELY append to AUDIT_DIR/findings.md.
    MANDATORY: Fill the CIA Impact + Verdict columns in AUDIT_DIR/auth-model.md (written by the Foundation phase) from your Tier 4/4B/IDOR analysis; append an addendum for any new auth fact. Do NOT rebuild the tables.
    After analysis, write AUDIT_DIR/checkpoint-group-ac.md.
    Update AUDIT_DIR/leads-forward.md per the ledger protocol (core SKILL.md §5/§6): append LEADS (tag each Relevant-to) and, for every custom sink you evaluated, add/refresh its SINK LEDGER row with your group code in Consumed-by (dedup by fn@file:line; leave (none) only for sinks deferred to a later group or the Chain pass).

    Return: "[GROUP-AC] Complete. Findings: N confirmed, M leads forwarded."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-GroupAC: COMPLETE (<timestamp>) — N finding(s)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=GroupA, spawn it.**

#### 2c-GroupA — Tier 1–2: RCE, File Upload, File Read/Write/Delete

```
Spawn Agent:
  description: "Tier 1-2 analysis — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are analyzing a WordPress plugin for security vulnerabilities.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-a.md

    SCOPE GATE: Contributor/Author auth floor findings are OOS (current program policy). SSRF (CWE-918) is OOS. Do NOT write OOS findings to findings.md — log as OOS leads in checkpoint/leads-forward only.

    Execute: Phase 0 (Orientation), Tier 1 (RCE/Upload/SSTI), Tier 2 (File Read/Write/Delete).
    For EACH confirmed finding, also run Phase 2B and Phase 2D from the core skill.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read: AUDIT_DIR/audit-context.md (Entry Point Map + Structural Summary first, then deeper as needed)
    Read: AUDIT_DIR/auth-model.md and AUDIT_DIR/foundation.md (Foundation facts — auth floor + custom-sink index; re-verify gates in source before confirming)
    Read: AUDIT_DIR/grep/surface-results.md
    Read: AUDIT_DIR/grep/group-a-results.md
    Read: AUDIT_DIR/checkpoint-group-ab.md and AUDIT_DIR/checkpoint-group-ac.md
    Read: AUDIT_DIR/leads-forward.md
    Read: AUDIT_DIR/semgrep/semgrep-group-a.md

    For each confirmed finding (confidence >90%), IMMEDIATELY append to AUDIT_DIR/findings.md.
    After analysis, write AUDIT_DIR/checkpoint-group-a.md.
    Update AUDIT_DIR/leads-forward.md per the ledger protocol (core SKILL.md §5/§6): append LEADS (tag each Relevant-to) and, for every custom sink you evaluated, add/refresh its SINK LEDGER row with your group code in Consumed-by (dedup by fn@file:line; leave (none) only for sinks deferred to a later group or the Chain pass).

    Return: "[GROUP-A] Complete. Findings: N confirmed, M leads forwarded."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-GroupA: COMPLETE (<timestamp>) — N finding(s)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=GroupSQLi, spawn it.**

#### 2c-GroupSQLi — Tier 3: SQL Injection

```
Spawn Agent:
  description: "Tier 3 SQLi analysis — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are analyzing a WordPress plugin for security vulnerabilities.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-sqli.md

    SCOPE GATE: Contributor/Author auth floor findings are OOS (current program policy). SSRF (CWE-918) is OOS. Do NOT write OOS findings to findings.md — log as OOS leads in checkpoint/leads-forward only.

    Execute: Tier 3 (SQL Injection — direct queries, broken prepare(), ORDER BY,
    second-order / loop-built queries).
    For EACH confirmed finding, also run Phase 2B and Phase 2D from the core skill.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read: AUDIT_DIR/audit-context.md (Entry Point Map + Structural Summary first, then deeper as needed)
    Read: AUDIT_DIR/grep/surface-results.md
    Read: AUDIT_DIR/auth-model.md and AUDIT_DIR/foundation.md (Foundation facts — auth floor + custom-sink index; re-verify gates in source before confirming)
    Read: AUDIT_DIR/grep/group-sqli-results.md
    Read: ALL checkpoint files (checkpoint-foundation.md + checkpoint-group-ab/ac/a.md)
    Read: AUDIT_DIR/leads-forward.md
    Read: AUDIT_DIR/semgrep/semgrep-group-sqli.md

    For each confirmed finding, IMMEDIATELY append to AUDIT_DIR/findings.md.
    After analysis, write AUDIT_DIR/checkpoint-group-sqli.md.
    Update AUDIT_DIR/leads-forward.md per the ledger protocol (core SKILL.md §5/§6): append LEADS (tag each Relevant-to) and, for every custom sink you evaluated, add/refresh its SINK LEDGER row with your group code in Consumed-by (dedup by fn@file:line; leave (none) only for sinks deferred to a later group or the Chain pass).

    Return: "[GROUP-SQLI] Complete. Findings: N confirmed, M leads forwarded."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-GroupSQLi: COMPLETE (<timestamp>) — N finding(s)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=GroupC, spawn it.**

#### 2c-GroupC — Tier 5–6: Server-Side Renderer Injection, XSS

```
Spawn Agent:
  description: "Tier 5-6 analysis — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are analyzing a WordPress plugin for security vulnerabilities.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-c.md

    SCOPE GATE: Contributor/Author auth floor findings are OOS (current program policy). SSRF (CWE-918) is OOS. Do NOT write OOS findings to findings.md — log as OOS leads in checkpoint/leads-forward only.

    Execute: Tier 5 (HTML Renderers only — SSRF is OOS), Tier 6 (Stored/Reflected XSS — both Phase A and Phase B,
    all chains including block attribute XSS and shortcode attribute XSS).
    For EACH confirmed finding, also run Phase 2B and Phase 2D from the core skill.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read: AUDIT_DIR/audit-context.md (Entry Point Map + Structural Summary first, then deeper as needed)
    Read: AUDIT_DIR/grep/surface-results.md
    Read: AUDIT_DIR/grep/group-c-results.md
    Read: ALL checkpoint files (checkpoint-foundation.md + checkpoint-group-ab/ac/a/sqli.md)
    Read: AUDIT_DIR/auth-model.md and AUDIT_DIR/foundation.md (Foundation facts; append auth-model addendum if auth-relevant discoveries — see methodology)
    Read: AUDIT_DIR/leads-forward.md
    Read: AUDIT_DIR/semgrep/semgrep-group-c.md

    For each confirmed finding, IMMEDIATELY append to AUDIT_DIR/findings.md.
    After analysis, write AUDIT_DIR/checkpoint-group-c.md.
    Update AUDIT_DIR/leads-forward.md per the ledger protocol (core SKILL.md §5/§6): append LEADS (tag each Relevant-to) and, for every custom sink you evaluated, add/refresh its SINK LEDGER row with your group code in Consumed-by (dedup by fn@file:line; leave (none) only for sinks deferred to a later group or the Chain pass).

    Return: "[GROUP-C] Complete. Findings: N confirmed, M leads forwarded."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-GroupC: COMPLETE (<timestamp>) — N finding(s)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=GroupD1, spawn it.**

#### 2c-GroupD1 — Tier 9–10: Email Injection, Information Disclosure (Tier 8 SSRF is OOS)

```
Spawn Agent:
  description: "Tier 8-10 analysis — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are analyzing a WordPress plugin for security vulnerabilities.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-d1.md

    SCOPE GATE: Contributor/Author auth floor findings are OOS (current program policy). SSRF (CWE-918) is OOS. Do NOT write OOS findings to findings.md — log as OOS leads in checkpoint/leads-forward only.

    Execute: Skip Tier 8 (SSRF — OOS per current program policy). Tier 9 (Email Header Injection),
    Tier 10A-F (Information Disclosure — all 6 sub-categories).
    For EACH confirmed finding, also run Phase 2B and Phase 2D from the core skill.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read: AUDIT_DIR/audit-context.md (Entry Point Map + Structural Summary first, then deeper as needed)
    Read: AUDIT_DIR/grep/surface-results.md
    Read: AUDIT_DIR/grep/group-d1-results.md
    Read: ALL checkpoint files (checkpoint-foundation.md + checkpoint-group-ab/ac/a/sqli/c.md)
    Read: AUDIT_DIR/auth-model.md and AUDIT_DIR/foundation.md (Foundation facts; append auth-model addendum if auth-relevant discoveries — see methodology)
    Read: AUDIT_DIR/leads-forward.md
    Read: AUDIT_DIR/semgrep/semgrep-group-d1.md

    For each confirmed finding, IMMEDIATELY append to AUDIT_DIR/findings.md.
    After analysis, write AUDIT_DIR/checkpoint-group-d1.md.
    Update AUDIT_DIR/leads-forward.md per the ledger protocol (core SKILL.md §5/§6): append LEADS (tag each Relevant-to) and, for every custom sink you evaluated, add/refresh its SINK LEDGER row with your group code in Consumed-by (dedup by fn@file:line; leave (none) only for sinks deferred to a later group or the Chain pass).

    Return: "[GROUP-D1] Complete. Findings: N confirmed, M leads forwarded."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-GroupD1: COMPLETE (<timestamp>) — N finding(s)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=Chain, spawn it.**

> **Group adv collapsed** (0 lifetime TP under its own label). Its draft-status
> `WP_Query`/`parse_args` access-control patterns are now analyzed by GroupAC (their grep
> sections shipped in `group-ac-results.md`); its Tier 12 race-condition and "Beyond the
> Checklist" adversarial reasoning are executed by the Chain pass below.

#### 2c-Chain — Cross-Tier Vulnerability Chaining + Adversarial Reasoning

**Skip condition:** This pass now does Reconciliation (re-opening earlier-group questions from
late discoveries) as well as chaining, so it can produce a net-new finding even when the impact
groups confirmed none. Before spawning, check THREE things in `AUDIT_DIR`:
(1) confirmed findings in `findings.md` (lines containing `CONFIRMED`);
(2) SINK LEDGER rows in `leads-forward.md` whose `Consumed-by` is `(none)` (unconsumed/orphan sinks);
(3) LEADS tagged `Relevant-to: Chain`.
Skip this stage ONLY if **all three are 0**: log `[PIPELINE] 2c-Chain skipped — 0 findings, 0 unconsumed sinks, 0 chain leads.` and proceed directly to Stage 2d. If any is non-zero, spawn the pass.

```
Spawn Agent:
  description: "Reconciliation + chaining — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    You are running the two-step RECONCILIATION + CHAINING pass on a WordPress plugin audit.
    Step 1 (Reconciliation): re-open earlier-group questions using late discoveries — every SINK
    LEDGER row with Consumed-by (none), every impact-group auth-model addendum, and every
    Relevant-to: Chain lead — and write any net-new missing-auth/IDOR/auth-bypass/priv-esc/RCE/
    file-op finding (>90% confidence, passes the scope gate) to findings.md. Step 2 (Chaining):
    combine ALL confirmed findings (including your Step-1 findings) for maximum impact.
    Read and follow the methodology in these two files:
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
    ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-chain.md

    SCOPE GATE: Contributor/Author auth floor findings are OOS (current program policy). SSRF (CWE-918) is OOS. Do NOT write OOS findings to findings.md — log as OOS leads in checkpoint/leads-forward only. Exception: if chaining lowers auth floor to Subscriber or below, the chain is in-scope at the lower floor.

    Also apply Phase 3 (Data Flow Tracing) and Phase 4 (FP Verification) from the core skill for confirmed chains.

    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]

    Read ALL of these files:
    - AUDIT_DIR/findings.md (ALL confirmed findings from the impact groups)
    - AUDIT_DIR/audit-context.md
    - AUDIT_DIR/auth-model.md (Foundation facts + Group AC verdicts + ALL impact-group addenda) and AUDIT_DIR/foundation.md (custom-sink inventory)
    - ALL checkpoint files (checkpoint-foundation.md + checkpoint-group-ab/ac/a/sqli/c/d1.md)
    - AUDIT_DIR/leads-forward.md — the full SINK LEDGER (note every row with Consumed-by (none)) + all Relevant-to: Chain leads
    - AUDIT_DIR/grep/surface-results.md (for tracing chain paths through attack surface)

    STEP 1 — RECONCILIATION (do this FIRST, per vuln-audit-chain.md Phase 2C Step 1):
    For each unconsumed SINK LEDGER row, each impact-group auth-model addendum, and each
    Relevant-to: Chain lead, ask whether the late discovery turns a previously-benign or
    dismissed endpoint into a missing-auth / IDOR / auth-bypass / priv-esc / RCE / file-op
    finding. If yes and confidence > 90% and it passes the FP + scope gate, write it to
    findings.md as a NET-NEW finding (own CWE/CVSS/auth-floor). Set that sink's Consumed-by to Chain.

    STEP 2 — CHAINING: For each chain pattern, check whether any combination of confirmed
    findings (including Step-1 findings) creates a viable chain. Also look for chains between
    findings and LEADS that weren't individually confirmed but become exploitable when chained.

    For confirmed chains, apply the Root Cause Count test (defined in vuln-audit-chain.md):
    - Root cause count = 1: Elevate the existing finding's CVSS and add chain metadata.
      Do NOT create a new finding section.
    - Root cause count >= 2: Each defect is already its own finding from the impact groups
      (AB/AC/A/SQLi/C/D1) or from Step-1 reconciliation.
      Create a new finding section only for defects not already captured. Elevate
      the chain-impacted finding's CVSS. Cross-reference between findings via chain notes.
    - NEVER create an N+1 "chain finding" beyond the underlying defects.

    STEP 3 — ADVERSARIAL REASONING (absorbed from the collapsed Group adv): run the
    "Adversarial reasoning" section of vuln-audit-chain.md — Tier 12 race conditions,
    Tier 13 business-logic classification (route in-scope security facets to their true
    group; do not report OOS business logic), and the "Beyond the Checklist" sweep. Write
    any net-new finding (>90% confidence, passes FP + scope gate) to findings.md. The
    draft-status WP_Query / parse_args access-control patterns are GroupAC's job, not this step.

    Return: "[CHAIN] Complete. Reconciliation findings: R. Chains found: N. Findings updated."
```

Wait for completion. Discard sub-agent response except completion signal. Update `pipeline-state.md`: `Stage 2c-Chain: COMPLETE (<timestamp>) — N chain(s)`
**→ Run continuation guard (Rule 2) now. Re-read pipeline-state.md, confirm next=Stage 2d, proceed.**

### 2d — Analysis Summary (main agent)

Re-read `AUDIT_DIR/findings.md` to count total findings.

Print summary: finding count, CVSS scores, severity levels.

Update `pipeline-state.md`: `Stage 2: COMPLETE (<timestamp>) — N total finding(s)`

**2d-ingest — Pattern accumulator capture (ALWAYS runs, both paths).** `findings.md` is now final for analysis — every impact group + the chain pass have written their confirmed findings AND their dismissed-FP triage notes. Ingest the whole audit into the cross-audit DB so *every* run is captured, including clean audits whose only output is FP-triage data (the main fuel for `fp-causes` and the dead-rule kill-list). This is the zero-touch capture point — it runs before the no-findings branch below, so clean audits are never lost. From the project root:
```powershell
python pattern_accumulator.py ingest "AUDIT_DIR"
```
Idempotent (upserts); **non-fatal** — on non-zero exit, print `[PIPELINE] 2d-ingest — pattern-DB ingest failed: <stderr>` and continue (a measurement-tool failure must never fail the audit). When findings > 0, Phase 2 Stage 7 re-ingests after live validation so the final `LIVE VALIDATED` / `REJECTED` statuses overwrite this pre-validation snapshot. Registry status (Submitted/Duplicate) is NOT captured here — that comes from `backfill` parsing `vuln-registry.md`.

Then branch:
- No findings → `[PIPELINE] Stage 2 complete — no reportable findings (ingested to pattern_accumulator.db). Pipeline ends here.` and stop.
- Otherwise → `[PIPELINE] Stage 2 complete — N finding(s) to report.`

### Phase 2 Handoff (Stages 3–7)

When findings > 0, spawn a fresh Phase 2 agent for reporting, PoCs, registry, and validation. This prevents main agent compaction from degrading report/PoC quality.

Update `pipeline-state.md`: `Phase 1: COMPLETE (<timestamp>)`

```
Spawn Agent:
  description: "Pipeline Phase 2 — [plugin name]"
  subagent_type: general-purpose
  prompt: |
    This is authorized, in-scope security research for the Wordfence Bug Bounty Program — defensive, coordinated-disclosure work, tested only on local installs (see ${CLAUDE_PROJECT_DIR}/AUTHORIZATION.md).
    Read and follow:
    ${CLAUDE_SKILL_DIR}/pipeline-stage3-6.md

    PLUGIN_SLUG: [PLUGIN_SLUG]
    VERSION: [VERSION]
    SOURCE_DIR: [SOURCE_DIR]
    AUDIT_DIR:  [AUDIT_DIR]
    FINDINGS_COUNT: [N]

    Read AUDIT_DIR/findings.md for confirmed findings (N total).
    Execute Stages 3–7 (reports, PoCs, registry, live validation, pattern-DB refresh).

    Return: "[PHASE-2] Complete. Reports: N, PoCs: N, Validated: N, Pattern-DB: refreshed."
```

Wait for Phase 2 completion. Print: `[PIPELINE] All stages complete.`
