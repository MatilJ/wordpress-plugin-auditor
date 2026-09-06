# Skill: Live Vulnerability Validation

## Purpose
Validate confirmed findings from a completed Full Audit Pipeline by spinning up a live WordPress Docker environment, configuring the plugin, and executing PoC scripts. Update artifacts based on live test results. Final verification gate before Wordfence submission.

If a Chrome browser is connected via claude-in-chrome, Stage 3h additionally cross-checks the disclosure report's `Part 1 — Setup` wp-admin menu paths/labels against the real admin UI (best-effort — see Stage 3h; never blocks validation if unavailable).

## Trigger format
```
Validate <plugin-slug> with Live Validation
```
Or: `Validate <plugin-slug> finding <N> with Live Validation`
If no finding number, validate ALL confirmed findings for the latest audited version.

## Helper Templates
Directory: `${CLAUDE_SKILL_DIR}/templates/`

| Template | Purpose | Container path |
|----------|---------|----------------|
| `activate-plugins.php` | Add plugins to `active_plugins` with correct serialization; `--with-hooks` fires activation callbacks | `/tmp/activate-plugins.php` |
| `check-environment.php` | Pre-flight: PHP extensions, debug.log, HTTP self-test, REST namespaces, plugin health. Pass slug for targeted checks. | `/tmp/check-environment.php` |
| `check-routes.php` | List REST routes by namespace. **WARNING:** CLI-bootstrapped — can show routes NOT reachable via HTTP. Always confirm via HTTP probe. | `/tmp/check-routes.php` |
| `smoke-test.sh` | Pre-PoC endpoint verification: login, nonce acquisition, request firing. Works for AJAX and REST. | `/tmp/smoke-test.sh` |

Deploy ALL templates at once in Stage 2d:
```powershell
docker cp "${CLAUDE_SKILL_DIR}/templates/." wordpress-plugin-auditor-wordpress-1:/tmp/
```

**NEVER hand-write PHP serialized strings.** Byte-count length prefixes — one byte off causes silent `false` from `unserialize()`. Always use `activate-plugins.php` or a PHP script with `serialize()`.

## Shell Command Rules (Windows/PowerShell host)
**NEVER inline multi-step bash through PowerShell.** PowerShell parses `$`, backticks, `()`, braces — compound bash commands WILL break.

**The rule:** If bash command has variables, pipes, or subshells → write to `.sh` file → `docker cp` → `docker compose exec -T wordpress bash /tmp/<file>.sh`.

Safe inline: simple commands without bash variables (`wp --allow-root plugin list`, `mysql -e "SELECT ..."`, `docker compose logs`).

Use `smoke-test.sh` template instead of ad-hoc curl scripts.

## Pre-conditions
- `./audit/<PLUGIN_SLUG>/<VERSION>/findings.md` exists with confirmed findings
- `./audit/<PLUGIN_SLUG>/<VERSION>/poc/` has at least one `.py` file
- `./audit/<PLUGIN_SLUG>/<VERSION>/reports/` has at least one `.md` file
- `./compose.yaml` and `./setup.sh` exist in project root
- Docker daemon is running (auto-start if needed — see below)

**Docker daemon check and auto-start (Windows):**
1. Run `docker compose version` to test if Docker is available.
2. If it fails (Docker daemon not running), attempt to start Docker Desktop:
   ```powershell
   Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
   ```
3. Poll `docker info` every 15 seconds, up to 120 seconds.
4. If Docker is responsive → continue. If still not responsive after 120s → stop and report.

If any other pre-condition fails, stop and report.

## Stage 0 — Path Resolution & Finding Intake

### 0a — Resolve paths
```
PLUGIN_SLUG  = slug from trigger phrase
VERSION      = highest version in ./audit/<PLUGIN_SLUG>/
AUDIT_DIR    = ./audit/<PLUGIN_SLUG>/<VERSION>
SOURCE_DIR   = ./plugins/<PLUGIN_SLUG>/<VERSION>
```

### 0b — Read audit artifacts
Read: `AUDIT_DIR/findings.md`, `AUDIT_DIR/reports/*.md`, list `AUDIT_DIR/poc/*.py`.
For each finding extract: vuln type, auth level, AJAX/REST endpoints, prerequisites, dependency plugins, target resource.

### 0c — Print intake summary
```
[VALIDATION] Stage 0 complete.
  Slug:       <PLUGIN_SLUG>
  Version:    <VERSION>
  Findings:   <N> confirmed finding(s) to validate
  PoCs:       <list of .py files>
  Dependencies: <list or "none">
```

## Stage 0d — Lock Acquisition (mandatory before Docker operations)

Acquire the live-validation lock via `lock_manager.py`. This prevents concurrent sessions from modifying the shared Docker environment.

```powershell
python lock_manager.py wait <PLUGIN_SLUG> --timeout 3600 --interval 90
```

Parse the **last line** of output as JSON:
- `"status": "acquired"` → save `SESSION_ID` from that line. Proceed.
- `"status": "timeout"` → stop and report: `[VALIDATION] Aborted — could not acquire lock within 60 minutes.`

**Heartbeat:** Before Stages 2, 3, and 4, run:
```powershell
python lock_manager.py heartbeat <SESSION_ID>
```
If exit code 1 → lock was lost. **STOP immediately** and report: `[VALIDATION] Aborted — lock lost.`

```
[VALIDATION] Stage 0d complete — lock acquired (session: <SESSION_ID>).
```

## Stage 1 — Source Code Pre-Verification (Haiku sub-agent)

Verify code claims in findings.md against actual source before Docker setup.

```
Agent(
  description: "Source verification — <PLUGIN_SLUG>",
  model: haiku,
  subagent_type: general-purpose,
  prompt: """
    Verify code references from findings document against plugin source.
    Do NOT assess vulnerability validity — only check cited code exists.

    FINDINGS: <AUDIT_DIR>/findings.md
    SOURCE:   <SOURCE_DIR>

    For each CONFIRMED finding verify:
    1. File existence in SOURCE
    2. Line numbers (±10 lines acceptable)
    3. Root cause code pattern present
    4. Function/hook names exist

    For AJAX findings also verify:
    5. Exact action string from add_action('wp_ajax_*')
    6. Nonce action string from wp_create_nonce()
    7. Nonce JS location: object name, key name, page hook/condition
    8. Handler success response structure

    For REST findings: route registration, permission_callback.

    Verify each PoC (AUDIT_DIR/poc/*.py) params against handler params.
    Check nonce source page capability → minimum role.

    Output per finding:
    FINDING <N>: <title>
      <path>:<lines> — EXISTS/MISSING, code MATCH/SHIFTED/NOT FOUND
      Functions: ALL EXIST / MISSING: <list>
      [AJAX/REST] contract values (action, nonce, params, response)
      [POC] MISMATCHES: <list or "none">
    END
  """
)
```

Note mismatches for correction in Stage 5. Do NOT abort — proceed to live testing.

```
[VALIDATION] Stage 1 complete — source verification done.
  Verified:   <N> of <M> code references match
  Mismatches: <list, if any>
```

## Stage 2 — Environment Setup

### 2a — Check for running containers
```powershell
docker compose ps --format "table {{.Name}}\t{{.Status}}"
```
If containers running, tear down first: `docker compose down -v`. Always start fresh.

### 2b — Start Docker environment
Always test the exact version from SOURCE_DIR.

**Standard flow (audited source exists locally):**
1. Start without PLUGIN_SLUG: `docker compose up -d --build`
2. After setup completes, deploy templates + copy source + fix ownership:
   ```powershell
   docker cp "${CLAUDE_SKILL_DIR}/templates/." wordpress-plugin-auditor-wordpress-1:/tmp/
   docker cp "<SOURCE_DIR>" wordpress-plugin-auditor-wordpress-1:/var/www/html/wp-content/plugins/<PLUGIN_SLUG>
   docker compose exec -T wordpress chown -R www-data:www-data /var/www/html/wp-content/plugins/<PLUGIN_SLUG>
   ```
3. Activate: `docker compose exec -T wordpress php /tmp/activate-plugins.php <PLUGIN_SLUG>/<main-file>.php --with-hooks`

For dependency plugins, pass via PLUGIN_SLUG: `$env:PLUGIN_SLUG = "<DEP1>,<DEP2>"; docker compose up -d --build`

### 2c — Wait for setup completion
```powershell
docker compose logs setup
```
Look for `━━━` summary with WordPress/Adminer URLs.

### 2d — Post-setup verification (GATE)
Deploy templates (if not done in 2b), then run:
```powershell
docker compose exec -T wordpress php /tmp/check-environment.php <PLUGIN_SLUG>
```

**STOP if any:** plugin not in `active_plugins`, fatal errors in debug.log, homepage non-200, required PHP extensions missing.

Fix sequence: missing extension → install/rebuild · plugin not active → `wp plugin activate` · tables missing → deactivate+reactivate · persistent crash → check debug.log.

### 2e — Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | Administrator |
| editor | editor123 | Editor |
| author | author123 | Author |
| contributor | contributor123 | Contributor |
| subscriber | subscriber123 | Subscriber |

### 2f — Install dependency plugins
Preferred: `docker compose exec -T wordpress wp --allow-root plugin install <dep-slug> --activate`
Manual: `docker cp` + `activate-plugins.php [--with-hooks]`

### 2g — Auth-level reachability check (GATE)
For each finding, verify claimed role reaches target endpoint before PoC execution.

```powershell
docker compose exec -T wordpress bash /tmp/smoke-test.sh <role> <role>123 rest /<target_page>
```
AJAX: `bash /tmp/smoke-test.sh <role> <role>123 ajax <action> <nonce_key> <nonce_page> "<extra_params>"`

200 → proceed. 403 → escalate to next role, note correction. 302 → retry login.

**Common page → capability mappings:**

| Page | Capability | Lowest role |
|------|-----------|-------------|
| `/wp-admin/edit.php` | `edit_posts` | Contributor |
| `/wp-admin/upload.php` | `upload_files` | Author |
| `/wp-admin/index.php` | `read` | Subscriber |
| `/wp-admin/profile.php` | `read` | Subscriber |
| `/wp-admin/admin-ajax.php` | (none) | Unauthenticated* |

\* `wp_ajax_` requires auth; `wp_ajax_nopriv_` does not.

```
[VALIDATION] Stage 2 complete — environment running.
  WordPress:  http://localhost:8000 (status 200)
  Plugin:     <PLUGIN_SLUG> (active)
  Auth check: Finding 1: <role> → <page> → <status>
```

## Stage 3 — Plugin Configuration

### 3a — Identify required settings
From findings.md prerequisites: features to enable, modules to activate, registration, forms/shortcodes, test content.

**Sub-component activation:** Many plugins have internal component systems where features are disabled by default. When a vuln targets a sub-component endpoint, activate it first. Check for CLI (`wp bp component activate`, `wp jetpack module activate`) or identify the controlling option. Do NOT deactivate/reactivate the whole plugin after — some reset component lists.

### 3b — Configure via WP-CLI or direct SQL
Priority order (stop at first that works):

1. **WP-CLI:** `wp --allow-root option update <name> <value>` or `option patch update`
2. **Direct PHP script:** write `.php`, `docker cp`, run with `php` (not `wp eval-file`)
3. **Direct SQL:** `docker compose exec -T db mysql -u wordpress -pwordpress wordpress -e "<SQL>"`
4. **WP-CLI eval — LAST RESORT:** fragile, bootstraps full WP stack

### 3c — Plugin option format awareness
Before modifying any option, read current value:
```powershell
docker compose exec -T db mysql -u wordpress -pwordpress wordpress -e "SELECT LEFT(option_value, 100) FROM wp_options WHERE option_name='<name>';"
```

Identify format and write back in same format:
- `{"key":...}` → JSON. Use PHP script with `json_decode()`/`json_encode()`. Do NOT use `update_option()` with array — re-serializes as `a:N:{...}` breaking `json_decode()` callers.
- `a:N:{...}` → PHP serialized. Safe for `update_option()` with array or `option patch`.
- Plain string/int → `update_option()` or direct SQL.

For JSON options, write a PHP script using `mysqli` directly to db container.
For user meta: direct SQL INSERT/UPDATE on `wp_usermeta`.

### 3d — Verify site loads after config changes (200 OK check)

### 3e — Create test content if needed
```powershell
docker compose exec -T wordpress wp --allow-root post create --post_title="Test Page" --post_status=publish --post_type=page
```

### 3f — Smoke test (mandatory before Stage 4)
```powershell
docker compose exec -T wordpress bash /tmp/smoke-test.sh <role> <password> <type> <action> [nonce_key] [nonce_page] [extra_params]
```

| Verdict | Meaning | Action |
|---------|---------|--------|
| ENDPOINT REACHABLE | 200 + response | Proceed to Stage 4 |
| NONCE FAILED | Response is `0` | Wrong nonce key/action |
| AUTH REJECTED | Capability error | Auth level wrong |
| AUTH BLOCKED | 403 | Role can't reach page |
| NOT FOUND | 404 | Endpoint not registered; check config |
| SERVER ERROR | 500 | Check debug.log |

Fix failures before proceeding. Do NOT run PoC with failing smoke test.

### 3g — Pre-PoC contract reconciliation (mandatory for AJAX/REST)
Compare Stage 1 contract values against PoC script. If Stage 1 data compacted away, delegate to Haiku sub-agent with SOURCE_DIR and PoC path.

| Check | Common mismatch |
|-------|----------------|
| AJAX `action=` value | PoC uses dispatcher instead of registered hook |
| Nonce JS object + key | Wrong key; page condition excludes role |
| Nonce page capability | Claims Subscriber but page needs `edit_posts` |
| Handler request params | Wrong param names, missing required params |
| Success response check | Different response structure |
| UNION column count (SQLi) | Wrong count — always DESCRIBE table first |

Update PoC before running if any mismatch found.

For SQLi — always DESCRIBE the table live:
```powershell
docker compose exec -T db mysql -u wordpress -pwordpress wordpress -e "DESCRIBE <table_name>;"
```

### 3h — GUI Setup verification (claude-in-chrome, best-effort)
Cross-checks the disclosure report's `### Part 1 — Setup` (and any wp-admin path under `### Part 2 — Triggering the Vulnerability` → `**Option A — Via GUI**`) against the real admin UI, so a Wordfence reviewer's first click-through succeeds. This is a read/confirm pass only — WP-CLI/SQL (3b) remains the actual mechanism that sets environment state; this step never replaces it. **Best-effort: never gates Stage 4, never blocks or fails validation.**

1. **Availability check:** call `tabs_context_mcp`. If it errors, times out, or no browser is connected (including no site permission granted for `localhost:8000`), print `[VALIDATION] 3h skipped — claude-in-chrome not available.` and proceed to Stage 4 using the report exactly as already drafted — no other fallback logic needed.
2. If available, batch-load the tools needed in one call: `ToolSearch("select:mcp__claude-in-chrome__tabs_context_mcp,mcp__claude-in-chrome__navigate,mcp__claude-in-chrome__computer,mcp__claude-in-chrome__read_page,mcp__claude-in-chrome__get_page_text,mcp__claude-in-chrome__tabs_create_mcp,mcp__claude-in-chrome__form_input")`.
3. Open a new tab, navigate to `http://localhost:8000/wp-login.php`, log in as `admin`/`admin123` (Stage 2e credentials — covers Setup steps 1-3, which are site-owner actions even when the account created in step 4 is a lower-privileged role).
4. Read the target report's `### Part 1 — Setup` from `AUDIT_DIR/reports/*.md`. Walk each concrete step one at a time (menu path, tab name, field label, button label), confirming the stated element exists with the stated label via `get_page_text`/`read_page`/`find`. Do the same for any wp-admin menu path quoted under `**Option A — Via GUI**`.
5. Record each mismatch as a short note: `step N: written "<X>" → actual "<Y>"`. Do **not** edit the report file in this stage — hand the note list to Stage 5c, which owns report corrections.
6. **Safety rules:**
   - Never click destructive/irreversible controls while verifying (delete, bulk-delete, reset-to-defaults) — this is a label/path confirmation pass, not a mutation pass.
   - Never trigger JS `alert`/`confirm`/`prompt` dialogs — they block the whole browser session.
   - If a step fails after 2-3 attempts (element not found, page not loading), note `could not verify — <reason>` and move on rather than retrying indefinitely.

```
[VALIDATION] Stage 3h complete — GUI setup: <N> verified, <M> corrected, <K> could not verify
```
(or `[VALIDATION] Stage 3h skipped — claude-in-chrome not available.` if no browser was connected)

```
[VALIDATION] Stage 3 complete — plugin configured.
  Settings changed: <list>
  Smoke test:       <endpoint> → <verdict>
  GUI setup check:  <N> verified, <M> corrected, <K> unverifiable / skipped
```

## Stage 4 — PoC Execution

**MANDATORY:** Run `AUDIT_DIR/poc/*.py` scripts only — never ad-hoc scripts. Fix failing PoCs in-place (4c), re-run. Finding validated only when its deliverable PoC passes both detect and exploit.

### 4a — Run detect mode first
```powershell
python "AUDIT_DIR/poc/<poc-script>.py" --url http://localhost:8000 --username <role> --password <role>123 --detect --verbose
```
Credential mapping: Unauthenticated → omit creds · Subscriber → subscriber/subscriber123 · Contributor → contributor/contributor123 · Author → author/author123

| Outcome | Action |
|---------|--------|
| `[+] VULNERABLE` | Proceed to exploit (4b) |
| `[-] NOT DETECTED` | Diagnose (4c) |
| Script error | Debug (4c) |

### 4b — Run exploit mode
```powershell
python "AUDIT_DIR/poc/<poc-script>.py" --url http://localhost:8000 --username <role> --password <role>123 --verbose
```

### 4c — Diagnose PoC failures

**Step 0 — Check debug.log immediately:**
```powershell
docker compose exec -T wordpress bash -c "tail -50 /var/www/html/wp-content/debug.log"
```

**Read `${CLAUDE_PROJECT_DIR}/.claude/skills/pipeline/live-validation-reference.md` Section 4** for the full diagnosis tree covering: login failures, nonce issues, plugin config, 500 errors, AJAX -1/0, 404 endpoints (permalink structure, REST namespace verification, active_plugins corruption, `?rest_route=` fallback).

### 4c-sqli — SQL injection specific diagnosis
1. **Space-splitting:** plugins may `explode(' ', $term)` — all payloads must be space-free: `AND(SLEEP(4))`, `UNION(SELECT(1),(2))`
2. **Comment chars:** use `#` not `-- ` (space gets stripped)
3. **SLEEP() requires rows:** empty table = no execution. Use UNION-based detection as primary. Populate table first if needed.
4. **UNION column count:** always `DESCRIBE` table before writing payloads
5. **WP 6.8+ password hashes:** bcrypt `$wp$2y$10$...` — regex: `r'\$(?:wp\$2y|2y|P)\$[A-Za-z0-9$./]{20,}'`, hashcat mode `-m 3200`

### 4d — Nonce generation fallback (mu-plugin)
**WARNING:** If the action nonce is not available on any page the attacker role can access, this is a strong signal that the effective auth floor is higher than claimed. The nonce acts as de facto authorization — the finding is likely a false positive at the claimed auth level (OOS as PR:H). Before using this fallback, document exactly why the nonce is inaccessible and whether this invalidates the finding.

When WP-CLI eval crashes and nonce confirmed accessible but hard to scrape:
1. Write mu-plugin that exposes `wp_create_nonce()` via AJAX
2. `docker cp` to `/var/www/html/wp-content/mu-plugins/test-nonce-gen.php`
3. Call as attacker user: `POST /wp-admin/admin-ajax.php action=test_nonce_gen&nonce_action=<action>`
4. **Remove after testing:** `docker compose exec -T wordpress rm -f /var/www/html/wp-content/mu-plugins/test-nonce-gen.php`

### 4e — Manual verification
If PoC can't fully automate, verify via standalone Python requests snippet. Disposable — do not save as permanent file.

### 4f — Database verification
```powershell
docker compose exec -T db mysql -u wordpress -pwordpress wordpress -e "<verification SQL>"
```
XSS: `WHERE post_content LIKE '%<script>%'` · User creation: `ORDER BY ID DESC LIMIT 3` · Options: `WHERE option_name='<name>'` · IDOR/2FA: `WHERE user_id=1 AND meta_key LIKE '%2fa%'`

```
[VALIDATION] Stage 4 complete.
  Finding 1: <PASS/FAIL> — <brief result>
```

## Stage 5 — Artifact Updates

### 5a — Update findings.md
- Status → `CONFIRMED — LIVE VALIDATED` or `REJECTED (live test)`
- Add `**Live Test:**` line with date, versions, result
- Correct any steps, auth levels, line numbers discovered during testing

### 5b — Update PoC script
Fix: nonce acquisition, error handling, detection logic, return values, usage examples.

### 5c — Update disclosure report
Correct factual values in the body only: nonce/auth steps, dispatch chain, prerequisites, line numbers, and the `All environment…` versions (keep them accurate, including the versions verified against). If Stage 3h found GUI Setup mismatches, correct the exact menu path/tab/field/button label in `Part 1 — Setup` (and `Part 2 → Option A — Via GUI`) to the verified real value — written as a plain factual GUI step, same rule as every other correction here. Do NOT add validation narrative to the body — no "(validated against…)", "confirmed in Docker/localhost", "live-validated", "GUI-verified via claude-in-chrome", or DB-verification "if desired" blocks. Any live-validation or GUI-verification stamp goes into the report's `## Internal Metadata (not submitted)` table only (e.g. a `Live Validation` or `GUI Setup Verified (claude-in-chrome)` row) — never into the main body.

### 5d — Verify PoC syntax
```powershell
python -c "import ast; ast.parse(open(r'AUDIT_DIR/poc/<script>.py').read()); print('Syntax OK')"
```

### 5e — Haiku sub-agent for templated updates (optional)
For mechanical edits (line number fixes, updating versions across multiple findings), delegate to Haiku with explicit edit instructions. The `**Live Test:**` status line goes to **findings.md**; any report validation stamp goes to the report's `## Internal Metadata (not submitted)` table only — never a live-test bullet in the report body. Do NOT delegate vulnerability re-assessment or exploit logic changes.

### 5f — Update vuln-registry.md
Passed findings: `Ready to submit - Validated: live-validation`

```
[VALIDATION] Stage 5 complete — artifacts updated.
```

## Stage 6 — Cleanup

```powershell
Remove-Item ".\tmp-*.php", ".\tmp-*.sh" -ErrorAction SilentlyContinue
docker compose exec -T wordpress rm -f /var/www/html/wp-content/mu-plugins/test-nonce-gen.php
docker compose down -v
python lock_manager.py release <SESSION_ID>
```

Always tear down immediately when validation is complete. The `release` command validates SESSION_ID ownership — safe even if the lock was already broken (no-op).

```
[VALIDATION] Stage 6 complete — environment torn down, lock released.
```

## Stage 7 — Verdict

```
[VALIDATION] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Plugin:     <PLUGIN_SLUG> <VERSION>

  Finding 1:  <title>
    Verdict:  TRUE POSITIVE / FALSE POSITIVE
    Live PoC: PASS / FAIL (with reason)

  Overall:    <N> of <M> findings confirmed via live testing
[VALIDATION] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

FALSE POSITIVE: update findings.md to `REJECTED (live test)`, document why, do NOT delete report/PoC.

## Database Surgery

### Reset active_plugins (deactivate all)
```powershell
docker compose exec -T db mysql -u wordpress -pwordpress wordpress -e "UPDATE wp_options SET option_value='a:0:{}' WHERE option_name='active_plugins';"
```
Re-activate via `activate-plugins.php`.

### Fix corrupted serialized option
Read current value → identify expected format from source → write PHP script using `serialize()`. Never fix by hand.

### Recreate missing tables
Find `register_activation_hook` → extract CREATE TABLE statements → run directly via db container.

### Reset user password
```powershell
docker compose exec -T wordpress wp --allow-root user update <username> --user_pass=<password>
```

## Pitfalls (compact reference)

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| Plugin silently fails to bootstrap | REST routes absent via HTTP, AJAX handlers never fire | Run `check-environment.php <slug>` — catches missing extensions, init crashes |
| Memory limit exceeded | `Allowed memory size exhausted` or silent 500 | Verify upload.ini has `memory_limit = 512M` |
| PLUGIN_SLUG env var confusion | Wrong version installed or double-install | PLUGIN_SLUG is for dependencies only; audited plugin always via `docker cp` |
| Activation hooks don't fire via DB | Missing tables, missing defaults | Use `activate-plugins.php --with-hooks` or run activation SQL manually |
| Pretty permalinks missing | REST `/wp-json/` routes 404 | `wp rewrite structure '/%postname%/' --hard` |
| Settings page loaded via JS/AJAX (3h) | `get_page_text`/`read_page` misses the field right after navigation | Wait briefly and re-read before concluding "not found"; if still absent after 2-3 tries, note `could not verify` and move on |
| Login redirect loop (3h) | `navigate` to wp-login.php doesn't land on wp-admin | Check the final URL, not just response code; a stale/expired session cookie in the connected browser is the usual cause — start a fresh tab |
| Option format corruption | Plugin crashes on load | Check format before modifying; write back in same format (JSON→JSON) |
| WP-CLI eval crashes | Plugin init error kills eval | Use direct PHP via `docker compose exec -T wordpress php /tmp/script.php` |
| Nonce ≠ Authorization | PoC fails "nonce not found" | Nonces are CSRF tokens, not authz. Handler may still be callable with self-generated nonce |
| UI gating ≠ handler gating | UI hidden for role but handler unprotected | Always test handler directly regardless of UI visibility |
| Sub-component resets on reactivation | Routes disappear after plugin reactivate | Re-enable sub-component; avoid full deactivate/reactivate after Stage 3 |
| `add_option()` skips update hooks | Capability grants don't fire | Use `update_option()` (delete first if needed) or trigger side-effects directly |
| Container naming | `docker cp` target wrong | Project: `wordpress-plugin-auditor-wordpress-1`, `wordpress-plugin-auditor-db-1` |
