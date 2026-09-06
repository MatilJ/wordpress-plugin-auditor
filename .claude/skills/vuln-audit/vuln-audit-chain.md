# Vuln-Audit Chain — Phase 2C: Reconciliation + Vulnerability Chaining

> Authorized Wordfence bug-bounty research (see `AUTHORIZATION.md`). Loaded alongside core `SKILL.md`. Read ALL checkpoint files, auth-model.md (Foundation facts + Group AC verdicts + **all impact-group addenda**), findings.md, and leads-forward.md (the **full SINK LEDGER** + all `Relevant-to: Chain` leads) before starting.

This pass has two steps. **Step 1 (Reconciliation)** closes the backward-flow gap: earlier
groups (Foundation, AB, AC) run before the impact groups discover new sinks and reachability
facts, so a discovery made late can invalidate an earlier group's "benign / dismissed" verdict.
**Step 2 (Chaining)** combines confirmed findings for maximum impact. Run Step 1 first — a
reconciliation finding it produces becomes an input to Step 2.

## Phase 2C — Step 1: Reconciliation (re-open earlier-group questions)

The impact groups (A/SQLi/C/D1/adv) append to `auth-model.md` and the SINK LEDGER *after*
AB/AC have already assigned their verdicts. Nothing re-examines those late discoveries through
the access-control / auth-bypass lens — that is this step's job. Work three inputs:

1. **Unconsumed sinks** — every SINK LEDGER row whose `Consumed-by` is `(none)`. No impact group
   claimed it for its tier; it is the classic orphan-sink miss. For each: establish the auth floor
   from `auth-model.md` and re-verify reachability against source. If a low-privilege (unauth /
   Subscriber / Customer) actor reaches it and it is a real in-scope sink (RCE, file op, SQLi,
   stored XSS write, options/content write, etc.), it is a finding. Read the sink function's own
   body directly before accepting its `Wraps`/`Missing` column values — Foundation's inventory
   description is a first-pass approximation and may understate OR overstate the sink's actual
   filtering; separately check whether an independent wrapper at the call site provides its own
   mitigation regardless of what the sink itself does internally.
   - **Non-empty `Consumed-by` does not mean every relevant tier evaluated the sink.** A single
     sink (e.g. a `do_shortcode()` call) can be independently relevant to multiple tiers (XSS,
     email/header injection, Tier 1 Code Injection); `Consumed-by` only proves the LISTED groups
     evaluated it for THEIR OWN tier. Before treating a row as fully resolved, check whether its
     `Type`-implied owning group (SINK LEDGER §5's `Type` column: `sqli`→SQLi, `xss`→C, `file-op`/
     `rce`/`poi`→A, `ssrf`→D1 (OOS)/`other`→case-by-case) actually appears in `Consumed-by` — if
     not, re-run that owning tier's analysis on the sink yourself before moving on.
2. **Impact-group auth-model addenda** — each `## Addendum — Group X` table records handlers/sinks
   the group found while tracing its tier. For any handler that AB/AC did not evaluate: ask "would
   AB/AC have flagged this as missing authorization, IDOR, privilege escalation, or an auth bypass?"
3. **`Relevant-to: Chain` leads** — LEADS the impact groups explicitly forwarded (e.g. an
   option-write that feeds a sink another group owns). Always re-derive any stated
   prerequisite/gate assumption in the forwarded lead directly from source before accepting it —
   a prior group's characterization of a gate (e.g. "requires plugin X active", "behind a
   capability check") may be incorrect; this pass exists specifically to catch defects that
   survived an earlier group's flawed assumption, not just to re-run its conclusion.

4. **Non-standard auth-floor consolidation** — when 2+ confirmed findings across different impact
   groups share the SAME custom, non-WordPress-native gating mechanism (→ Foundation Phase F1's
   "custom non-WordPress authentication pipeline" fact), do not let each finding independently
   characterize its own auth floor. Determine ONCE, with full source verification: (a) is the
   mechanism confirmed cryptographically unforgeable (no bypass found by the Auth-Bypass group)?
   (b) is the credential it requires ever distributed to any customer/end-user tier, or does it
   exist solely on the vendor's own infrastructure? Record this as an explicit "Auth-floor scope
   assessment" note covering every finding sharing the gate (not a per-finding CVSS change), and
   surface it prominently in the Chain-pass output — this determination is frequently the deciding
   factor in whether the researcher submits the affected findings, since the standard
   PR:N/Contributor/Subscriber taxonomy doesn't cleanly describe a vendor-infrastructure-only
   credential requirement. Do not resolve this ambiguity yourself; document the assessment and let
   the researcher decide.

5. **Confirmed finding's own primitive re-examined for broader reach.** A finding first
   characterized as "self-only" (e.g. an attacker can plant a payload only into their OWN
   record, or can only view their own data) may share its write/read sink with a SEPARATE
   authorization gap discovered later (e.g. a missing-ownership-check endpoint reaching the
   SAME sink) that extends it to target an arbitrary victim. Re-trace each confirmed finding's
   write/read sink against every other confirmed finding and leads-forward entry sharing that
   sink before finalizing severity — the combination is Root Cause Count ≥ 2 (its own separate
   finding, per the test below), not a CVSS bump folded into the original.
6. **Branch-conditional scoping mismatch.** A handler that resolves "whose record" via two
   different mechanisms in an if/else — a session/cookie-derived identifier on the common path,
   and a bare request-supplied value (email, token, slug) as a fallback when that identifier is
   absent — can be correctly self-scoped on the primary branch while the fallback branch has no
   ownership binding at all. An earlier group's "self-scoped, not a finding" verdict on such a
   handler reflects only the branch it traced; when re-examining any handler named in an
   addendum or a forwarded lead, verify every conditional branch's scoping mechanism
   independently rather than accepting the earlier verdict at face value.

For each candidate, ask: **"Does this newly-surfaced sink/fact turn a previously-benign or
previously-dismissed endpoint into a missing-auth / IDOR / auth-bypass / privilege-escalation /
RCE / file-op finding?"** If yes AND confidence > 90% AND it passes the core Phase 4 FP gate and
scope gate (Contributor/Author floor and SSRF remain OOS), write it to `findings.md` as a
**net-new finding** with its own CWE/CVSS/auth-floor — this is a real defect the relay's forward-only
ordering would otherwise have dropped, NOT a CVSS elevation of an existing finding. Then feed it
into Step 2. Record each unconsumed sink you resolved by setting its `Consumed-by` to `Chain`.

Log: `[RECONCILE] <sink/fact> @ file:line → <verdict: new finding CWE-xxx | dismissed: reason>`.

## Phase 2C — Step 2: Vulnerability Chaining for Maximum Impact

**Wordfence awards bounty multiplier for chained findings.** After confirming any finding (including reconciliation findings from Step 1), run this analysis. Chained finding escalating to admin reported as single elevated-severity finding.

> "What can an attacker do NEXT with the access or data this vulnerability provides?"

### Chain patterns

#### Stored/Reflected XSS → Admin Account Creation — does NOT elevate CVSS/bounty (Wordfence-confirmed)
JS payload `fetch('/wp-admin/user-new.php')` → parse `_wpnonce_create-user` → POST with `role=administrator` → full compromise is a real, valid technical exploitation path and may still be described in the report's Impact/PoC narrative to illustrate realistic severity. **But it does NOT elevate the finding's CVSS or bounty, and must NOT change the report/registry title to "XSS leading to Admin Account Creation."** Confirmed directly with Wordfence: any XSS that reaches an authenticated admin session can reach `wp-admin/user-new.php` (or any other admin-only screen) — this is generic to the CWE-79 class itself, true of literally every XSS regardless of which plugin carries it, not a plugin-specific second defect being chained. Report and score strictly at the XSS's own base severity (reflected: typically ~6.1; stored: typically ~120-value class, scored per its own auth floor/reach). This is the general rule for **any** XSS chained only to generic WP-Core admin-session functionality (creating a user, flipping a core option via wp-admin, etc.) — the exception does not extend to genuine multi-defect chains (Root Cause Count ≥ 2) where the XSS combines with a SEPARATE plugin-specific defect (e.g. a CSRF gap, a second missing-auth sink) to reach impact; those still elevate normally per the Root Cause Count test below.

#### Missing Auth / IDOR → Options Update → Priv Esc
Auth-bypassed `update_option()` → write `wp_user_roles` (any role → admin), `default_role` (→ administrator), `admin_email` (→ recovery takeover), `siteurl`/`home` (→ redirect to attacker domain). The same mechanism applies when the hijacked option is a linked third-party/SaaS-service credential (API key, linked-account ID) that a later render path uses to construct a remotely-hosted `<script>`/iframe URL: the credential swap grants the attacker indefinite, unconstrained control over content executed in every visitor's browser — a supply-chain-equivalent impact scored at that reach, not a bounded config-field hijack.

#### Blast-Radius Amplification via Intermediate Action Hook Inside a Sink Function
A confirmed sink function (delete/update/write) may itself fire a WordPress action hook mid-execution, BEFORE completing its own side effect — the caller-facing sink is not the last thing that happens. For any confirmed finding, read the sink function's full body (not just the flagged call) for `do_action()`/`apply_filters()` calls, then enumerate what is registered on that hook. Plugin-internal "trusted caller" logic (data-migration, cascade-cleanup, revision/history splicing) commonly assumes the hook only fires from an already-authorized path — the missing-auth defect that reaches the sink also reaches this intermediate logic, and it may propagate the unauthorized operation's effect onto a SECOND object never directly targeted by the attacker (e.g. splicing an unauthorized-deletion victim's own history onto an unrelated object, or trimming that second object's own legitimate records to make room). This is a Root Cause Count = 1 pattern — same defect, broader documented blast radius, not a new finding: elevate the existing finding's Chain Assessment (CVSS may stay unchanged if the CIA vector doesn't move) rather than filing a second entry.

**Variant — delayed trigger via a routine, third-party action, not the attacker's own request:** the intermediate hook does not need to fire within the same request that reaches the sink. An earlier, separately-confirmable defect (e.g. an IDOR/missing-ownership-check write) can plant an attacker-chosen ID into persisted post/comment meta; a hook that fires later as a side effect of an unrelated, ordinary operation performed by a DIFFERENT user (e.g. a moderator trashing/deleting the object the attacker created) then reads that meta and performs a destructive/privileged operation on the attacker-chosen ID with no re-validation of ownership. Still Root Cause Count = 1 — the moderator's routine action is not a second defect — elevate the planting defect's own finding with this escalation path documented in its Chain Assessment; do not file the downstream hook-triggered sink as a separate finding.

#### Mass Assignment → Option Update Hook → Capability Grant → Priv Esc (CVSS 8.0–9.8)
Auth-bypassed bulk POST merge → `update_option()` → `update_option_<name>` hook fires → `add_cap()` for attacker-controlled role array → subscribers gain plugin capability → all handler behind that capability now subscriber-accessible.

#### SQLi → Admin Credential Theft / Direct DB Write
Read: `user_pass` hash → crack, `session_tokens` → hijack, `auth_key` → forge cookies (only viable when auth keys are stored in `wp_options` — standard WP installs define these as PHP constants in wp-config.php, so `wp_options` rows are absent; verify before reporting cookie forgery as reliable).
Write: `UPDATE wp_users SET user_pass=MD5('x')`, `INSERT INTO wp_users` + admin capabilities, `UPDATE wp_options...wp_user_roles`.

#### Arbitrary File Delete → Install Wizard → Admin (CVSS 10.0)
Delete `wp-config.php` → install wizard → new DB config + admin. Always check for unconstrained file delete.

#### Arbitrary File Read → wp-config.php → Full Compromise
`wp-config.php` yields DB credentials + auth salts (→ forge any auth cookie).

**Escalation taxonomy (assess all paths when file read confirmed):**
1. **wp-config.php → Auth Salt Cookie Forgery → Admin Takeover:** Auth salts (`AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY` + salt variants) enable forging admin authentication cookies without knowing the password. The `logged_in_` cookie is `HMAC(username|expiration|session_token, HMAC(username|expiration, wp_hash(username|expiration, 'logged_in')))` where `wp_hash()` uses `LOGGED_IN_KEY` + `LOGGED_IN_SALT`. With salts known, attacker computes valid cookie for user ID 1 (admin). DB credentials enable direct database manipulation as an alternative path.
2. **wp-config.php → DB Credentials → Direct Admin Insert:** Connect to MySQL with extracted `DB_USER`/`DB_PASSWORD`/`DB_HOST` → `INSERT INTO {$table_prefix}users` + admin capabilities row in `{$table_prefix}usermeta` → full admin access. Table prefix is also in wp-config.php.
3. **Combined file read + file delete chain:** When plugin has BOTH arbitrary file read AND arbitrary file delete (common): read `wp-config.php` for DB credentials first, then delete `wp-config.php` to trigger install wizard → attacker reconnects with known credentials and creates new admin. Document both steps.
4. **wp-content/debug.log → Secondary Credential Harvest:** `WP_DEBUG_LOG` writes PHP errors, DB queries, and stack traces to `wp-content/debug.log`. May contain API keys, payment gateway secrets, email credentials, internal paths. Often accessible when `WP_DEBUG` was enabled temporarily and log was never cleaned.
5. **Plugin config file read → API Key Theft:** Many plugins store API keys in PHP config files (payment gateways, email services, SMS providers, social media APIs). File read allows extracting these keys for abuse outside the WordPress installation.
6. **Verify the read primitive's own type/extension restriction before claiming this escalation.** A file-read sink gated by an allowed-extension dispatch (e.g. an image-proxy/thumbnail script restricted to `.jpg`/`.jpeg`/`.png`/`.gif`) categorically blocks every target above whose name doesn't end in an allowed extension — `wp-config.php`, `debug.log`, `.htaccess` are unreachable through it regardless of traversal depth. Confirm the actual gate (extension dispatch, MIME sniff, or none) before asserting this chain is viable.

#### PHP Object Injection → RCE via POP Chain (CVSS 8.8–9.8)

**Prerequisites:** Confirmed unserialize/maybe_unserialize sink with user-reachable input.

**Step 1 — Gadget inventory:**
- Read `POI_MAGIC_METHODS` grep results for plugin-defined `__destruct`, `__wakeup`, and `__unserialize` (entry points) plus `__toString` and `__call` (intermediate gadgets)
- Read `POI_BUNDLED_LIBRARIES` results for phpggc-compatible libraries
- Check `vendor/`, `lib/`, `third-party/` dirs for: GuzzleHttp (6.x/7.x), Monolog (1.x-3.x), TCPDF, FakerPHP, Symfony components, Doctrine, Illuminate, SwiftMailer, Dompdf
- If `composer.lock` exists, read exact versions

**Step 2 — Known chain lookup:**
- GuzzleHttp: FnStream/__destruct (6.x+), PumpStream (7.x)
- Monolog: BufferHandler/__destruct → StreamHandler (1.x-3.x)
- Illuminate: PendingBroadcast/__destruct (5.5-9.x)
- Symfony: Process/__destruct (various)
- TCPDF: destructor-based file deletion
- FakerPHP: ValidGenerator magic methods
- Contact Form 7: file deletion chain
- SwiftMailer: SimpleSerialization (FW1-FW4 file write, FD1 file delete)
- Dompdf: file deletion chain (FD1, 1.1.1+)
- WordPress Core: no known unpatched POP chain since WP 6.4.2 (WP_HTML_Token patched)

**Step 3 — Scoring:**
- Known phpggc chain with matching version → CVSS 9.8 (adjust PR per auth floor of deserialization sink)
- Plugin-defined `__destruct`/`__wakeup` with file_put_contents/unlink/exec → CVSS 9.8 (custom chain)
- Plugin-defined `__destruct` with DB write only → CVSS 8.8
- No exploitable chain found → report POI sink, note absence, CVSS per data-flow impact. Add note: "POP chain not identified in current version; exploitability may increase with plugin updates or site-specific library additions"

**Document:** `Chain path: [unserialize sink] → [gadget class]::__destruct → [impact] | Gadget source: phpggc/plugin-defined/none found`

#### Subscriber/Customer Write → Stored XSS in Admin → Admin Takeover
Profile fields in admin Users list, review/booking meta in admin screens. Writable by Subscriber + rendered unescaped in admin → session compromise → new admin.

#### Authentication Bypass → Direct Admin Access
Endpoint sets auth cookies/sessions/resets passwords without verifying credentials. Auth as any user including admin? Set password for any user ID? Set admin email without current-password? → Auth Bypass → Admin (highest reward).

#### Empty Secret Auth Bypass → REST Admin Account Creation (CVSS 9.8)
Unconfigured plugin secret (empty `get_option()`) → REST API auth bypass on permission callback → `POST /wp-json/wp/v2/users` with `role=administrator` → full site compromise. Verify: (1) plugin has REST endpoint requiring the empty secret for auth; (2) endpoint allows admin-level actions (user creation, option update); (3) plugin has no mandatory setup wizard forcing secret configuration.

#### OAuth Token Forgery → User Impersonation → Admin Takeover (CVSS 9.8)
Attacker supplies victim's email via unverified social login callback → plugin calls `get_user_by('email', ...)` → `wp_set_auth_cookie($user->ID)` → authenticated as victim. If victim is admin = full compromise. Empty Google login parameter → `get_users(['meta_value' => ''])` → first user with social meta (admin) returned → admin session. Verify: (1) social login callback does not verify OAuth token against provider endpoint; (2) email or user_id from request accepted without cryptographic binding.

#### Predictable Token → Targeted Admin Login (CVSS 9.8)
`md5(1)` = `c4ca4238a0` (deterministic for admin user_id=1). Auto-login URL with computed token → `wp_set_auth_cookie(1)` → authenticated as admin. `substr(md5($user_id), 0, 10)` as auto-login token, feature cannot be disabled. Verify: (1) token generation algorithm uses only public/guessable inputs; (2) token is the sole gate before auth cookie; (3) no rate-limiting or IP binding on the auto-login endpoint.

#### Loose Comparison Bypass → Session Hijack → Admin Actions (CVSS 9.8)
`json_decode('true') == "stored_secret"` passes PHP type juggling → auth cookie set for attacker → full admin session. `json_decode($body)->wptc_token == get_option('token')` → sending `{"wptc_token":true}` bypassed token check. Verify: (1) `==`/`!=` used, not `===`/`!==`; (2) user input undergoes `json_decode()` producing non-string type; (3) comparison gates auth function call.

#### wp_authenticate_application_password() Null Bypass → REST Admin Account Creation (CVSS 9.8)
Invalid credentials → `wp_authenticate_application_password()` returns `$input_user` (null when feature disabled) → plugin treats null as non-error → `wp_set_current_user($username)` → impersonates admin → `POST /wp-json/wp/v2/users` with `role=administrator`. Verify: (1) `is_wp_error()` check absent after auth call; (2) null/error return not handled; (3) subsequent code calls `wp_set_current_user()` or grants privileges.

#### Auth Bypass on SMTP/Email Log → Password Reset Token Harvesting → Admin Takeover (CVSS 9.1)
Auth-bypassed endpoint exposes email logs → find password reset email (within 24h TTL) → visit reset URL → set new password. Verify: endpoint returns full email body, log retention > token TTL, reset URL extractable.

#### Missing Webhook Signature → Payment Manipulation (CVSS 7.5–9.1)
Forged webhook → handler routes on `event_type` → trusts `resource` from forged JSON → writes terminal state (failed/cancelled/refunded). Escalates to 9.1 if can forge `PAYMENT.CAPTURE.COMPLETED`.

#### Nonce-Vending Public REST → Nonce-Only Permission Callback → Unauth Privileged Action (CVSS 5.0–7.5)
`__return_true` route + handler calls `wp_create_nonce('wp_rest')` → visitor gets UID-0 nonce → sends to sibling route with nonce-only `permission_callback` → `wp_verify_nonce()` passes (same UID-0) → unauth action.

#### Info Disclosure → Resource-Secret-Gated Write (CVSS elevated to the write's own impact)
Distinct from the nonce-vending pattern above: here the attacker doesn't reuse their OWN token across routes — they harvest a DIFFERENT USER'S per-resource bearer secret (order key, share token, reset key, invite code) via an unrelated info-disclosure bug, then present it to a SEPARATE write endpoint elsewhere in the plugin that authorizes solely by that secret's validity (no session/account-identity binding). Check: (1) does any confirmed/candidate info-disclosure finding return a value that is ALSO accepted as a bearer credential by a different handler in the same plugin (grep the disclosed field name — `order_key`, `token`, `key`, `code` — against every `key_is_valid()`/`hash_equals()`/direct-comparison call site); (2) does the write's own gate check possession only, with no `is_user_logged_in()`/`current_user_can()`/`get_current_user_id()` binding to the resource's actual owner (→ see Group AC "Order-key possession ≠ account ownership for durable-state writes"). Root Cause Count = 2 (disclosure + write are independently confirmable defects) — elevate the write finding's CVSS for the chain per the Root Cause Count test below; do not create a third "chain finding."

#### Low-Auth → Backup/Export Archive → Direct HTTP Download → PII Exfiltration (CVSS 6.5–8.8)
A low-privilege/unauthenticated actor obtains a web-accessible backup/export archive URL under `wp-content/uploads/` (no HTTP-deny) and downloads sensitive data (PII, credentials, records) via direct GET. Two acquisition vectors:
- **Trigger-to-generate:** actor hits a purge/bulk-delete/export endpoint that WRITES `{uploads}/[plugin]/[sub]/export-{time()}.csv`, with the filename predictable (Unix timestamp/sequential counter) OR the URL returned in the 200 response body (grep `TIME_BASED_EXPORT_FILENAME` for the file-creation side). Combined with missing-auth/IDOR on the trigger: C:H/I:H/A:H, qualifies for Chaining Master bonus (+15%).
- **Disclose-to-discover:** a weaker-auth diagnostic/debug/support endpoint LEAKS an internal filename/hash/path token for an EXISTING archive; the actor derives the URL and downloads it. Viable when the identifier is the sole enumeration protection (no per-request auth token) and the storage `.htaccess` blocks only PHP execution, not data extensions (ZIP/SQL/DAF/CSV) — Nginx ignores `.htaccess` entirely. Grep `EXPORT_FILE_PREDICTABLE_PATH` + `LOG_FILE_PUBLIC_WRITE`; cross-ref the Tier 10B three-condition check.

### Confirming and documenting a chain

Before recording: verify each hop is real code, attacker can reach hop 1, each intermediate step reachable, final outcome achievable.

**Branch-mutual-exclusivity check before combining findings.** When two confirmed findings share the same enclosing function/file, do not assume they compound — trace whether a boolean/mode parameter (e.g. a `$local`/`$is_rest`-style flag selecting between two code paths) routes each finding's sink into a mutually exclusive branch. If so, no single request can trigger both; document the reconciliation (which branch each finding occupies, and the flag/condition that separates them) and keep them as separate, non-combined findings rather than filing or scoring a chain.

#### Registry entry count: Root Cause Count test

Count the distinct **plugin code defects** exploited in the chain. A "code defect" is a specific location in the plugin source where the developer made a security mistake (missing auth, missing escaping, missing validation, etc.). Standard WordPress core behavior (nonce generation by any authenticated user, admin pages like user-new.php, cookie handling, wp_users table structure) is NOT a code defect.

**Root cause count = 1 (impact-demonstration chain):**
The chain shows what an attacker can DO with a single vulnerability. Examples: SQLi → credential theft via wp_users; File Read → wp-config.php secrets. In these examples the vulnerability's OWN mechanism directly discloses/controls the sensitive data — the elevated CVSS reflects what the primary defect itself reaches, not a separate WP-Core feature bolted on afterward.

- Elevate the existing finding's CVSS in findings.md. Do NOT create a new finding section.
- Add chain metadata to the existing finding: `Chain assessed: Yes | Chain viable: Yes | Chain path: [base] → [intermediate] → [final] | Chain CVSS: [score] | Chain notes: [reasoning]`
- ONE registry entry with the elevated CVSS and summary mentioning the chain outcome (e.g., "SQL Injection leading to Credential Theft")

**Exception — XSS chained only to generic WP-Core admin-session functionality does NOT elevate (Wordfence-confirmed):**
Any XSS (reflected or stored) whose "escalation" step is nothing more than an authenticated admin's session reaching standard WP-Core admin functionality (`wp-admin/user-new.php`, an options-page toggle, etc.) is NOT a Root-Cause-Count=1 elevation case, even though only one plugin defect is involved. Unlike the SQLi/File-Read examples above, the XSS itself does not directly reach the sensitive action — any admin session can already do that, with or without this plugin's bug. Score and report at the XSS's own base severity; document the chain path in the finding's Chain Assessment section as a technical note only, not as CVSS justification. See the "Stored/Reflected XSS → Admin Account Creation" chain-pattern entry above for the full rationale.

**Root cause count >= 2 (multi-defect chain):**
Two or more independently exploitable plugin code defects chain together. Each defect is reportable on its own, even without the chain. Example: Missing Auth on toolkit download (defect at file A) + htaccess gap allowing direct backup download (defect at file B).

- N findings in findings.md (one per defect), each independently documented
- N registry entries (one per defect)
- The chain-elevated finding (typically the highest-impact one) gets the elevated CVSS and summary noting the chain (e.g., "Missing Authorization Chain: Subscriber+ Full Site Backup Download")
- The base finding(s) get chain metadata cross-referencing the elevated finding
- NEVER create an N+1 "chain finding" — the chain is documented within the existing findings, not as a separate entry

---

## Adversarial reasoning (absorbed from Group adv)

Group adv was collapsed into this pass (0 lifetime TP under its own label; its
findings always reclassified to their impact type). Run the following AFTER Step-1
reconciliation, as part of the cross-tier chaining sweep. The draft-status /
`parse_args` access-control half moved to `vuln-audit-group-ac.md`.

### Tier 12 — Race Conditions (CVSS varies, min ~7.1)
- File upload: check-then-move in separate steps.
- One-time tokens checked and invalidated in separate queries.
- Rate-limiting relying on DB state.
- FP rule (second-order via cron/background jobs): cron processing DB-stored URLs/data planted by an earlier attacker request = second-order injection. Trace cron handler → DB column → write path.

### Tier 13 — Business-logic classification (mostly OOS)
Business-logic flaws are **OOS** when the demonstrated impact is primarily business/revenue/transactional (payment/checkout bypass, pricing manipulation, discount/coupon abuse, order/cart workflow abuse, loyalty/points/quota abuse, rate-limiting CWE-799/770, unlimited voting/liking, resource-exhaustion DoS). When a state/workflow/idempotency flaw yields a **direct security impact**, classify it in its true group, do not double-report:
- Workflow / sequential-state bypass (CWE-841) or one-time-action / idempotency replay (CWE-840) reaching an **auth/identity** sink (login, set-password, activate/verify account) → **Group AB**.
- Self-service **account-state** escalation (CWE-639: membership/plan/tier/verification/approval written from request) → **Group AC**.
- Generic missing capability/nonce on a state change → **Group AC**; per-record ID without ownership check → Tier 11 IDOR (Group AC).

### Beyond the Checklist — the checklist is a floor, not a ceiling
- **Weaponize features:** import/export, previews, templates, log viewers — user-facing functionality with unintended security side effects.
- **Trace sensitive data:** credentials, tokens, PII through storage, display, export, email, logs, error messages, API relay (structured methodology is Group D1's Tier 10 — apply it first, then look for plugin-specific flows).
- **Chain benign into dangerous:** public nonce + settings update; safe read + unsafe write to same table; combinatorial gaps between tiers.
- **Challenge assumptions:** plugin trusts its own stored data? assumes only its UI calls endpoints? assumes field types, numeric IDs, safe filenames?
- **Setup/migration paths:** wizards and first-run handlers with reduced auth that persist post-setup.
- **Unusual entry points:** cron processing attacker-planted data, `the_content` filters, widget renders, oEmbed, PDF/CSV export pipelines.
- **Audit JavaScript:** DOM XSS via `innerHTML`, `eval()`, `jQuery.html()`, unsafe `postMessage`, URL linkification missing `"` encoding.
- **WP-CLI / UI-less REST routes:** often weaker `permission_callback`.
- **"Boring" shared code:** utility classes, helpers, traits, base classes — one flaw multiplies across all consumers.
- **AJAX content renderers — `post_password_required()`:** nopriv/WC AJAX handlers that fetch and render post/product content must call `post_password_required()` before rendering. Password-protected posts have `post_status='publish'`, so gates using only `->get_status() !== 'publish'` with `&&` logic bypass for that content class.

### FP rules absorbed from Group adv
- **Public export/backup files:** when `CSV_EXPORT_SURFACE` / `TIME_BASED_EXPORT_FILENAME` / `EXPORT_FILE_PREDICTABLE_PATH` surface a class writing backup/export files to `uploads/[plugin]/`, verify (a) an `.htaccess`/deny rule restricts HTTP access; (b) the filename is unpredictable (`time()`, sequential ID, static string, or `uniqid()` = guessable; `wp_generate_password()`, `wp_hash()`, `bin2hex(random_bytes())` = safe); (c) the file URL is not returned in the API response. Missing any one = sensitive-file disclosure; missing (a) + guessable = unauthenticated access.
- **Dead code / reachability:** confirm a function is actually called before deep investigation. Freemium PRO code behind `is_pro()`/`is_premium()` or `defined('PLUGIN_PRO')` constant gates (constant defined only by a separate premium add-on) is dead in the free version = FP. Verify REST controller `register_routes()` is reached from `rest_api_init`, factory/dispatcher methods are actually called, and a method name matching a WP action is really registered via `add_action()` before investigating.
- **REST route CSRF-chain viability:** a route dispatched through `register_rest_route()` inherits WP Core's own `rest_cookie_check_errors()` cookie-nonce enforcement — a request lacking a valid `_wpnonce`/`X-WP-Nonce` is silently downgraded to an anonymous (uid=0) request BEFORE the route's `permission_callback` runs, so its `current_user_can()` check fails closed and an off-site CSRF cannot forge that nonce. A candidate CSRF chain against a standard REST route is therefore non-viable unless the plugin's own dispatch bypasses the REST layer entirely (see the `MANUAL_REST_REQUEST_CONSTRUCTION`/E.12 alternate-dispatch pattern in Group AB).
