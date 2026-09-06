# Skill: WordPress Plugin Vulnerability Audit

## Purpose
Systematic source code security audit of WordPress plugins, themes, and core.
Follow all phases in order.

## Scope & Authorization
Authorized in-scope research for the Wordfence Bug Bounty Program: defensive, coordinated-disclosure work on public plugin source, tested only on local installs. Findings reported privately to Wordfence. Basis/scope: `AUTHORIZATION.md` in the wordpress-plugin-auditor project root.

## Canonical Definitions

**CANON:entity-encoding** — HTML entity encoding (`&#60;`) is NOT an XSS vector. Per WHATWG spec, character references in Data state resolve to character tokens (text), never tag openers. Entity-encoded payloads render as visible text, not executable HTML. Entity attribute injection (`&#39;`/`&#34;`) also NOT exploitable — decoded values are APPENDED to attribute values, not processed as terminators. Entities become executable ONLY via: (1) server-side `html_entity_decode()`, `htmlspecialchars_decode()`, or `wp_specialchars_decode()` before echo; (2) JS `innerHTML`; (3) `srcdoc`/`data:text/html` re-parsing contexts.

**CANON:wp-magic-quotes** — WordPress auto-adds slashes to `$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER` via `wp_magic_quotes()`. Quoted SQL contexts (`WHERE col='$val'`) may be protected. Unquoted numeric contexts (`WHERE id=$val`) remain vulnerable. `wp_unslash()` removes this protection — if called before SQL concat without `prepare()`, SQLi is restored. `filter_input(INPUT_SERVER, ...)` reads from PHP's original SAPI input layer, NOT from the modified `$_SERVER` array — `"` characters pass through unescaped even when `$_SERVER['REQUEST_URI']` would have them backslash-escaped.

**CANON:esc-like** — `$wpdb->esc_like()` escapes ONLY LIKE wildcards (`%`, `_`, `\`). Single quotes pass through unchanged. NOT a SQLi defense. Result MUST flow into `$wpdb->prepare("...LIKE %s", $like)` as a `%s` argument, not interpolated into the format string.

**CANON:nonce-verification** — Trace ALL `wp_create_nonce($action)`, `wp_nonce_field($action)`, and `wp_localize_script()` calls for the nonce action string across the entire codebase. For each creation site, determine the minimum capability to access that page. The lowest-privilege page sets the auth floor. If ANY page accessible without auth embeds the nonce → nonce is public → endpoint is functionally unauthenticated. WordPress does NOT provide a generic endpoint to generate nonces for arbitrary actions. Conversely, if the lowest-privilege emission site requires a capability the attacker role lacks, the nonce acts as de-facto authorization (it is minted only for higher-privileged sessions and is uid/token-bound, so an admin-minted nonce will not validate for a lower-privileged attacker) → raise the auth floor to that capability; an Editor/Admin floor (PR:H) is OOS (note as defense-in-depth), unless a nonce-vendor endpoint mints it for the attacker role.

**CANON:rest-permission-callback** — Named `permission_callback` functions may unconditionally `return true`. Read the body. Nonce-only callbacks (calling only `wp_verify_nonce()`) = zero capability verification. `current_user_can('edit_posts')` (plural, no ID) = global role check, NOT per-resource auth. Per-resource check requires `current_user_can('edit_post', $id)` (singular + ID). For `(?P<id>\d+)` routes, verify the callback extracts the ID and passes it.

**CANON:sanitize-text-field-limits** — Strips HTML tags and normalizes whitespace ONLY. Preserves: `'`, `"`, `;`, `()`, `{}`, `[]`, `:`, `/`, `=`, `+`, `!`, `$`, `*`, `|`, `~`, SQL functions (`SLEEP`, `BENCHMARK`, `CASE`), boolean operators (`OR`, `AND`), comment syntax (`#`, `--`), template syntax (`{{ }}`), PHP callable names (`system`, `exec`, `passthru`). NOT a defense for: SQL, JS, path traversal, SSTI, or callable injection contexts. Only `intval`/`absint`/`(int)` prevent callable injection.

**CANON:capability-meta-exist** — `current_user_can('exist')` is WP Core's universal always-true meta-capability (`WP_User::has_cap()` hardcodes `$capabilities['exist'] = true` for every user object, including guests — `wp-includes/class-wp-user.php`). A self-referential capability string computed fresh per-request for the CURRENT viewer (e.g. `$cap = current_user_can($real_cap) ? 'exist' : 'no_access'`, then passed to `add_menu_page()`/`add_submenu_page()`) is a legitimate, fail-closed idiom — not a broken or bypassable check — since it still gates on `$real_cap` for every request. Before flagging `'exist'`/`'no_access'` as a weak or undefined capability, confirm whether it is computed dynamically from a real prior capability check versus hardcoded as a static literal (only the latter grants universal access).

## Phase 0: Orientation

### Authoritative WP Core Reference
- Reference document: `${CLAUDE_PROJECT_DIR}/wp-core-reference.md`
- Raw source (edge cases): `${CLAUDE_PROJECT_DIR}/wp-core/7.0/wp-includes/`

Read before any grep: main plugin `.php` file (`Plugin Name:` header), `includes/`/`src/`/`classes/` dirs, `readme.txt` (latest stable version).

Document: name/version, PHP entry points, autoloader, bundled third-party libs (check versions vs CVEs), custom DB tables (→ custom queries → SQLi surface).

**Standalone PHP files — check immediately.** Files processing requests without loading WordPress run outside the auth system. Use GREP_RESULTS `STANDALONE_PHP`.

## Incremental Write-Through Protocol

**CRITICAL — applies to ALL phases below:**

1. **Findings:** Write each confirmed finding (confidence >90%) to `AUDIT_DIR/findings.md` *immediately* — do NOT batch to the end. If the pipeline crashes or context compacts, `findings.md` must hold everything confirmed so far.

2. **Tier-group checkpoints:** After completing each tier group, write a checkpoint file:
   - After the Foundation phase: `AUDIT_DIR/checkpoint-foundation.md`
   - After Auth Bypass: `AUDIT_DIR/checkpoint-group-ab.md`
   - After Access Control (missing-auth + IDOR + CSRF): `AUDIT_DIR/checkpoint-group-ac.md`
   - After Tiers 1–2: `AUDIT_DIR/checkpoint-group-a.md`
   - After Tier 3 (SQLi): `AUDIT_DIR/checkpoint-group-sqli.md`
   - After Tiers 5–6: `AUDIT_DIR/checkpoint-group-c.md`
   - After Tiers 8–10: `AUDIT_DIR/checkpoint-group-d1.md`
   - (Group adv collapsed: race/adversarial → Chain pass; draft-status → Group AC)

   Each checkpoint is a COMPACT per-group state record — **target ≤ 40 lines**. It is NOT
   where cross-group information lives; it only summarises this group's own pass:
   - Findings confirmed in this group (one line each; full detail is in findings.md)
   - Key observations this group established (auth-floor refinements, notable dismissals with a one-line reason)

   **Cross-group leads and custom sinks do NOT go in checkpoints** — they go in the
   `leads-forward.md` ledger (§5/§6); auth facts go in `auth-model.md`. This keeps the
   "read ALL prior checkpoints" step cheap as the relay grows: later groups read one lead
   channel (the ledger) + N *bounded* checkpoints, not N growing free-text logs.

   Group files may specify additional checkpoint sections (e.g. Group AC auth-model tables,
   Group AB auth-bypass tables); when defined the group template takes precedence over this
   minimum, but those tables belong in `auth-model.md` — the checkpoint references them, it
   does not duplicate them.

3. **Auth model:** `AUDIT_DIR/auth-model.md` is written by the **Foundation phase** (before any impact group) with FACTS only — custom roles, nonce availability, per-handler gates (see `vuln-audit-foundation.md`). The Access-Control analysis fills the `CIA Impact`/`Verdict` columns; any group that discovers a new auth-relevant fact appends an addendum. Do NOT rebuild the tables from scratch.

4. **Re-read on group entry:** Before starting each tier group, re-read:
   - `AUDIT_DIR/audit-context.md` (structural summary section at minimum)
   - `AUDIT_DIR/auth-model.md` + `AUDIT_DIR/foundation.md` (Foundation facts — your auth floor + custom-sink index; re-verify gates against source before confirming)
   - `AUDIT_DIR/leads-forward.md` — the ledger (§5). Read **every SINK LEDGER row** (bounded, high-value) and grep its callers within your tier's code paths; read **only the LEADS rows tagged `Relevant-to` your group / `Any` / `Chain`**. Do not re-read LEADS addressed to other groups.
   - Latest checkpoint file (if any exist)
   - The tier-group's grep file: `AUDIT_DIR/grep/group-X-results.md`

5. **Cross-group ledger (`AUDIT_DIR/leads-forward.md`):** a single structured, **deduplicated**
   file with exactly two sections — the SINK LEDGER and LEADS. It is the ONLY channel for
   cross-group information (checkpoints hold per-group state only). Foundation initialises it;
   every group appends to it. Structure:

   ```
   ## SINK LEDGER   (deduped by fn@file:line — one row per sink; update in place, never duplicate)
   | Sink | Type | Wraps | Missing | Auth-floor | Callers | Consumed-by |
   |------|------|-------|---------|-----------|---------|-------------|
   | my_query@inc/db.php:88 | sqli | $wpdb->query | prepare | unauth | 3 | SQLi |
   | render_row@inc/view.php:12 | xss | echo | esc_html | subscriber | 5 | (none) |

   ## LEADS         (deduped; each row Relevant-to a group / Chain / Any)
   ### From Group [X] — [timestamp]
   - LEAD: [file:line] — [description] — Relevant-to: [Group Y / Chain / Any]
   ```

   - **Sink Type** ∈ `sqli | xss | file-op | rce | ssrf | poi | other`. **Consumed-by** lists
     the group code(s) that have already evaluated the sink for their tier, or `(none)`.
   - **Dedup rule:** a sink is keyed by `fn@file:line`. If a row for that key exists, UPDATE it
     (append your group code to `Consumed-by`, refine `Callers`/`Auth-floor`) — do not add a
     second row. Likewise collapse duplicate LEADS to the same `file:line`.
   - **The Chain pass MUST analyse every SINK LEDGER row whose `Consumed-by` is `(none)`** — an
     orphan sink no impact group claimed is the classic cross-tier miss.

6. **Custom sink discovery (feeds the SINK LEDGER):** The Foundation phase pre-inventories
   greppable wrappers in `AUDIT_DIR/foundation.md` (read it first) and seeds the SINK LEDGER;
   this protocol is the backstop for wrappers found during deeper analysis. When analysis
   reveals a plugin-defined function acting as an unprotected sink (e.g. wraps `$wpdb->query()`
   without `prepare`, or echoes a parameter without escaping):
   - **Grep all callers:** `Grep(pattern: "function_name\\(", path: SOURCE_DIR)` — every call site is a potential instance; record the count in `Callers`.
   - **Add/refresh its SINK LEDGER row** (dedup by `fn@file:line`). Set `Consumed-by` to your
     group code once you have evaluated it for your tier, or `(none)` if you are only recording
     it for a later group / the Chain pass.

## Phase 1: Attack Surface Mapping

**Pipeline mode:** `grep_scan.py` has written tier-segmented files to `AUDIT_DIR/grep/`. Read `AUDIT_DIR/grep/surface-results.md` for Phase 1 attack surface data. Each tier group reads its own grep file (group-ab, group-ac, group-a, group-sqli, group-c, group-d1). Run individual greps only to follow up on specific leads.

**Standalone mode:** Run the grep scanner script directly:

    python grep_scan.py "[SOURCE_DIR]" "[AUDIT_DIR]/grep"

Then read `AUDIT_DIR/grep/surface-results.md` for Phase 1 attack surface data.

**GREP_RESULTS section mapping for Phase 1 Attack Surface:**

| Analysis target | GREP_RESULTS section |
|---|---|
| Unauthenticated/authenticated AJAX | `AJAX_HOOKS` |
| WooCommerce AJAX (all users, incl. unauthenticated) | `WC_AJAX_HOOKS` |
| admin_init, admin_menu, admin_notices | `ADMIN_HOOKS` |
| init, wp_loaded, parse_request, plugins_loaded, template_redirect | `INIT_HOOKS` |
| Page builder editor hooks (Elementor, Beaver Builder, etc.) | `PAGEBUILDER_HOOKS` |
| REST API endpoints | `REST_ENDPOINTS` |
| REST field registrations | `REST_FIELD_REGISTRATIONS` |
| wp_rest nonce exposure | `REST_NONCE_EXPOSURE` |
| Shortcodes | `SHORTCODES` |
| Outbound HTTP | `OUTBOUND_HTTP` |
| Redirects | `REDIRECTS` |
| Email sending | `EMAIL` |
| CSV/spreadsheet export | `CSV_EXPORT_SURFACE` |
| WP-CLI commands | `WP_CLI_COMMANDS` |
| Non-AJAX dispatchers (wp_send_json) | `NON_AJAX_DISPATCHERS` |
| Raw action-string dispatch outside wp_ajax_ hook system | `RAW_ACTION_PARAM_DISPATCH` |
| SQL filter hooks | `SQL_FILTER_HOOKS` |
| Block render callbacks | `BLOCK_TYPES` |
| json_encode without JSON_HEX_APOS | `JSON_ENCODE_SURFACE` |
| Admin list tables | `ADMIN_LIST_TABLES` |
| WP_User_Query | `WP_USER_QUERY` |
| GET-based admin dispatchers (CSRF) | `ADMIN_GET_DISPATCHERS` |
| Internal routing frameworks (Slim, FastRoute) | `SLIM_FASTROUTE_ROUTER` |
| Bulk action handler registrations | `BULK_ACTION_HANDLERS` |
| WooCommerce Blocks Store API extension callbacks | `WC_STORE_API_ENDPOINTS` |

**Analysis notes for specific sections (apply when reviewing GREP_RESULTS):**

- **REST_FIELD_REGISTRATIONS:** `update_callback` fires during PUT/PATCH for any user who can edit the parent object; does NOT inherit the parent route's permission_callback. Missing `current_user_can()` in update_callback = any Contributor editing their own post can write the field.

- **REST_NONCE_EXPOSURE:** "nonce-vendor" endpoints handing visitors a valid wp_rest nonce. When found, enumerate sibling REST routes for permission_callbacks calling only `wp_verify_nonce()` without `current_user_can()`.

- **SHORTCODES:** `add_shortcode`: read callback for superglobal reads — `$_POST` w/o nonce = CSRF/unauth write. `do_shortcode`/`apply_shortcodes` with user input: does user control the full expression (name+params) or only VALUES? `apply_shortcodes()` = WP Core alias for `do_shortcode()` (shortcodes.php:223) — treat identically. When shortcode attrs map to WP_Query args, check whether `post_status` accepts non-public values (`draft`, `pending`, `future`, `trash`, `any`) — `perm=readable` does NOT author-scope these, only `private`; a Contributor can read all matching posts from all authors. For access-control callbacks, verify the gate calls `current_user_can()` for the requesting user, NOT `user_can($post->post_author, ...)` for the page author — the latter is a static whitelist on the page, not the visitor: any admin-authored page passes for all visitors regardless of auth. Use `BROKEN_AUTH_LOGIC` to surface this. Also check `DO_SHORTCODE_CONTENT_FILTER` for `do_shortcode`/`apply_shortcodes` registered as callbacks on non-standard content hooks — extends shortcode execution beyond `the_content`.

- **NON_AJAX_DISPATCHERS:** Custom JSON responses routed through WP_Query filter callbacks checking `$_GET`/`$_REQUEST` + `wp_send_json_success()` + exit. Not in wp_ajax_ results. Trace to hook registration; audit capability + nonce gates.

- **RAW_ACTION_PARAM_DISPATCH:** Raw `$_POST`/`$_REQUEST` comparisons against an action-style key (`action`, `task`, `do`, `cmd`, etc.) evaluated outside the `wp_ajax_` hook system — often inside a class constructor or file-scope code that runs on every request. For each hit: trace whether the matched branch calls a sink directly or registers a callback (`add_action()`); determine the floor from the surrounding execution context (→ Phase 4 item 22) rather than assuming Subscriber+ — code that runs unconditionally at construct/load time has an Unauthenticated floor regardless of what the condition checks. Also verify any apparent third-party-plugin dependency is enforced by an actual presence check, not just an action-name coincidence (→ Phase 4 item 4).

- **WC_AJAX_HOOKS:** WooCommerce AJAX, separate from `wp_ajax_*`. `add_action('wc_ajax_{action}', ...)` accessible to ALL users via `/?wc-ajax={action}`. Check: (1) where nonce is created/localized — publicly localized = functionally no auth; (2) ownership/capability beyond nonce; (3) record-level writes → full Tier 11 IDOR analysis; (4) handlers calling `wc_get_product()`/`get_post()` — verify `post_password_required()` is called; password-protected posts have `post_status='publish'`, so `->get_status() !== 'publish'` is bypassable as a sole gate.

- **SQL_FILTER_HOOKS:** SQLi invisible to `$wpdb->*` grep. Plugin callbacks on `posts_where`, `posts_join`, `get_meta_sql` inject SQL fragments WP Core executes. `get_meta_sql` callbacks modify `$sql['where']`/`$sql['join']` array keys.

- **BLOCK_TYPES:** `$attributes` in render_callback is Contributor-controlled via block JSON. A string-typed block attribute passed as the first arg to `wp_parse_args()` → `parse_str()` makes it an associative array — any WP_Query key (`post_status`, `meta_query`, `tax_query`) can be injected; apply the shortcode `post_status` override analysis above.

- **JSON_ENCODE_SURFACE:** `json_encode()` does NOT encode `'`. In single-quoted HTML attributes via PHP interpolation, stored `'` breaks out. Surface calls lacking `JSON_HEX_APOS` or an `esc_attr()` wrapper. **`SCRIPT_BLOCK_ECHO` hits:** `json_encode()` escapes `/`→`\/` (blocks `</script>`) but NOT `<`/`>`. If the JS consumer uses `dangerouslySetInnerHTML`/`innerHTML`/`document.write` on the value, payloads like `<img src=x onerror=alert(1)>` (no slashes) execute; trace JS consumer before dismissing a `<script>`-block echo as safe.

- **ADMIN_LIST_TABLES:** Primary source of search/filter SQLi via the SQL hook pattern.

- **WP_USER_QUERY:** User-controlled args (especially `fields`) can bypass post-query redaction.

- **ADMIN_GET_DISPATCHERS:** Primary CSRF target (CWE-352). SameSite=Lax on auth cookies: top-level GET navigation sends cookies cross-site. Missing nonce + `current_user_can()` only = confirmed CSRF.

- **BULK_ACTION_HANDLERS:** `add_filter('handle_bulk_actions-{screen}', callback)` fires when a bulk action is submitted on an admin list table. WP Core verifies the bulk-action nonce but the callback must enforce its own `current_user_can()`. The page capability (e.g. `edit_posts` for `edit-comments.php`) sets a floor, but lower-privilege users passing the page gate can submit arbitrary item IDs via the bulk form — the handler gets whatever IDs the user POSTs without ownership filtering. Also surface `bulk_actions-{screen}` registrations adding the action to the dropdown without a capability guard (visible to all users who can access the page).

- **WC_STORE_API_ENDPOINTS:** `woocommerce_store_api_register_update_callback()`/`register_endpoint_data()` extend the WooCommerce Blocks Cart/Checkout Store API — reachable at whatever auth level the Store API's own cart/checkout routes allow (guest-accessible by default, since carts are anonymous-session-scoped). The `$cart`/`$request` object passed to the callback is inherently scoped to the caller's own session, so a callback that only reads/writes fields on that object is self-scoped by design (not an IDOR); it becomes a cross-customer issue only if the callback additionally accepts a resource ID from the request body used to look up a DIFFERENT customer's order/data — apply the same ownership-check analysis as Tier 11 IDOR to that case.

- **SLIM_FASTROUTE_ROUTER:** Plugin dispatches through an internal routing framework. When a nopriv AJAX callback is the entry point, the framework's route registry is the real attack surface — enumerate all registered routes and audit each handler's authorization gate independently. Framework auth middleware may have HTTP-method bypass conditions (e.g. verifying nonce only for POST, returning `true` for GET) making state-changing routes fully unauthenticated.

### Custom Role / Capability Architecture Mapping

**Run before analyzing any endpoint.** Use GREP_RESULTS section `ROLE_CAPABILITY_MAPPING`.

Build a **four-column capability grant map**:

| Role name | Capabilities granted | How role is obtained | AJAX/REST handlers gated by these caps |
|---|---|---|---|
| (e.g.) `plugin_host` | `plugin_manage_options` | Public self-registration via nopriv AJAX | `wp_ajax_plugin_action` |

Steps:
1. For every `add_cap()`/`add_role()` hit, record capabilities granted below Editor level.
2. For every AJAX/REST handler, find the capability in `current_user_can()`. Match against Step 1.
3. Mark Contributor-accessible handlers: `[CONTRIBUTOR-ACCESSIBLE]`.
4. For each `[CONTRIBUTOR-ACCESSIBLE]` handler: → See CANON:nonce-verification — determine if a Contributor can obtain the nonce.
5. Can an unauthenticated visitor self-obtain this role? Trace `set_role('custom_role')` to its entry point. If reachable via nopriv hook or public page → role is self-obtainable → endpoints behind that capability are open.

Carry this map into Tier 4.

### WordPress Route → Hook → Auth Quick Reference

| Route | Key hooks | Auth required |
|---|---|---|
| `/` (frontend) | `template_redirect`, `wp_head` | None |
| `/wp-admin/` | `admin_init`, `admin_menu` | Subscriber+ (any authenticated user; `admin_init` has no per-capability gate beyond being logged in) |
| `/wp-admin/{core-file}.php` (post.php, edit.php, users.php, upload.php, edit-comments.php, etc.) | `load-{pagenow}.php`, `admin_action_{action}` | Subscriber+ (any authenticated user). Verified against WP Core: `wp-admin/admin.php`'s core-file dispatch branch calls only `auth_redirect()` before firing `do_action("load-{$pagenow}")` / `do_action("admin_action_{$action}")` — there is NO per-object or per-list capability check ahead of either hook. The page's own `current_user_can()` gate (e.g. `post.php`'s per-post `edit_post` check for the `edit` action) lives in that page's own script and runs strictly AFTER these hooks have already fired. A plugin callback registered on either hook family must perform its own capability check — do not assume it inherits the target page's normal capability requirement |
| `/wp-admin/admin-ajax.php` | `admin_init`, `wp_ajax_{action}`, `wp_ajax_nopriv_{action}` | `admin_init` = none (fires unconditionally, before the `is_user_logged_in()` branch below it — do not pair its floor with the ajax-action figures that follow); nopriv = none; ajax = subscriber+. **`is_admin()` = `true` here — NOT security.** Fires `admin_init` but NOT `admin_menu` — hooks registered inside `admin_menu` callbacks are unreachable via AJAX |
| `/wp-admin/admin-post.php` | `admin_post_{action}`, `admin_post_nopriv_{action}` | nopriv = none; post = subscriber+ |
| `/wp-json/` | `rest_api_init` | None by default; controlled by `permission_callback` |
| `/wp-cron.php` | scheduled hooks | None (public) |
| Any page load | `init` | None |
| Any page load | `plugins_loaded` | None — fires before auth |
| Any page load (front-end AND `/wp-admin/`) | `after_setup_theme` | None — WP Core bootstrap hook, fires before `auth_redirect()` on every request regardless of admin/front-end context |

`admin_init` fires for all authenticated users (Subscriber+) — any logged-in user visiting a `/wp-admin/` URL can trigger `admin_init` handlers (no per-capability gate beyond authentication; PR:L floor, not PR:N). `admin_post_nopriv_` is fully public. `plugins_loaded` and `after_setup_theme` handlers reading superglobals bypass standard routing — audit completely. A callback registered unconditionally in a class constructor that itself runs at file-scope (e.g. a singleton `get_instance()` call executed on `require_once` of the file) is reachable the same way — trace hook registration back to the file's unconditional load path, not just the hook name, before assuming an authentication context.

## Phase 1B: Input Source Enumeration

Use GREP_RESULTS sections `INPUT_SUPERGLOBALS`, `INPUT_STREAMS`, `DB_READS`, `CRYPTO_OPS`.

**Input sources:**
- `$_POST/$_GET/$_REQUEST/$_COOKIE/$_FILES` — primary attack surface
- `$_SERVER` — `HTTP_X_FORWARDED_FOR`, `HTTP_USER_AGENT`, `HTTP_REFERER`, `HTTP_AUTHORIZATION` are user-controlled
- DB reads (`get_option`, `get_user_meta`, `$wpdb->get_results()`, `$wpdb->get_row()`) — second-order injection; rows from user-writable tables carry attacker-influenced values
- `php://input` — REST/webhook handlers; `simplexml_load_string()` without `LIBXML_NOENT` disabled → XXE. **Webhook signal:** `__return_true` endpoint reading `php://input` → check for `hash_hmac()`, signature header, or `*verify*` method → see Phase 2B. Slim/FastRoute routers routinely read `php://input` for JSON body parsing in non-webhook handlers — apply webhook signature analysis only when the endpoint receives callbacks from an external payment/notification provider.
- `filter_input()` — treat as user-controlled; `filter_input(INPUT_SERVER, 'REQUEST_URI')` bypasses `wp_magic_quotes()` (reads SAPI input, not modified `$_SERVER`) — `"` reaches HTML attribute sinks unescaped → See CANON:wp-magic-quotes
- `$wp_query->query_vars` — user-controlled via URL path. Percent-encoding the path prefix (e.g. `events` → `%65%76%65%6e%74%73`) forces `WP::parse_request()` (class-wp.php:239) into its `urldecode()` fallback regex match, bypassing `wp_magic_quotes()` (no-op on `%27`) and `WP_MatchesMapRegex` double-encoding. `parse_str()` then decodes `%27` to a literal unescaped `'`. Treat as **confirmed injectable** when the plugin interpolates `$wp_query->get()` values into raw SQL without `$wpdb->prepare()`.
- Third-party API responses, webhook payloads — untrusted without sanitization

**Crypto/auth intermediary outputs:** Trace as untrusted until: (a) success checked, AND (b) failure halts execution.

**`preg_replace_callback` + `base64_decode` in content filters:** callback on `the_content` matching HTML comments with alphanumeric (base64) inner content, `wp_kses_post()` preserves it (kses passes alphanumeric-only content unchanged), and a Contributor can write the payload → Stored XSS (CVSS ≈ 8.8). Verify: decoded output returned without `wp_kses()`/`esc_html()`.

**Unserialize fast-triage (use TIER1_DESERIALIZATION, SHORTCODE_ATTR_UNSERIALIZE):**
- `[caller: user-controlled]` → Tier 1 priority, begin POP chain analysis
- `[caller: shortcode/widget/block attribute]` → Contributor+ controlled; verify shortcode_atts() doesn't filter value to non-serialized type; begin POP chain at Contributor auth floor
- `[caller: transient/cache/meta/option — server-written]` → requires secondary write-path analysis
- `[caller: magic method]` → check outer `unserialize()` input
- `[caller: unknown]` → read enclosing function, trace manually

Don't spend context on POP chain analysis until the data source is confirmed user-reachable.

## Phase 2: Tier-Ordered Vulnerability Analysis

**Exhaustive scan — do not stop after the first finding.** Every tier applies to every audit.

**Tier-specific methodology is loaded from group files (in run order):**
- Foundation (auth model + custom-sink facts, runs first): `vuln-audit-foundation.md`
- Group AB (Authentication Bypass, runs early after Foundation): `vuln-audit-group-ab.md`
- Group AC (Access Control — Missing Auth + IDOR + CSRF + options/content writes; fills auth-model Verdict/CIA): `vuln-audit-group-ac.md`
- Group A (Tier 1-2: RCE, File Ops, POI): `vuln-audit-group-a.md`
- Group SQLi (Tier 3: SQL Injection): `vuln-audit-group-sqli.md`
- Group C (Tier 5-6: HTML Renderers, XSS): `vuln-audit-group-c.md`
- Group D1 (Tier 8-10: SSRF, Email, Info Disclosure): `vuln-audit-group-d1.md`
- Chain analysis (incl. Tier 12 race + "Beyond the Checklist" adversarial reasoning,
  absorbed from the collapsed Group adv): `vuln-audit-chain.md`
- Adversarial draft-status / parse_args access-control patterns: see Group AC (`vuln-audit-group-ac.md`)

Each group agent reads the shared core (this file) plus its group-specific file.

## Phase 2B: Security Gate Failure Analysis

**Core question:** What happens when this gate FAILS — and does execution actually stop?

**Step 1:** Determine failure return value (read source): `false`, `null`, `0`/`""`, exception, degraded value.
**Step 2:** Trace failure through every caller. Return value compared? Failure branch halts execution?
**Step 3:** Analyze downstream: type coercion (`false` → `""` string, `0` int), library behavior on invalid input, predictability of failure state.

Use GREP_RESULTS `SECURITY_GATE_FUNCTIONS`, `AUTH_INTERMEDIARIES`.

### The "encryption as authentication" anti-pattern

Breaks when: (1) decryption failure not checked → continues with predictable state; (2) key derivable/leaked; (3) cipher mode malleable (CBC without HMAC, ECB, padding oracle); (4) weak key generation. For every encryption-as-auth endpoint: read implementation line by line, read library source, determine all failure modes, check cipher/padding/IV/key derivation/storage.

### Token-based authentication flows

Use GREP_RESULTS `TOKEN_AUTH_FLOWS` and `TOKEN_LOCALIZE_EXPOSURE`. For every token-based flow, answer all seven:
1. **Strict equality?** `===` vs `==`. With `==`: `"0" == false == null == ""` — bypass with predictable value.
2. **Invalidated after use?** `delete_user_meta()`/`update_user_meta()` unconditional on success path?
3. **Expiry enforced?** No TTL = permanently valid.
4. **Token scoped to action?** Reuse across operations = bypass.
   - When a token-verified permission callback gates a destructive endpoint (purge, bulk delete, export), verify the destructive handler applies a scope filter matching the token's validated record ID — verifying a token for record N does NOT restrict the operation to record N unless the handler explicitly filters by that ID.
5. **Entropy sufficient?** `rand()`/`mt_rand()`/`time()`/short hex = brute-forceable. `wp_generate_password(32, false)` adequate.
6. **Multi-step completable out of order?** Step 2 reachable without step 1? User ID in step 2 from `$_POST`?
7. **Token publicly accessible?** Trace ALL `wp_localize_script()`, REST response outputs, and page HTML for the option/variable used as the token. A token correctly compared via `===` provides zero security if it is embedded in frontend JavaScript globals on any public page.

### Webhook Signature Verification

Webhook endpoints via `php://input` or `$request->get_body()` (WP REST pattern) — auth expected from provider's HMAC. Detection: find every `php://input` read and `$request->get_body()` call in files containing `register_rest_route`; check the same function body for `hash_hmac()`, `$_SERVER['HTTP_X_*']` header read, `$request->get_header()` for a signature header, or SDK verify method — none → missing verification (CWE-345). With `permission_callback => '__return_true'`, the vuln is trusting the payload without HMAC. Also read named `permission_callback` functions: one returning `true` when a signing-secret option is empty fails open to unauthenticated callers regardless of handler-body logic — fails-open-on-missing-config is as dangerous as `__return_true`. After confirming → run Phase 2C webhook chain.

### Nonce-only protection on nopriv endpoints

→ See CANON:nonce-verification. `wp_ajax_nopriv_` with nonce-only: if nonce publicly embedded → functionally unauthenticated. **ACF:** `acf_verify_ajax()`/`acf_verify_nonce()` bind to `acf.data.nonce` embedded on public pages → functionally unauthenticated. After confirming public nonce: trace ALL `$_POST`/`$_GET` through full call chain including cross-file hops to Tier 1-6 sinks.

### False-Safe (Illusory) Security Gates

→ See CANON:sanitize-text-field-limits. Functions named `prepare_search()`/`sanitize_query()`/`clean_input()` imply SQL safety. Read the body. Safe only if: `$wpdb->prepare()` with placeholder, `esc_sql()` in quoted context, or numeric cast. Regex DML blocklists (`SELECT.*FROM`) bypassed by `SLEEP(5)`, `BENCHMARK()`, `CASE WHEN`. **Detection trigger:** Any reassuringly-named function in SQL data path must have body read.

### Checklist before Phase 3
- [ ] Failure return values documented from source
- [ ] Every call site checked for return value validation
- [ ] Failure path traced downstream
- [ ] Predictability/exploitability of failure state assessed
- [ ] Token flows: strict equality, single-use, expiry, scope, entropy, step ordering
- [ ] Nopriv + nonce-only: confirmed nonce not publicly embedded
- [ ] Reassuringly-named SQL functions: body read, parameterization confirmed

## Phase 2D: Multi-Function Coverage Check

After confirming a vuln type, grep plugin for same pattern in other functions/widgets/endpoints. Wordfence scaling bonus: +20% each for first 5 functions, +10% per 5 from 6–20, +5% per 5 from 21–50 (cap 50). Verify each instance independently. Document all with `file:line` in findings.md under **Affected Functions**.

## Phase 3: Data Flow Tracing

For each suspicious entry point: `Input source → Sanitization (function+line) → Trust boundary → Sink`

| Source → Sink | Vulnerability class |
|---|---|
| User input → file system path | Path traversal, arbitrary upload |
| User input → SQL query | Injection |
| User input → shell command | Command injection |
| User input → HTML renderer | XSS (SSRF is OOS) |
| User input → PHP execution | RCE |
| User input → template engine render() | SSTI → RCE |
| User input → HTTP request URL | SSRF **(OOS — current program policy, skip)** |
| User input → redirect URL | Open redirect |
| User input → email headers | Header injection |
| User input → unserialize() | Object injection → RCE |
| User input → do_shortcode() | Arbitrary shortcode execution |
| User input → JS via DOM | DOM XSS |
| DB value (attacker-written) → any sink | Second-order injection |
| nopriv write (sanitize_text_field only) → admin render without esc_html | **Stored XSS** (CVSS 8.0+) |
| nopriv write (sanitize_text_field only) → later unescaped SQL read/query by another actor | **Second-order SQLi** (CVSS 6.5+) |
| User-supplied record ID → write/delete without ownership check | **IDOR / Missing Authorization** |
| User-supplied record ID → resource fetch + export or file download without ownership check | **IDOR** (C:L/I:N, CVSS 4.3+) — read-only disclosure qualifies when exported data is non-public (config, credentials, PII) |
| User-supplied key/field projection → PHP object in REST response | **Info Disclosure** — `WP_User` cast-to-array exposes `data->user_pass` |

**Multi-step write flow:** → see Tier 6 "Multi-step write flows" in group-c methodology — hydration overlay may break chain.

**Ownership verification — mandatory for record-level operations.** Capability checks = class-level auth. Instance-level auth requires: (1) fetch record by user-supplied ID; (2) read ownership field; (3) compare against `get_current_user_id()` with strict equality; (4) return 403 on mismatch BEFORE write. The vulnerability is the code NOT there.

## Phase 4: False Positive Verification

Before writing any finding, answer all of these:

1. **Code path reachable?** Trace from HTTP request to sink without assuming conditions.
   - Dynamic property dispatch guarded by `isset($obj->$prop)`: PHP returns `null` for undefined properties, `isset(null)`=`false`, so the guard is an implicit allowlist when the object exposes only defined, typed properties. Verify the full property list before treating as arbitrary property injection.
   - Handler iterating a plugin's registered field/object list (e.g. `foreach ($plugin->get_fields() as $field)`) reading `$_POST[$field['key']]` does NOT process arbitrary POST keys — extra attacker keys are silently ignored; mass-assignment applies only when iteration is over POST keys, not registered objects.
   - Verify write and render paths use the same meta key at every chain hop — similar names (e.g. `review_image` vs `review_image2`) often represent separate data flows; a chain requires the write key and read key to be identical.
   - `update_option()` flagged as CWE-915: confirm the value is a wholesale `$_POST`/`$_REQUEST` copy via `array_merge()` or direct assignment — an array individually built from named, sanitized fields is not mass assignment regardless of field-value origin.
   - JS `innerHTML`/`dangerouslySetInnerHTML` rendering REST/AJAX response data is XSS only if another user can trigger the render with the attacker's payload; if the read endpoint is scoped to `get_current_user_id()` (e.g. `'author' => get_current_user_id()` in WP_Query), the stored content fires only in the attacker's own session — Self-XSS, not reportable.
   - An option/transient write (`update_option`, `Cache::update()`, `set_transient`) flagged as stored-XSS write path: verify the stored value originates from user input (POST/GET/REST body), not a server-fetched third-party API response — plugin caches storing external API data (Instagram Graph, YouTube, WooCommerce, etc.) are not user-controlled write paths → FP.
   - Code reading `$_SERVER['X_FORWARDED_FOR']` (no `HTTP_` prefix): value is always null — PHP maps request headers to `$_SERVER` by uppercasing, hyphens→underscores, prepend `HTTP_` (correct key: `HTTP_X_FORWARDED_FOR`); no attacker header can populate the prefixless key.
   - Callbacks on `save_post`/`post_updated`/`edit_attachment`: WP Core verifies the post-save nonce and `current_user_can('edit_post', $post_id)` before these hooks fire; a callback writing only the saved post's own `$post_id` to plugin settings inherits Core's per-post auth. Confirm it does NOT use attacker `$_POST` values to write OTHER post IDs, other users' data, or global options beyond the saved post's scope — those are NOT covered by Core's pre-hook auth.
   - Taint from `$_POST`/`$_GET` into a rendering function then an `echo` sink: verify whether the tainted value is used only as a DB lookup key (taxonomy slug, post type, term ID) to retrieve DB-stored content — if the function queries the DB with the tainted arg as an index and echoes only DB-sourced values (e.g. `get_taxonomy()->label`, `get_terms()` results) independent of the arg value, the tainted input doesn't appear in output and the chain breaks at the DB read. Read the rendering function body to confirm the output source before flagging.
   - `include`/`require` path resolved via a user-supplied value as a lookup key into a developer-defined static array (e.g. `$templates[$atts['template']]`): user controls only the key, not the values — if the array is populated exclusively from plugin source with no low-privilege write path, path injection is impossible; confirm no endpoint lets attacker data populate the array at runtime.
   - A sink reached via a FUNCTION PARAMETER (not a superglobal/property read directly at the sink) cannot be classified taint-or-not from the function's own body — grep every call site of the function; if all of them pass a hardcoded/developer-defined literal or array, the parameter is not attacker-controlled regardless of what the sink itself does with it, and at least one call site must pass genuinely request-derived data before confirming.
   - Before deep-diving a Semgrep/grep hit located inside a specific function's body, grep every call site of that function's own name across the plugin tree — a pattern rule matches on the function's source text regardless of whether the function is ever invoked, and a zero-caller (superseded helper, abandoned feature) hit is not reachable. → See also the dead-code/reachability FP rule in `vuln-audit-chain.md`.
2. **Capability/nonce gate bypassable?** → See CANON:nonce-verification. Check full menu hierarchy incl. `show_in_menu` parent capability inheritance. `admin_enqueue_scripts` without `current_user_can()` before nonce creation = all authenticated users get the nonce.
   - Admin bar node via `add_node()` with `parent => 'edit'`: WP Core renders that parent only when `current_user_can('edit_post', $object->ID)` for the current object; nonces created inside such child nodes are inaccessible to users lacking edit rights on the viewed object, raising the auth floor above the role alone.
   - AJAX handler routing all writes through a model/data-access class: read the model's `save()`/`create()`/`update()` methods (incl. parent/abstract base classes) for `current_user_can()`/`user_can()` — model-layer enforcement blocks the operation regardless of handler-level auth; both layers must lack authorization to confirm.
   - REST-exposed CPTs with `capability_type => 'post'`: the REST API enforces `publish_posts` (Author+) for `status: publish` — Contributors (only `edit_posts`) get HTTP 403 `rest_cannot_publish`. Auth floor for REST CPT creation requiring `status: publish` is Author+, not Contributor.
   - Chain requiring the attacker to hold Contributor via nopriv self-registration (e.g. `wp_insert_user()`): verify the site's `default_role` — standard installs set `default_role = subscriber`, so self-registration yields Subscriber not Contributor, making the chain non-viable unless a separate priv-esc path exists.
3. **Vulnerable version is latest?** Check changelog/wordpress.org. If `AUDIT_VERSION_OVERRIDE.md` exists, read it.
4. **Requires admin-only configuration? — Non-Default Prerequisite Gate:**
   - **Single common prerequisite** (e.g. "WooCommerce active", "contact form exists"): document, proceed — most sites meet it.
   - **Single niche prerequisite** (e.g. "MailChimp configured with valid API key", "iframe ad mode enabled", "Children Events feature on"): document prominently, flag as reducing real-world exploitability. Proceed only if CIA is Moderate+ and the feature is plausibly enabled on a meaningful fraction of installs.
   - **Compound prerequisites** (2+ independent non-default settings must align, e.g. "admin grants caps to non-admin role AND REST module disabled by default AND form exists"): downgrade confidence below 90% — do NOT confirm, do NOT generate PoC. Log as a lead with the prerequisite chain. Per Wordfence payout factors, compound prerequisites reduce payout toward $0 and risk FP budget.
   - **Non-default + low CIA:** if a prerequisite narrows scope AND impact is Low/None per the CIA Impact Gate, dismiss immediately — never bounty-eligible.
   - **Assumed-but-unverified plugin-presence prerequisite:** a dispatch block matching another specific plugin's known action/hook name (a third-party compatibility shim) is NOT itself proof of a presence gate — verify an explicit `isPluginActive()`/`class_exists()`/`function_exists()` check actually wraps the dispatch before treating "requires plugin X active" as a real prerequisite. Compatibility shims frequently reuse a third-party plugin's action string as a trigger with no such check, making the dispatch reachable regardless of whether that plugin is installed.
   - **Precondition framed as "some state/marker must already exist":** trace its origin before treating it as prerequisite-narrowing — if the state is created as a normal side effect of the attacker's OWN first, ordinary request to the same feature (no separate secret or administrator action required), it does not raise the auth floor; verify by reproducing from a completely clean state with zero prior privileged interaction. Only a precondition requiring genuine administrator/secret-holder participation independent of the attacker's own reachable requests narrows the floor.
5. **Confidence > 90%?** If not, note finding + blocker, do not report.
6. **Secondary mitigations?** `(int)` casts, `intval()`, `wp_magic_quotes()` effects, allowlist checks.
   - `wp_kses($val, [])` with an empty allowed-tags array strips literal `<` bytes at write time; verify the 2nd arg is empty (not merely restrictive) before confirming write-side XSS protection.
   - A `ctype_digit()`/`ctype_alnum()` conditional wrapping the flagged DB write: Semgrep taint mode doesn't model the conditional as a sanitizer — manually verify the gate exists in the call path and restricts the character class before dismissing as FP.
   - `preg_match()` with a digit-restricting whitelist regex (e.g. `preg_match('/[^0-9,]/', $val)`) = equivalent SQL protection to `ctype_digit()` — Semgrep doesn't model regex-conditional gates; verify the gate fires on the specific variable before the SQL sink before flagging injectable.
   - A strict-equality string comparison against a small fixed literal set (e.g. `strtolower($val) == 'asc' || strtolower($val) == 'desc'`) gating entry into the branch that interpolates the value into a SQL format string is an equally valid allowlist gate — Semgrep taint mode doesn't model this either; verify the gate's literal set before flagging the interpolation as injectable.
   - `wp_json_encode()` with `JSON_UNESCAPED_SLASHES` in a `<script>` block: verify at least one serialized field comes from a user-writable string source; structures with exclusively server-computed numerics (IDs, prices, counts) can't carry `</script>` regardless of flag.
   - `html_entity_decode()`/`htmlspecialchars_decode()`/`wp_specialchars_decode()` preceding an `echo` (Chain 3 pattern): check whether `esc_html()`/`wp_kses()` is applied to the decoded value before output — a post-decode encoding step re-encodes restored `<` bytes and breaks the chain; dismiss as FP only when this second-stage encoding is confirmed for ALL output paths.
7. **CVE-worthy?** Requires: vuln in plugin code, reproducible vector, measurable CIA, not theoretical.
8. **Scope gate (mandatory — check BEFORE confirming):**
   - Auth floor is Contributor or Author → **OOS** (current program policy). Do NOT write to findings.md. Log as OOS lead in checkpoint.
   - Vulnerability type is SSRF (CWE-918) → **OOS** (current program policy). Do NOT write to findings.md. Log as OOS lead in checkpoint.
   - Disclosed resource is non-public post/page/CPT content (private, draft, pending, future, trashed, or **password-protected** — including title/excerpt/slug/metadata) → **OOS**, regardless of auth floor (even unauthenticated) and regardless of whether the missing gate is a simple status check or an access-control bypass (e.g. a missing `post_password_required()` call) — the resource type controls, not the mechanism that reached it. Do NOT write to findings.md. Log as OOS lead in checkpoint. Exception: the disclosed data is user/customer PII (orders, private messages, form submissions, account/profile data), which is NOT this exclusion and remains in-scope Non-trivial Information Disclosure.
   - Disclosed data is bare file paths, or an exception/stack trace whose only content beyond file paths/line numbers/call chain is non-credential, non-PII, and not independently-sensitive query/schema structure → **OOS** ("full path disclosure", Low/theoretical). Verify the exact disclosed content before confirming: an error message reflecting only data the same attacker request already supplied (e.g. a DB connection error built from credentials the attacker submitted) discloses nothing incremental and does not clear the Non-trivial-Information-Disclosure bar.
   - Exception: if chaining lowers the effective auth floor to Subscriber or below, the chain is in-scope at the lower floor.
   - A weak/predictable-token or entropy-insufficient finding (Phase 2B item 5) is exploitable only by brute force: before marking CONFIRMED/submittable, compute the keyspace size and a realistic sustained-request timeframe against any rate-limiting present. Absent a demonstrated high-success-likelihood (small keyspace, seconds-to-minutes), this is **OOS** ("excessive brute force required") — log it as a lead with the computed keyspace/timeframe, do not write it to findings.md as submittable.
   - A cryptographic/obfuscation mechanism being fully broken (key forgeable, cipher reversible, hash predictable) does not itself confirm an in-scope finding — classify by the DOWNSTREAM DISCLOSURE the break enables. If the only effect is making an already-OOS disclosure class reachable (e.g. forgeable per-record tokens producing a valid/invalid existence oracle — standard username enumeration), the finding stays OOS regardless of how completely the crypto fails; escalate only when the disclosed content is itself in-scope.
13. **Audit context claims of missing auth:** Read flagged function source directly. Context agents can wrongly assert absence of auth calls.
   - Semgrep hitting one function in a multi-handler class file neither certifies nor excludes siblings — read each handler body independently. A miss at one line doesn't make the file clean; a hit at one line doesn't make all siblings vulnerable.
18. **Dispatcher-routed handlers:** Plugins may route through a dispatcher with internal auth. Read the callback body and trace into the dispatcher for auth-wrapper calls.
   - Internal routing framework (Slim, FastRoute) inside an AJAX callback: use SLIM_FASTROUTE_ROUTER grep to enumerate all registered routes — per-route handlers have independent authorization scopes from the dispatcher callback.
   - WordPress REST API: the REST dispatcher enforces `permission_callback` before the callback body — a callback lacking `current_user_can()` in its own body is not a finding if the named `permission_callback` calls `current_user_can()`. Trace `register_rest_route()` for the handler and read the referenced `permission_callback`.
   - When a `permission_callback` delegates to a custom token-verification function, confirm whether the token (JWT, signed API key, HMAC) is obtainable by the target attacker role — tokens signed by an external service the attacker doesn't control are a PR:H gate regardless of the WP capability check.
   - AJAX handler body calling only `$this->validate()`/`$this->check()` or a similar private method before delegating to writes: read that method's body for `current_user_can()` — OOP auth delegation to a validation method is equivalent to handler-level auth; absence from the handler body alone is not a finding.
   - Nopriv AJAX handler dispatching via `do_action('prefix_' . $action)` with no direct write sinks in the body: verify at least one `add_action('prefix_*', ...)` handler is registered before flagging — zero registered handlers = no exploitable action paths in the audited version.
   - MCP (Model Context Protocol) / JSON-RPC-style tool dispatchers may resolve the caller's WordPress identity once at connection time (admin session, static bearer token, or an OAuth grant bound to an admin account at issuance) rather than per-operation, making an individual tool case's missing `current_user_can()` a non-finding only when EVERY registered identity-resolution path is independently verified to converge to admin-equivalent. Read each path's own resolution code, not just the most common one, before dismissing the dispatcher as a whole.
20. **Nopriv handler nonce "protection":** → See CANON:nonce-verification. Publicly-readable nonce (frontend-embedded, localized script) = zero auth value.
22. **Hook registration inside capability gate:** `add_action()` inside capability-gated constructor/init = hook never registered for unprivileged roles. Trace ALL paths from plugin entry to `add_action()`.
   - A condition checking request parameters (`isset($_REQUEST['action'])`, `$_GET['action'] === ...`) is NOT a capability gate — it controls which handler is registered or which call is dispatched at class-load/construct time, not who can access it. The resulting auth floor depends on the surrounding execution context, not the parameter check itself: Subscriber+ when the condition lives inside code reachable only via an authenticated-only hook (e.g. `admin_init`); **Unauthenticated** when the condition and its dispatched call/registration execute unconditionally on every request (e.g. directly inside a class constructor invoked on plugin load, or a hook with no auth context such as `plugins_loaded`/`init`).
27. **Missing authz ≠ automatic finding** — → See Tier 4 CIA Impact Gate. Low/none impact = CVE-only/OOS. Editor-level access = PR:H → OOS.

### False Negative Prevention

Before concluding "not exploitable":

1. **"Protected by encryption"** — Audit the crypto implementation. Check decryption failure modes.
   - A malleable cipher mode (CBC without HMAC, ECB) is exploitable only when the attacker also controls what gets encrypted (a chosen-plaintext oracle) or can distinguish decryption-failure signals (a padding oracle) — if every caller of the encrypt function passes exclusively server-computed values, the malleability has no attacker-triggerable effect and should not by itself justify an Auth Bypass finding.
2. **"Requires secret key/token"** — Check storage location, readability via other vulns, presence in logged URLs.
   - When `wp_localize_script()` embeds the option/variable used as the REST auth token in a JavaScript global on any public page, the token is not secret — regardless of comparison correctness.
   - When a token gates a destructive write operation, read the operation's filter/WHERE clause — token verification proves record-level ownership for the validated ID only; a downstream query with no ID filter destroys all matching records regardless of which record the token was issued for.
3. **"Input is validated"** — Read the validation function body. → See CANON:sanitize-text-field-limits. `esc_sql()` insufficient in unquoted contexts. `wp_check_filetype()` = extension only.
   - `apply_filters()` returns input unchanged when no callback is registered — NOT a sanitizer; verify a callback is actually registered and applies context-appropriate escaping before treating a path through `apply_filters()` as sanitized.
   - A shared sanitizer/expansion function that takes a `$context`/`$mode` argument restricting its behavior (e.g., an allowlist applied only for certain context values) is safe only for the call sites that pass the restrictive argument — a sibling call site passing a permissive value, an unrelated value, or omitting the argument (falling back to a permissive default) loses the restriction even though the function "looks" the same; check the actual argument at each call site, not just the function's safest-case behavior. When the output feeds a raw header line (`"Reply-To: {$name} <{$addr}>"`-style string built from per-record/per-submission field data), also verify a field type whose sanitizer preserves `\r\n` (e.g. a textarea/multi-line variant) can populate that specific tag — single-line sanitizers collapse `\r\n` and block CRLF injection, multi-line ones don't.
   - User input (nested array or string) flowing into `wp_parse_args($user_input, $query_defaults)` as the first arg overrides security-critical defaults like `post_status => 'publish'` — string args trigger `parse_str()` internally, converting `"post_status=private&meta_query[0][key]=secret"` into an associative array; `sanitize_text_field('private')` returns `'private'` unchanged. Verify arg order: first arg wins.
   - Handler setting a safe default after parsing user input (e.g. `$args['post_status'] = 'publish'`): verify no later conditional branch — triggered by user-controlled params (class name, widget type, feature flag) — overrides it to a non-public status (`'any'`, `'draft'`, `'private'`); trace all paths between the safe assignment and the WP_Query call.
   - `sanitize_text_field()` on a comma-separated integer string (e.g. `"1,2,3"`) returns it unchanged; when `explode()` produces IDs from such values, those IDs flow unsanitized into write sinks (`wp_update_post`, `wp_delete_post`) — zero protection against ID injection.
   - `wp_unslash()` REMOVES the `addslashes()` protection WP auto-applies to superglobals via `wp_magic_quotes()` — not a sanitizer; when `wp_unslash($_POST['x'])` flows to SQL via `sanitize_text_field()` or direct interpolation, single-quote breakout is re-enabled.
   - `perm=readable` in WP_Query only author-scopes `private` — `draft`, `pending`, `future`, `trash` go into the unrestricted bucket with no `post_author` restriction; a shortcode/AJAX/REST handler explicitly listing these statuses (e.g. `'post_status' => ['publish', 'draft']`) with `perm=readable` as the sole fence still discloses all matching draft/pending/future/trash posts from all authors; if `perm` is absent the disclosure also covers `private` posts. Also applies to `get_pages()` with non-public `post_status` (wraps `WP_Query`, identical behavior).
   - `media_handle_upload()`, `wp_handle_upload()`, `media_sideload_image($url)` validate MIME but do NOT enforce authorization — the caller must verify `current_user_can('upload_files')` before the call, else the write operates at the endpoint's auth floor (unauthenticated for nopriv handlers). (`media_sideload_image` sniffs MIME only after download.)
   - Copy/clone/duplicate handlers reading all rows via `$wpdb->get_results()` and building bulk SQL (INSERT...SELECT UNION) via string interpolation or array push + implode: `sanitize_text_field()` on column values is not SQL-safe; verify `esc_sql()` wraps each interpolated value before concluding protected.
   - Array items individually escaped but the `implode()`/`join()` separator comes from user input (shortcode attr, `$_GET`/`$_POST`): the separator is inserted unescaped between escaped items in HTML output — verify both items AND separator are escaped, especially when a sibling "prefix" param is escaped while the "glue" param is not.
   - POST JSON body decoded and a URL/path field extracted before bulk sanitization (e.g. `$url = $params['url']; $params = sanitize($params)`): the extracted variable carries the raw unsanitized value regardless of later sanitization — verify fields used in outbound HTTP, file ops, or SQL sinks are extracted AFTER sanitization of the containing structure.
   - `register_post_meta()` without `sanitize_callback` stores REST-written values verbatim — WP Core doesn't apply `wp_kses_post()` to REST-written meta lacking this callback. Surface via `POST_META_NO_SANITIZE_CALLBACK`; confirm the parent CPT has `show_in_rest: true`.
   - `register_post_meta()` called with a variable as the options arg (e.g. `register_post_meta($type, $key, $config['args'])`): trace the variable to its definition — config-driven registration stores `sanitize_callback` in a separate structure; absence of the key is only determinable there, not at the call site.
   - A `ctype_digit()`/`ctype_alnum()` if-gate before a DB write is a valid character-class constraint, but Semgrep taint mode doesn't model conditional gates as sanitizers — the variable stays tainted after the check; manually confirm the gate exists in the actual code path and restricts the relevant character class.
   - `sanitize_text_field()` on a URL/link field is NOT safe for href/src contexts — `javascript:` contains no `<` and passes unchanged; if the render path uses `esc_attr()` instead of `esc_url()`, the stored URI executes on click. Verify the render-side escaping against the output context (URL → `esc_url()` required), not just that some escaping is present.
   - `wp_kses_post()` on `post_content` does NOT strip `javascript:` from shortcode attribute text — kses parses HTML tags/attributes, not shortcode parameter values; page-builder module URL fields (Divi props, Elementor widget settings, Beaver Builder field values) stored as shortcode attributes pass `javascript:` URIs unchanged through save; if the module's render method outputs the prop in an `href`/`src` context via `sprintf()` without `esc_url()`, Contributor+ stored XSS is confirmed.
   - `wp_kses_post()` at save time does NOT encode `"` — kses strips HTML tags but passes `"` unchanged. When the stored value is concatenated into a double-quoted HTML attribute without `esc_attr()`, the `"` breaks attribute context → event-handler injection; verify all render paths using saved TEXT control values in HTML attribute context use `esc_attr()`.
   - An ORM read method (`get($id)`) enforcing post_type constraints does not imply write methods (`delete($id)`, `update($id)`) call `get($id)` before proceeding; verify each write method independently — direct `wp_delete_post()`/`wp_update_post()` without prior `get()` accepts any post ID regardless of type.
   - A security-critical comparison pattern (e.g. a cookie/token checked against a hash of a stored secret, gated by a `strlen()`/`!empty()` precondition) being correctly guarded at ONE call site does not mean a duplicate or copy-pasted occurrence of the same comparison elsewhere in the codebase carries the same guard. Verify every occurrence of the pattern independently by reading its own enclosing conditional, not just the pattern's presence at the first site found.
   - When a vulnerability exists in a plugin addon class file, verify the addon class is actually loaded — many plugins use a conditional `require_once` in a central addon loader guarded by a global settings option, so the class and all its hooks never register unless the admin has enabled the addon globally. The vulnerability is real but the attack surface is narrower than a default-loaded class.
   - `esc_html()` on DB-stored user data does not protect HTML renderer sinks — mPDF, wkhtmltopdf, and DOMDocument decode HTML entities at parse time, turning `&lt;img src=&quot;http://attacker.com&quot;&gt;` back into an executable `<img>` tag; verify whether the renderer reads `esc_html()`-encoded values from the database.
   - WooCommerce order billing and shipping fields (`get_billing_first_name()`, `get_billing_city()`, `get_billing_state()`, `get_shipping_*()`, etc.) are customer-submitted checkout data — they are attacker-controlled and must be treated as untrusted second-order injection sources whenever echoed into HTML output without `esc_html()`. Use `WC_BILLING_FIELD_READS` grep results to surface these in the XSS read path.
   - A `urlencode()` → `urldecode()` round-trip (often with an intermediate `str_replace()`) is a no-op for XSS-relevant characters — `"`, `<`, `>`, `;`, `(`, `)` are restored by `urldecode()` unchanged, providing zero protection for HTML or JS output contexts. Do not treat this pattern as sanitization when tracing data from `$_GET`/`$_POST` into echo sinks.
   - When a plugin buffers `$_GET`/`$_REQUEST` values into a shared state object (class property, global variable) and exposes them via a getter method, sanitization applied by ONE access path (e.g., an AJAX handler that sanitizes before populating the object) does not protect ALL access paths that read from the same object. Verify every output site that calls the getter and echoes results applies its own context-appropriate escape (`esc_js()`, `esc_html()`, `esc_url()`).
   - When `wp_kses_post()` appears in the same function as an `update_post_meta()` call, verify the kses call is applied to the value passed to `update_post_meta()` — kses applied only to a separately-echoed AJAX response does not sanitize the stored value, and the raw post meta remains an XSS source for all subsequent read paths.
   - Save-time content filtering (`wp_filter_post_kses()`/`wp_kses_post()` applied because the writer lacks `unfiltered_html`) is not proof a render-time sink is safe — it is a tag-pattern-matching filter with a documented history of parser-differential bypasses, not a substitute for the plugin's own output escaping at the sink. Do not dismiss a plugin-defined sink lacking `esc_html()`/`esc_attr()` solely because kses is presumed to catch the input upstream; if a later patch to the same code adds output escaping at that exact sink, treat that as confirmation the kses-reliance dismissal was wrong.
4. **"Only internal call"** — Check if also registered as hook callback, REST endpoint, or AJAX handler.
   - The inverse also holds: a WP-CLI command class/registration is NOT remote attack surface unless reachable over HTTP — verify it isn't wrapped in `class_exists(WP_CLI::class)`/`defined('WP_CLI')` before analyzing it as attacker-reachable; WP-CLI requires local/SSH shell access.
   - Conditional `add_action('admin_init', handler)` registered inside a request-parameter check (`if (isset($_REQUEST['action']) && ...)`) at class-load time: reachable fully UNAUTHENTICATED via `admin-ajax.php` (see below) — do not default to Subscriber+. Check the registered handler body for both `current_user_can()` and `wp_verify_nonce()`.
   - An `admin_init` handler using only `check_admin_referer()` without `current_user_can()` before write operations is reachable fully UNAUTHENTICATED via `admin-ajax.php` — `check_admin_referer()` verifies CSRF origin only, not authorization level, and does not raise the floor above the unauthenticated `admin_init` default.
   - An `admin_init` handler whose sole trigger is `isset($_GET[...])` or `isset($_POST[...])` with neither `current_user_can()` nor nonce verification is accessible fully UNAUTHENTICATED — the GET/POST presence check is a routing condition, not an auth gate; verify the full handler body for both checks before concluding protected. Use `ADMIN_INIT_SUPERGLOBAL_READS` grep results to surface this pattern.
   - Handlers registered on the `init` hook with only `wp_verify_nonce()` and no `current_user_can()` before write operations are reachable by unauthenticated visitors (PR:N); audit all `INIT_HOOKS` grep results with the same nonce-only analysis applied to AJAX handlers.
   - `admin_init` handlers at file scope or inside `plugins_loaded`/`init` are reachable via `/wp-admin/admin-ajax.php?action=<any>` **fully unauthenticated** — `admin-ajax.php` fires `admin_init` unconditionally before the `is_user_logged_in()` branch and never calls `auth_redirect()`, so a `wp_doing_ajax()` redirect guard does not raise this floor. It does NOT fire `admin_menu` — a handler registered only inside an `admin_menu` callback instead needs a regular `/wp-admin/` page request (e.g. `profile.php`, `read` cap). Check registration context for the real exploit path.
   - When a `template_redirect` hook restricts CPT frontend access via login or capability checks, verify the CPT registration's `public` parameter — CPTs with `'public' => true` automatically receive a REST API route at `/wp-json/wp/v2/<slug>/` that fires before `template_redirect` and is unprotected by PHP redirect gates. Confirm `show_in_rest => false` disables the endpoint, or a dedicated REST-level auth handler covers the route.
   - A standalone file that self-bootstraps WordPress via its own `require`/`include` of `wp-load.php`/`wp-blog-header.php` (`STANDALONE_PHP` grep results) is reachable directly at its own file path and operates entirely outside the hook/nonce/capability system regardless of which WP functions it calls afterward — read the full file for `$_GET`/`$_POST`/`$_REQUEST` reaching a sensitive sink with no `wp_verify_nonce()`/`current_user_can()` present anywhere in it.
5. **"Error handling catches it"** — Verify error handler runs AND halts execution.
6. **"Shortcodes only render HTML"** — Read callback for superglobal reads. `$_GET`/`$_POST` in shortcode = unauthenticated surface.
   - Shortcode parameters used as PHP `date()` / `wp_date()` format strings in `get_the_time()` / `get_the_modified_time()` pass non-format-code characters including `<` and `>` through literally — verify `esc_html()` wraps the function's return value, especially when a safe sibling call (e.g., `get_the_time`) correctly applies `esc_html()` while the vulnerable sibling (e.g., `get_the_modified_time`) does not.
   - A shortcode callback using `user_can($post->post_author, ...)` as its sole auth gate checks the PAGE AUTHOR's capabilities, not the requesting visitor's — on any admin-authored page the check always passes for all visitors regardless of their own authentication status; confirm auth gates call `current_user_can()` to evaluate the actual requesting user.
   - Shortcode `$atts`/`$attributes` and widget `$instance` parameters are contributor-controlled input; when these flow to `$wpdb` query methods without `$wpdb->prepare()`, the result is Contributor+ SQLi — do not treat shortcode attributes as safe internal data.
7. **"Admin menu page = admin only"** — Some CPTs use `show_in_menu => false` with lower capability.
8. **"Admin-only nonce"** — Check for second page outputting same nonce with lower capability. Grep nonce action string/constant across ALL `wp_create_nonce()`/`wp_localize_script()` calls — lowest-capability site = auth floor.
   - `enqueue_block_editor_assets` fires for any `edit_posts` user (Contributor+) opening the block editor; a `wp_create_nonce()` inside a function hooked there (without a `current_user_can()` guard) sets the auth floor to Contributor, not admin.
   - If the `enqueue_block_editor_assets` callback checks `get_post_status($post_id)` for `'publish'` before nonce creation, Contributors cannot reach it — they lack `publish_posts` and cannot edit published posts; the auth floor is Author, not Contributor. Always read the full callback body before concluding Contributor access.
   - A `wp_create_nonce()` call inside a function hooked to `wp_head` without a capability guard exposes the nonce on all public pages (auth floor: any visitor can read it, though `wp_ajax_` handlers still require login); `admin_head` without a capability guard sets the auth floor to Subscriber.
   - `wp_create_nonce()` inside a `current_user_can()` conditional block within a hook callback sets the auth floor to that capability, not the hook's own floor. An `admin_footer` hook fires for Subscribers, but `wp_create_nonce()` inside `if (current_user_can('manage_plugins')) { ... }` within that callback requires Administrator — trace into the callback body before concluding nonce is Subscriber-accessible.
   - Page builder editor hooks (e.g., `elementor/editor/before_enqueue_scripts`, `elementor/editor/after_enqueue_scripts`) fire when the visual editor is loaded and are accessible to any `edit_posts` user (Contributor+); treat nonces localized inside these hooks identically to `enqueue_block_editor_assets` — auth floor is Contributor unless a `current_user_can()` guard raises it.
   - An early `if (!current_user_can($cap)) { return; }` guard at the start of a hook callback is semantically equivalent to wrapping the remainder in a conditional — `wp_create_nonce()` calls following the early return are gated at `$cap`, not at the hook's native floor.
   - Nonce hashing includes the requester's session token, not just user ID (→ See CANON:nonce-verification for the full emission-site/floor-determination method — do not re-derive it here). When the lowest-privilege emission site of the verified action string IS reachable at the attacker's role, a handler lacking `current_user_can()` is CONFIRMED Missing Authorization at that floor. For `wp_ajax_nopriv_` handlers the same method applies at uid 0: the nonce helps an anonymous attacker only if emitted on a logged-out-reachable surface.
   - **Gate action:** when all emission sites of the verified action string are above the attacker's role, treat the finding as OOS at that role — do NOT write it to findings.md; record it as a lead (defense-in-depth observation) instead.
9. **Read the function body before concluding safe/unsafe.** Applies to:
   - Named `permission_callback` — → See CANON:rest-permission-callback. May be empty, global-only, or evaluate wrong user identity.
     - A named permission_callback that reads a signing secret from options and returns `true` when the secret is absent fails open to unauthenticated callers; verify the callback returns `false` or `WP_Error` on empty/missing config, not `true`.
     - A custom routing framework that resolves `permission_callback` via Reflection (comparing `ReflectionMethod::$class`/`getDeclaringClass()->getName()` against the concrete class name to detect method overrides) silently falls back to a weaker default whenever the security-checking method is declared on an intermediate base class rather than the leaf class. Trace the actual resolution logic — not just the base class's capability check — before concluding a route is protected.
     - PHP permits multiple classes to share an identical short name across different namespaces; a refactor commonly leaves an old implementation as unreferenced dead code in a sibling namespace, and that dead copy's capability check (or lack of one) does not apply to the live copy the concrete routes actually extend. Before trusting a class's capability check, confirm via the route file's `use`/`namespace` declaration which fully-qualified class the concrete route actually extends — a short-name-only match (by grep or by eye) can silently resolve to the wrong implementation.
   - Named `prepare_*()`/`sanitize_*()` in SQL path — `sanitize_text_field()` + DML blocklist ≠ SQL safety. → See Phase 2B "False-Safe Gates".
   - Custom auth wrappers (`is_user_allowed()`, `can_access()`, etc.) — may return `true` when restriction lists empty (default state on fresh installs).
   - A custom auth wrapper comparing a role-slug array (e.g. `array_intersect([...], $user->roles)`) against literal strings is only as strong as those strings being real WP/WC role slugs — a capability name that merely resembles a role (e.g. `manage_woocommerce`, a capability granted to `administrator`+`shop_manager`, never a role slug itself) will never match, silently narrowing the gate. Verify each compared string against the plugin's/WP's/WC's actual default role slugs before accepting the wrapper's apparent floor.
   - `call_user_func` with callable from object property — trace ALL writes to source property for user-controlled key overwrite.
   - Semgrep flagged `$OBJ->update()`/`delete()` — check for ownership-verification call before flagged operation.
   - Semgrep missed custom auth wrapper around `current_user_can()` — empty method body = not exploitable.
   - HTML output utility functions that explicitly delegate escaping responsibility to callers (rather than escaping internally) require verification of every call site — a single unescaped caller breaks the chain even when all other callers pre-escape correctly; check function docblock or source comment for "caller must escape" language as the signal.
   - A validation/containment helper signaling rejection via a truthy sentinel value (e.g. a literal error-marker string) rather than `false`/`null`/empty silently defeats every caller's `if (!$result)`-style guard, since the sentinel is never falsy in PHP — verify the actual rejection return value, not just the presence of a negation guard, before treating such a check as protective.
   - AJAX handlers whose body contains only a nonce check and a single static or instance method call — with no write sinks directly in the body — delegate all writes to the called method; read that method's source (and its callees) for write operations before concluding the handler performs no state changes.
     - When `$_POST['user_id']` (or any per-user record ID from POST/GET) is passed to the called method, also verify `current_user_can('edit_user', $user_id)` appears in the handler before the call — `check_ajax_referer()` establishes session authenticity but not per-user ownership, and absence of the ownership check is Missing Authorization (CWE-862) regardless of nonce validity.
   - When Semgrep traces tainted input through an OOP method call (`$this->transform($input)`) into the method's return value and then to a SQL sink, read that method's body — a switch/allowlist or integer-producing transform inside the method is invisible to the outer taint trace and may fully neutralize the taint before the database query.
   - When Semgrep flags a function for missing `check_ajax_referer()`, verify whether `check_admin_referer()` or `wp_verify_nonce()` appears anywhere in the function body, including inside conditional expressions (`if (isset(...) && check_admin_referer(...))`). Both are equivalent CSRF verification functions; their presence suppresses the nonce-missing finding regardless of which variant Semgrep's rule checks for.
   - When Semgrep taint flags a meta write (`update_post_meta`, `update_user_meta`) where the VALUE argument was processed through `array_walk_recursive()`/`array_map()` with a sanitizer callback (e.g., `array_walk_recursive($data, 'sanitize_text_field')`), taint mode does not model indirect function application as sanitization — read the call site to confirm the callback is applied to each value and no raw unsanitized values survive before dismissing as FP.
   - A shared "preflight"/"gatekeeper" helper method bundling BOTH nonce verification and `current_user_can()` (called as the first statement of many otherwise-unrelated AJAX handlers) protects every caller identically to an inline check. Semgrep patterns keyed on nonce/capability calls appearing in the SAME function body cannot trace into a called helper — read the helper's body once, then confirm each flagged handler's first statement actually invokes it before treating a same-shape hit as a finding.
10. **"Not a raw superglobal at the sink" is not proof of safety.** A value reaching a sensitive sink (privileged write, destructive delete, re-authentication) may be resolved through the plugin's own internal data-staging/templating layer — a form-field value cache, a `{tag:key}`-style merge-tag resolver, an admin-configured "which related record" selector — rather than a direct `$_GET`/`$_POST` read at the sink call site. Trace backward through such intermediary layers to their actual origin before concluding a value isn't attacker-influenced; the absence of a literal superglobal read at the sink is not evidence of safety when the plugin has its own request-staging or relationship-resolution machinery sitting between the two.
11. **"Vendor/ directory is third-party, skip it."** `grep_scan.py`'s vendor-inclusion heuristic only treats a `vendor/<subdir>/` as first-party when the subdirectory name matches the plugin's own slug. A shared framework bundled under the publisher's company/brand name rather than the individual plugin's slug is silently excluded from every grep tier and must be read and audited manually like first-party code.
   - When a finding's confidence hinges on a third-party dependency's own behavior (e.g. whether WooCommerce/WP core's own function sanitizes a value) and that dependency isn't obviously bundled, search the full source tree for a vendored copy before treating the question as unverifiable — the actual source may be present under a different path than expected.
12. **A shared custom sink's dismissal must cover every caller, not just the first traced.** A SINK LEDGER-inventoried function fed by multiple call sites can have its CIA impact wrongly judged Low/None from the first-examined caller's data alone — grep and read every caller before dismissing a shared sink as low-impact, since a separate, untraced caller may pass more sensitive content through the identical sink.
   - The same rule applies to sanitization, not only impact: when two or more entry points (e.g. a REST route and a local AJAX handler) converge on the same shared write function for a given field, one caller applying a sanitizer to that field does not imply a sibling caller does — verify each entry point's sanitization of the shared field independently before dismissing the sink as protected.
   - The same rule applies WITHIN a single parser: when a switch/case (or per-key handler) block normalizes several allowlisted keys into a shared static/instance property, one case applying a numeric cast (`intval()`/`absint()`) does not imply a sibling case does — check every case independently, especially when the property is later read by a DIFFERENT function/file than the one that populated it, since that distance is what let an inconsistent case go unnoticed.
   - A form-plugin add-on that saves submissions to its own database table commonly also copies file-upload attachments into a second, plugin-controlled directory for admin review — a separate code path from the base form plugin's own upload handling that does not automatically inherit its access controls. Verify the destination directory's access restriction and filename predictability independently, regardless of how well-protected the base plugin's own temporary upload storage is.

**The "never assume" rule cuts both ways.** Do not assume exploitable without verifying full access chain. Do not assume unexploitable without verifying no alternative access path. Trace actual code.

## Phase 5: Output

**Record every confirmed finding** — no limit. Complete full findings list before triggering vuln-report or poc-generator.

**Output paths:** Pipeline: `AUDIT_DIR` from Stage 0. Standalone: `./audit/`.

For each confirmed finding (confidence > 90%, in scope, CVE-worthy):

1. **Finding entry** in `AUDIT_DIR/findings.md` using this template:
   ```markdown
   ---
   ## Finding [N]: [Short Title]
   **Status:** CONFIRMED
   **CWE:** [CWE-NNN]
   **CVSS:** [score] ([vector string])
   **Auth Floor:** [Unauthenticated / Subscriber / Customer]
   **Affected:** `[file.php:line]` [, additional file:line]
   **Attack Vector:** [1-2 sentence description]
   **Prerequisites:** [e.g., "None", "Requires WooCommerce active", "Feature X enabled"]
   **Semgrep:** [Yes — rule-id / No — independent discovery]
   **Affected Functions:** [file:line list for multi-function bonus]
   ---
   ```

2. **Disclosure report** in `AUDIT_DIR/reports/` — use vuln-report skill.

3. **PoC** in `AUDIT_DIR/poc/` — use poc-generator skill.

4. **Registry update** — append row to `${CLAUDE_PROJECT_DIR}/vuln-registry.md`.

5. **Cross-plugin notes** — add `## Cross-Plugin Notes` to findings.md for:
   - Template echoing unescaped variable from meta that companion plugin writes
   - Capability/role companion plugin likely grants
   - REST/AJAX handler with `permission_callback` deferring to companion-defined function

   Format: `### Cross-plugin: [file:line] | Pattern: [type] | Data source: [key] | Populated by: [companion/unknown] | Risk: [XSS/auth bypass/other]`

## Key WordPress Security Reference

**Reference:** `${CLAUDE_PROJECT_DIR}/wp-core-reference.md`
**Source:** `${CLAUDE_PROJECT_DIR}/wp-core/7.0/wp-includes/`

### Inline interrupt rules
1. → See CANON:entity-encoding
2. → See CANON:esc-like
3. **`is_admin()` is NOT authorization.** `true` for ALL admin-ajax.php requests incl. unauthenticated `wp_ajax_nopriv_`; `false` for REST API.
