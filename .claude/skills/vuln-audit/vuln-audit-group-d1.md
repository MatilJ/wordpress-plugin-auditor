# Vuln-Audit Group D1 — Tier 8–10: SSRF, Email Injection, Information Disclosure

> Authorized Wordfence bug-bounty research (see `AUTHORIZATION.md`). Loaded alongside core `SKILL.md`. Read prior checkpoint files (foundation, ab, ac, a, sqli, c), auth-model.md (format: Custom Roles table, Nonce Availability table, Handler Auth Summary table — written by the Foundation phase, Verdict/CIA filled by Group AC; may contain addenda from earlier groups), and leads-forward.md before starting.

## Tier 8 — SSRF via HTTP Requests — OOS (current program policy)

> **OOS (current program policy): SSRF (CWE-918) is entirely Out of Scope for the Wordfence Bug Bounty Program. Skip Tier 8 analysis. Do NOT write SSRF findings to findings.md. Forward any SSRF-adjacent leads (e.g., outbound HTTP with user-controlled URL that could serve as a chain primitive for non-SSRF vulns) to leads-forward.md as informational only.**

~~(CVSS 5.0–8.0)~~

- `wp_remote_get/post()`: no SSRF protection — any IP/port
- `wp_safe_remote_get()`: internally calls `wp_http_validate_url()`, which blocks 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 0.0.0.0/8. Restricts ports to 80/443/8080. **Does NOT block 169.254.0.0/16** (link-local / AWS EC2 IMDS / Azure IMDS) — direct SSRF to cloud metadata endpoints (IAM credentials, instance identity) is possible even through `wp_safe_remote_get()`. `download_url()` uses the same function internally and has the same gap.
- Trace webhook URLs, API endpoint settings, URL preview features
- `fetch_feed()` / SimplePie: `fetch_feed()` uses `WP_SimplePie_File` which calls `wp_safe_remote_request()` internally — same 169.254.0.0/16 gap. RSS/feed import features accepting user-supplied URLs are SSRF vectors.
- `media_sideload_image()` / `wp_remote_fopen()`: `media_sideload_image($url)` chains through `download_url()` → `wp_safe_remote_get()` — same 169.254 gap. `wp_remote_fopen()` also calls `wp_safe_remote_get()`. Common in image import features.
- **PHP native HTTP sinks (no IP blocking):** `file_get_contents($url)`, `fopen($url, 'r')` — PHP stream wrappers make HTTP requests for URLs. `getimagesize($url)` — makes HTTP request for remote URLs to read image headers (does NOT make network request on local file paths). `get_headers($url)` — makes HTTP HEAD request. `stream_socket_client()` — raw socket, attacker controls host/port.
- **REST/AJAX proxy pattern:** Endpoint accepts URL from client, fetches server-side, returns content. Common in URL preview, link validation, content import, AI/API proxy features.
- **`esc_url()` / `filter_var(FILTER_VALIDATE_URL)` are NOT SSRF sanitizers:** Common developer mistake. `esc_url()` validates URL structure and limits schemes to http/https but does NOT check destination IP ranges. `filter_var($url, FILTER_VALIDATE_URL)` validates format only. `sanitize_text_field()` strips HTML but preserves complete URLs. `sanitize_url()` is a core alias of `esc_url_raw()` (same non-protection) and is easy to mistake for a host-validating function because of its name. Only `wp_http_validate_url()` performs IP-range blocking (with the documented 169.254 gap).
- **Plugin-defined HTTP-fetch wrappers inherit the caller's gap:** a thin helper method that just forwards its own `$url` parameter into `wp_remote_get()`/`wp_remote_post()` adds no validation of its own — treat a call to such a wrapper exactly like a direct call to the core function it wraps.

Use GREP_RESULTS `TIER8_SSRF`, `RAW_CURL`, `DOM_XML_PARSING`, `REST_WEBHOOK_BODY`, `SSRF_SAFE_REMOTE_USER_INPUT`, `SSRF_FETCH_FEED`, `SSRF_IMAGE_SIDELOAD`, `SSRF_GETIMAGESIZE`, `SSRF_GET_HEADERS`, `SSRF_STREAM_SOCKET`, `SSRF_WEBHOOK_URL_STORE`, `SSRF_CRON_HTTP_FETCH`, `SSRF_SANITIZE_URL_NO_HOST_CHECK` (or `AUDIT_DIR/grep/group-d1-results.md` in file-based mode).

**Second-order SSRF — favicon/link preview/OGP scraper:** Two-hop chain: (1) fetch remote URL, parse HTML with `DOMDocument::loadHTML()`, extract child URLs via `getAttribute()`; (2) second fetch to extracted URL without host validation. Attacker's HTML: `<link rel="icon" href="http://169.254.169.254/...">` → plugin fetches internal address. Detection: find `DOMDocument::loadHTML()` receiving HTTP response → `getAttribute()` → network function without `wp_http_validate_url()`/`wp_safe_remote_*`.

**Cron-triggered second-order SSRF:** Cron jobs processing DB-stored URLs planted by earlier attacker request. Trace cron callbacks making outbound HTTP; find DB column read; check low-privilege write path. Use `SSRF_CRON_HTTP_FETCH` grep results.

**Webhook URL storage second-order SSRF:** Admin/editor stores a webhook URL via settings page → URL saved to `wp_options` or `postmeta` → later cron/event handler reads URL from DB and fetches it via `wp_remote_post()`. Use `SSRF_WEBHOOK_URL_STORE` grep results to find storage sites; trace corresponding `get_option()`/`get_post_meta()` read sites that flow into HTTP functions. Lower severity if storage requires `manage_options`, higher if accessible at Contributor/Subscriber level.

**Import/export URL SSRF:** Plugins importing content from user-supplied external URLs (CSV, XML, JSON, RSS, media) are common SSRF vectors. The TOCTOU/DNS-rebinding gap applies to all `wp_http_validate_url()` calls — DNS may resolve differently between validation time and request time.

## Tier 9 — Email Header Injection (CVSS 5.3–7.5)

`wp_mail()` where `$headers` built from user input. `\r\n` injects additional headers. `sanitize_text_field()` collapses `\r\n` to space (safe). `sanitize_email()` restricts to RFC chars (safe). Only raw superglobals without sanitization vulnerable.

**Distinct sub-class — recipient hijack, not header injection.** `$to` taken from request data with no comparison against the feature's own configured/expected address is still a finding even with zero CRLF chars — sanitizing the value doesn't fix a missing recipient-identity check; only re-deriving the expected address server-side does.

Use GREP_RESULTS `EMAIL` (surface) and `EMAIL_HEADER_LINE_BUILD` (or `AUDIT_DIR/grep/group-d1-results.md`) — the header-literal grep finds the "From:"/"Reply-To:"/"Cc:"/"Bcc:" construction site directly, which is frequently a different file/function than the `wp_mail()` call itself.

**Second-order header injection via merge-tag/smart-tag expansion (form-builder plugins):** Notification "Reply-To"/"From Name" settings in form-builder plugins commonly accept a tag/merge-field syntax (`{field_id="N"}` or similar) so the admin can populate the header from a submitted field. The tag-expansion function is buffered through the plugin's own field-value cache, not a direct `$_POST`-to-header flow, so Semgrep taint tracking will not surface it — trace manually. Two things must both hold for it to be exploitable: (1) the plugin lets the admin reference ANY field for that tag, not just an email-typed one — check whether the expansion call for the header's display-name half passes the same restrictive `$context` argument as the address half, or a more permissive default/omitted one (a function safe for one caller can be unsafe for a sibling caller that passes a different context); (2) at least one selectable field type's sanitizer preserves `\r\n` — `sanitize_text_field()`-style sanitizers collapse it (safe), but textarea/paragraph-text/HTML/hidden-type fields typically use a `sanitize_textarea_field()`-style sanitizer that explicitly preserves line breaks (unsafe). If the header value is built as a "Name <email>" pair, verify the sanitizer covering the address half (`is_email()`/`sanitize_email()`) also covers the display-name half — plugins commonly validate the address and forget the name. (3) confirm `$headers` reaches `wp_mail()` as an ARRAY, not a string — WP Core skips its own newline-splitting when `$headers` is already an array, so an embedded `\r\n` stays part of that one header's value; only a raw multi-line STRING `$headers` argument is exploitable this way.

## Tier 10 — Sensitive Information Disclosure (CVSS 4.3–7.5)

Systematic check for each sub-pattern. Use GREP_RESULTS `LOCALIZE_SCRIPT_SENSITIVE_DATA`, `LOG_FILE_PUBLIC_WRITE`, `USER_OBJECT_RESPONSE_EXPOSURE`, `REST_PREPARE_FIELD_FILTERS`, `EXPORT_FILE_PREDICTABLE_PATH`, `PHPINFO_SERVER_INFO`, `ERROR_HANDLER_PATH_EXPOSURE`, `NOPRIV_DATA_RESPONSE`, `POSTS_RESULTS_FILTER_HOOK`. Also cross-reference: `TOKEN_LOCALIZE_EXPOSURE` (group-ab), `CSV_EXPORT_SURFACE` (surface), `TIME_BASED_EXPORT_FILENAME`.

### 10A — Sensitive Data in Frontend JavaScript (CWE-200)

`wp_localize_script()` and `wp_add_inline_script()` embed PHP values into JavaScript globals visible in page source to any visitor. Vulnerable when: secret API keys (Stripe `sk_*`, OpenAI, reCAPTCHA secret key), admin email addresses, internal API endpoints with credentials, or authentication tokens are passed.

Detection: (1) Use GREP_RESULTS `LOCALIZE_SCRIPT_SENSITIVE_DATA` and `TOKEN_LOCALIZE_EXPOSURE`. (2) For each hit: read the array/string passed — identify every key-value pair. (3) Trace value sources: `get_option()` for stored secrets, hardcoded keys, `$_SERVER` data. (4) Determine hook context: `wp_enqueue_scripts` (frontend, all visitors) vs `admin_enqueue_scripts` (admin pages, Subscriber+ can access profile.php). Frontend hooks = unauthenticated exposure. (5) Distinguish public keys (reCAPTCHA site key, Stripe publishable key `pk_*`, Google Maps JS API key) from secret keys (reCAPTCHA secret key, Stripe secret key `sk_*`, API tokens with write access, `client_secret` values).

Same class also occurs without `wp_localize_script()`: a widget/element settings value named like a secret (e.g. `*_access_token`, `*_api_key`) serialized and echoed directly into a `data-*` HTML attribute for front-end JS to read back — use GREP_RESULTS `SETTINGS_SECRET_TO_HTML_ATTR`; escaping the value (`esc_attr()`, `wp_json_encode()`) prevents XSS but does not prevent the secret's disclosure. `LOCALIZE_SCRIPT_SENSITIVE_DATA` also catches the raw inline-`<script>` variant — `echo json_encode($config)`/`wp_json_encode($config)` embedding a config array straight into a `<script>` block instead of going through `wp_localize_script()` — same disclosure, no wrapper function to grep for.

**Nested pagination/cursor fields, not just top-level secret-named keys, can carry a credential.** Some OAuth-based REST APIs (e.g. Instagram/Facebook Graph API) embed the caller's own access_token inside their own response's pagination cursor URL (`paging`/`next`/`next_url`) — check every nested field of a forwarded third-party API response for an embedded credential, not just obviously-named ones. Use GREP_RESULTS `API_RESPONSE_PAGINATION_TOKEN` and Semgrep `claude.php.wordpress.info-disclosure.api-response-pagination-url-credential-leak`; `esc_attr()`/`esc_url()` do not redact the token.

FP filter: Public-facing API keys intended for client use are NOT sensitive — reCAPTCHA site key, Stripe publishable `pk_*`, Google Maps JS API, Mapbox public token. Secret/server-side keys (`sk_*`, `secret_key`, `client_secret`, private API tokens, SMTP passwords) ARE sensitive. Admin-only enqueue (`admin_enqueue_scripts`) reduces severity but does not eliminate for Subscriber+ accessible pages.

CVSS: Unauthenticated + secret API key with write scope = 7.5 (C:H). Unauthenticated + admin email only = 5.3 (C:L). Admin-only page + secret key = 4.3 (C:L, PR:L).

### 10B — Export/Backup Files in Predictable Public Locations (CWE-552)

Plugins writing CSV, JSON, SQL, ZIP exports to `wp-content/uploads/` with predictable filenames and no access restriction. Attack: guess filename → download file directly via HTTP.

Same disclosure shape also covers user-uploaded FILE ATTACHMENTS mirrored to a second public directory — common in form-plugin (Contact Form 7/Gravity Forms/WPForms/Formidable) database or logging add-ons that persist a copy of a submitted file upload for later admin review. Unlike an admin-triggered export, this write path fires on every unauthenticated form submission, making it reachable at PR:N by design rather than requiring an admin action first.

Detection: (1) Use GREP_RESULTS `EXPORT_FILE_PREDICTABLE_PATH` and `TIME_BASED_EXPORT_FILENAME`. (2) For each hit: trace the full file path construction. (3) Check three conditions — ALL must fail for vulnerability:
  - (a) `.htaccess`/`index.php` deny rule in the target subdirectory — search for `deny from all`, `Require all denied`, or `exit;` in `index.php` within the plugin's upload directory creation code
  - (b) Filename unpredictability — `wp_generate_password()`, `wp_hash()`, `bin2hex(random_bytes())` = safe; `time()` (1-second resolution, ~86400 attempts/day), `date()`, sequential `$post_id`, static string = guessable; `uniqid()` uses `microtime()` internally = predictable
  - (c) File URL returned in API response body — if the handler returns the download URL only to authorized users, direct URL guessing is the sole attack path

Missing (a) + guessable (b) = unauthenticated file access. Missing only (b) with (a) present = may still be vulnerable on Nginx (does not process `.htaccess`). Verify file lifetime — many export plugins create temporary files and clean up immediately; check for `unlink()` / `wp_delete_file()` after the response.

CVSS: Unauthenticated + PII/credentials in export = 7.5 (C:H). Unauthenticated + non-sensitive data = 5.3 (C:L). Subscriber+ required = reduce by PR:L.

### 10C — Log File Exposure (CWE-532)

Plugin-created log files in publicly accessible directories containing sensitive data (auth tokens, API keys, email addresses, passwords, full HTTP request/response bodies, stack traces with file paths).

Detection: (1) Use GREP_RESULTS `LOG_FILE_PUBLIC_WRITE`. (2) For each hit: determine log file path — is it under `wp-content/uploads/`, `wp-content/plugins/`, or the WordPress root? (3) Check what is logged: auth tokens, API keys, email addresses, user passwords, full HTTP request/response bodies, stack traces with file paths, database query strings. (4) Check access protection: `.htaccess` deny rule, randomized directory name, `download_url()`-based authenticated access, file permissions. (5) Check whether the log path is configurable by admin — a hardcoded public path is worse than a configurable one.

FP filter: `error_log()` with default PHP config writes to the server error log (not web-accessible) — only flag when `error_log($msg, 3, $file)` (third arg = custom file path) targets a web-accessible directory. Logging to `WP_CONTENT_DIR . '/debug.log'` is WP native debug log behavior, not plugin-specific. Log paths using `sys_get_temp_dir()`, `/tmp/`, or paths outside ABSPATH are not directly web-accessible. Filename-entropy claims for a randomized log filename (e.g. `uniqid()`) require quantifying the attacker's actual unknown keyspace, not just the generator's algorithmic weakness — when the reference timestamp (install time, first-log-write time) is not independently narrowable or disclosed, the combined date-range × microsecond-fraction search space is excessive brute force (OOS) even though `uniqid()` alone is not cryptographically secure.

CVSS: Unauthenticated + credentials/tokens in logs = 7.5 (C:H). Unauthenticated + PII only = 5.3 (C:L). Log file exists but contains only non-sensitive operational data = not a finding.

### 10I — Cache-Replayed Response Headers (Cross-Visitor Disclosure, CWE-524/CWE-384)

Distinct from 10C: the disclosure mechanism here is NOT direct navigation to an exposed log/cache file — it is a full-page-cache subsystem's own normal "serve from cache" response replaying a PRIOR visitor's captured response headers to every SUBSEQUENT visitor of the same cached URL. `.htaccess`-deny/randomized-path mitigations that neutralize 10C do not apply here — the leak happens through the cache's intended request/response path, not a direct file fetch. Use GREP_RESULTS `LOG_FILE_SESSION_TOKEN_WRITE` and Semgrep `claude.php.wordpress.info-disclosure.unfiltered-response-headers-cached-to-file` (heuristic — flags the write-side shape, does not confirm reachability).

1. **Mechanical rule:** a cache-population function captures `headers_list()` (the full response header set for the current request) and persists it to a per-URL cache file/entry with no `Set-Cookie`-specific filtering, AND a sibling "serve cached page" function later replays the stored headers via `header()` in a loop for a DIFFERENT visitor's request to the same cached URL. Both sides must be confirmed — a write-side hit alone does not prove cross-visitor replay.
2. **Impact:** any `Set-Cookie` header present in the header set at cache-write time (a session/cart/tracking cookie set by the plugin itself, WordPress core, OR any other active plugin/theme on that page) is disclosed to, and silently fixes, every subsequent visitor of that URL until the cache entry invalidates. Exclusion of `wordpress_logged_in_*` from the CACHE KEY/request-side filter (common, since caching a logged-in page at all is usually avoided) does not exclude it from a RESPONSE-side capture like this — check both sides independently.
3. **FP indicator:** the cache-write function filters the captured header list (allow-list, or explicit `Set-Cookie` exclusion) before persisting, OR the plugin's caching feature demonstrably never caches any response that could carry a session-bearing cookie (verify by tracing every code path that could set a cookie on a cacheable request — a request-side login-cookie exclusion is not sufficient by itself).

### 10D — User Object / Password Hash Exposure in Responses (CWE-200)

AJAX/REST handlers returning WP_User objects or arrays containing the `user_pass` bcrypt hash.

Detection: (1) Use GREP_RESULTS `USER_OBJECT_RESPONSE_EXPOSURE`, cross-reference `WP_USER_QUERY` (surface). (2) `(array)$user` on WP_User exposes `data->user_pass`. `json_encode()` on WP_User without field selection serializes all properties. (3) Check for post-query redaction: `unset($user->data->user_pass)` works ONLY for WP_User objects, NOT for flat `stdClass` returns from `WP_User_Query` with `fields` set to an array — verify redaction matches ALL return shapes. (4) Also check `get_users()` with custom `fields` parameter — `fields => 'all_with_meta'` returns full user objects. (5) Check endpoint auth: `manage_options` gated = lower severity (admin already has DB access); Subscriber+ or unauthenticated = higher severity.

FP filter: Handlers that explicitly `unset($data['user_pass'], $data['user_activation_key'])` before response. Handlers gated by `manage_options` capability. REST endpoints returning only public fields via `prepare_item_for_response()` with schema-validated output. WP REST `/wp/v2/users` intentionally exposes public user data (display name, avatar) — not a vulnerability. See FP rule 26 for redaction-bypass analysis on `WP_User_Query` with flat `fields`.

CVSS: Unauthenticated password hash exposure = 7.5 (C:H). Subscriber+ (PR:L) = 6.5 (C:H). Admin-gated = not a finding.

### 10E — Server/System Information Exposure (CWE-200, CWE-209)

`phpinfo()`, system info functions, or verbose error messages reachable from HTTP handlers.

Detection: (1) Use GREP_RESULTS `PHPINFO_SERVER_INFO` and `ERROR_HANDLER_PATH_EXPOSURE`. (2) For `phpinfo()`: confirm reachability from HTTP handler (`wp_ajax_`, REST callback, `admin_init`). Even admin-only `phpinfo()` pages are notable when accessible at Subscriber+ level. (3) For error handlers: trace what data reaches `wp_die()`, `trigger_error()`, or custom error handler output — `$exception->getMessage()` may contain file paths, table names, query structure; `$wpdb->last_error` contains the failed SQL query with table names; `__FILE__`/`__DIR__` expose absolute server paths. (4) Check whether error output is conditional on `WP_DEBUG` — if unconditional, production sites expose this data. (5) For `set_error_handler()`/`set_exception_handler()`: read the handler function body for what it outputs to the user vs what it logs server-side.

FP filter: `wp_die(__('Access denied'))` and other static translated strings are safe. Error handlers writing to `error_log()` only (not HTTP response) are not directly exploitable. Functions behind `if (defined('WP_DEBUG') && WP_DEBUG)` reduce likelihood but do not eliminate — many sites run with debug enabled. `trigger_error()` with `E_USER_NOTICE` does not output to the browser unless `display_errors` is on (unusual in production). An exception/error message whose only content is data the same attacker request already supplied (e.g. a DB connection error built from host/credential values the attacker submitted in that request) discloses nothing incremental regardless of trace verbosity — per the core Scope Gate's "full path disclosure" carve-out, a stack trace disclosing only file paths/line numbers/call chain with no credentials, PII, or query/schema structure beyond what's already attacker-known is OOS even when technically reachable.

CVSS: Unauthenticated `phpinfo()` = 5.3 (C:L). Database structure in error messages = 5.3. File paths in stack traces = 4.3. All require manual confirmation of reachability and data sensitivity.

### 10F — Unprotected Data Endpoints (CWE-862 + CWE-200)

Nopriv AJAX handlers and REST endpoints with `__return_true` permission_callback returning user data, system configuration, or plugin settings.

Detection: (1) Use GREP_RESULTS `NOPRIV_DATA_RESPONSE`. (2) Cross-reference `REST_ENDPOINTS` (surface) for `__return_true` permission callbacks. (3) For each nopriv handler returning data: what specific data is returned? User PII (emails, names, addresses, phone numbers, meta) = high impact. System info (PHP version, WP version, DB prefix, server path) = medium impact. Plugin settings with no secrets = low impact / not a vuln. (4) Verify the handler is not intentionally public (e.g., public directory listing, search endpoint returning published content only, contact form submission endpoint).

FP filter: Endpoints returning only published, public-facing data (post titles, published content, public user profiles with display name/avatar only). Search/filter endpoints that return only data already visible on the frontend. REST endpoints registered with `permission_callback => '__return_true'` for intentionally public APIs (e.g., form submission handlers, public content queries). WP REST Core endpoints for public data are by design.

CVSS: Unauthenticated + user PII (email, billing address) = 5.3–7.5 depending on data sensitivity and volume. Unauthenticated + system info = 5.3. Subscriber+ required = adjust PR:L.

### 10G — REST Field-Level Capability Bypass via `rest_prepare_*` Filters (CWE-862 + CWE-200)

WordPress Core's REST controllers (`WP_REST_Users_Controller`, `WP_REST_Posts_Controller`, etc.) apply field-level capability checks INSIDE `prepare_item_for_response()` before the `rest_prepare_{object}` filter runs — e.g. `WP_REST_Users_Controller` withholds the `roles` field unless the viewer has `list_users` or `edit_user`. A plugin callback hooked on `rest_prepare_user`/`rest_prepare_post`/`rest_prepare_{post_type}`/`rest_prepare_comment` that reads `$response->get_data()`, adds back a field Core just redacted, and writes it via `$response->set_data()` bypasses that field-level protection — even when the REST route's OWN `permission_callback` is correctly capability-gated, because the filter is a separate extension point Core does not re-check.

Detection: (1) Use GREP_RESULTS `REST_PREPARE_FIELD_FILTERS` for `add_filter('rest_prepare_*', ...)` registrations. (2) Read the callback body: does it call `$response->get_data()` → mutate a key → `$response->set_data()`? (3) Identify the callback's own gate (if any) — a bespoke check (URI substring match, `is_user_logged_in()` alone, or no check) is weaker than `current_user_can()`; any viewer who merely satisfies the weak gate receives the restored field regardless of whether they hold the capability Core originally required for it. (4) Confirm the restored field is genuinely one Core redacts by capability (e.g. `roles`, non-public `email`) by checking the matching WP Core controller's `prepare_item_for_response()` — a filter re-adding a field Core never redacted in the first place is not this bug. (5) `rest_route` is a WP Core public query var (`rest_api_register_rewrites()`) — routes are reachable via `?rest_route=/wp/v2/...` independent of pretty permalinks; a weak gate matching on `REQUEST_URI` substrings can be satisfied by appending an unrelated query parameter containing the matched string to an otherwise-normal request for a different route, without any routing ambiguity.

FP filter: the restored field must be one Core's controller actually gates by capability — verify against WP Core source before confirming. Filters that only re-add already-public fields, or that gate the restoration with `current_user_can()` matching or exceeding Core's own requirement, are not findings.

### 10H — Pagination Count/Existence Oracle via Late-Filtered `posts_results`/`the_posts` (CWE-200)

A callback hooked on the `posts_results` or `the_posts` query filter removes restricted/private entries from the post array (typically `unset($posts[$key])` inside a permission-check loop) to hide them from the caller, but never adjusts `$query->found_posts` or `$query->max_num_pages`. WordPress computes those two properties from the raw SQL result set (`SQL_CALC_FOUND_ROWS`) BEFORE this filter runs, so they still reflect the unfiltered count. On any paginated collection query — most notably REST API endpoints, where `found_posts`/`max_num_pages` are surfaced directly as the `X-WP-Total`/`X-WP-TotalPages` response headers — the true count of hidden entries remains observable even though the entries themselves never appear in the response body. Combined with a caller-controlled search/filter query parameter, the (unadjusted) total becomes a boolean oracle: whether a keyword guess increments the reported total reveals whether it matched content inside a post the caller cannot otherwise view.

Detection: (1) Use GREP_RESULTS `POSTS_RESULTS_FILTER_HOOK` for `add_filter('posts_results'|'the_posts', ...)` registrations — note the hook registration and the callback definition are often in different files within the same plugin; resolve the callback across the whole plugin, not just the file containing the `add_filter` call. (2) Read the callback body: does it iterate the `$posts` array and drop entries (`unset()`, `array_filter()`, `array_diff_key()`) based on a permission/visibility check? (3) Search the SAME function body for any write to `$query->found_posts` or `$query->max_num_pages` (the `$query`/second parameter) — absence of both is the vulnerable shape. (4) Confirm reachability: is the query a paginated collection query exposed with per-item counts/headers to the caller (REST collection endpoints are the primary vector; `WP_Query`-backed shortcode/widget listings that render a "N results" or page-count string are a secondary vector)? (5) Confirm the removed entries are genuinely restricted/private content, not just deduplication or post-type filtering.

FP filter: the callback recomputing `found_posts`/`max_num_pages` after removing entries (even a partial per-page decrement) closes the pagination-header side of the oracle. Filters excluding rows at the SQL level instead (a `posts_where`/`posts_clauses` clause reproducing the same permission check) never inflate `found_posts` in the first place and are not this bug. A `posts_results`/`the_posts` callback that filters entries but is never exposed through a caller-visible count/pagination surface (e.g. only used for `The Loop` rendering with no total/page-count in the response) has no oracle to exploit.

CVSS: Unauthenticated + REST search parameter available (keyword-oracle variant, discloses content/keywords) = 5.3 (C:L, but scales with volume of extractable content). Unauthenticated + existence/count only, no search oracle = 5.3 (C:L). Reduce if the restricted-content feature itself requires non-default configuration to be enabled (a plugin-setting prerequisite, not an attacker-side constraint).

CVSS: Subscriber+ (PR:L) disclosure of another user's `roles` = 4.3 (C:L/I:N/A:N). Higher when the restored field carries more sensitive data (email addresses, private meta) or the callback's own gate is reachable unauthenticated.

## CHECKPOINT: Group D1 Complete (after Tier 8–10)

Write `AUDIT_DIR/checkpoint-group-d1.md` with: confirmed findings summary, SSRF/info-disc leads for chaining, any IDOR-relevant observations (handlers with user-controlled URLs that also accept resource IDs).

Update `AUDIT_DIR/leads-forward.md` per the core ledger protocol (SKILL.md §5/§6): append any LEADS for later groups (tag each `Relevant-to`), and for every custom sink you evaluated add/refresh its **SINK LEDGER** row with `D1` in `Consumed-by` (dedup by `fn@file:line`) — leave `(none)` only for a sink deferred to a later group or the Chain pass.

### Auth Model Addendum (Group D1)

If during Tier 8-10 analysis you discovered any auth-relevant facts NOT already in auth-model.md — new nonce availability, new handler auth observations, capability/role discoveries, or auth-relevant structural facts (e.g., a nopriv data endpoint revealing a nonce action string, or a webhook handler with an undocumented auth gate) — append an addendum to `AUDIT_DIR/auth-model.md`:

```markdown
---

## Addendum — Group D1 (<ISO timestamp>)

### New Nonce Availability
| Action String | Min Capability | Public? | Source Page/Hook | Discovery Context |

### New Handler Auth Observations
| Handler | Type | Auth Gate | Nonce | CIA Impact | Discovery Context |

### Capability/Role Discoveries
- ...

### Auth-Relevant Structural Facts
- ...
```

Omit sub-sections with no new observations. Omit the entire addendum if no auth-relevant discoveries were made. Do NOT modify the Foundation phase's original tables or earlier addenda — only append below them.

## Group D1 — FP Verification Rules

These rules supplement the universal FP rules in the shared core SKILL.md Phase 4.

19. **`wp_remote_get()` flagged as SSRF:** Confirm user input controls HOST component, not only path/query on hardcoded domain.
   - `DOMDocument::loadHTML()` alone is not an SSRF vector — PHP's DOM API is a server-side HTML parser that does NOT fetch external URLs for `src`/`href` attributes; SSRF requires a subsequent network call using a URL extracted from the parsed DOM. Confirm a second HTTP call exists before escalating.
35. **`wp_localize_script()` flagged for sensitive data:** Confirm the value is a SECRET key, not a public/client key. Stripe `pk_*` (publishable), reCAPTCHA site key, Google Maps JS API key, Mapbox public token = intentionally public, NOT a vulnerability. Only `sk_*` (secret), `secret_key`, `client_secret`, server-side API tokens with write/admin scope, SMTP passwords = sensitive. Also check hook: `admin_enqueue_scripts` = lower severity than `wp_enqueue_scripts` (frontend), but Subscriber+ can access admin pages (profile.php).
36. **Log file write flagged as exposure:** Confirm the log path is web-accessible. `error_log()` with default config (no third argument) writes to PHP error log (server-side, not web-accessible). `error_log($msg, 3, $file)` with third argument writes to a custom file — only flag when `$file` targets a path under `wp-content/uploads/`, `wp-content/plugins/`, or the WordPress root. Log paths using `sys_get_temp_dir()`, `/tmp/`, or paths outside ABSPATH are not directly web-accessible.
37. **Export file write flagged as predictable:** Verify the complete filename is actually predictable. Plugins using `wp_unique_filename()` or appending `wp_generate_password()` output produce unpredictable filenames. `time()` alone = brute-forceable (1-second resolution, ~86400 attempts/day window). `microtime(true)` is harder but feasible with timing correlation. `uniqid()` = predictable (uses `microtime()` internally). Also verify the export contains sensitive data — a CSV of published post titles is not an information disclosure finding.
38. **User data endpoint flagged as exposure:** Confirm the returned data actually contains sensitive fields. WP REST API `/wp/v2/users` intentionally exposes public user data (display name, avatar URL, author URL) — this is by design and NOT a vulnerability. Only flag when `user_pass`, `user_activation_key`, `user_email` (when not intentionally public), billing addresses, phone numbers, or custom sensitive meta fields are included in the response. Endpoints gated by `manage_options` are low-value findings (admin already has direct DB access).
39. **`fetch_feed()` flagged as SSRF:** Verify the feed URL originates from user input or a DB value writable at low privilege. `fetch_feed()` called with a hardcoded URL or an admin-only configurable URL (behind `manage_options`) is not a finding. WordPress Core calls `fetch_feed()` for dashboard widgets with admin-configured URLs — expected behavior. SDK/vendor dashboard widgets using hardcoded feed URLs are not findings.
40. **`getimagesize()` flagged as SSRF:** Confirm the argument is a URL (starts with `http://` or `https://`), not a local file path. `getimagesize()` on a local file path (`$_FILES['upload']['tmp_name']`, `get_attached_file($id)`, `$image_path`, `$file_path`, `$abspath`) does NOT make a network request. Only remote URLs trigger HTTP. Also verify the argument is user-controlled — `getimagesize()` on a file path returned by `download_url()` (which already fetched and validated) is a local read, not a second network request. Object method calls (`$this->getimagesize()`, `$obj->getimagesize()`) are class methods, not the PHP built-in.
41. **`esc_url()` before HTTP function flagged as insufficient SSRF sanitizer:** Correct — `esc_url()` is NOT an SSRF sanitizer. However, check whether a SEPARATE `wp_http_validate_url()` call or explicit IP-range check occurs elsewhere in the same code path. Some developers apply `esc_url()` for XSS prevention AND `wp_http_validate_url()` for SSRF prevention as two separate steps — only flag when `wp_http_validate_url()` or equivalent IP check is genuinely absent from the entire execution path.
42. **Encrypted response field flagged as information disclosure:** Confirm which party holds the decryption key. A value encrypted with a vendor-controlled public key (matching private key never distributed to any customer/requester tier) before being placed in an API response is not a disclosure to the requester regardless of how sensitive the plaintext is — verify the requester cannot independently decrypt before treating the response field as exposed information.
43. **JSON/serialized-column exact-match lookup keyed by an attacker-supplied field name (`JSON_PATH_DYNAMIC_KEY_LOOKUP` / semgrep `wpdb-json-extract-dynamic-path`):** confirm the query is NOT scoped to the caller's own record (no `user_id`/session-bound WHERE clause) and that no server-side allowlist restricts which key the caller may probe against the resource's actual configuration — both absent turns a routine duplicate/uniqueness check into a cross-user existence oracle (CWE-639/CWE-203) even though the query itself is fully parameterized against SQL injection. Not a finding if either control is present, or the exposed field cannot plausibly hold PII.
44. **Prefix-namespaced key merge is not injectable into a differently-named reserved key.** When raw request data is merged into a shared params/template-tag array via a fixed key-prefixing scheme (e.g. `$params['user_'.$key] = $value`), the prefix makes collision with an unprefixed reserved key (`cc`, `bcc`, `to_email`) structurally impossible — verify the prefix is a fixed, non-attacker-influenceable string before dismissing the merge as non-injectable.

45. **Getter's return value used only as a boolean/conditional test is not disclosed.** A DB/meta getter (`get_comment_meta()`, `get_post_meta()`, `get_option()`, etc.) called with an attacker-supplied ID whose result is used ONLY to decide a conditional branch (`if (0 < get_comment_meta(...))`) — never itself placed into the JSON/HTML response — does not leak the underlying value; only a derived true/false flag or a static label reaches the requester. Trace whether the retrieved VALUE itself (not a boolean outcome) is serialized into the response before flagging Tier 8-10 Info Disclosure.
   - **A broad SQL `SELECT`/ORM fetch is not proof every selected column reaches the response.** Read the response-array CONSTRUCTION step field-by-field (the code building the JSON/array actually returned to the caller), not just the query — a query routinely selects columns (e.g. `full_name`, `email`, raw payment fields) into a local result array that the response-building loop then only partially copies, and only the copied subset counts toward the Confidentiality score.

46. **Merchant/product feed file public reachability is intended function, not a finding.** Data-feed plugins (Google Shopping, Facebook Catalog, or similar XML/CSV output) generate files that must be unauthenticated-reachable by design so third-party ad/marketplace platforms can crawl them with no WordPress session — plain public reachability of the feed URL is not itself an access-control or information-disclosure finding. Only flag when the feed's fields include non-public data (draft/private products, PII, or an admin-mapped secret custom field) beyond what the storefront itself already displays for the same product.

47. **REST field-addition filter is safe when it adds a field Core's schema never defined at all** (distinct from 10G's field-*restoration* bypass above) **and fires only after the route's own `permission_callback` already gated the whole response.** The addition sits within the existing permission boundary rather than opening a new or lower-privilege access path. Confirm the added field is genuinely absent from Core's own controller schema (not merely renamed) before applying this dismissal.
