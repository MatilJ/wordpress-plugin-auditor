# Vuln-Audit Group A — Tier 1–2: RCE, File Upload, File Read/Write/Delete

> Authorized Wordfence bug-bounty research; coordinated-disclosure, local-only. See `AUTHORIZATION.md`.

> **Scope gate:** Contributor/Author auth floor findings are OOS for the Wordfence bounty program (current program policy). Analyze the code path fully for architectural accuracy, but do NOT write Contributor/Author-floor findings to findings.md. Log them as OOS leads in the checkpoint file. SSRF (CWE-918) is also OOS.

Loaded alongside core `SKILL.md`. Follow core Phase 0, Write-Through Protocol, Phase 1/1B before these tiers.

## Tier 1 — RCE / Arbitrary File Upload / SSTI (CVSS 9.0–10.0)

Use GREP_RESULTS sections `TIER1_FILE_WRITE`, `TIER1_CODE_EXEC`, `TIER1_DESERIALIZATION`, `TIER1_COMMAND_EXEC`, `TIER1_TEMPLATE_ENGINES`, `WEBSERVER_DIRECTIVE_HEADER_CONCAT`, `RECURSIVE_UNSERIALIZE_REPLACE`, `POI_MAGIC_METHODS`, `SHORTCODE_ATTR_UNSERIALIZE`, `BASE64_TO_UNSERIALIZE`, `VARIABLE_FUNCTION_CALLS`, `CALLBACK_ACCEPTING_FUNCTIONS`, `REGEX_CAPTURE_CALLBACK_HANDLERS`, `DO_SHORTCODE_RCE`, `REST_RETURN_TRUE_CODE_EXEC`, `REST_RETURN_TRUE_PLUGIN_INSTALL`, `PLACEHOLDER_CODE_EXEC`, `UPLOAD_DESTINATION_FROM_USER`, `IMPORT_HANDLER_UNSERIALIZE`, `UPLOAD_MIMES_FILTER`, `FILETYPE_AND_EXT_FILTER_OVERRIDE`, `DIRECT_FILES_SUPERGLOBAL_UPLOAD`, `REST_FILE_PARAMS`, `SIDELOAD_HANDLERS`, `UPLOAD_PREFILTER_HOOKS`, `WP_UPLOAD_BITS_USER_FILENAME`, `FORM_RECORD_RAW_VALUE_ACCESS`.

**Branch-inconsistency in safety checks:** a validation gate (`file_exists()`, `realpath()`, permission/ownership check) present in one branch of an if/else but silently absent in a sibling branch reached only under different runtime state (e.g. a "fresh/first-run" vs. an "already-initialized/resumed" code path) is a common defect class for Tier 1-2 sinks — read every branch of a conditional guarding a dangerous sink, not only the branch a first-time/default request exercises. This is especially easy to miss when the "resumed" branch's precondition (a marker file, a flag, prior state) is itself created as a side effect of an earlier ordinary request to the same endpoint.

**Intentional capability vs. defective boundary check.** A remote-automation/administrative-tool plugin (site management, deployment, backup orchestration) may expose a sink whose raw power (arbitrary code execution via an "execute custom code" feature, unrestricted remote package installation) is the plugin's own documented purpose, not a code defect — do NOT file these as findings solely because the sink is powerful, PROVIDED (a) no scoping/boundary check was ever attempted for that specific sink (compare: a `realpath()`/prefix check that exists but is discarded or bypassable IS a defect, not by-design), and (b) the sink sits behind the exact same authorization floor as the plugin's other, uncontested administrative actions — a powerful sink gated MORE weakly than sibling actions in the same dispatcher is still a finding. Distinguish "this feature is inherently dangerous by design" from "the floor gating it is also correct by design" — only the latter clears the sink.

**SSTI analysis — mandatory when any template engine found:**
1. **Sandbox check:** Twig: `$twig->addExtension(new Twig_Extension_Sandbox(...))`. Absent → full PHP access via `_self.env`. Smarty: `$smarty->enableSecurity()`. Mustache/Blade/Plates: no PHP exec by design.
2. **Template string vs. variables:** User controls template string → SSTI regardless. Variables only → SSTI only if no sandbox AND engine allows escaping variable context.
3. **Sanitization gap:** See CANON:sanitize-text-field-limits — zero protection against template syntax.
4. **Trace input:** Work backwards from every `->render()`.

**Twig SSTI exploit:** `{{ _self.env.registerUndefinedFilterCallback("system") }}{{ "id"|filter }}` — Twig 1.x without sandbox.

**`call_user_func` callable source analysis (TIER1_CODE_EXEC hits):**

For every `call_user_func($CALLABLE, ...)` hit, classify:
1. **Direct user input:** `call_user_func($_POST['fn'])` — TP.
2. **Registry dispatch (FP):** `call_user_func($this->reg[$key]['callback'])` — two-level subscript, user controls only lookup key, value is developer-registered. FP.
3. **Single-level property with user key (TP):** `call_user_func($this->callbacks[$_POST['action']])` — user directly selects slot.
4. **Internal property, write-path trace required:** Callable `$this->property['key']` seeded with developer callables → grep ALL writes to property (`$this->propName[`, `$this->propName =`) across class + parents. Look for foreach over `$_POST` writing user-derived keys. See CANON:sanitize-text-field-limits — `system`/`exec`/`passthru` pass through unchanged. Write → callable-invoke chain may span 4+ hops; Semgrep cannot track key-level taint. Manual trace mandatory.
5. **Function-parameter-mediated callable:** `is_callable($param)`/`call_user_func($param, ...)` where `$param` is a FUNCTION PARAMETER, not a superglobal or object property read directly in the flagged function — the function body alone cannot establish taint. Grep every call site (`Grep(pattern: "function_name\\(", path: SOURCE_DIR)`); if EVERY call site passes a hardcoded/developer-defined array or literal, it is FP regardless of the sink's own protection level — confirm at least one call site passes genuinely request-derived data before treating as a TP.

**Variable function call analysis (VARIABLE_FUNCTION_CALLS hits):**

PHP allows calling any function via `$var(...)` where `$var` is a string — functionally identical to `call_user_func($var, ...)` but bypasses `call_user_func` detection. Pattern: form field keys mapped to internal placeholders, placeholder values passed to variable function calls — attacker called `wp_set_auth_cookie(1)` for instant admin takeover.

For every `$variable(...)` hit where `$variable` is not a method call (`$this->method()`):
1. **Trace source of $variable:** from `$_POST`/`$_GET`/`$_REQUEST`/shortcode attrs/REST params → TP.
2. **Placeholder/substitution pattern:** plugin stores user input as values in a key-value map, then iterates the map and calls values as functions. Two-step: (a) user input → placeholder/map storage, (b) map iteration → variable function invocation. Steps may be in different methods/files. Example: `prepare_post_data()` maps user-submitted keys to `$this->placeholdered_data`, then `process_data()` iterates and calls `$this->placeholdered_data[$key]()`. Trace: (a) ALL writes to the placeholder/map structure, (b) whether any user-supplied value can become a callable entry, (c) whether the resolution step validates callables against an allowlist.
3. **Allowlist check:** variable validated against a fixed set of permitted function names before invocation? `in_array($var, ['func1', 'func2'])` = safe. `is_callable($var)` alone = NOT safe (any PHP function is callable).
4. **Sanitization check:** `sanitize_text_field()` does NOT prevent callable injection — `system`, `exec`, `passthru`, `wp_set_auth_cookie` all pass through unchanged. Only `intval()`/`absint()`/`(int)` prevent callable injection.
5. **Dynamic method calls `$this->$action()`:** `$action` user-controlled → attacker can invoke any public method on the object. Trace whether the object has methods with dangerous side effects (file write, DB update, option write). Even without arbitrary PHP function access, calling unintended methods = privilege escalation.

**Callback-accepting function analysis (CALLBACK_ACCEPTING_FUNCTIONS hits):**

PHP functions that accept callbacks (`array_map`, `array_filter`, `array_walk`, `array_walk_recursive`, `usort`, `uasort`, `uksort`, `preg_replace_callback`, `ob_start`, `register_shutdown_function`, `spl_autoload_register`, `set_error_handler`, `set_exception_handler`, `array_reduce`) execute the callback on each element or event. Callback argument user-controlled → attacker can specify any PHP function.

For every hit where the callback position contains a variable (`$var`, not a string literal or `[$obj, 'method']` array):
1. **String literal callbacks safe:** `array_map('intval', $data)` = FP. Only variable callbacks require analysis.
2. **Array callable `[$obj, 'method']` is developer-controlled:** FP unless `$obj` or `$method` is user-controlled.
3. **Trace callback source:** from `$_POST`/`$_GET`/`$_REQUEST`/options/meta → TP.
4. **`ob_start($callback)`:** user-controlled callback processes ALL buffered output — high impact.
5. **`preg_replace_callback` with `eval()`/`include()`/`require()` in callback body:** callback body passes content captured by the regex match array (`$matches[N]`, possibly reassigned through `trim()`/ternary hops before use) to `eval()` (RCE) or `include`/`include_once`/`require`/`require_once` (LFI, chainable to RCE) → confirmed code/file-inclusion injection when the string being matched comes from user-controllable sources (cached page output, post/comment content, request headers). Use `REGEX_CAPTURE_CALLBACK_HANDLERS` grep results — it lists every function/closure with a `$matches`/`$match` parameter regardless of how it was registered as a callback (named method via `array($this, 'method')`, plain function name, or inline closure), which `CALLBACK_ACCEPTING_FUNCTIONS` alone misses for array-callable registrations. Custom "dynamic tag" syntax (opening/closing HTML-comment markers around inline code or a file path) is frequently implemented as twin sibling handlers with the identical root cause — check both, not just the one Semgrep/grep surfaced (e.g. an inline-code `mfunc`-style `eval()` handler paired with a file-path `mclude`-style `include()` handler, both consuming content captured from the same `<!-- TAG token -->...<!-- /TAG token -->` markers).
   - **Gating check ≠ safe — read what the token is compared against.** A plain string/constant comparison of a token embedded in the *same* content stream (`===`, `in_array`, `strpos`) is security-by-obscurity, not authorization: the token is only as secret as every other place that content can leak from (verbose errors, a debug/raw-output bypass, an unrelated disclosure bug). Do not dismiss as safe merely because *some* token check exists.
   - **Constant-time HMAC against a server-side-only secret is a materially stronger gate.** `hash_equals($expected, $submitted)` where `$expected` is derived from a value never echoed to the client (e.g. `AUTH_KEY`/`AUTH_SALT`, not the token embedded in the tag itself) means the attacker cannot forge a valid tag even with full knowledge of the content-embedded token. Treat as mitigated — but check for a fallback branch (e.g. `if (empty($secret)) { $key = $fallback; }`) that degrades the HMAC key back to attacker-visible data.

**`do_shortcode()`/`apply_shortcodes()` arbitrary execution analysis (DO_SHORTCODE_RCE, COMMENT_TEXT_DO_SHORTCODE, SHORTCODE_CONSTRUCTION_INJECTION, DO_SHORTCODE_CONTENT_FILTER hits):**

`do_shortcode()` renders ALL registered shortcodes in the input string. `apply_shortcodes()` is a WP Core alias (wp-includes/shortcodes.php:223) — treat identically. Wordfence classifies as CWE-94 (Code Injection). Typical CVSS: 7.3 unauth (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L), 5.4 subscriber+ (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N).

Classification:
1. **User controls full shortcode expression (name + params):** HIGH. Attacker invokes any registered shortcode with arbitrary parameters. Impact depends on shortcodes registered site-wide (not just in the audited plugin).
2. **User controls only parameter VALUES inside developer-hardcoded tag:** MEDIUM. Impact limited to what the specific shortcode callback does with parameters.
3. **User controls content between shortcode tags only:** LOWER. Most shortcode callbacks treat inner content as display text.

Six vulnerable code patterns (check ALL):

**Pattern 1 — Direct AJAX/REST handler → do_shortcode():** `wp_ajax_nopriv_*` or REST endpoint with `__return_true`/`is_user_logged_in` passing `$_POST`/`$_GET`/`$request` to `do_shortcode()`. Most common. Use `DO_SHORTCODE_RCE` grep results.

**Pattern 2 — Comment filter registration:** `add_filter('comment_text', 'do_shortcode')` or `add_filter('comment_text', 'apply_shortcodes')`. Makes ALL public comments shortcode-executable — unauthenticated write surface via comment form. Also check `get_comment_text` and `comment_excerpt` filters. Use `COMMENT_TEXT_DO_SHORTCODE` grep results.

**Pattern 3 — Shortcode construction injection:** user input concatenated into shortcode string: `'[' . $user_input`, `"[$var"`, `sprintf('[%s', $var)`. Attacker injects `]` to close the intended tag and appends arbitrary shortcode expressions. Use `SHORTCODE_CONSTRUCTION_INJECTION` grep results.

**Pattern 4 — Content filter hooks:** plugin adds `do_shortcode`/`apply_shortcodes` as filter callback on non-standard hooks (`widget_text`, `term_description`, custom hooks). Extends shortcode execution to content sources not covered by WP Core's `the_content` filter. Use `DO_SHORTCODE_CONTENT_FILTER` grep results (surface group).

**Pattern 5 — Second-order via DB content:** `do_shortcode(get_option(...))`, `do_shortcode(get_post_meta(...))`, `do_shortcode(get_user_meta(...))`. Exploitable when the write path is accessible to low-privilege users. Forward to Group C for write-path triage. Use `DO_SHORTCODE_DB_CONTENT` grep results (group-c).

**Pattern 6 — REST `$request->get_param()` flow:** REST endpoint extracting content parameter and passing to `do_shortcode()`. Check `permission_callback` — `__return_true` or `is_user_logged_in` = unauthenticated or subscriber+. Covered by `DO_SHORTCODE_RCE` cross-file filter.

**Pattern 7 — Cross-file merge-tag resolver into `do_shortcode()`:** a `preg_replace_callback()`/`str_replace()` token resolver (e.g. a form-builder's `[field id="..."]`/`{tag}`-style merge-tag substitution) runs in one method/class while the resolved string is passed to `do_shortcode()` in a different method/class. Trace EVERY `SHORTCODES`/`do_shortcode()` hit backward through any preceding token-substitution call before treating it as covered — a SINK LEDGER row already `Consumed-by` another group (e.g. XSS/email-injection) only means that group's OWN tier evaluated it, not Tier 1 Code Injection.

Exploitation assessment:
- Enumerate ALL `add_shortcode()` registrations. Look for shortcodes that: call `wp_insert_user()`/`wp_update_user()`, execute `$wpdb->query()`, call `update_option()`, perform file operations, or call `wp_mail()` with user-controlled recipients.
- `sanitize_text_field()` does NOT prevent shortcode execution — `[tag attr=value]` bracket syntax passes through unchanged.
- `wp_kses_post()` does NOT strip shortcode syntax — kses processes HTML tags, not shortcode brackets.
- `strip_shortcodes()` IS a valid mitigation — removes all shortcode syntax from the string.
- `wp_strip_all_tags()` strips brackets — valid mitigation.
- `(int)`/`intval()`/`absint()`/`sanitize_key()` — valid mitigations (produce values that cannot form shortcode expressions).
- `do_shortcode()` early-returns unchanged if input lacks `[` (shortcodes.php:246) — irrelevant to defense since attacker controls the input.
- WP Core `pre_do_shortcode_tag` filter (WP 6.3.2+) can allowlist specific shortcodes — if present and used, assess allowlist scope.

**REST API `__return_true` + code execution chain analysis (REST_RETURN_TRUE_CODE_EXEC, REST_RETURN_TRUE_PLUGIN_INSTALL hits):**

REST endpoints with `permission_callback => '__return_true'` or `permission_callback => function() { return true; }` are unauthenticated. Callback handler performing code execution, plugin installation, or deserialization → unauthenticated RCE.

For every `REST_RETURN_TRUE_CODE_EXEC` hit:
1. Read the `register_rest_route()` call to find the callback function.
2. Read the callback body for: `eval()`, `call_user_func()`, `$var()`, `unserialize()`, `activate_plugin()`, `Plugin_Upgrader`, `file_put_contents()`, `include()`.
3. If the callback takes user input from the REST request body/params and passes it to any Tier 1 sink → confirmed unauthenticated RCE.

Patterns:
- Unauthenticated REST endpoint with `__return_true` called `activate_plugin()` / `Plugin_Upgrader`, enabling installation of a known-vulnerable plugin which then provides the RCE vector.
- Backdoor: REST endpoint with always-allow permission callback + `unserialize()` on attacker-controlled data + arbitrary function call via `call_user_func` on remote-fetched function name.

**File upload checklist:**
- `wp_check_filetype()` = extension only. `wp_check_filetype_and_ext()` adds content inspection (images: `exif_imagetype()`; non-images: `finfo_file()` if loaded, else extension-only fallback).
- `$_FILES['type']` is client-supplied — never trust
- Block `.phtml`, `.phar`, `.shtml`
- Upload path web-accessible with no `.htaccess` deny?
- Handler callable unauthenticated?
- **Source vs destination filename mismatch (UPLOAD_DESTINATION_FROM_USER hits):** `handle_upload()` validates SOURCE file type (`$_FILES['name']` extension) but the DESTINATION filename comes from a separate user-supplied parameter. Attacker uploads `image.jpg` (passes type check) but sets destination to `shell.php`. For every upload handler: (a) which filename the type/extension check runs against, (b) which filename is used in the destination path of `move_uploaded_file()`/`rename()`/`copy()`, (c) if they differ and the destination is user-controlled → confirmed arbitrary file upload even with valid type checking on the source
- **Verify failed filetype check HALTS execution** before file-move call. Error stored in `$errors[]` without `return`/`die()` before `rename()`/`move_uploaded_file()` = file moves regardless.
- **`media_handle_upload()` callers:** WP Core function creating a full Media Library entry (`wp_posts` attachment + file in `wp-content/uploads/`); validates MIME types internally but does NOT enforce authorization. For every `media_handle_upload(` hit in `TIER1_FILE_WRITE`, verify `current_user_can('upload_files')` appears in the same function before the call — absent = unauthenticated Media Library write regardless of filetype restrictions.
- **`wp_handle_upload()` callers:** Writes file to uploads directory only (no Media Library post). Does NOT enforce authorization. For every `wp_handle_upload(` hit in `TIER1_FILE_WRITE`, verify `current_user_can('upload_files')` appears in the same function before the call — absent = unauthenticated file upload at the endpoint's auth floor. `['test_form' => false]` suppresses the form-origin check (common for AJAX uploads) but is not an auth mechanism.
- **Per-field upload validation keyed by submitted field name, null on no match:** `$config = isset($allowlist[$name]) ? $allowlist[$name] : null; if ($config) { validate_type_and_size(); }` skips VALIDATION — not the upload itself — for any submitted `$_FILES`/field key absent from the allowlist; the file for an unrecognized name still reaches the upload sink unconditionally outside that `if` block. Read the code path for an unconditional upload call after a null-config branch before concluding per-field type/size checks apply to every submission.
- **`edit_posts` vs `upload_files` dispatcher split:** WordPress default roles give Contributor `edit_posts` but NOT `upload_files`. When a parent AJAX handler gates entry on `edit_posts` (or nonce alone) and dispatches to sub-functions invoking `media_handle_upload()`/`media_sideload_image()`/`wp_handle_upload()`, verify each sub-function independently checks `current_user_can('upload_files')` — the parent's capability check does NOT cascade. A sub-function missing `upload_files` allows Contributor-level arbitrary Media Library writes regardless of the parent gate.
- **Public guest-upload feature is not automatically the same defect as the two rules above.** A `media_handle_upload()`/`wp_handle_upload()` call with no `current_user_can('upload_files')` check is not reportable when ALL of the following hold: (a) the endpoint's own documented purpose is public content submission by design (not an admin/dispatcher action gated elsewhere), (b) the handler applies its own extension allowlist restricted to non-executable, non-HTML-capable types (image/video/audio only — no `.php`/`.phtml`/`.svg`/`.html` family) independent of WP Core's own `wp_check_filetype_and_ext()`, and (c) the write operates at the same auth floor as the plugin's other actions in the same public flow (no downgrade relative to sibling handlers). All three must hold — a file-type allowlist alone does not excuse a handler that is narrower-gated than its siblings.
- Upload path behind crypto/auth gate → audit the gate (Phase 2B)
- **Remote sideload pattern (SIDELOAD_HANDLERS, TIER1_FILE_WRITE `download_url` hits):** `download_url()` + `wp_handle_sideload()` or `wp_remote_get()` + `file_put_contents()`. Three checks: (1) source URL user-controlled? from `$_POST`/`$_GET`/REST param/option writable by low-priv user → attacker controls downloaded content. (2) extension derived from URL path? `basename(wp_parse_url($url, PHP_URL_PATH))` preserves attacker-chosen extension from the URL. (3) `wp_check_filetype()` or `wp_check_filetype_and_ext()` called between download and file-store? absent → arbitrary type reaches disk. Common in avatar importers, font uploaders, media migration tools.
- **`upload_mimes` filter expansion (UPLOAD_MIMES_FILTER hits):** `add_filter('upload_mimes', $callback)` — check the callback return value. Dangerous additions: any PHP-executable extension (`php`, `phtml`, `phar`, `shtml`, `php5`, `pht`), `.htaccess`. Adding JSON/CSV generally safe. Check whether the filter runs unconditionally or only for specific user roles — admin-only filter = PR:H, OOS.
- **`wp_check_filetype_and_ext` filter override (FILETYPE_AND_EXT_FILTER_OVERRIDE hits):** `add_filter('wp_check_filetype_and_ext', $callback, ...)` — fires inside WP Core's `wp_check_filetype_and_ext()` (wp-includes/functions.php:3100) and can override ALL validation results. Read the callback body: (a) returns forced `$data['ext']`/`$data['type']` unconditionally? → bypasses ALL WP type checking, any file type passes. (b) only runs for specific extensions (e.g., SVG, JSON)? → scoped bypass, assess risk per extension. (c) performs its own content inspection (e.g., `simplexml_load_file()` for SVG, `json_decode()` for JSON)? → partial mitigation but may miss polyglots. Pattern: plugin adds SVG support by forcing the filter return without sanitizing SVG content → Stored XSS.
- **Web-server directive injection from a stored value (WEBSERVER_DIRECTIVE_HEADER_CONCAT hits):** an `.htaccess`/`nginx.conf` rule-generator builds a line like `'Header set X "' . $val . '"'` / `"add_header X \"" . $val . "\";"`. For every hit: (1) trace `$val` back to its source — a plugin option/config getter (`get_option`, a settings-wrapper `->get_string()`/`->get_array()`) is the vulnerable shape; a hardcoded string or an integer/enum-constrained value is not. (2) confirm NO sanitizer (custom CRLF/quote-stripping helper, `sanitize_text_field()`, an enum/allowlist check) sits between the read and this concatenation — check both the render site and the option's own `sanitize_callback`/`register_setting()`. (3) confirm the buffer is actually written to a `.htaccess`/`*.conf`/LiteSpeed-rules file (cross-reference `TIER1_FILE_WRITE`/`file_put_contents`/`->put_contents()` in the same class) rather than merely echoed to the browser via PHP's own `header()` (a different bug class, CWE-113). If (1)-(3) all hold, a value containing `\r\n` injects a new Apache/Nginx directive once the file (re)generates — confirm the write path's auth floor (an admin-only settings save is a much weaker finding than an unauthenticated/low-priv write path or an automatic regeneration trigger such as a cache flush).
- **`wp_upload_bits()` with user-controlled filename (WP_UPLOAD_BITS_USER_FILENAME hits):** `wp_upload_bits($filename, $deprecated, $content)` — internally calls `wp_check_filetype($filename)` (wp-includes/functions.php:2910) which validates extension ONLY (no content inspection via `finfo_file()`). `$filename` from user input (`$_POST`, `$_FILES['name']`, REST param) → attacker controls the extension. Common in import handlers accepting `.json`/`.xml`/`.csv`/`.zip` where the filename is extracted from the uploaded file's original name. Verify: (a) source of `$filename`, (b) whether additional extension validation exists before the call, (c) whether the plugin expands `upload_mimes` to add dangerous types, (d) whether `wp_upload_bits` return value `['file']` path is later served or included.
- **Form-builder integration trusting a raw field value as an upload path (FORM_RECORD_RAW_VALUE_ACCESS hits):** a third-party form-builder's submission object exposes a generic/raw field value (e.g. `'raw_value'`) alongside a separate, distinct accessor for legitimately uploaded files — if code treats the raw value as an uploaded file's path for a field typed `upload`/`file` without checking the dedicated accessor (no file need exist in `$_FILES`), an attacker submits the field as plain text to control that path; check where the stored value is later used (`copy()`/`rename()`/`file_get_contents()`/include) for read/copy/traversal impact.
- **Archive extraction without per-file validation (ZIP_HANDLING grep hits):** `ZipArchive::extractTo()` or `PclZip` extracts ALL files without per-file type validation. Check: (1) handler validates each file's extension INSIDE the archive before extraction? Iterating `$zip->getNameIndex()` and checking extensions is the safe pattern. (2) Post-extraction cleanup (extract → scan → delete dangerous files) has a TOCTOU window — concurrent request may access the `.php` file between extraction and deletion. (3) extraction target a web-accessible directory? `wp-content/uploads/` subdirectories are publicly accessible by default. (4) `ZipArchive::extractTo()` called with a specific entry list (second argument), or extracts everything?
- **REST API file upload endpoints (REST_FILE_PARAMS hits):** `$request->get_file_params()` in REST callbacks may bypass the standard `$_FILES` + `wp_handle_upload()` flow. Check: (1) `permission_callback` enforces `upload_files`? `__return_true` or `is_user_logged_in` alone is insufficient. (2) after retrieving file params, callback validates file type/extension before writing to disk? (3) uses `move_uploaded_file()` or `file_put_contents()` directly (no WP upload function)? Direct write without WP validation = complete absence of type checking.
- **Import/migration upload handlers:** Plugins accepting `.json`, `.xml`, `.csv`, `.zip` uploads for import/migration/demo-content. Often: (a) accept uploads via `wp_upload_bits()` with original filename preserved, (b) process content without re-validating actual file type matches expected import format, (c) extract ZIP to temp directories that remain web-accessible, (d) run with reduced auth (`import` capability or `edit_posts` instead of `manage_options`). Trace import handlers from AJAX hooks or REST endpoints containing `import`, `migrate`, `restore`, `demo`, `template` in the action name.
- **Chained settings-update + auto-download:** Two-step chain: (1) a settings page or AJAX handler stores a URL in `update_option()` without proper auth/CSRF (cross-reference TIER4_OPTION_WRITES from Group AC), (2) a cron job, `init` hook, or page-load callback later calls `download_url()` or `wp_remote_get()` + `file_put_contents()` using that stored URL (cross-reference SSRF_CRON_HTTP_FETCH from Group D1). Neither step alone is an AFU, but the chain enables RCE: attacker writes a URL pointing to a PHP file → auto-download saves it to a web-accessible path. Look for option names containing `url`, `endpoint`, `source`, `feed`, `webhook` that flow to HTTP fetch + file write.

### PHP Object Injection Analysis (use with TIER1_DESERIALIZATION, BASE64_TO_UNSERIALIZE, RECURSIVE_UNSERIALIZE_REPLACE, SHORTCODE_ATTR_UNSERIALIZE, COOKIE_DESERIALIZATION, POI_MAGIC_METHODS, POI_BUNDLED_LIBRARIES, IMPORT_HANDLER_UNSERIALIZE, CUSTOM_UNSERIALIZE_WRAPPERS, CUSTOM_META_TABLE_UNSERIALIZE, TOKEN_META_WRITE_NO_SERIALIZE)

**Source classification (triage order):**
1. **Direct user input:** `unserialize($_POST[...])`, `unserialize($_COOKIE[...])`, `session_decode($_POST[...])` → immediate TP, begin POP chain assessment. `COOKIE_DESERIALIZATION` hits are highest priority: cookies are unauthenticated input by definition (PR:N, no nonce/auth possible)
2. **Shortcode/widget/block attributes:** `unserialize($atts[...])`, `maybe_unserialize($instance[...])` → Contributor+ controlled. Confirm shortcode is registered and attribute passes through `shortcode_atts()` without type coercion to non-serialized format
3. **AJAX handler POST params:** `maybe_unserialize()` on `$_POST` value inside `wp_ajax_*`/`wp_ajax_nopriv_*` → check nonce/auth gates per CANON:nonce-verification
4. **Import/export/backup:** `RECURSIVE_UNSERIALIZE_REPLACE` hits → trace to import handler entry point; determine auth floor. These functions internally call `unserialize()` without `allowed_classes` restriction
5. **Encoding-wrapped:** `BASE64_TO_UNSERIALIZE` hits → `unserialize(base64_decode($input))`. Trace `$input` to source; base64 layer does not add security
6. **Second-order (DB-stored):** `unserialize(get_option(...))`, `maybe_unserialize(get_post_meta(...))` → trace ALL writes to the specific option/meta key. Writable by Subscriber (REST meta, AJAX) or Contributor (block attributes) → chain viable. Writable only by admin → dismiss. Cross-reference `TIER4_OPTION_WRITES` and `OPTION_TRANSIENT_WRITES` (Group AC grep) for write paths to the same option/meta/transient keys — `get_option()` and `get_transient()` internally call `maybe_unserialize()`
7. **Server-fetched:** `unserialize(wp_remote_retrieve_body(...))` → requires MitM (OOS) unless confirmed SSRF endpoint controls the remote host
8. **Custom key/value meta table (CUSTOM_META_TABLE_UNSERIALIZE hits):** `unserialize($row['meta_value'])` / `maybe_unserialize($row['option_value'])` where the row was fetched by a plugin-defined `$wpdb` query (not WP core's `get_post_meta()`/`get_option()`/`get_user_meta()`). Trace every write path to that column — plugins reimplementing a WP-style meta table frequently insert scalar values without wrapping them in `serialize()` first, so any request field reaching that column unvalidated is a direct POI sink
8b. **Write-side companion (TOKEN_META_WRITE_NO_SERIALIZE hits):** a getter call (`$obj->get_X()`) or array/subscript access, sourced from a form submission/webhook/CRM record created via a public opt-in, is passed straight into a plugin's own `save`/`meta`/`token`-named persistence call, or into a literal `'meta_value'` array-literal slot, with no `maybe_serialize()`/`serialize()`/`wp_json_encode()`/`json_encode()` wrapping (the real-world shape: unauthenticated CRM/form field values written unwrapped to a plugin log-meta table, later deserialized raw via `maybe_unserialize()` on read). Pair with a #8-style read-side hit for the SAME table/column before reporting — this write-side hit alone does not prove a read path deserializes the value. `sanitize_text_field()`-style tag-stripping on the value does NOT count as a fix (does not reliably break a valid serialized-value string)
9. **SQL-injection-synthesized input (do not require a naturally-tainted stored value):** when an `unserialize()`/`maybe_unserialize()` sink's input is itself the value of an attacker-selectable field FROM a query the attacker also controls (e.g. an API parameter letting the caller supply a raw `SELECT` statement or column list — see Tier 3 SQLi's raw-query patterns), the attacker does not need to find or wait for a naturally-occurring serialized value anywhere in the database: they synthesize the exact byte content of the eventual `unserialize()` argument directly via a SQL literal (`SELECT 'O:8:"stdClass":0:{}' AS x`). If a SEPARATE parameter also lets the attacker choose WHICH result column gets deserialized, both the unserialize() input value and the decision to deserialize it are fully attacker-controlled — report as POI distinct from the underlying SQLi (different CWE/root-cause point in the data flow) per the Root Cause Count test.

**`allowed_classes` check (mandatory for every unserialize sink):**
- `unserialize($data, ['allowed_classes' => false])` → safe, no object instantiation possible
- `unserialize($data)` without second argument → vulnerable
- `maybe_unserialize()` → always calls `@unserialize(trim($data))` with NO `allowed_classes` parameter (wp-includes/functions.php:653) → always vulnerable if input is attacker-controlled
- `session_decode()` → triggers PHP deserialization of session data with no `allowed_classes` equivalent → always vulnerable if input is attacker-controlled
- A wrapper exposing `allowed_classes` (or a similarly-named parameter) as its OWN parameter with a default value is safe only if that default is `false` and no call site overrides it to `true` — verify by quoting the function's own docblock/behavior against native PHP semantics (`false` = no classes permitted = safe) rather than inferring meaning from the parameter or variable name.

**`__unserialize` priority bypass (PHP 7.4+, mandatory check when __wakeup found):**
- If a class defines `__unserialize()`, PHP 7.4+ IGNORES `__wakeup()` entirely
- Security checks in `__wakeup()` (e.g., exception throwing to prevent deserialization) are bypassed if `__unserialize()` does not replicate them
- When `POI_MAGIC_METHODS` shows `__wakeup` with security checks, grep the same class for `__unserialize` — if present without equivalent checks, the protection is nullified

**Custom wrapper functions (CUSTOM_UNSERIALIZE_WRAPPERS hits):**
When a plugin defines its own `*unserialize*` function, read the body: (a) passes `allowed_classes => false` to `unserialize()`? (b) adds any validation? Then grep all callers of the wrapper — the wrapper name becomes a custom sink for taint analysis

**POP chain assessment (run only after confirming user-reachable sink):**
1. Read `POI_MAGIC_METHODS` grep results — inventory `__destruct`, `__wakeup`, `__unserialize` definitions (auto-invoked during deserialization), plus `__toString` and `__call` definitions (intermediate POP chain gadgets, not auto-invoked but triggerable from `__destruct` body operating on controllable properties). `__unserialize` (PHP 7.4+) takes PRIORITY over `__wakeup` — if both exist, `__wakeup` is completely ignored
2. Read `POI_BUNDLED_LIBRARIES` grep results — check for phpggc-compatible libraries: GuzzleHttp, Monolog, TCPDF, FakerPHP, Symfony, Doctrine, Illuminate, SwiftMailer, Dompdf
3. If bundled library detected: check version in `composer.json` or `composer.lock` or library header constants against phpggc chains
4. Check for Contact Form 7 compatibility — CF7 classes provide a file deletion chain usable from any POI sink on a site with CF7 installed
5. **Scoring:** Known chain with matching version → CVSS 9.8. Plugin-defined `__destruct` with file/exec operations → CVSS 9.8 (custom chain). No chain found → report as POI sink, note absence, CVSS per data-flow impact

**Import/export deserialization sub-pattern** (`RECURSIVE_UNSERIALIZE_REPLACE` hits):
1. Trace function to caller — typically import, migration, or search-replace handler
2. Admin-only import with nonce = low priority. Subscriber/nopriv import = critical
3. Check if import accepts file uploads (.json, .xml, .csv, .zip, .sql) containing serialized PHP data — attacker controls serialized payload directly
4. These functions walk serialized data via unserialize → modify → serialize in a loop; no `allowed_classes` restriction

**POI-specific FP rules:**
- `maybe_unserialize(get_option('plugin_settings'))` where option is only written by admin settings page (no lower-privilege write path) = FP
- `unserialize($data, ['allowed_classes' => false])` = FP regardless of input source
- `unserialize()` on `wp_remote_retrieve_body()` data without confirmed SSRF = FP (MitM required = OOS)
- `maybe_unserialize()` calls inside WordPress Core's own `get_option()`/`get_post_meta()` implementation = not plugin code, not auditable
- `CUSTOM_META_TABLE_UNSERIALIZE` hit = FP only if EVERY write path to that column always wraps the value in `serialize()` first (reversing a trusted internal encoding, not deserializing a raw attacker string) AND no write path is reachable below the minimum in-scope privilege
- `TOKEN_META_WRITE_NO_SERIALIZE` hit = FP if the accessor value is admin-only/numeric-only (an ID, count, or status code — not free-text), OR if no read path for the same column ever calls `unserialize()`/`maybe_unserialize()` on the raw value (structural write-side match alone is not proof of exploitability — pair with a read-side hit)
- A write primitive that only performs a deterministic, content-preserving substitution on bytes already present in the target field (e.g. a fixed find/replace) is a POI *trigger*, not a payload-delivery vector, and does not make an unserialize() sink exploitable by itself. Confirm the write path can introduce genuinely new, attacker-chosen bytes into the field before treating unserialize() reachability as exploitable.

- **`download_url($url)` remote-fetch pattern:** Fetches URL to temp file. Plugin calling `$wp_filesystem->move($tmpfile, $dest_dir . basename(wp_parse_url($url, PHP_URL_PATH)))` writes attacker-influenced filename. Check TIER1_FILE_WRITE for `download_url(` hits: (1) destination filename from URL path = user-influenced extension; (2) `wp_check_filetype()` called before move?; (3) frontend filter hooks make this unauthenticated; (4) user-controlled URL argument without a preceding `wp_http_validate_url()` → forward as Tier 8 SSRF lead — `download_url()` uses `wp_safe_remote_get()` internally, which does NOT block 169.254.0.0/16.

## Tier 2 — Arbitrary File Read / Write / Delete (CVSS 7.5–9.0)

Use GREP_RESULTS sections `TIER2_FILE_READ`, `TIER2_FILE_DELETE`, `FILE_EXISTS_BEFORE_DELETE`, `WP_FILESYSTEM_DELETE`, `DELETE_HANDLER_REGISTRATION`, `FILE_DELETE_USER_INPUT_DIRECT`, `BATCH_FILE_DELETE`, `RECURSIVE_DIRECTORY_DELETE`, `ATTACHMENT_METADATA_UNLINK`, `FILE_DOWNLOAD_ENDPOINTS`, `FILE_READ_STREAM_FUNCTIONS`, `DOWNLOAD_HANDLER_REGISTRATION`, `WP_FILESYSTEM_READ`, `READFILE_USER_INPUT_DIRECT`, `TIER2_CONTENT_DELETE`, `CONTENT_DELETE_HANDLER_REGISTRATION`, `CONTENT_DELETE_USER_INPUT_DIRECT`.

- File delete → RCE: deleting `wp-config.php` triggers install wizard → attacker creates admin
- File read → full compromise: `wp-config.php` yields DB credentials and auth salts
- Path traversal: `sanitize_file_name()` strips `../`; `sanitize_text_field()` does NOT
- File downloads: `realpath()` + directory prefix check present?

### Arbitrary File Deletion Analysis (use with TIER2_FILE_DELETE, FILE_EXISTS_BEFORE_DELETE, WP_FILESYSTEM_DELETE, DELETE_HANDLER_REGISTRATION, FILE_DELETE_USER_INPUT_DIRECT, BATCH_FILE_DELETE, RECURSIVE_DIRECTORY_DELETE, ATTACHMENT_METADATA_UNLINK)

File deletion vulnerabilities where plugins use `unlink()`, `wp_delete_file()`, `rmdir()`, `$wp_filesystem->delete()`, or `array_map('unlink', ...)` to remove files. Typically escalatable to RCE: deleting `wp-config.php` triggers the install wizard, allowing an attacker to reconfigure the site with an attacker-controlled database and gain admin access (CWE-22/CWE-73).

**Priority order:** (1) Direct superglobal → unlink/wp_delete_file/rmdir (`FILE_DELETE_USER_INPUT_DIRECT`) — highest confidence, nearly always TP; (2) Delete handler registrations (`DELETE_HANDLER_REGISTRATION`) — follow each `wp_ajax_nopriv_*delete*file*` / `wp_ajax_*delete*file*` to its callback; (3) WP_Filesystem deletes (`WP_FILESYSTEM_DELETE`) — `$wp_filesystem->delete()` has NO path validation (class-wp-filesystem-direct.php:392, calls `@unlink()` directly); (4) Batch deletion (`BATCH_FILE_DELETE`) — `array_map('unlink', glob(...))` where glob path is user-influenced; (5) Recursive directory deletion (`RECURSIVE_DIRECTORY_DELETE`) — custom `rrmdir`/`recursive_delete` functions; (6) Attachment metadata poisoning (`ATTACHMENT_METADATA_UNLINK`) — poisoned `thumb`/`file` metadata fields → unlink; (7) file_exists()-only-guarded deletes where the path is a concatenated base-dir + stored-value expression (`FILE_EXISTS_BEFORE_DELETE`) — the path's variable portion may have been written by an earlier, less-trusted request rather than the current one; trace its origin before dismissing; (8) Generic delete hits from `TIER2_FILE_DELETE`.

**Delete endpoint analysis checklist:**
1. **Identify the entry point:** delete function registered via `wp_ajax_nopriv_*` (unauthenticated), `wp_ajax_*` (Subscriber+), `admin_post_nopriv_*`, `admin_post_*`, REST endpoint, `template_redirect`, `init`/`plugins_loaded`/`after_setup_theme` hook (all Unauthenticated — fire before auth on every request, see SKILL.md Quick Reference), or standalone PHP file? Also check whether the deleting class is instantiated unconditionally at file scope (e.g. a singleton `get_instance()` call on the last line of a file loaded via unconditional `require_once`) — this is an Unauthenticated entry point regardless of which hook the constructor itself registers on. Cross-reference `DELETE_HANDLER_REGISTRATION` with `AJAX_HOOKS`, `INIT_HOOKS`, and `STANDALONE_PHP` from surface results.
2. **Trace the file path parameter:** which `$_GET`/`$_POST`/`$_REQUEST` key supplies the filename/path? Common names: `file`, `filename`, `path`, `filepath`, `attachment`, `name`, `image`, `media`, `target`.
3. **Check auth/nonce gates:** handler verifies `wp_verify_nonce()` and/or `current_user_can()`? If nonce-only, trace the nonce creation site per CANON:nonce-verification. `wp_ajax_nopriv_` handler with no auth check = unauthenticated file deletion (CRITICAL).
4. **Assess path sanitization on the deletion path** — see sanitizer misuse and correct sanitization below.
5. **Check delete function:** `unlink()` and `wp_delete_file()` have NO built-in path validation. `$wp_filesystem->delete()` has NO path validation. `wp_delete_file_from_directory()` IS safe (realpath + prefix check, functions.php:7786). `wp_delete_attachment()` IS safe (integer ID-based, media library constrained).

**Sanitizer misuse patterns (false sense of security — specific to deletion):** identical set of ineffective path checks as Tier 2 File Read's "Sanitizer misuse patterns" below (`sanitize_text_field()`, `file_exists()`/`is_file()`, single-pass `str_replace('../','')`, `ltrim()`, `wp_normalize_path()`, `urldecode()` double-decode) applies equally to unlink/`wp_delete_file()` sinks. One deletion-specific addition: `wp_delete_file()` itself calls `@unlink()` directly with ZERO path validation (functions.php:7760) — only applies the `wp_delete_file` filter hook. It is a SINK, not a sanitizer.

**Correct sanitization verification (must be applied to the unlink/wp_delete_file PATH argument):**
- `wp_delete_file_from_directory($file, $directory)` — SAFE. Uses `realpath()` + `str_starts_with()` to confine deletion to the specified directory (functions.php:7786). Added in WP 4.9.7.
- `realpath($path)` + prefix check: `$real = realpath($path); if (strpos($real, $allowed_dir) !== 0) die();` — correct ONLY when both calls are present together. `realpath()` alone without prefix check is NOT sufficient.
- `basename()` applied to the path argument of unlink/wp_delete_file — correct, strips all directory components. Deletion confined to the hardcoded directory prefix.
- `sanitize_file_name()` — correct, strips `../`, `/`, `\`, special chars. Output: `[a-zA-Z0-9._-]` plus UTF-8 multibyte.
- `intval()` / `absint()` on an attachment ID used with `wp_delete_attachment()` — correct. Integer cannot be a path.
- `sanitize_key()` — correct, output `[a-z0-9_-]` only. No dots, no slashes.

**Second-order deletion/move (stored path/ID → later delete/move/copy):**
When `get_option()`, `get_post_meta()`, `get_user_meta()`, or database query results flow to `unlink()`/`wp_delete_file()`/`rename()`/`$wp_filesystem->delete()`/`$wp_filesystem->move()`/`$wp_filesystem->copy()`/`wp_delete_attachment()`:
1. Trace ALL writes to the specific option/meta key or DB column.
2. If writable by lower-privilege users (Subscriber via REST meta, Contributor via block attributes, unauthenticated via missing-auth AJAX form submission) → chain viable. The common case — the plugin computes the path itself (e.g. swapping a file's extension) and only ever writes what it computed — is benign; the vulnerability requires a separate write path an attacker can reach.
3. Common pattern: form plugin stores a file path OR a bare attachment-ID-shaped value on submission → admin or cron job cleans up entries → deletes the stored value without validating it was ever a genuine path/upload for that record. The same shape applies to move/copy sinks and to ID-based sinks (`wp_delete_attachment()`) alike — do not limit this check to path-string `unlink`-family sinks.
4. Record it as a **SINK LEDGER** row in leads-forward.md (`Consumed-by = (none)` if only a chain primitive).
5. **Variant analysis on a partial fix:** if a security patch added a `realpath()`+prefix-check helper around only ONE consumer of a meta/option field holding file paths, grep the entire plugin for every OTHER read of that same field — a validator wired into one call site is commonly not propagated to sibling consumers of the same stored data, leaving those siblings exploitable in the "fixed" version.

**REST API delete endpoints:**
REST routes containing `delete`, `remove`, or `file` in the path, where the callback calls unlink/wp_delete_file:
1. Check `permission_callback` — `__return_true` or `function() { return true; }` = unauthenticated. `is_user_logged_in` alone = Subscriber+.
2. Route parameters with `'sanitize_callback' => 'sanitize_text_field'` do NOT prevent path traversal — `sanitize_text_field()` preserves `../`.
3. Check if `$request->get_param('file')` or `$request->get_param('path')` flows to deletion functions.

**Attachment metadata poisoning:**
When `ATTACHMENT_METADATA_UNLINK` hits appear:
1. Trace metadata access (`wp_get_attachment_metadata`, `wp_get_attachment_url`, `wp_get_attachment_thumb_file`) to deletion sinks.
2. If metadata fields (`thumb`, `file`, `sizes[*].file`) flow to `unlink()`/`wp_delete_file()` without `wp_delete_file_from_directory()` — path traversal via poisoned metadata is possible.
3. WP Core itself now uses `wp_delete_file_from_directory()` in `wp_delete_attachment_files()` (post.php:6791) — SAFE since 4.9.7. Plugin code reimplementing attachment deletion without this function may be vulnerable.
4. Trace metadata write paths — `wp_update_attachment_metadata()` may accept partially user-controlled metadata from import/edit flows.

**File deletion → RCE escalation paths:**
1. **wp-config.php deletion** — triggers the WordPress install wizard (`/wp-admin/install.php`). Attacker connects an attacker-controlled database, creates admin account, uploads PHP webshell via theme/plugin editor or file upload → full RCE. Canonical AFD escalation, applies to every WordPress install.
2. **.htaccess deletion** — removes access restrictions, rewrite rules, directory protections. May expose admin areas, disable authentication rules, or enable direct PHP execution in upload directories.
3. **Plugin/theme file deletion** — deleting security plugin files (e.g., Wordfence, iThemes Security) removes protection. Deleting core plugin files may break site functionality (DoS).
4. **index.php deletion** — enables directory listing, exposing file structure and potentially sensitive files.

### Arbitrary File Download/Read Analysis (use with FILE_DOWNLOAD_ENDPOINTS, FILE_READ_STREAM_FUNCTIONS, DOWNLOAD_HANDLER_REGISTRATION, WP_FILESYSTEM_READ, READFILE_USER_INPUT_DIRECT, TIER2_FILE_READ, REQUEST_ARRAY_FILE_LIST_LOOP)

File download/read vulnerabilities where plugins use `readfile()`, `file_get_contents()` + echo, `fpassthru()`, `fopen()`/`fread()` to output raw file contents. Distinct from LFI — outputs raw bytes without PHP execution, but reading `wp-config.php` yields DB credentials and auth salts for full compromise.

**Priority order:** (1) Direct superglobal → readfile/file_get_contents/fopen (`READFILE_USER_INPUT_DIRECT`) — highest confidence, nearly always TP; (2) Download handler registrations (`DOWNLOAD_HANDLER_REGISTRATION`) — follow each `wp_ajax_nopriv_*download*` / `admin_post_nopriv_*download*` to its callback; (3) Download endpoint files with Content-Disposition/octet-stream headers (`FILE_DOWNLOAD_ENDPOINTS`) — cross-file-filtered to files also containing readfile/file_get_contents/fpassthru/fread; (4) Stream-based file reading (`FILE_READ_STREAM_FUNCTIONS`) — fpassthru/fread/fgets, the output stage after fopen; (5) WP_Filesystem reads (`WP_FILESYSTEM_READ`) — `$wp_filesystem->get_contents()` / `get_contents_array()`; (6) Generic file read hits from `TIER2_FILE_READ` (readfile, file_get_contents, fopen — excluding include/require which go to LFI analysis below); (7) Multi-file combiner/minifier endpoints (`REQUEST_ARRAY_FILE_LIST_LOOP`) — a request-array (`$_GET['files'][]`-style) is looped over and each entry resolved via `is_file()`/`realpath()`/`file_exists()` with no extension allow-list, letting an attacker name any file (e.g. `wp-config.php`) as a list entry; check whether the accepted path is later read/output as combined asset content; (8) Image-proxy/thumbnail variant, also surfaced by `TIER2_FILE_READ` (`imagecreatefromjpeg`/`png`/`gif`/`webp`, `getimagesize`) — a GD image-decode call is functionally the same read sink as `file_get_contents()`/`readfile()`, just re-encoding rather than streaming raw bytes; the extension-based file-type dispatch these scripts use to select the decode function is NOT a directory/path containment check — verify the path argument independently against the sanitizer list above.

**Download endpoint analysis checklist:**
1. **Identify the entry point:** file-serving function registered via `wp_ajax_nopriv_*` (unauthenticated), `wp_ajax_*` (Subscriber+), `admin_post_nopriv_*`, `admin_post_*`, REST endpoint, `template_redirect`, `init` hook, or standalone PHP file? Cross-reference `DOWNLOAD_HANDLER_REGISTRATION` with `AJAX_HOOKS` and `STANDALONE_PHP` from surface results.
2. **Trace the file path parameter:** which `$_GET`/`$_POST`/`$_REQUEST` key supplies the filename/path? Common names: `file`, `filename`, `path`, `download`, `f`, `doc`, `attachment`, `export`, `filepath`, `download_file`.
3. **Check auth/nonce gates:** handler verifies `wp_verify_nonce()` and/or `current_user_can()`? If nonce-only, trace the nonce creation site per CANON:nonce-verification. `wp_ajax_nopriv_` handler with no auth check = unauthenticated file read.
4. **Assess path sanitization on the FILE PATH** (not the Content-Disposition header filename — see misuse patterns below).

**Sanitizer misuse patterns (false sense of security):**
- `basename()` applied to Content-Disposition header filename but NOT to the readfile/fopen path — cosmetic only, controls the download name displayed to the browser, does not prevent path traversal on the actual file read.
- `sanitize_text_field()` on file path — preserves `/`, `.`, `\` entirely. `../../../wp-config.php` passes through unchanged. Zero traversal prevention.
- `file_exists()` / `is_file()` before readfile — confirms the traversed path resolves to a real file on disk but does NOT validate against a base directory. `../../wp-config.php` passes `file_exists()` because the file always exists in WordPress.
- `ltrim($filename, ".\\/")` — strips only LEADING dots/slashes. Input `foo/../../../wp-config.php` bypasses because `../` chars are not at the start.
- `str_replace('../', '', $path)` — single-pass replacement. Input `....//....//wp-config.php` becomes `../../wp-config.php` after one pass.
- `urldecode()` applied before path validation but after the web server has already URL-decoded the request — double-decode allows `%252e%252e%252f` to become `../` after the check.
- `wp_normalize_path()` — normalizes slashes (`\` to `/`) but does NOT strip `../` sequences.
- **Hand-rolled string-based `../` collapse (not PHP's `realpath()`).** A custom normalizer that splits the path on `/` and, for each `..` segment, calls `array_pop()` on an accumulator array of preceding segments: PHP's `array_pop()` on an EMPTY array is a silent no-op (no error/warning). Once enough leading `..` segments have popped every component of the intended base directory off the accumulator, further `..` segments are harmless and subsequent literal segments push onto the now-empty stack — reconstructing an arbitrary absolute path with zero relationship to the base directory. This applies equally to real `realpath()` with no post-call boundary check: excess `../` beyond the base directory's actual depth is harmless (the function simply stops ascending at the filesystem root) — the attacker does not need to know the exact directory depth for either variant.

**Correct sanitization verification (must be applied to the readfile/fopen PATH argument):**
- `realpath($path)` + prefix check: `$real = realpath($path); if (strpos($real, $allowed_dir) !== 0) die();` — correct ONLY when both calls are present together. `realpath()` alone without prefix check is NOT sufficient — it resolves `../` but does not restrict the resulting path.
- `basename()` applied to the path argument of readfile/fopen/file_get_contents (not just the Content-Disposition header) — correct, strips all directory components.
- `sanitize_file_name()` — correct, strips `../`, `/`, `\`, special chars. Output: `[a-zA-Z0-9._-]` plus UTF-8 multibyte.
- `validate_file()` with return value checked — correct ONLY when `if (0 !== validate_file($path)) return;` or equivalent halt pattern is present. The function only returns a status code; ignoring the return value = no protection.
- `intval()` / `absint()` on an attachment ID used with `get_attached_file()` — correct for integer-ID-based download handlers. Integer cannot be a path.
- `sanitize_key()` — correct, output `[a-z0-9_-]` only. No dots, no slashes.

**Stream-based download pattern analysis:**
When `fopen()` + `fread()`/`fpassthru()` or `fopen()` + while/`fread()` + echo appear:
1. Trace the first argument to `fopen()` — this is the file path sink. The vulnerability is in what path reaches `fopen()`, not in fread/fpassthru themselves.
2. `fpassthru($handle)` outputs the entire remaining stream — functionally identical to `readfile()` after `fopen()`.
3. Loop pattern: `while (!feof($fh)) { echo fread($fh, 8192); }` — streaming download of large files. Same sink analysis as `readfile()`.
4. `fgets($handle)` — line-by-line output, often used for log file downloads.

**Standalone PHP file download handlers:**
Cross-reference `STANDALONE_PHP` results from surface scan (fires on files that self-bootstrap WordPress via a raw `require`/`include` of `wp-load.php`/`wp-blog-header.php`; a file with zero WordPress reference at all is not grep-covered — identify by manual read). Files that:
1. Are reachable directly at their own file path rather than through WP's hook system (self-bootstrapping, or no WordPress integration at all).
2. Read a file parameter from `$_GET`/`$_POST`/`$_REQUEST`.
3. Output the file's content — via Content-Disposition headers + readfile/fpassthru/file_get_contents+echo, OR via a GD image-decode call (`imagecreatefromjpeg`/`png`/`gif`/`webp`, output through `imagepng()`/`imagejpeg()`) for an image-proxy/thumbnail script.
These bypass ALL WordPress auth infrastructure — no `wp_ajax_*` hook, no nonce system, no capability checks unless explicitly coded. Direct HTTP request to the file = unauthenticated access.

**REST API download endpoints:**
REST routes containing `download`, `export`, or `file` in the path, where the callback outputs file contents:
1. Check `permission_callback` — `__return_true` or `function() { return true; }` = unauthenticated. `is_user_logged_in` alone = Subscriber+.
2. Route parameters with `'sanitize_callback' => 'sanitize_text_field'` do NOT prevent path traversal — `sanitize_text_field()` preserves `../`.
3. Check if `$request->get_param('file')` or `$request->get_param('path')` flows to file-read functions.

**Database-stored path to file read (second-order):**
When `get_option()`, `get_post_meta()`, or `get_user_meta()` values flow to `readfile()`/`file_get_contents()`/`fopen()`:
1. Trace ALL writes to the specific option/meta key.
2. If writable by lower-privilege users (Subscriber via REST meta, Contributor via block attributes, unauthenticated via missing-auth AJAX) → chain viable.
3. Record it as a **SINK LEDGER** row in leads-forward.md for the Chain group (`Consumed-by = (none)`).

**File read → full compromise escalation paths:**
1. **wp-config.php** — DB credentials (DB_NAME, DB_USER, DB_PASSWORD, DB_HOST), auth salts (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY + salt variants), table prefix, ABSPATH. Auth salts enable forging admin authentication cookies.
2. **wp-content/debug.log** — may contain API keys, DB queries with sensitive data, stack traces revealing internal paths and configuration.
3. **.htaccess** — server configuration, rewrite rules, auth restrictions, IP allow/deny rules.
4. **/etc/passwd** — system user enumeration, home directory discovery.
5. **Plugin/theme PHP config files** — many plugins store API keys (payment gateways, email, SMS) in PHP files readable via file download.
6. **Private key files (.pem, .key)** — TLS/SSL private keys if stored on the server filesystem.

### Arbitrary Content Deletion Analysis (use with TIER2_CONTENT_DELETE, CONTENT_DELETE_HANDLER_REGISTRATION, CONTENT_DELETE_USER_INPUT_DIRECT)

Content deletion vulnerabilities where plugins use `wp_delete_post()`, `wp_trash_post()`, `wp_delete_attachment()`, `wp_delete_comment()`, `wp_trash_comment()`, `wp_delete_term()`, `wp_delete_user()`, `$wpdb->delete()`, `delete_post_meta()`, `delete_comment_meta()`, `delete_user_meta()`, or `delete_term_meta()` to remove WordPress content or database records. NONE of these perform internal authorization — the caller MUST verify `current_user_can()` before invocation (CWE-862).

**Priority order:** (1) Direct superglobal → content deletion function (`CONTENT_DELETE_USER_INPUT_DIRECT`) — highest confidence, nearly always TP; (2) Content delete handler registrations (`CONTENT_DELETE_HANDLER_REGISTRATION`) — follow each `wp_ajax_nopriv_*delete*` / `wp_ajax_*delete*` to its callback; (3) Nopriv content deletes (`NOPRIV_CONTENT_DELETES` from group-ac grep) — deletion sinks in files with nopriv hooks; (4) Generic content delete hits from `TIER2_CONTENT_DELETE`.

**Content deletion endpoint analysis checklist:**
1. **Identify the entry point:** delete function registered via `wp_ajax_nopriv_*` (unauthenticated), `wp_ajax_*` (Subscriber+), `admin_post_nopriv_*`, `admin_post_*`, REST endpoint, `admin_init`, or `init` hook? Cross-reference `CONTENT_DELETE_HANDLER_REGISTRATION` with `AJAX_HOOKS` and `REST_ENDPOINTS` from surface results.
2. **Trace the ID parameter:** which `$_GET`/`$_POST`/`$_REQUEST` key supplies the post/comment/term/user ID? Common names: `id`, `post_id`, `comment_id`, `term_id`, `user_id`, `item_id`, `entry_id`, `result_id`, `record_id`.
3. **Check auth gates:** handler verifies `current_user_can()` with the appropriate capability AND the specific resource ID? Nonce-only is insufficient — nonces prevent CSRF but do NOT authorize the action. `wp_ajax_nopriv_` handler with no auth check = unauthenticated content deletion (CRITICAL).
4. **Check per-resource ownership:** even with a capability check, verify the handler confirms the requesting user owns or has authority over the specific content being deleted. `current_user_can('delete_posts')` (plural, no ID) is a class-level check — only `current_user_can('delete_post', $post_id)` (singular + ID) is per-resource.
5. **Check post type validation:** handler verifies the target belongs to the plugin's intended CPT? `wp_delete_post()` accepts any post ID regardless of type — a handler meant to delete only plugin-created listings can delete admin pages if the post type is not validated. Use `get_post_type($id)` check before deletion.

**WP Core function authorization requirements (none perform internal auth):**

| Function | What it deletes | Required capability |
|---|---|---|
| `wp_delete_post($id, $force)` | Post + meta + terms + comments | `current_user_can('delete_post', $id)` |
| `wp_trash_post($id)` | Moves post to trash | `current_user_can('delete_post', $id)` |
| `wp_delete_attachment($id, $force)` | Attachment post + physical file | `current_user_can('delete_post', $id)` |
| `wp_delete_comment($id, $force)` | Comment permanently or trash | `current_user_can('moderate_comments')` or ownership |
| `wp_trash_comment($id)` | Moves comment to trash | `current_user_can('moderate_comments')` or ownership |
| `wp_delete_term($term, $taxonomy)` | Taxonomy term + relationships | `current_user_can('delete_term', $term)` or `manage_categories` |
| `wp_delete_user($id, $reassign)` | User + cascading post/link deletion | `current_user_can('delete_users')` |
| `$wpdb->delete($table, $where)` | Arbitrary table rows | Caller-defined — no WP hook protection |
| `delete_post_meta($id, $key)` | Post metadata row | `current_user_can('edit_post', $id)` |
| `delete_comment_meta($id, $key)` | Comment metadata row | `current_user_can('moderate_comments')` |
| `delete_user_meta($id, $key)` | User metadata row | `current_user_can('edit_user', $id)` |
| `delete_term_meta($id, $key)` | Term metadata row | `current_user_can('manage_categories')` |

**Key patterns (real-world exploitation chains):**

1. **REST `permission_callback => true` + delete:** REST endpoint's `permission_callback` returns `true` unconditionally, making the delete callback publicly accessible. Any unauthenticated visitor can call the endpoint and delete arbitrary posts.

2. **`wp_ajax_nopriv_` + no auth + delete:** AJAX action registered with `wp_ajax_nopriv_` prefix, handler takes `$_POST['id']` directly to `wp_delete_post()` with zero auth, nonce, or type checks. Fully unauthenticated post deletion.

3. **Nonce treated as authorization:** AJAX handler checks `wp_verify_nonce()` but has no `current_user_can()` call. The nonce is obtainable by any authenticated user from `profile.php`. Any Subscriber can delete quiz results. Mechanical rule: nonce present + no capability check before deletion = confirmed Missing Authorization.

4. **CSRF-to-deletion:** AJAX/admin_post handler performs deletion without nonce verification. Attacker crafts a form that tricks an admin into submitting a deletion request. SameSite=Lax cookies: top-level GET navigation sends cookies cross-site.

5. **Bulk deletion without per-item auth:** AJAX handler accepts a `type` parameter to delete post revisions, trashed posts, trashed comments, spam comments, or transients — no `current_user_can('manage_options')` check. Any Subscriber can trigger database cleanup operations.

6. **Incorrect ownership check on REST:** REST API deletion endpoint checks authentication but not per-resource ownership. Any authenticated user can delete any other user's reviews by manipulating the review ID.

**`$wpdb->delete()` specific analysis:**
Direct DB deletion bypasses ALL WordPress hooks and cascading delete logic. The `$where` array determines which rows are deleted — if any key-value pair contains user input, the attacker controls the scope of deletion. `sanitize_text_field()` on the WHERE value does NOT prevent ID manipulation — `sanitize_text_field('999')` returns `'999'`. For every `$wpdb->delete()` hit: (1) trace the `$where` argument to its source; (2) check for `current_user_can()` before the call; (3) verify the table name is hardcoded (not user-influenced); (4) common in quiz, form, booking, and custom table plugins accepting record IDs from AJAX handlers.

**Content deletion FP rules (specific to this section):**
50. **`wp_delete_post()` inside `register_uninstall_hook` / `register_deactivation_hook`:** Plugin cleanup during uninstall/deactivation with hardcoded queries (`get_posts(['post_type' => 'plugin_cpt'])`) = standard behavior, not vulnerability. Confirm: (a) deletion targets only the plugin's own CPT, (b) no user input influences the query, (c) hook is uninstall/deactivation not a general AJAX/REST handler.
51. **`wp_delete_post()` on ID returned by plugin's own `wp_insert_post()` in same function:** Temporary content cleanup (e.g., create draft → process → delete) within a single operation = not arbitrary deletion. Confirm the ID is locally generated, not from user input.
52. **`wp_delete_comment()` inside WP Core's own `wp_delete_post()` cascade:** Comments deleted as part of post deletion cascade are WP Core behavior, not plugin code. Only flag when the plugin directly calls `wp_delete_comment()` with a user-supplied ID.
53. **`$wpdb->delete()` with only hardcoded WHERE values:** WHERE array contains only constants, literals, or internally-computed values with no user input path = FP. Example: `$wpdb->delete($table, ['expired' => 1])` in a cron cleanup.
54. **Content deletion gated by per-resource capability check:** `current_user_can('delete_post', $post_id)` with the tainted ID = secure (WP Core evaluates ownership). Dismiss as FP. Verify the check uses the SAME variable as the deletion call.
55. **`wp_trash_post()` / `wp_delete_post()` called by admin-only page callback:** Check `add_menu_page()` / `add_submenu_page()` capability argument. `manage_options` = admin-only = PR:H, OOS. `edit_posts` = Contributor-accessible, continue analysis.

**Content deletion escalation paths:**
1. **Post/page deletion** — published content loss, SEO damage (broken URLs, lost rankings), business disruption. On e-commerce: product pages, order records.
2. **User deletion (`wp_delete_user`)** — cascading deletion of ALL user's posts, media, comments, links. If `$reassign` parameter is also attacker-controlled, victim's content is reassigned to attacker's account (data theft vector). Highest-impact content deletion.
3. **Comment/review deletion** — reputation manipulation (remove negative reviews), data loss. On review-heavy sites: significant business impact.
4. **Term deletion** — taxonomy structure destruction, post-term relationships broken. On e-commerce: category hierarchy disrupted.
5. **`$wpdb->delete()` on custom tables** — quiz results, form submissions, booking records, order data, license keys — direct business data destruction with no WordPress undo mechanism.

### LFI/RFI-Specific Analysis (use with TIER2_FILE_READ, INCLUDE_REQUIRE_USER_INPUT, TEMPLATE_LOADING_USER_INPUT, INCLUDE_CONCAT_VARIABLE, SHORTCODE_ATTR_TEMPLATE_INCLUDE, WP_TEMPLATE_PARAM_NAMES, PHP_STREAM_WRAPPERS, DB_STORED_PATH_TO_INCLUDE, AJAX_TEMPLATE_PARAM_INCLUDE, NESTED_ARRAY_INPUT_TO_INCLUDE, FILE_EXISTS_BEFORE_INCLUDE, DYNAMIC_FILE_EXTENSION_INCLUDE, CUSTOM_TEMPLATE_LOADER_FUNCTIONS, WP_KSES_ON_FILE_PATH, EXTRACT_VARIABLE_CLOBBER, DYNAMIC_CLASS_FROM_REQUEST)

**Priority order:** (1) Direct superglobal → include (`INCLUDE_REQUIRE_USER_INPUT`); (2) AJAX handler template parameters (`AJAX_TEMPLATE_PARAM_INCLUDE`); (3) Template param names in user input (`WP_TEMPLATE_PARAM_NAMES`); (4) Shortcode/widget/block attribute → include chain (`SHORTCODE_ATTR_TEMPLATE_INCLUDE`); (5) Template loading with variable args (`TEMPLATE_LOADING_USER_INPUT`); (6) Variable concatenation includes (`INCLUDE_CONCAT_VARIABLE`); (7) Database-stored paths to include (`DB_STORED_PATH_TO_INCLUDE`); (8) Nested array input (`NESTED_ARRAY_INPUT_TO_INCLUDE`); (9) PHP stream wrappers (`PHP_STREAM_WRAPPERS`); (10) Custom template wrappers (`CUSTOM_TEMPLATE_LOADER_FUNCTIONS`); (11) file_exists before include (`FILE_EXISTS_BEFORE_INCLUDE`); (12) Dynamic extension includes (`DYNAMIC_FILE_EXTENSION_INCLUDE`); (13) extract() variable clobbering ahead of an include (`EXTRACT_VARIABLE_CLOBBER`); (14) Dynamic class instantiation reaching a custom autoloader (`DYNAMIC_CLASS_FROM_REQUEST`).

**Template loading pattern analysis:**
1. For every `TEMPLATE_LOADING_USER_INPUT` hit, trace the variable argument to its source:
   - `get_template_part($slug)` — if `$slug` built from user input (shortcode attr, `$_GET`, REST param), attacker controls template filename passed to `locate_template()`. If first arg is hardcoded and only `$name` (second arg) is variable, scope is narrower but `locate_template()` still has no traversal check.
   - `load_template($path)` — WP Core does `require`/`require_once` with ZERO path validation (template.php:782). Any user-controlled `$path` = full LFI.
   - `locate_template($names)` — searches child theme → parent theme → ABSPATH/WPINC/theme-compat/ only. Path construction is `$dir . '/' . $template_name` — NO traversal validation (template.php:736). User-controlled `$template_name` with `../` reaches outside theme directories.
   - Custom template wrappers in plugin code — read the wrapper body; many do `include(PLUGIN_DIR . '/templates/' . $arg . '.php')` with no sanitization.

2. For every `SHORTCODE_ATTR_TEMPLATE_INCLUDE` hit, trace the attribute value through intermediate variables to the include sink:
   - `$atts['template']` → `$template = $atts['template']` → `include(PLUGIN_DIR . '/templates/' . $template . '.php')`.
   - Widget `$instance['template']` → `load_template($instance['template'])` — widget settings stored in DB, writable by users with `edit_theme_options`.
   - Block `$attributes['template']` → include — block attributes are Contributor-controlled via block JSON.

**AJAX endpoint LFI checklist:**
MOST COMMON LFI pattern. For every `wp_ajax_nopriv_*` and `wp_ajax_*` handler:
1. AJAX callback reads a parameter named template/tmpl/tpl/file/filename/path/view/layout from `$_POST`/`$_GET`/`$_REQUEST`?
2. That parameter value flows (directly or through intermediate variables) to `include`/`require`/`load_template`?
3. Handler registered with `nopriv`? If yes → unauthenticated LFI (CRITICAL). If no → authenticated LFI (HIGH, check required capability).
4. Check grep patterns: `AJAX_TEMPLATE_PARAM_INCLUDE` + `WP_TEMPLATE_PARAM_NAMES` cross-referenced with `AJAX_HOOKS` from surface results.
5. Common bypass: nonce check exists but nonce is exposed in frontend JS (`wp_localize_script`) or public-facing page source → effectively unauthenticated.

**Nested array user input tracing:**
Semgrep taint rules track `$_POST['key']` but may miss multi-level access like `$_POST['form']['content_path']` or `$_REQUEST['args']['template_path']`. When `NESTED_ARRAY_INPUT_TO_INCLUDE` grep hits appear:
1. Trace the nested value through assignment chains: `$form = $_POST['form']; $path = $form['content_path'];`
2. Check if `wp_parse_args` or `shortcode_atts` is applied to the top-level array — values flow through these mergers.
3. `wp_unslash()` and `sanitize_text_field()` do NOT prevent path traversal in nested values.
4. Prioritize when the nested parameter name contains: template, path, file, view, layout, content_path, template_path.

**Custom template wrapper identification:**
Many plugins define their own template loading functions (e.g., `render_template()`, `load_view()`, `get_partial()`, `include_template()`) that internally call `include`/`require`. These become custom sinks.
1. When `CUSTOM_TEMPLATE_LOADER_FUNCTIONS` grep hits appear, read each function body.
2. If the function's parameter flows to `include`/`require` without sanitization, add it as a **SINK LEDGER** row (Type `file-op`) in leads-forward.md.
3. Then search for all CALLERS of that function — trace user input to the function's parameters.
4. Common pattern: `Plugin_Template::render($template_name)` called from shortcode callback with `$atts['template']` — the shortcode rule may miss this because the include is inside the wrapper, not adjacent to the attribute access.

3. For `INCLUDE_CONCAT_VARIABLE` hits, classify:
   - **TP pattern:** `include(CONSTANT . '/' . $user_var . '.php')` where `$user_var` from `$_GET`/`$_POST`/`$atts` — path traversal with `../../` reaches arbitrary .php files.
   - **FP pattern — verify, do not assume:** `include($this->plugin_path . '/includes/' . $class_name . '.php')` inside an autoloader is FP ONLY when `$class_name` is itself proven developer-controlled at every call site. "The autoloader is developer-written" does NOT make `$class_name` developer-controlled — trace where the autoloader's `$class` parameter is bound (every `new $var(...)`/`$var::method(...)` call site that could resolve to this autoloader) back to its ultimate source before dismissing; a request-tainted class-name suffix reaching a developer-written autoloader is still a TP (see `DYNAMIC_CLASS_FROM_REQUEST` below).
   - **Requires trace:** `include($path)` where `$path` built across multiple lines/functions — follow full data flow.

4. **Dynamic class instantiation → autoloader LFI (`DYNAMIC_CLASS_FROM_REQUEST` hits, `new $var(...)`/`$var::method(...)`):** when the resolved class is not already declared, PHP invokes every registered `spl_autoload_register()` callback with the class-name string before raising an error. A common custom-autoloader idiom (`str_replace('\\', DIRECTORY_SEPARATOR, $class)` then `include $base . strtolower($filename) . '.php'`) only neutralizes namespace separators, not `../` — a request-tainted suffix on an otherwise-fixed namespace prefix traverses out of the intended `includes/` tree the same way `INCLUDE_CONCAT_VARIABLE` does. Trace the class-name string back to its source across the FULL call chain, not just the immediate assignment — a common shape passes it through an intermediate object's property (`$this->record['field']`/`$this->data[...]`/`$this->params[...]`, populated from `$_POST` in a different method/class than the one doing `new $CLASS()`), which single-function taint tracking will not connect on its own. Read the actual registered autoloader(s) (`spl_autoload_register(...)` call sites) and confirm whether the class-to-path conversion strips `..` (not just `\\`) AND force-appends a fixed extension (narrows to `*.php` targets but does not by itself prevent traversal to an existing `*.php` file elsewhere on the server) before dismissing as safe.

**PHP stream wrapper exploitation assessment:**
When `PHP_STREAM_WRAPPERS` hits appear in files also containing include/require or file-read functions:
- `php://filter/convert.base64-encode/resource=wp-config.php` — reads source code of any PHP file, bypasses `.php` extension appending. Works regardless of `allow_url_include` setting.
- `phar://` — deserialization via phar metadata. Works regardless of `allow_url_include`. PHAR deserialization triggers not only through `include('phar://...')` but also through `file_exists('phar://...')`, `is_file('phar://...')`, `stat('phar://...')`, `getimagesize('phar://...')`, and any PHP filesystem function. When auditing `FILE_EXISTS_BEFORE_INCLUDE` hits: if user controls the FULL path (not just a suffix after a hardcoded prefix), `phar://` scheme injection triggers deserialization BEFORE the include even executes. Two-prerequisite attack: (1) attacker controls full path including scheme, (2) attacker can upload a file with valid PHAR metadata (can be embedded in JPEG/GIF/PNG).
- `zip://uploads/media.zip#shell.php` — access files inside uploaded ZIPs. Works regardless of `allow_url_include`.
- `data://text/plain;base64,...` — inline PHP execution. Requires `allow_url_include=On` (off by default since PHP 5.2).
- `expect://` — command execution wrapper. Requires PECL expect extension (rare).
- Assessment: `php://filter` always exploitable for source reading; `phar://` for deserialization; others depend on server config (OOS per Wordfence exploit requirements).

**extract() variable-clobbering analysis:**
For every `EXTRACT_VARIABLE_CLOBBER` hit, check the flags argument: `extract($arr)` and `extract($arr, EXTR_OVERWRITE)` (the default) silently redefine ANY existing local variable whose name matches an array key — including a same-named variable set earlier in the function from a validated/sanitized source (a checked file path, an auth flag). If `$arr`'s contents are influenced by request data at any point upstream (directly, or via an object wrapper reached through `->getArrayCopy()`/`->toArray()`/similar), trace every variable name used in a dangerous sink (`include`/`require`, a capability check, a SQL fragment) later in the same function — if any of those names could also be a key of `$arr`, the validated value can be overwritten post-validation, bypassing checks performed before the `extract()` call entirely. `EXTR_SKIP` is the standard, sufficient fix (refuses to overwrite existing variables); its absence is the finding.

**Extension appending analysis:**
When code appends `.php` (e.g., `include($template . '.php')`):
- Limits traversal to `.php` files only — reduces impact but does NOT prevent LFI.
- `php://filter` bypasses: `php://filter/convert.base64-encode/resource=wp-config` + `.php` appended = reads wp-config.php source.
- Null byte (`%00`) truncation — blocked since PHP 5.3.4.
- Assessment: `.php` suffix makes traversal narrower but NOT safe; wp-config.php, plugin files, theme files all end in `.php`.

**Remote File Inclusion (RFI) methodology:**
RFI is a subset of file inclusion where the included path is a URL rather than a local file path.
1. **`allow_url_include` check:** Off by default since PHP 5.2. When off, `include('http://...')` and `include('data://...')` fail. However: (a) some shared hosting or Docker configs enable it, (b) `file_get_contents('http://...')` works by default via `allow_url_fopen` regardless of `allow_url_include`.
2. **`data://` wrapper RFI:** `include('data://text/plain;base64,' . base64_encode('<?php system($_GET["cmd"]); ?>'))` — works if `allow_url_include=On`. Payload is self-contained, no external server needed.
3. **Second-order RFI:** database option stores a URL → later `include(get_option('template_url'))`. If attacker can write to the option (via REST, AJAX, or lower-privilege path), any URL is included on next page load. Use `DB_STORED_PATH_TO_INCLUDE` grep results to identify candidates.
4. **Assessment:** Direct superglobal → include with URL = CRITICAL if `allow_url_include` is on. Per Wordfence scope: document as "requires non-default PHP configuration" but still reportable — the code fails to validate the URI scheme. When `allow_url_include` is off, the LFI vector (local path traversal) remains fully exploitable.

**WP Core sanitizer effectiveness for LFI prevention:**

| Function | Prevents LFI? | Mechanism |
|---|---|---|
| `sanitize_file_name()` | YES | Strips `../`, special chars, preserves only `[a-zA-Z0-9._-]` |
| `basename()` | YES | Strips directory path entirely |
| `sanitize_key()` | YES | Output `[a-z0-9_-]` only — no dots, no slashes |
| `sanitize_title()` | YES | Output `[a-z0-9%-_]` — no dots, no slashes |
| `sanitize_html_class()` | YES | Output `[A-Za-z0-9_-]` — no path separators |
| `realpath()` | CONDITIONAL | Resolves `../` but does NOT validate prefix — must pair with `strpos($real, $allowed_dir) === 0` |
| `validate_file()` | CONDITIONAL | Returns status code only — NO-OP if return value not checked |
| `sanitize_text_field()` | NO | Preserves `/`, `.`, `\` — `../` passes through unchanged |
| `esc_html()` / `esc_attr()` | NO | Encodes `<>&"'` only — path chars pass through |
| `wp_normalize_path()` | NO | Normalizes slashes but does NOT strip `../` |
| `wp_kses()` / `wp_kses_post()` | NO | Strips HTML tags/attributes only — `../../wp-config.php` passes through unchanged. Use `WP_KSES_ON_FILE_PATH` grep hits to detect this misuse. |
| `intval()` / `absint()` | YES | Integer output cannot be path |

**LFI → RCE escalation paths (assess when LFI confirmed):**
1. **wp-config.php read** — DB credentials + auth salts → forge admin cookie → full admin access.
2. **Log poisoning** — write PHP payload to access log via User-Agent header → include log file via LFI.
3. **PHP session inclusion** — `include('/tmp/sess_' . session_id())` with serialized PHP in session.
4. **Uploaded file inclusion** — include previously uploaded file (Media Library, plugin uploads dir).
5. **`php://filter` chain** — advanced technique using filter chains to write arbitrary content; enables RCE from read-only LFI.
6. **`PHP_SESSION_UPLOAD_PROGRESS`** — PHP stores upload progress in session file with user-controlled prefix; include session file during upload.

**Second-order LFI (database-stored template paths):**
When `get_option()`, `get_post_meta()`, or `get_user_meta()` values flow to include/require sinks, the LFI requires a prior write to the option/meta key. Trace the write path: if writable by lower-privilege users (Subscriber via REST, Contributor via block attributes), the chain is viable. Document as a chaining lead for the Chain group.

## CHECKPOINT: Group A Complete (after Tier 1–2)

Write `AUDIT_DIR/checkpoint-group-a.md` with: confirmed findings summary, file upload/RCE/deserialization leads for chaining, key observations about plugin architecture relevant to later tiers.

**Auth Observations (mandatory checkpoint section; append to the auth-model.md addendum):** The Foundation phase wrote auth-model.md and the Access-Control group already filled its Verdict/CIA columns before this group runs — document any NEW auth patterns observed during Tier 1-2 sink tracing in a structured table:

| Handler / Function | Auth Gate | Nonce | Notes |
|---|---|---|---|
| (e.g.) `wp_ajax_nopriv_upload` | None | `upload_nonce` (public) | File upload sink at line 123 |

Include: which handlers had/lacked `current_user_can()`, which nonce action strings were encountered and where created, which custom capabilities observed, which REST `permission_callback` functions were read and what they returned. Append these as an `## Addendum — Group A` section in auth-model.md so later groups inherit them.

Update `AUDIT_DIR/leads-forward.md` per the core ledger protocol (SKILL.md §5/§6): append any LEADS for later groups (tag each `Relevant-to`), and for every custom sink you evaluated add/refresh its **SINK LEDGER** row with `A` in `Consumed-by` (dedup by `fn@file:line`) — leave `(none)` only for a sink you are deferring to a later group or the Chain pass.

**Read AUDIT_DIR/grep/group-sqli-results.md before continuing to Tier 3 (SQLi).**

## Group A — FP Verification Rules

These rules supplement the universal FP rules in the shared core SKILL.md Phase 4.

9. **Callback/callable dispatch — is the callable attacker-controlled?**
   - `call_user_func`: two-level subscript with developer-registered callbacks = FP; single-level `$callbacks[$_POST['action']]` = TP — read the callable source.
   - Variable function `$var()`: FP only when `$var` is checked against a hardcoded `in_array()` allowlist (strict comparison, string-only) before invocation; `is_callable($var)` alone is NOT an allowlist (`system`/`exec` are callable).
   - String-literal/array callables (`array_map('intval', $data)`, `usort($arr, [$this, 'compare'])`) = FP regardless of data source; only variable callbacks require taint analysis.
10. **Deserialization from a remote/response source, SSTI sandboxes, and shell-command argument tracing.**
   - `unserialize()`/`maybe_unserialize()` fed by `wp_remote_retrieve_body()` or any `wp_remote_*` — data originates from the remote server, so injecting it needs MitM (OOS); FP unless a confirmed SSRF lets the attacker control the host.
   - Twig `SecurityPolicy` with BOTH `$allowed_methods = []` AND `$allowed_properties = []` empty blocks all method/property access (and `_self.env` needs method calls) → FP for RCE; verify both are truly empty and there is no downstream CIA impact.
   - A shell command built via `sprintf()`/concatenation with multiple substituted arguments is not exploitable just because some are not `escapeshellarg()`-wrapped — trace each unwrapped argument's own origin independently. One may be constrained to a small hardcoded-literal set via a strict comparison/ternary, or force-integer-coerced by a `%d` format specifier regardless of what the caller passed in; only an unwrapped argument confirmed to carry unconstrained request-derived text is a TP.
11. **Hit in bundled third-party library.** Bundled vendor code is generally in-scope, but verify the class/function is actually instantiated and reachable from the plugin entry point — dead vendor code is FP regardless of the flaw.
   - Same reachability check applies to the plugin's OWN code: a class with zero `new $class(`/instantiation sites, or a handler gated behind an `apply_filters()`/`do_action()` hook that is never fired anywhere in the plugin tree, is unreachable dead code regardless of the flaw it contains — grep the full tree for both before treating a hit as exploitable.
12. **Multi-step upload/write flows.** Step 1 (AJAX) may validate while step 2 (process/format) skips validation — check ALL steps before dismissing.
13. **`file_get_contents()` / stream wrappers — local read vs HTTP vs raw body.**
   - `file_get_contents('php://input')` reads the raw request body, not a URL — no SSRF/file-read; confirm the argument is the literal `'php://input'` (not a variable) before dismissing a `TIER2_FILE_READ` hit.
   - `php://filter`/`data://` in a hardcoded string is an intentional stream, not LFI; flag only when the wrapper protocol is built from user input.
   - `file_get_contents($url)`/`file_get_contents('https://...')` is an HTTP request (SSRF surface → Tier 8), not a Tier-2 local read; classify as Tier 2 only when the argument is a local filesystem path (a user-controlled `$url` stays a Tier 8 TP).
14. **Template/include path resolved through an allowlist or the WP template hierarchy.**
   - `include`/`require` via a switch/case/if/array resolver returning only hardcoded paths with a safe default = FP (also covers custom `render_template($name)`/`load_view($name)` wrappers with a hardcoded map); confirm all branches are hardcoded, the default is safe, and no user input is concatenated inside the resolver.
   - `locate_template()` reached via `get_query_template()` → `get_{type}_template()` is safe — `$type` is `preg_replace('|[^a-z0-9-]+|', '', $type)`'d (template.php:24); only DIRECT `locate_template()` calls with user input are suspect.
   - `get_template_part('content', $name)` with a hardcoded first arg still concatenates `$name` into `content-{$name}.php`, and `locate_template()` does NO traversal validation (template.php:736) — confirm `$name`'s source/sanitization before dismissing a `../` payload.
15. **`file_exists()`/`is_file()` is NOT a path sanitizer.** They confirm a path resolves to a real file but do not confine it to a base directory — `../../wp-config.php` passes. Dismiss only when a separate sanitizer (`basename`/`sanitize_file_name`/`realpath`+prefix check/`sanitize_key`) is applied to the user-input portion BEFORE the call; trace the variable source (Composer/Redux autoloaders use this pattern with developer-controlled names). This applies equally to `FILE_EXISTS_BEFORE_DELETE` hits guarding a delete/read/copy, not only the `FILE_EXISTS_BEFORE_INCLUDE` case documented under phar:// above — the deserialization trigger fires on the guard call itself, before the guarded action ever runs.
   - **When the request parameter is itself an already-absolute path** (not a relative remainder concatenated onto a base directory), a `../`-substring/traversal check is irrelevant regardless of correctness — no traversal sequence is needed to name an arbitrary file directly. The only valid gate for this input shape is root-directory containment (`realpath()` + prefix check, or an allow-list of permitted roots) after the existence check, not before/instead of it.
16. **Download/read endpoint with no user-controlled path component.**
   - `readfile(PLUGIN_DIR . '/exports/report.csv')` fully developer-controlled = FP; flag only when a path component is built from user input (superglobal, REST param, shortcode attr, or option/meta writable by a lower-privilege user).
   - `get_attached_file(intval($_GET['id']))` with a `current_user_can('read_post', $id)`/author-ownership check = FP (integer-coerced, ownership verified); flag only when that check is missing or insufficient for the auth floor.
   - `fread()`/`fgets()`/`fpassthru()` on `fopen($_FILES['field']['tmp_name'], 'r')` is upload processing, not download — `tmp_name` is PHP's server-generated `/tmp/phpXXXX` (the user controls `name`/`full_path`, not `tmp_name`); flag only when the `fopen()` path has user-controlled components beyond `tmp_name`. The same reasoning applies when `tmp_name` (from `$_FILES` directly, or a plugin's own copy of the same upload array) reaches `file_exists()`/`is_file()`/`getimagesize()`/`exif_imagetype()` or another stat-family guard used as a `phar://`-stream-wrapper trigger check — the value is still PHP-generated regardless of which array wraps it or which stat function consumes it.
   - **Forged `$_FILES`-shaped array with attacker-controlled `tmp_name`:** when a plugin builds its own `$_FILES`-style array from raw request data (not the true superglobal) and passes it to a `move_uploaded_file()`-based validator, `is_uploaded_file($tmp_name)` still gates the call — it checks PHP's per-request upload registry, not merely whether the string looks like a path, so a forged `tmp_name` is rejected regardless of what value the attacker supplies. Confirm the validator actually calls `is_uploaded_file()` before `move_uploaded_file()` (not just `file_exists()`/`is_readable()`, which a forged path CAN satisfy) before dismissing.
17. **`do_shortcode()` on `the_content` output.** WP Core already runs `do_shortcode` on `the_content` (priority 11), so `do_shortcode(apply_filters('the_content', $post->post_content))`/`do_shortcode(get_the_content())` adds no surface — flag only when `do_shortcode()` receives input from sources OTHER than post content (`$_GET`/`$_POST`, comment content, user meta, widget fields).
18. **Deletion sink on a server-controlled or hardcoded path.**
   - `unlink()`/`wp_delete_file()` on `wp_handle_upload()['file']`/`wp_handle_sideload()['file']`/`wp_upload_bits()['file']`/`$_FILES['key']['tmp_name']` is standard upload-failure cleanup (server-controlled) — CAUTION: if `$status['file']` is reassigned from user input between upload and `unlink()`, taint returns; read the full function.
   - `array_map('unlink', glob(HARDCODED_CONSTANT . '/*.ext'))` with an entirely hardcoded glob (constants like `WP_CONTENT_DIR`/`ABSPATH` + literal segments) = FP; flag only when user input influences any part of the pattern.
   - `$wp_filesystem->delete()` in `register_uninstall_hook`/`register_deactivation_hook` callbacks deleting hardcoded plugin cache dirs = standard cleanup; confirm hardcoded/constant paths, no user input, and the hook is uninstall/deactivation not a general AJAX handler.
   - `wp_delete_file_from_directory()` (functions.php:7786) uses `realpath()` + `str_starts_with()` to confine deletion — SAFE regardless of the first arg when the second (`$directory`) is hardcoded/server-controlled.
19. **`wp_delete_attachment($id)` with integer ID = IDOR, not AFD.** It takes a post ID and internally uses `wp_delete_file_from_directory()` (post.php:6791); even with a user-controlled ID the file path is never directly user-controlled, so the worst case is deleting an attachment the user shouldn't access — classify per Group AC's Tier 11 IDOR methodology and note in leads-forward.md for the Chain pass.
20. **Meta/option-derived path in a delete/move/copy sink, no confirmed lower-privilege write path.** The dominant case is a plugin reading back a path it computed and wrote itself (backup/cache/export cleanup) — not standalone-exploitable; record it as a SINK LEDGER chain primitive (`Consumed-by = (none)`) unless a separate, traced write path lets a lower-privileged user influence that specific meta/option key.
21. **Redundant second `unserialize()`/`maybe_unserialize()` on a subscript of `get_post_meta()`/`get_post_custom()`/`get_user_meta()`/`get_comment_meta()`'s "return all" array result.** WP core already ran `maybe_unserialize()` once building that array — this is a TP only when some write path stores a raw external scalar string (not an array/object, not wrapped in `serialize()`) at a reachable privilege: `maybe_serialize()` re-wraps a string that merely *looks* serialized in one extra `serialize()` layer, so it survives the storage round-trip byte-for-byte and reaches the plugin's second unserialize call intact.
22. **Request value used only as a `get_transient()`/`get_site_transient()`/`get_option()`/`get_*_meta()` lookup KEY, not as path/content.** The returned VALUE is developer-set data from an earlier `set_transient()`/`update_option()`/`update_*_meta()` call, unrelated to the key string's own content — dismiss a path-traversal/file-read/file-write finding built on the key argument alone; confirm the returned value's own write path has no independent lower-privilege attacker influence before dismissing (Semgrep `absolute-path-param-no-root-allowlist`/`arbitrary-file-read`/`weak-sanitizer-request-param-to-delete-call` encode this exclusion).
23. **`class_exists()`/`interface_exists()`/`enum_exists()` triggering a custom `spl_autoload_register()` autoloader is not exploitable when the ONLY viable payload requires embedding `..` or another non-identifier character in the class-name string.** PHP's engine validates the class name before invoking any registered autoloader and silently skips the callback entirely when the string contains a character outside `[A-Za-z0-9_\x80-\xff]` (confirmed empirically PHP 5.6–8.3) — live-test any finding of this shape (see `DYNAMIC_CLASS_FROM_REQUEST` grep results for candidate `new $var(`/`$var::$method()` sinks reachable from a `class_exists()` gate) before reporting; this exclusion does NOT apply when a traversal-free payload (letters/digits/underscore/backslash only) reaches the same unsanitized class-name-to-path conversion.
