# WordPress Core Security Functions Reference

**Source:** WordPress 7.0 (`wp-core/7.0/`)
**Purpose:** Ground-truth reference for vulnerability audit false-positive prevention

## 1. Input Sanitization Functions

Source: `wp-includes/formatting.php`

### `sanitize_text_field( $str )` — L5581
Delegates to `_sanitize_text_fields($str, false)`.

Chain: returns `''` for objects/arrays → cast to string → `wp_check_invalid_utf8()` → if contains `<`: `wp_pre_kses_less_than()` + `wp_strip_all_tags()` → collapse `\r`,`\n`,`\t`,spaces → `trim()` → strip all `%XX` sequences.

**Strips:** HTML tags, `<script>`/`<style>`, percent-encoded chars, newlines/tabs, invalid UTF-8
**Preserves:** `'` `"` `&` `\` `` ` `` `()` `{}` `[]` `:` `;` `/` `=` `+` `!` `$` `*` `|` `~` and all Unicode

**Safe for:** Storing cleaned text (with `$wpdb->prepare()` for SQL)
**NOT safe for:** Direct HTML output (quotes/ampersands survive), SQL, JS, URLs, file paths, SSTI

### `sanitize_textarea_field( $str )` — L5609
Identical to `sanitize_text_field` except preserves newlines.

### `sanitize_file_name( $filename )` — L2035
**Strips:** `? [ ] / \ = < > : ; , ' " & $ # * ( ) | ~ ` ! { } % +`, Unicode quotes, null bytes
**Preserves:** `a-zA-Z0-9`, `-`, `_`, `.` (single), UTF-8 multibyte
Multi-extension: intermediate extensions matching 2-5 alpha not in allowed MIME get `_` appended.
**Safe for:** Filesystem (prevents traversal). **NOT safe for:** Preventing `.php` uploads.

### `sanitize_key( $key )` — L2190
Lowercases, strips everything not `[a-z0-9_-]`.

### `sanitize_title( $title )` — L2227
Removes accents, applies `sanitize_title_with_dashes`. Output: `[a-z0-9%-_]` only.

### `sanitize_email( $email )` — L3760
RFC 5321. Local: `[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]`. Domain: `[a-z0-9-.]`. Returns `''` on invalid.

### `sanitize_mime_type( $mime_type )` — L5725
Strips everything not `[-+*.a-zA-Z0-9\/]`.

## 2. Output Escaping Functions

Source: `wp-includes/formatting.php`

### `esc_html( $text )` — L4680
`wp_check_invalid_utf8()` → `_wp_specialchars($text, ENT_QUOTES)` → `esc_html` filter.
**Encodes:** `&`→`&amp;` `<`→`&lt;` `>`→`&gt;` `"`→`&quot;` `'`→`&#039;`
**Safe for:** HTML text content, quoted attribute values.
**NOT safe for:** URL attrs (`javascript:` survives), inline JS, SQL, `<script>`/`<style>` content, unquoted attrs.

### `esc_attr( $text )` — L4705
**Functionally identical to `esc_html()`** — same `_wp_specialchars($text, ENT_QUOTES)`. Only difference: `attribute_escape` filter.
**NOT safe for:** URL attributes (`href`/`src`) — does NOT check protocols. Always pair with `esc_url()`.

### `esc_js( $text )` — L4652
`_wp_specialchars(ENT_COMPAT)` → `stripslashes()` → normalize single-quote entities → strip `\r` → escape `\n` → `addslashes()`.
**Preserves:** Backticks, `${}` (template literal injection), parens, braces.
**Safe for:** Inline JS in HTML attrs with **quoted** string context only.
**NOT safe for:** `<script>` blocks, template literals, JSON.

### `esc_url( $url, $protocols, $_context='display' )` — L4480
Strips chars not in `[a-z0-9-~+_.?#=!&;,/:%@$|*'()\[\]\\x80-\\xff]` → strips `%0d`/`%0a` → protocol validation (blocks `javascript:`, `data:`, `vbscript:`) → display context: `'`→`&#039;`, `&`→`&#038;`.
**Safe for:** `href`, `src`, `action` (prevents protocol injection).
**NOT safe for:** Open redirect (any http/https passes), SSRF, SQL.

### `esc_url_raw( $url )` / `sanitize_url()` — L4598/L4618
Same as `esc_url()` with `'db'` context — no entity encoding.
**Safe for:** DB storage, redirects, API calls. **NOT safe for:** Direct HTML attr output.

### `esc_sql( $data )` — L4456
Delegates to `$wpdb->_escape()` → `mysqli_real_escape_string()`. Also replaces `%`.
**Safe for:** String values in single-quoted SQL. **NOT safe for:** Integer contexts, column/table names.

## 3. Database Functions

Source: `wp-includes/class-wpdb.php`

### `$wpdb->prepare( $query, ...$args )` — L1458
NOT true parameterized queries — uses `vsprintf()` + `mysqli_real_escape_string()`.

| Placeholder | Behavior |
|---|---|
| `%s` | String — auto-quoted. **Numbered `%1$s` NOT auto-quoted** when `$allow_unsafe_unquoted_parameters = true` (default) |
| `%d` | Integer cast via vsprintf |
| `%f`/`%F` | Float — `%f` → `%F` (locale-unaware) |
| `%i` | Identifier (WP 6.2+) — backtick-wrapped |

Key: strips existing quotes around simple `%s`, escapes unrecognized `%`, non-scalar→`''`, returns void/null on errors.

**LIKE:** `%s` does NOT escape LIKE wildcards. Must use `$wpdb->esc_like()` BEFORE `prepare()`:
```php
$wpdb->prepare("... LIKE %s", '%' . $wpdb->esc_like($input) . '%')
```

**ORDER BY:** `%s` wraps in quotes, breaking SQL. Use allowlist or `%i`.

### `$wpdb->esc_like( $text )` — L1785
`addcslashes($text, '_%\\')` — escapes ONLY `_`, `%`, `\`. Does NOT escape SQL metacharacters. MUST be followed by `prepare()`.

### `$wpdb->insert()`/`update()`/`delete()`
Call `prepare()` internally for VALUES. **Table name NOT escaped** (interpolated). **Column names (keys) NOT escaped** (backtick-wrapped only).

### `$wpdb->query()` — L2212
Raw execution. NO sanitization. `mysqli_query()` directly.

### `$wpdb->get_var()`/`get_row()`/`get_results()`/`get_col()`
Pass-through to `query()`. No input sanitization, no output escaping.

## 4. Authentication & Authorization

### `current_user_can( $capability, ...$args )` — capabilities.php L913
Wrapper for `user_can(wp_get_current_user(), ...)`. Logged-out (UID 0): always `false`.

### `wp_verify_nonce( $nonce, $action )` — pluggable.php L2470
Returns: `1` (valid, current window), `2` (valid, previous window), `false` (invalid).
Composition: `substr(wp_hash(tick|action|uid|session_token, 'nonce'), -12, 10)`
User binding: bound to user ID + session token. UID 0: nonces interchangeable across ALL unauthenticated visitors within same 12h tick.

### `check_ajax_referer( $action, $query_arg=false, $stop=true )`
Sources: `$_REQUEST[$query_arg]` → `$_REQUEST['_ajax_nonce']` → `$_REQUEST['_wpnonce']`.
`$stop=true` (default): halts on failure. `$stop=false`: returns false, execution continues.
**Audit rule:** `check_ajax_referer($action, false, false)` without return value check = nonce bypass.

### `check_admin_referer( $action, $query_arg='_wpnonce' )`
Always halts on failure (no `$stop` parameter).

### `is_admin()` — load.php L1356
Checks request context, NOT user role. Returns `true` for admin-ajax.php (ALL AJAX, including `wp_ajax_nopriv_`). Returns `false` for REST API. **NOT an authorization check.**

## 4B. Options API Security Model

Source: `wp-includes/option.php`

### `update_option( $option, $value, $autoload = null )` — L844
**NO capability check.** Directly writes to `wp_options` via `$wpdb->update()`. Any code path reaching this function modifies the database unconditionally. Authorization is the caller's responsibility.

### `add_option( $option, $value = '', $deprecated = '', $autoload = null )` — L1067
**NO capability check.** Inserts a new row into `wp_options` via `$wpdb->insert()`. If the option already exists, returns `false` without modifying. Combined with `delete_option()`, this pair bypasses `update_option()` hooks.

### `delete_option( $option )` — L1199
**NO capability check.** Removes the row from `wp_options`. The `delete_option + add_option` pair is a known pattern to bypass `update_option_{$option}` hooks.

### `update_site_option()` / `delete_site_option()`
Multisite equivalents. Same behavior: **NO built-in capability check.**

### `register_setting( $option_group, $option_name, $args )` — L2994
Registers an option with the Settings API. The `sanitize_callback` argument is invoked **exclusively** by `wp-admin/options.php`, which enforces `manage_options` (or the capability specified via the `option_page_capability_{$option_group}` filter) before firing any sanitize callback. Functions registered as `sanitize_callback` are therefore **admin-gated by the Settings API** — they do NOT need their own `current_user_can()` check. However, if the same function is called directly (outside the Settings API flow), it has no auth protection.

### Critical WordPress options (security impact when overwritten)

| Option name | Impact |
|---|---|
| `users_can_register` | Enables open user registration (default: `0`) |
| `default_role` | Role assigned to new registrations (default: `subscriber`) |
| `siteurl` | Base URL for WordPress installation — overwrite redirects all traffic |
| `home` | Site address — overwrite redirects frontend |
| `admin_email` | Receives password reset emails and admin notifications |
| `active_plugins` | Serialized array — overwrite to deactivate security plugins |
| `template` / `stylesheet` | Active theme — overwrite to force malicious theme |
| `wp_user_roles` | Serialized role/capability definitions — overwrite for privilege escalation |
| `permalink_structure` | Rewrite rules — overwrite can break site routing |
| `blogname` / `blogdescription` | Stored XSS if echoed unescaped in frontend/admin |

### Audit relevance
Any code path where user-controlled input reaches `update_option()`, `add_option()`, or `delete_option()` without a prior `current_user_can('manage_options')` check is a potential Arbitrary Options Update vulnerability. The `admin_init` hook fires for all authenticated users (Subscriber+), NOT only administrators — this is the most common developer misconception leading to this vulnerability class.

## 4C. Plugin/Theme Install & Activation Security Model

Source: `wp-admin/includes/plugin.php`, `wp-admin/includes/class-plugin-upgrader.php`, `wp-admin/includes/class-theme-upgrader.php`, `wp-includes/theme.php`, `wp-admin/includes/ajax-actions.php`

### Install/activate sinks — NO built-in capability check
These functions perform the install/activate action only; **authorization is entirely the caller's responsibility** (same model as the Options API). A path reaching any of them from an attacker-reachable entry point without a matching `current_user_can()` is a Plugin/Theme Installation or Activation vulnerability — installing an attacker-supplied plugin ZIP yields RCE.

| Function | Location | Behavior | Gating capability (caller must check) |
|---|---|---|---|
| `activate_plugin( $plugin, $redirect, $network_wide, $silent )` | plugin.php:641 | Activates one plugin by basename. No cap check. | `activate_plugins` |
| `activate_plugins( $plugins, ... )` | plugin.php:869 | Activates an array of plugins. No cap check. | `activate_plugins` |
| `deactivate_plugins( $plugins, ... )` | plugin.php:758 | Deactivates plugins. No cap check. | `activate_plugins` |
| `Plugin_Upgrader::install( $package, $args )` | class-plugin-upgrader.php:21 | Downloads/unzips/installs a plugin from a local path or URL. No cap check. | `install_plugins` |
| `Theme_Upgrader::install( $package, $args )` | class-theme-upgrader.php:21 | Installs a theme from a path/URL. No cap check. | `install_themes` |
| `switch_theme( $stylesheet )` | theme.php:757 | Activates (switches to) a theme. No cap check. | `switch_themes` |

### Manual install primitive (no upgrader)
A plugin can install WITHOUT `Plugin_Upgrader` by combining `download_url( $url )` (fetch ZIP) + `unzip_file( $zip, WP_PLUGIN_DIR )` (extract into `wp-content/plugins`). The destination constant (`WP_PLUGIN_DIR`, or `get_theme_root()` for themes) is what turns a generic `unzip_file()` into a plugin/theme **install**. Neither `download_url()` nor `unzip_file()` checks capabilities. This is the actual install sink in CVE-2024-9234 (GutenKit) — a pattern that pure `Plugin_Upgrader`/`activate_plugin` detection misses.

### Install/activate capabilities

| Capability | Action | Held by (single-site) |
|---|---|---|
| `install_plugins` | Install a new plugin | Administrator only |
| `activate_plugins` | Activate/deactivate a plugin | Administrator only |
| `update_plugins` | Update a plugin | Administrator only |
| `delete_plugins` | Delete a plugin | Administrator only |
| `install_themes` | Install a new theme | Administrator only |
| `switch_themes` | Switch (activate) a theme | Administrator only |
| `update_themes` | Update a theme | Administrator only |
| `delete_themes` | Delete a theme | Administrator only |

On multisite these capabilities belong to Super Admins only (and `install_plugins`/`install_themes` are further gated by `DISALLOW_FILE_MODS`). Any path that lets a Subscriber/Customer/Contributor or an unauthenticated user reach an install/activate sink crosses a privilege boundary.

### Correct-gating baseline — core's own AJAX handlers
WordPress's own install/update/delete AJAX handlers (`wp-admin/includes/ajax-actions.php`) gate with **both** a nonce and a capability — the reference for "done correctly":

| AJAX handler | Nonce | Capability |
|---|---|---|
| `wp_ajax_install_plugin` (:4459) | `check_ajax_referer('updates')` (:4460) | `current_user_can('install_plugins')` (:4477) |
| `wp_ajax_update_plugin` (:4618) | `check_ajax_referer('updates')` (:4619) | `current_user_can('update_plugins')` (:4640) |
| `wp_ajax_delete_plugin` (:4726) | `check_ajax_referer('updates')` (:4727) | `current_user_can('delete_plugins')` (:4746) |
| `wp_ajax_install_theme` (:4164) | `check_ajax_referer('updates')` (:4165) | `current_user_can('install_themes')` (:4184) |
| `wp_ajax_update_theme` (:4290) | `check_ajax_referer('updates')` (:4291) | `current_user_can('update_themes')` (:4311) |
| `wp_ajax_delete_theme` (:4385) | `check_ajax_referer('updates')` (:4386) | `current_user_can('delete_themes')` (:4404) |

### Audit relevance
A nonce is **NOT** a capability check. Several CVEs (CVE-2025-64374 Motors, CVE-2025-1562 FunnelKit, CVE-2025-8418 B Slider) verify a nonce but omit `current_user_can()`, and the nonce is reachable by the low-privilege role (or, for `wp_ajax_nopriv_`, interchangeable across all unauthenticated visitors within a 12h tick — see §4 `wp_verify_nonce`). The finding is the absent install/activate capability check on the reachable path, regardless of any nonce present. A custom token/hash check substituted for `current_user_can()` (CVE-2025-1562) is not a mitigation.

## 5. KSES System

Source: `wp-includes/kses.php`

### `wp_kses( $content, $allowed_html, $allowed_protocols )` — L958
Strips null bytes/control chars → normalizes entities → `pre_kses` filter → `wp_kses_split()`.

### `wp_kses_post( $data )` — L2418
Uses `$allowedposttags`: allows `a`, `img`, `div`, `span`, `table`, `video`, etc. NOT allowed: `script`, `style`, `iframe`, `form`, `input`, `svg`, `embed`. Event handlers stripped unconditionally. `javascript:` protocol stripped from all URI attrs. `style` attr filtered through `safecss_filter_attr()`.

### `wp_filter_post_kses( $data )` — L2368
Expects slashed data. Hooked to `content_save_pre`.

### `wp_filter_kses( $data )` — L2337
Restrictive `$allowedtags` (L602-L630): only `a`, `abbr`, `acronym`, `b`, `blockquote`, `cite`, `code`, `del`, `em`, `i`, `q`, `s`, `strike`, `strong`.

### Block attribute preservation
`wp_pre_kses_block_attributes()` preserves block comment structure but attribute values containing HTML ARE still KSES-filtered. Event handlers stripped, `<script>` removed, `javascript:` stripped.
**Genuine vector:** Attribute context breakout — plain-text payload breaking out of HTML attribute in render_callback output (no HTML tags needed, KSES-irrelevant).

### KSES activation logic
`kses_init()` (L2522): users WITH `unfiltered_html` (Admins/Editors single-site; Super Admins multisite): KSES NOT active. Users WITHOUT (Contributors, Authors, Subscribers, unauth): KSES active on `content_save_pre`, `excerpt_save_pre`, `title_save_pre`, `pre_comment_content`.

`kses_remove_filters()`: removes ALL KSES save filters. If called without re-init, content from any user saved unfiltered for remainder of request.

## 6. User Data Sanitization Pipeline

Source: `wp-includes/default-filters.php` L31-L36

### Auto-sanitized fields on save

`pre_user_display_name`, `pre_user_first_name`, `pre_user_last_name`, `pre_user_nickname`:
Triple sanitization: `sanitize_text_field` → `wp_filter_kses` → `_wp_specialchars` (priority 30). No HTML survives.

`pre_user_description`: Single `wp_filter_kses` pass only. Basic HTML survives but no `<script>`/handlers.

`pre_user_email`: `trim` → `sanitize_email` → `wp_filter_kses`.

### Fields NOT auto-sanitized
`wp_insert_user()` does not sanitize directly — relies on `pre_user_*` filters from `default-filters.php`. If plugin removes these filters, sanitization bypassed.

## 7. Post Save Sanitization Pipeline

### `wp_insert_post()` chain
`sanitize_post($postarr, 'db')` → KSES filters (when user lacks `unfiltered_html`): `content_save_pre`→`wp_filter_post_kses()`, `title_save_pre`→`wp_filter_kses()` → `post_name`→`sanitize_title()` → int casts → `wp_unslash()` + `$wpdb->insert()`/`update()`.

### Post meta
**No automatic sanitization.** `update_post_meta()`/`add_post_meta()` store as-is (SQL-escaped only). XSS prevention must happen at output.

### `unfiltered_html` holders
Single-site: Administrators, Editors. Multisite: Super Admins only. Bypass ALL KSES.

## 8. File Handling

### `wp_check_filetype( $filename )` — functions.php L3056
Extension-only check. Does NOT read file contents.

### `wp_check_filetype_and_ext( $file, $filename )` — functions.php L3100
Extension + content-based MIME (`getimagesize()`/`finfo`). Can be fooled by polyglots.

### `wp_handle_upload()` — file.php L1097
Key overrides: `test_type = false` → disables ALL type checking. `unfiltered_upload` cap → type check failure ignored.

### `wp_delete_file( $file )` — functions.php L7760
Applies `wp_delete_file` filter, then calls `@unlink( $delete )`. **NO path validation.** User-controlled `$file` = arbitrary file deletion. Does not check if file is within uploads dir or any other base directory.

### `wp_delete_file_from_directory( $file, $directory )` — functions.php L7786
**SAFE.** Uses `realpath(wp_normalize_path($file))` + `str_starts_with($real_file, trailingslashit($real_directory))` to confine deletion to the specified directory. Returns `false` if file is outside directory. Added in WP 4.9.7 to fix CVE-2018-20714. Internally calls `wp_delete_file()` only after validation passes.

### `wp_delete_attachment( $post_id )` — post.php L6687
**SAFE for path traversal.** Takes integer post ID, retrieves attachment record from DB, verifies `post_type === 'attachment'`. Calls `wp_delete_attachment_files()` for actual file deletion. Path is never directly user-supplied.

### `wp_delete_attachment_files( $post_id, $meta, $backup_sizes, $file )` — post.php L6791
**SAFE.** Deletes all files (thumbnails, intermediate sizes, original) associated with an attachment. Uses `wp_delete_file_from_directory()` for every file operation, confining deletion to `$uploadpath['basedir']`.

### `WP_Filesystem_Direct::delete( $file, $recursive, $type )` — class-wp-filesystem-direct.php L392
**NOT safe for path traversal.** Calls `@unlink($file)` directly for files, `@rmdir($file)` for directories. Only checks `empty($file)` — no path validation, no base directory check. When `$recursive = true`, recursively deletes all contents.

## 9. HTTP / Redirect Functions

### `wp_redirect( $location )`
URL sanitization only (CRLF prevention). **NO host validation.** Any http/https URL accepted.

### `wp_safe_redirect( $location )`
`wp_validate_redirect()`: allows only site's own host, rejects userinfo, returns fallback on failure.

### `wp_remote_get()`/`wp_remote_post()`
**NO SSRF protection.** Requests any URL including private ranges.

### `wp_safe_remote_get()`/`wp_safe_remote_post()`
Sets `reject_unsafe_urls=true` → `wp_http_validate_url()`: blocks private IPv4 (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), only http/https, ports 80/443/8080. Does NOT block IPv6 private.

## 10. Connectors API (WP 7.0+)

Source: `wp-includes/connectors.php`, `wp-includes/class-wp-connector-registry.php`

### API Key Storage
API keys stored in `wp_options` as `connectors_ai_{$provider_id}_api_key`. **Not encrypted** — plaintext in DB. Sanitized via `sanitize_text_field` only. Exposed via REST (`show_in_rest => true`) to users with `manage_options`.

Priority order for key resolution: environment variable → PHP constant → database (`get_option`).

### Audit relevance
Plugins using the Connectors API inherit its key storage model. If a plugin reads `get_option('connectors_ai_*_api_key')` and echoes or logs the value, the API key leaks. The `show_in_rest => true` setting means the key is readable via `wp/v2/settings` by any user with `manage_options` (Administrators).

### Key functions
- `wp_is_connector_registered( $id )` — checks registry
- `wp_get_connector( $id )` — returns connector data or null
- `wp_get_connectors()` — returns all registered connectors
- `_wp_connectors_get_api_key_source()` — resolves key from env/constant/DB

## 11. Indexed FP Pattern Catalog

### FP-1: `sanitize_text_field()` output → echo → "XSS via HTML entities"
**Why FP:** HTML entities in PCDATA decode to character tokens (text), never tag tokens. `&#60;img onerror=alert(1)&#62;` renders as visible text. Only exploitable via server-side `html_entity_decode()` before echo, or JS `innerHTML`.
Source: `_sanitize_text_fields()` L5633 strips literal `<` via `wp_strip_all_tags()` L5645.

### FP-2: `wp_kses_post()` passes entities → "entity bypass XSS"
**Why FP:** Same WHATWG tokenizer rule as FP-1. Entities decode to text characters not markup. Real risk: when write path permits literal `<` (no sanitizer at all).

### FP-3: `wp_insert_user()` name fields → "Stored XSS via first_name/last_name"
**Why FP:** `default-filters.php` L32-L36 registers triple sanitization (`sanitize_text_field` + `wp_filter_kses` + `_wp_specialchars`). No HTML survives.
**Caveat:** If plugin removes these filters, sanitization bypassed.

### FP-4: Block attribute HTML → "Contributors bypass KSES"
**Why partial FP:** Attribute values ARE KSES-filtered (handlers stripped, `<script>` removed). Genuine vector: attribute context breakout in render_callback output (plain text, KSES-irrelevant). Requires empirical verification.

### FP-5: `check_ajax_referer()` present → "nonce verified"
**Why can be FP:** Only when `$stop=true` (default). With `$stop=false` (third arg), returns false but doesn't halt. If return unchecked → nonce bypass. When `$stop` true/omitted → IS valid nonce check.

### FP-6: Entity reference in HTML attribute → "attribute injection"
**Why FP:** Per WHATWG, character references inside attribute values are decoded and APPENDED to value — do NOT terminate attribute context. `<div title="a&#39;b">` = attribute value `a'b`.

### FP-7: Pro-only code path flagged in free plugin
**Why FP:** Code gated behind `function_exists()`/`class_exists()`/`defined()` where referenced symbol only in premium add-on not in free plugin. Path unreachable.
**Rule:** Verify ALL functions/classes/constants depended on are defined in audited source tree.

### FP-8: `is_admin()` used as authorization check
**Why FP:** Returns `true` for ALL `admin-ajax.php` requests (including `wp_ajax_nopriv_`). Checks request context, not user role.

### FP-9: Nonce in parent/dispatch handler not visible in endpoint function
**Why can be FP:** Many plugins verify nonce in dispatcher before calling handler. Always trace full call chain from hook registration to execution.

### FP-10: `esc_like()` present → "query is safe"
**Why NOT safe:** `esc_like()` = `addcslashes($text, '_%\\')` — escapes ONLY LIKE wildcards. Quotes pass through. If output concatenated directly (not via `prepare()`), SQLi still possible.
Correct: `$wpdb->prepare("...LIKE %s", '%'.$wpdb->esc_like($input).'%')`
Vulnerable: `$wpdb->query("...LIKE '%".$wpdb->esc_like($input)."%'")`
