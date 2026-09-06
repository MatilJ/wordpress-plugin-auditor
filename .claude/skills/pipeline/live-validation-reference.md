# Live Validation Reference — Diagnosis & Recovery

Read on-demand during Pipeline Stage 6d (PoC Execution) or when Stage 6b/6c hits issues. Do NOT read at pipeline start.

## Section 1 — Shell Command Rules (Windows/PowerShell host)

**NEVER inline multi-step bash through PowerShell.** PowerShell parses `$`, backticks, `()`, braces — compound bash with variables/subshells WILL break.

**Rule:** If bash command has variables, pipes, or subshells:
1. Write to `.sh` file using Write tool
2. `docker cp <file>.sh wordpress-plugin-auditor-wordpress-1:/tmp/<file>.sh`
3. `docker compose exec -T wordpress bash /tmp/<file>.sh`

**Safe inline** (no bash variables/subshells):
- `docker compose exec -T wordpress wp --allow-root plugin list`
- `docker compose exec -T db mysql -u wordpress -pwordpress wordpress -e "SELECT ..."`
- `docker compose logs setup`

## Section 2 — Helper Templates

| Template | Purpose | Path |
|----------|---------|------|
| `activate-plugins.php` | Add plugins to `active_plugins` with correct serialization; `--with-hooks` | `/tmp/activate-plugins.php` |
| `check-environment.php` | PHP extensions, debug.log, HTTP self-test, REST namespaces, plugin health | `/tmp/check-environment.php` |
| `check-routes.php` | List registered REST routes. **WARNING:** CLI-bootstrapped, may show routes not HTTP-reachable | `/tmp/check-routes.php` |
| `smoke-test.sh` | Login + nonce + endpoint probe (AJAX and REST) | `/tmp/smoke-test.sh` |

Deploy all: `docker cp "${CLAUDE_PROJECT_DIR}/.claude/skills/live-validation/templates/." wordpress-plugin-auditor-wordpress-1:/tmp/`

## Section 3 — Plugin Configuration Patterns

Priority order:
1. **WP-CLI option commands** (non-eval): `wp option update/patch`
2. **Direct PHP script** (complex types, JSON, hooks): `docker cp` + `php /tmp/script.php`
3. **Direct SQL**: `docker compose exec -T db mysql ...`
4. **WP-CLI eval** (last resort, fragile): `wp eval "<code>"`

### JSON option update script
```php
<?php
$conn = new mysqli('db', 'wordpress', 'wordpress', 'wordpress');
$res = $conn->query("SELECT option_value FROM wp_options WHERE option_name='<name>'");
$opts = json_decode($res->fetch_row()[0], true);
$opts['target_key'] = 1;
$stmt = $conn->prepare("UPDATE wp_options SET option_value=? WHERE option_name='<name>'");
$json = json_encode($opts);
$stmt->bind_param('s', $json);
$stmt->execute();
$conn->close();
```

### User meta update
```powershell
docker compose exec -T db mysql -u wordpress -pwordpress wordpress -e "INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (<uid>, '<key>', '<value>') ON DUPLICATE KEY UPDATE meta_value='<value>';"
```

## Section 4 — PoC Failure Diagnosis

### Step 0 — Check debug.log
```powershell
docker compose exec -T wordpress bash -c "tail -50 /var/www/html/wp-content/debug.log"
```

### Diagnosis order
1. **Login failure** → `wp --allow-root user list --fields=ID,user_login,roles`
2. **Nonce not found** → handler may still be callable. Generate via WP-CLI: `wp eval "wp_set_current_user(<uid>); echo wp_create_nonce('<action>');"`
3. **Feature not enabled** → re-check Stage 6c settings
4. **Plugin crash (500)** → debug.log. Common: option format corruption
5. **AJAX returns -1/0** → nonce validation failed. Regenerate.
6. **AJAX returns 403** → `check_ajax_referer()` failed. Same fix.
7. **404** → systematic:
   - a. Check permalinks: `wp option get permalink_structure`. Fix: `wp rewrite structure '/%postname%/' --hard`
   - b. Check REST namespace via HTTP (authoritative): `curl -s "http://localhost:8000/wp-json/<namespace>"`
   - c. DB active_plugins check: `SELECT option_value FROM wp_options WHERE option_name='active_plugins'`. If `a:0:{}` → use `activate-plugins.php`
   - d. Fallback: `?rest_route=/namespace/v1/route`

### SQL injection diagnosis
1. **Space-splitting parsers:** `AND SLEEP(4)` → `AND(SLEEP(4))`, `UNION SELECT 1,2` → `UNION(SELECT(1),(2))`
2. **Comment char:** Use `#` not `--` (space-splitting strips trailing space)
3. **SLEEP() requires rows:** Empty table = never executes. Use UNION-based or populate first.
4. **Wrong UNION columns:** `DESCRIBE <table_name>;` first
5. **WP 6.8+ bcrypt hashes:** regex `r'\$(?:wp\$2y|2y|P)\$[A-Za-z0-9$./]{20,}'`, hashcat `-m 3200`

## Section 5 — Nonce Generation Fallback (mu-plugin)

**WARNING:** If the action nonce is not on any page the attacker role can access, the effective auth floor may be higher than claimed (finding likely OOS as PR:H). Only use this fallback when the nonce is confirmed accessible but hard to scrape programmatically.

When WP-CLI eval crashes and nonce confirmed accessible but hard to scrape:

```php
<?php
add_action('wp_ajax_test_nonce_gen', function() {
    $action = isset($_POST['nonce_action']) ? $_POST['nonce_action'] : '';
    if ($action === '') { wp_send_json_error('missing nonce_action'); }
    wp_send_json_success(array('nonce' => wp_create_nonce($action), 'user_id' => get_current_user_id()));
});
```

Install: `docker cp <path> wordpress-plugin-auditor-wordpress-1:/var/www/html/wp-content/mu-plugins/test-nonce-gen.php`
Call: `POST /wp-admin/admin-ajax.php action=test_nonce_gen&nonce_action=<target>`
Remove after: `docker compose exec -T wordpress rm -f /var/www/html/wp-content/mu-plugins/test-nonce-gen.php`

## Section 6 — Database Surgery

- **Reset active_plugins:** `UPDATE wp_options SET option_value='a:0:{}' WHERE option_name='active_plugins';` then use `activate-plugins.php`
- **Fix corrupted serialized option:** Check format first (JSON vs serialized), write PHP script with `serialize()` — NEVER hand-write
- **Recreate tables:** Find `register_activation_hook`, extract CREATE TABLE, run directly
- **Reset password:** `wp --allow-root user update <username> --user_pass=<password>`
- **Grant capabilities:**
```php
<?php
define('ABSPATH', '/var/www/html/');
define('WPINC', 'wp-includes');
require('/var/www/html/wp-load.php');
$role = get_role('subscriber');
$role->add_cap('target_capability');
echo "Done. Caps: " . implode(', ', array_keys(array_filter($role->capabilities)));
```

## Section 7 — Pitfalls

- **Version mismatch:** Always `docker cp` from SOURCE_DIR. `wp plugin install` fetches latest.
- **Plugin silently fails:** Listed active but never initializes. Run `check-environment.php <slug>` after setup.
- **PHP serialization:** NEVER hand-write. One byte off → `unserialize()` returns false → all plugins deactivated.
- **Memory limit:** upload.ini has 512M. Symptom: "Allowed memory size exhausted" or silent 500.
- **PLUGIN_SLUG env var:** Start empty (setup.sh skips install). Only for dependency plugins.
- **Activation hooks don't fire via DB:** Use `activate-plugins.php --with-hooks` or run activation SQL manually.
- **Pretty permalinks:** Required for `/wp-json/` routes. Verify after setup. Fallback: `?rest_route=`.
- **Option format corruption:** `update_option()` with PHP array → serialized. Plugins using `json_decode()` will crash.
- **WP-CLI eval vs. direct PHP:** `wp eval-file` bootstraps full WP. If plugin has init error, crashes. Use `php /tmp/script.php`.
- **Xdebug noise:** Filter with `Select-String -NotMatch "Xdebug"` (PS) or `grep -v Xdebug` (bash).
- **Nonce ≠ Authorization:** Nonces are anti-CSRF only. `check_ajax_referer()` passing ≠ user authorized.
- **UI gating vs. handler gating:** No UI element ≠ handler protected. Always test handler directly.
- **check-routes.php lies:** CLI-bootstrapped. HTTP namespace index is authoritative.
- **Sub-component activation resets:** Avoid plugin-level reactivation after Stage 6c config.
- **`add_option()` does NOT fire update hooks:** Only `added_option` fires. Use `update_option()` if needed.
- **PowerShell cleanup:** Use `Remove-Item`, not `del` or bash `rm`.
