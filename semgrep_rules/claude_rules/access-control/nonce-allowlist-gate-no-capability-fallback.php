<?php
/**
 * Test cases for claude.php.wordpress.access-control.nonce-allowlist-gate-no-capability-fallback
 *
 * The rule fires on: a permission/dispatcher function that gates
 * check_ajax_referer()/wp_verify_nonce() behind a positive in_array()
 * allow-list membership test, with NO current_user_can() (or recognized
 * isAdmin()/has_access()-style wrapper) call anywhere in the function.
 */

// ── MATCH: generalized shape of the real-world vulnerable pattern ─────────────
// (opt-in nonce allow-list, zero capability check anywhere in the function)

class RouterOne {
    public function havePermissions($code, $action) {
        $res = true;
        $mod = $this->getModule($code);
        if ($mod) {
            $noncedMethods = $mod->getController()->getNoncedMethods();
            if (!empty($noncedMethods)) {
                $noncedMethods = array_map('strtolower', $noncedMethods);
                // ruleid: claude.php.wordpress.access-control.nonce-allowlist-gate-no-capability-fallback
                if (in_array($action, $noncedMethods)) {
                    check_ajax_referer('my-plugin-nonce', 'myNonce');
                }
            }
        }
        return $res;
    }
}

// wp_verify_nonce() variant, different variable/method names
class RouterTwo {
    public function authorize($action) {
        $allowed = true;
        $whitelist = $this->getUnprotectedActions();
        // ruleid: claude.php.wordpress.access-control.nonce-allowlist-gate-no-capability-fallback
        if (in_array($action, $whitelist)) {
            wp_verify_nonce($_REQUEST['nonce'], 'router2-nonce');
        }
        return $allowed;
    }
}

// ── NO MATCH: official fix shape — default-deny capability wrapper added ──────
// (isAdmin() wrapper flips the result to false for any action not in an
// explicit public allow-list; nonce check itself is now inverted/opt-out)

class RouterThree {
    public function havePermissions($code, $action) {
        $res = true;
        $mod = $this->getModule($code);
        if ($mod) {
            $frontMethods = $mod->getController()->getFrontMethods();
            if (empty($frontMethods) || !in_array($action, $frontMethods)) {
                $user = new WaicUser();
                // ok: claude.php.wordpress.access-control.nonce-allowlist-gate-no-capability-fallback
                if (!$user->isAdmin()) {
                    $res = false;
                }
            }
            if ($res) {
                $notNoncedMethods = $mod->getController()->getNotNoncedMethods();
                if (empty($notNoncedMethods) || !in_array($action, $notNoncedMethods)) {
                    check_ajax_referer('my-plugin-nonce', 'myNonce');
                }
            }
        }
        return $res;
    }
}

// Direct current_user_can() present alongside the allow-list nonce gate — safe
class RouterFour {
    public function authorize($action) {
        $allowed = true;
        $whitelist = $this->getPublicActions();
        if (in_array($action, $whitelist)) {
            // ok: claude.php.wordpress.access-control.nonce-allowlist-gate-no-capability-fallback
            check_ajax_referer('router4-nonce', 'nonce');
        } elseif (!current_user_can('manage_options')) {
            $allowed = false;
        }
        return $allowed;
    }
}

// Unrelated safe code: plain WP DB read, no auth-decision logic at all
class ItemsReader {
    public function getItems() {
        global $wpdb;
        return $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items");
    }
}
