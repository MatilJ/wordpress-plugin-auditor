<?php
// Test file: claude.php.wordpress.access-control.dependent-field-context-to-meta-key-no-allowlist

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// VULNERABLE: real pre-fix shape — dependent-field context value assigned
// straight into the settings 'meta_key' with no allow-list check.
class Vuln_Get_From_DB {
    public function generate_with_context(array $settings, array $context = array()): array {
        if (!empty($context)) {
            $context_value = reset($context);
            $meta_key = is_scalar($context_value) ? trim(sanitize_text_field((string) $context_value)) : '';

            if ('' !== $meta_key) {
                // ruleid: claude.php.wordpress.access-control.dependent-field-context-to-meta-key-no-allowlist
                $settings['meta_key'] = $meta_key;
            }
        }

        return $this->generate($settings);
    }

    public function generate($args) {
        global $wpdb;
        return $wpdb->get_results(
            $wpdb->prepare("SELECT DISTINCT meta_value FROM {$wpdb->postmeta} WHERE meta_key = %s", $args['meta_key'])
        );
    }
}

// VULNERABLE: variant — different class/function naming, sink is get_user_meta()
// instead of a settings array, still no allow-list check on the requested key.
class Vuln_Cascading_User_Field {
    public function get_options_for_watched_field(array $settings, array $context = array()) {
        $trigger_value = current($context);
        $field_key = sanitize_key((string) $trigger_value);

        // ruleid: claude.php.wordpress.access-control.dependent-field-context-to-meta-key-no-allowlist
        return get_user_meta($settings['user_id'], $field_key, true);
    }
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: the actual 3.6.3.1 fix — dependent-field value must match a
// server-computed allow-list before it is used as the meta_key.
class Safe_Get_From_DB {
    public function generate_with_context(array $settings, array $context = array()): array {
        if (!empty($context)) {
            $context_value = reset($context);
            $meta_key = is_scalar($context_value) ? trim(sanitize_text_field((string) $context_value)) : '';

            if ('' !== $meta_key) {
                $allowed_meta_keys = $settings['_jfb_runtime']['allowed_meta_keys'] ?? array();

                if (in_array($meta_key, $allowed_meta_keys, true)) {
                    // ok: claude.php.wordpress.access-control.dependent-field-context-to-meta-key-no-allowlist
                    $settings['meta_key'] = $meta_key;
                }
            }
        }

        return $this->generate($settings);
    }
}

// SAFE: ordinary DB read helper — meta_key comes from a DB row, not a
// dependent-field context array, so the taint source never applies.
class Safe_Db_Read {
    public function get_setting_value($post_id) {
        global $wpdb;
        $meta_key = $wpdb->get_var("SELECT option_name FROM {$wpdb->options} WHERE option_id = 1");

        // ok: claude.php.wordpress.access-control.dependent-field-context-to-meta-key-no-allowlist
        return get_post_meta($post_id, $meta_key, true);
    }
}
