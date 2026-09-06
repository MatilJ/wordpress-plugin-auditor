<?php
// Test cases for claude.php.wordpress.sqli.foreach-request-key-to-wpdb-write

class VulnerableCopyVar {
    // Real pre-fix shape: $_POST copied to a local var, then iterated, with
    // the loop KEY folded straight into the array later passed to insert().
    public function handle() {
        global $wpdb;
        $table = $wpdb->prefix . 'contact_lists';
        $postArr = $_POST;
        $params = array();
        if (true) {
            foreach ($postArr as $key => $val) {
                if ($key != 'action' && $key != 'widget_id') {
                    // ruleid: claude.php.wordpress.sqli.foreach-request-key-to-wpdb-write
                    $params[$key] = esc_sql(sanitize_text_field($val));
                }
            }
            $params['widget_id'] = esc_sql(sanitize_text_field('1'));
            if (!empty($params)) {
                $wpdb->insert($table, $params);
            }
        }
    }
}

class VulnerableDirectUpdate {
    // Direct-loop variant reaching $wpdb->update() instead of insert().
    public function handle() {
        global $wpdb;
        $table = $wpdb->prefix . 'settings';
        $data = array();
        foreach ($_REQUEST as $key => $val) {
            // ruleid: claude.php.wordpress.sqli.foreach-request-key-to-wpdb-write
            $data[$key] = sanitize_text_field($val);
        }
        $wpdb->update($table, $data, array('id' => 1));
    }
}

class FixedAllowList {
    // Patched shape: iterate a hardcoded allow-list array instead of the
    // request superglobal, so the key can never be attacker-controlled.
    public function handle() {
        global $wpdb;
        $table = $wpdb->prefix . 'contact_lists';
        $allowed_keys = array('contact_name', 'contact_email', 'contact_phone');
        $params = array();
        foreach ($allowed_keys as $key) {
            if (isset($_POST[$key]) && $_POST[$key] !== '') {
                // ok: claude.php.wordpress.sqli.foreach-request-key-to-wpdb-write
                $params[$key] = sanitize_text_field($_POST[$key]);
            }
        }
        if (!empty($params)) {
            $params['widget_id'] = esc_sql(sanitize_text_field('1'));
            $wpdb->insert($table, $params);
        }
    }
}

class FixedInlineAllowListGuard {
    // Alternate fix style: still loops over $_POST directly but validates
    // the key against an allow-list before ever assigning it.
    public function handle() {
        global $wpdb;
        $table = $wpdb->prefix . 'contact_lists';
        $allowed = array('contact_name', 'contact_email');
        $params = array();
        foreach ($_POST as $key => $val) {
            if (in_array($key, $allowed, true)) {
                // ok: claude.php.wordpress.sqli.foreach-request-key-to-wpdb-write
                $params[$key] = sanitize_text_field($val);
            }
        }
        $wpdb->insert($table, $params);
    }
}

class SafeDbRead {
    // Ordinary WP DB-read pattern, unrelated to request-driven writes.
    public function handle($post_id) {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.foreach-request-key-to-wpdb-write
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->postmeta} WHERE post_id = %d", $post_id));
        return $row;
    }
}
