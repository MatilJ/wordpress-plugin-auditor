<?php

// Vulnerable: dynamically-named per-field property substituted into a
// merge-tag template with no escaping — the common "profile_N" loop idiom.
function render_merge_tags_vuln($text, $user, $max_fields) {
    for ($i = 1; $i <= $max_fields; $i++) {
        $p = 'profile_' . $i;
        // ruleid: claude.php.wordpress.xss.merge-tag-dynamic-property-str-replace-unescaped
        $text = str_replace('{profile_' . $i . '}', $user->$p, $text);
    }
    return $text;
}

// Vulnerable: compound-assignment (.=) variant with a different loop/field
// naming convention, still an unescaped dynamic property substitution.
function build_email_body_vuln($body, $subscriber, $fields) {
    foreach ($fields as $i => $label) {
        $field = 'custom_' . $i;
        // ruleid: claude.php.wordpress.xss.merge-tag-dynamic-property-str-replace-unescaped
        $body .= str_replace('{custom_' . $i . '}', $subscriber->$field, $body);
    }
    return $body;
}

// Fixed: value resolved through a sanitizer into an intermediate variable
// before being handed to str_replace() (the real-world patch shape — the
// bare property access no longer occupies the replacement argument).
function render_merge_tags_fixed($text, $user, $max_fields) {
    for ($i = 1; $i <= $max_fields; $i++) {
        $p = 'profile_' . $i;
        $value = sanitize_user_field($user->$p);
        // ok: claude.php.wordpress.xss.merge-tag-dynamic-property-str-replace-unescaped
        $text = str_replace('{profile_' . $i . '}', $value, $text);
    }
    return $text;
}

// Fixed: escaped inline at the call site.
function render_merge_tags_inline_escaped($text, $user, $max_fields) {
    for ($i = 1; $i <= $max_fields; $i++) {
        $p = 'profile_' . $i;
        // ok: claude.php.wordpress.xss.merge-tag-dynamic-property-str-replace-unescaped
        $text = str_replace('{profile_' . $i . '}', esc_html($user->$p), $text);
    }
    return $text;
}

// Ok: a plain WP DB-read pattern (named, not dynamically-indexed, property)
// substituted through the same str_replace idiom — out of this rule's
// narrow scope by design (fixed property names are covered by other rules).
function render_static_merge_tag($text, $user) {
    global $wpdb;
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}subscribers WHERE id = 1");
    // ok: claude.php.wordpress.xss.merge-tag-dynamic-property-str-replace-unescaped
    $text = str_replace('{email}', esc_html($user->email), $text);
    return $text;
}
