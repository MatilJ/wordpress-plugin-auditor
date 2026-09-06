<?php
/**
 * Test cases for claude.php.wordpress.rce.unrestricted-unserialize-variable
 * ruleid = must fire; ok = must stay silent.
 */

// maybe_unserialize() is NOT safe — unrestricted object deserialization on a
// request-derived function parameter (the real pre-fix shape).
function vuln_maybe_unserialize_param($fieldSubmissionValue) {
    if (is_string($fieldSubmissionValue)) {
        // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
        $fieldSubmissionValue = maybe_unserialize($fieldSubmissionValue);
    }
    return $fieldSubmissionValue;
}

// Single-argument unserialize() on a bare variable — no allowed_classes.
function vuln_single_arg_unserialize($payload) {
    // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize($payload);
}

// Two-argument unserialize() but allowed_classes => true (still unrestricted).
function vuln_allowed_classes_true($blob) {
    // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize($blob, ['allowed_classes' => true]);
}

// The actual fix — allowed_classes => false disables object instantiation.
function safe_allowed_classes_false($data) {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize($data, ['allowed_classes' => false]);
}

// Long-array syntax of the fix.
function safe_allowed_classes_false_long($data) {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize($data, array('allowed_classes' => false));
}

// Inline WP core read — argument is a FuncCall, not a bare variable; core's own
// serialized data, not separately reportable.
function safe_inline_core_read() {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return maybe_unserialize(get_option('my_plugin_settings'));
}

// Array-access custom-table column — left to the dedicated meta-table rule.
function safe_meta_row_handled_elsewhere($row) {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return maybe_unserialize($row['meta_value']);
}

// trim()-wrapped variable, no options array at all — still unrestricted.
function vuln_trim_wrapped_no_opts($logColumnValue) {
    // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize(trim($logColumnValue));
}

// trim()-wrapped variable with a MISSPELLED protection key (the real
// pre-fix CVE-2024-9511 shape) — PHP ignores the unrecognized
// 'allow_classes' key, so allowed_classes silently defaults to true.
function vuln_trim_wrapped_typo_key($data) {
    if (is_serialized($data)) {
        // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
        return unserialize(trim($data), ['allow_classes' => false]);
    }
    return $data;
}

// The real fix — trim() wrapper plus the CORRECTLY spelled key.
function safe_trim_wrapped_allowed_classes_false($data) {
    if (is_serialized($data)) {
        // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
        return unserialize(trim($data), ['allowed_classes' => false]);
    }
    return $data;
}

// Long-array syntax of the trim()-wrapped fix.
function safe_trim_wrapped_allowed_classes_false_long($data) {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize(trim($data), array('allowed_classes' => false));
}

// Decode-wrapped POST superglobal, no allowed_classes — the real
// pre-fix CVE-2025-0769 shape (an async postback handler's run_action()).
function vuln_postback_handler_run_action() {
    // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
    $data = unserialize(base64_decode($_POST['data']));
    return $data;
}

// Bare request superglobal, no decode wrapper and no allowed_classes.
function vuln_bare_request_superglobal() {
    // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize($_REQUEST['payload']);
}

// The real CVE-2025-0769 fix — allowed_classes restricted to a specific list.
function safe_postback_handler_allowed_classes($blob) {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize(base64_decode($_POST['data']), ['allowed_classes' => ['App\\Event']]);
}

// Correctly restricted bare-cookie form.
function safe_cookie_allowed_classes_false() {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize($_COOKIE['token'], ['allowed_classes' => false]);
}

// Decode-wrapped inline WP core read — not request-derived, core's own
// serialized data.
function safe_decode_wrapped_core_read() {
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return maybe_unserialize(base64_decode(get_option('my_plugin_settings')));
}

// Single-level object-property access on a $wpdb->get_row() result — the real
// pre-fix shape (a PropertyFetch, not a bare Variable — the bare-variable
// branch above cannot match this).
function vuln_wpdb_row_property_unserialize($cartId) {
    global $wpdb;
    $cart = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}plugin_carts WHERE id = %s", $cartId));
    if (!empty($cart)) {
        // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
        return unserialize($cart->cart);
    }
    return false;
}

// The fix — allowed_classes => false on the property-access form.
function safe_wpdb_row_property_allowed_classes_false($cartId) {
    global $wpdb;
    $cart = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}plugin_carts WHERE id = %s", $cartId));
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return unserialize($cart->cart, ['allowed_classes' => false]);
}

// Two-step "assign, then unserialize" idiom on a WP core meta accessor — the
// value is data WordPress itself serialized via update_comment_meta(), the
// same core-accessor exclusion as the inline get_option() form above, just
// one statement further apart (a common vote-tracking-array idiom).
function safe_comment_meta_assign_then_unserialize($comment_id) {
    $registered_upvoters = get_comment_meta($comment_id, 'cr_question_reg_upvoters', true);
    if (!empty($registered_upvoters)) {
        // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
        $registered_upvoters = maybe_unserialize($registered_upvoters);
    }
    return $registered_upvoters;
}

function safe_post_meta_assign_then_unserialize($post_id) {
    $stored = get_post_meta($post_id, 'plugin_options_array', true);
    // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return maybe_unserialize($stored);
}

// Negative control: same two-statement shape, but the source call is a
// differently-named function, not one of the four covered core accessors —
// must still fire, proving the exclusion isn't a wildcard on any "assign
// then unserialize" idiom.
function vuln_custom_source_assign_then_unserialize($request) {
    $payload = get_plugin_submitted_payload($request);
    // ruleid: claude.php.wordpress.rce.unrestricted-unserialize-variable
    return maybe_unserialize($payload);
}

// $PROP is exactly "meta_value" — the literal column name WordPress core
// uses for every meta table (wp_postmeta/wp_commentmeta/wp_usermeta). A raw
// $wpdb query result exposing this column is the same WordPress-itself-
// serialized data get_*_meta() accessors return.
function safe_wpdb_meta_value_property_unserialize() {
    global $wpdb;
    $rows = $wpdb->get_results("SELECT comment_id, meta_key, meta_value FROM {$wpdb->commentmeta} WHERE meta_key = 'ivole_review_image'", OBJECT);
    foreach ($rows as $row) {
        // ok: claude.php.wordpress.rce.unrestricted-unserialize-variable
        $value = maybe_unserialize($row->meta_value);
    }
    return $value;
}
