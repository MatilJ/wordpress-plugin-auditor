<?php
/**
 * Test cases for claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
 *
 * Detects ACF-ecosystem hook handlers that re-derive the save/validate target
 * object by reading the raw '_acf_post_id' request field directly, instead of
 * trusting the framework-resolved post_id, with no current_user_can() gate.
 *
 * Motivating real-world pattern (ACF Extended <= 0.9.2.5, CVE-2026-8809):
 *   acfe_hooks::validate_save_post() read
 *   $post_id = acf_maybe_get_POST('_acf_post_id'); and used the raw value,
 *   unchecked, to select which object (post/user/term/...) received the
 *   submitted ACF field data — allowing an attacker to redirect a save
 *   operation to an arbitrary object such as "user_1" (the administrator).
 *   Fixed by switching to acf_get_form_data('post_id').
 */

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// Generalized pre-fix shape: raw '_acf_post_id' read via the ACF wrapper,
// used as a dynamic array key that selects the save target, no capability
// check anywhere in the function.
function validate_save_post_acfe_style() {
    $rows = array();
    $acf = acf_maybe_get_POST('acf');

    if (!empty($acf)) {
        // ruleid: claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
        $post_id = acf_maybe_get_POST('_acf_post_id');

        if ($post_id) {
            $rows[$post_id] = $acf;
        }
    }

    foreach ($rows as $post_id => $acf_values) {
        $data = decode_object($post_id);
        if (!$data) {
            continue;
        }
        do_action("acfe/validate_save_{$data['type']}/id={$post_id}", $post_id, $data['object']);
    }
}

// Variant: raw superglobal read (no wrapper function), still no auth check.
function handle_frontend_submission() {
    // ruleid: claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
    $post_id = $_POST['_acf_post_id'];

    if ($post_id) {
        $object = resolve_object_by_id($post_id);
        save_mapped_fields($object, $_POST['acf']);
    }
}

// Variant: $_REQUEST form, still no auth check.
function process_acf_request() {
    // ruleid: claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
    $target_id = $_REQUEST['_acf_post_id'];

    $object = resolve_object_by_id($target_id);
    save_mapped_fields($object, $_REQUEST['acf']);
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// Safe: the actual upstream fix — sourced from ACF core's own validated form
// data instead of a raw request read. Structurally distinct from the
// vulnerable pattern-either, so it never matches.
function validate_save_post_fixed() {
    $rows = array();
    $acf = acf_maybe_get_POST('acf');

    if (!empty($acf)) {
        // ok: claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
        $post_id = acf_get_form_data('post_id');

        if ($post_id) {
            $rows[$post_id] = $acf;
        }
    }
}

// Safe: same raw '_acf_post_id' read, but gated by an explicit capability
// check against the resolved object before it is used.
function handle_frontend_submission_with_capability_check() {
    // ok: claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
    $post_id = acf_maybe_get_POST('_acf_post_id');

    if (!$post_id || !current_user_can('edit_post', (int) $post_id)) {
        return;
    }

    save_mapped_fields($post_id, $_POST['acf']);
}

// Safe: same raw '_acf_post_id' read, gated by an inline negated capability
// check (early-return style).
function handle_admin_submission_with_negated_check() {
    // ok: claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
    $post_id = $_POST['_acf_post_id'];

    if (!current_user_can('edit_user', (int) $post_id)) {
        wp_die('Unauthorized');
    }

    save_mapped_fields($post_id, $_POST['acf']);
}

// Safe: WP DB-read pattern — the object id comes from a server-side query
// result, not from any request superglobal, so the source pattern never
// matches regardless of downstream capability checks.
function process_scheduled_batch() {
    global $wpdb;

    // ok: claude.php.wordpress.access-control.acf-post-id-param-trust-no-capability-check
    $post_id = $wpdb->get_var("SELECT post_id FROM {$wpdb->prefix}acfe_queue LIMIT 1");

    if ($post_id) {
        save_mapped_fields($post_id, get_post_meta($post_id, '_acfe_pending_values', true));
    }
}
