<?php
/**
 * Test cases for
 * claude.php.wordpress.access-control.moderation-only-gate-role-write-missing-enable-toggle
 *
 * Rule catches: a request-flag-triggered role-elevation function that grants a
 * hardcoded, non-default role via wp_update_user()/wp_insert_user(), gated
 * ONLY by a single admin-configurable "premoderation" option — with no
 * separate "feature enabled at all" option checked in the same condition.
 *
 * Motivating real-world TP: masterstudy-lms-learning-management-system <= 3.3.23
 * (CVE-2024-5973) — stm_lms_set_user_role() promoted a newly-registered account
 * to 'stm_lms_instructor' whenever the client-supplied $data['become_instructor']
 * flag was truthy and the 'instructor_premoderation' option was off, without ever
 * checking the separate 'register_as_instructor' master enable/disable option —
 * so an unauthenticated visitor could self-promote to Instructor even on sites
 * where instructor self-registration was turned off entirely.
 */

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// Real pre-fix shape: bare get_option(), single-condition negated gate,
// wp_update_user() with a hardcoded elevated role.
// ruleid: claude.php.wordpress.access-control.moderation-only-gate-role-write-missing-enable-toggle
function stm_lms_set_user_role( $user, $data ) {
    if ( ! empty( $data['become_instructor'] ) && $data['become_instructor'] ) {
        $instructor_premoderation = get_option( 'instructor_premoderation', false );
        if ( ! $instructor_premoderation ) {
            wp_update_user( array(
                'ID'   => $user,
                'role' => 'stm_lms_instructor',
            ) );
        }
    }
}

// Variant: static options-wrapper getter, wp_insert_user() instead of
// wp_update_user(), different flag/role names — same missing-master-toggle shape.
// ruleid: claude.php.wordpress.access-control.moderation-only-gate-role-write-missing-enable-toggle
function ajax_register_vendor( $user, $data ) {
    if ( ! empty( $data['become_vendor'] ) && $data['become_vendor'] ) {
        $vendor_premoderation = Vendor_Options::get_option( 'vendor_premoderation', false );
        if ( empty( $vendor_premoderation ) ) {
            wp_insert_user( array(
                'ID'   => $user,
                'role' => 'shop_vendor',
            ) );
        }
    }
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// The actual CVE-2024-5973 fix: the gating condition ALSO requires the
// separate master "is this feature enabled" option (register_as_instructor)
// — a two-flag && conjunction, not a single negated premoderation check.
function stm_lms_set_user_role_fixed( $user, $data ) {
    if ( ! empty( $data['become_instructor'] ) && $data['become_instructor'] ) {
        $register_as_instructor   = get_option( 'register_as_instructor', false );
        $instructor_premoderation = get_option( 'instructor_premoderation', false );

        // ok: claude.php.wordpress.access-control.moderation-only-gate-role-write-missing-enable-toggle
        if ( $register_as_instructor && ! $instructor_premoderation ) {
            wp_update_user( array(
                'ID'   => $user,
                'role' => 'stm_lms_instructor',
            ) );
        }
    }
}

// Role is the conventionally low-risk 'subscriber' default — public
// self-registration into 'subscriber' is not the privilege-escalation shape
// this rule targets, even with the single-flag gate.
function ajax_register_default_subscriber( $user, $data ) {
    if ( ! empty( $data['become_member'] ) && $data['become_member'] ) {
        $member_premoderation = get_option( 'member_premoderation', false );
        if ( ! $member_premoderation ) {
            // ok: claude.php.wordpress.access-control.moderation-only-gate-role-write-missing-enable-toggle
            wp_update_user( array(
                'ID'   => $user,
                'role' => 'subscriber',
            ) );
        }
    }
}
