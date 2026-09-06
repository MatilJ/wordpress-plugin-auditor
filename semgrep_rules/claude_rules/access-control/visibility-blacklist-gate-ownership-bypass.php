<?php
// claude.php.wordpress.access-control.visibility-blacklist-gate-ownership-bypass test cases

// ── Vulnerable patterns ─────────────────────────────────────────────────────

// array() literal, unbraced inner if (real shape from the seeding CVE)
function gamipress_ajax_get_logs_vuln() {
    $atts = $_REQUEST;
    // ruleid: claude.php.wordpress.access-control.visibility-blacklist-gate-ownership-bypass
    if ( in_array( $atts['access'], array( 'private', 'both' ) ) ) {
        if ( get_current_user_id() !== absint( $atts['user_id'] ) )
            $atts['access'] = 'public';
    }
    return $atts;
}

// [] literal, braced inner if
function get_activity_entries_vuln( $args ) {
    // ruleid: claude.php.wordpress.access-control.visibility-blacklist-gate-ownership-bypass
    if ( in_array( $args['visibility'], [ 'private', 'members' ] ) ) {
        if ( get_current_user_id() !== intval( $args['owner_id'] ) ) {
            $args['visibility'] = 'public';
        }
    }
    return get_activity_query( $args );
}

// ── Safe patterns ────────────────────────────────────────────────────────────

// ok: claude.php.wordpress.access-control.visibility-blacklist-gate-ownership-bypass
// Correct: default-deny comparison against the single safe value instead of
// enumerating the unsafe ones — this is the real 7.9.5 fix shape.
function gamipress_ajax_get_logs_fixed() {
    $atts = $_REQUEST;
    if ( $atts['access'] !== 'public' ) {
        if ( get_current_user_id() !== absint( $atts['user_id'] ) )
            $atts['access'] = 'public';
    }
    return $atts;
}

// ok: claude.php.wordpress.access-control.visibility-blacklist-gate-ownership-bypass
// No ownership check inside the in_array() branch at all — out of scope for
// this rule (a different / missing-authorization issue, not this variant).
function toggle_display_mode( $args ) {
    if ( in_array( $args['mode'], array( 'compact', 'expanded' ) ) ) {
        $args['mode'] = sanitize_text_field( $args['mode'] );
    }
    return $args;
}
