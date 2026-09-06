<?php

// ---- TRUE POSITIVES ----

function tp_direct_post_uid() {
    $uid = $_POST['user_id'];
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie($uid);
}

function tp_get_uid() {
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie($_GET['uid'], true);
}

function tp_rest_param_uid($request) {
    $user_id = $request->get_param('user_id');
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie($user_id, false, '', '');
}

function tp_request_uid() {
    $uid = intval($_REQUEST['user_id']);
    // ruleid: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie($uid);
}

function tp_session_fallback_raw_source_no_comparison() {
    // A bare isset()/non-empty check on a $_SESSION slot that is itself the
    // exact value later passed to the sink — not a comparison against any
    // independently-resolved identifier. The slot is just an alternate
    // attacker-writable fallback source, not a verification.
    if ( isset( $_COOKIE['switch_user_id'] ) && '' !== $_COOKIE['switch_user_id'] ) {
        $user_id = absint( $_COOKIE['switch_user_id'] );
    } elseif ( isset( $_SESSION['switch_user_id'] ) && '' !== $_SESSION['switch_user_id'] ) {
        $user_id = absint( $_SESSION['switch_user_id'] );
    }

    if ( isset( $user_id ) ) {
        // ruleid: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
        wp_set_auth_cookie( $user_id, true, is_ssl() );
    }
}

function tp_record_lookup_no_ownership_check( $record_id = null ) {
    if ( ! empty( $_GET['record_id'] ) )
        $record_id = absint( $_GET['record_id'] );

    if ( empty( $record_id ) )
        return;

    // A request-supplied id resolves a domain record; its own user_id field
    // reaches the sink with no check that the requester actually owns it.
    $record = get_record_by_id( $record_id );

    if ( ! empty( $record->user_id ) )
        // ruleid: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
        wp_set_auth_cookie( $record->user_id );
}

function tp_skippable_empty_guarded_mismatch_check() {
    // The real pre-fix shape (CVE-2026-15014, sms-alert <= 3.9.7): the
    // mismatch-reject is gated behind !empty() on the session comparison
    // value, so when that value is unset (e.g. a DIFFERENT, unrelated flow
    // set the shared "verified" flag) the whole check is skipped instead of
    // failing closed.
    if ( isset( $_SESSION['mobile_verified'] ) ) {
        $phone = sanitize_text_field( wp_unslash( $_REQUEST['billing_phone'] ) );
        if ( ! empty( $_SESSION['verified_mobile'] ) && strpos( $_SESSION['verified_mobile'], $phone ) === false ) {
            return;
        }
        $user_info = get_user_by_phone( $phone );
        if ( $user_info ) {
            // ruleid: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
            wp_set_auth_cookie( $user_info->ID );
        }
    }
}

// ---- FALSE POSITIVES ----

function ok_current_user() {
    $uid = get_current_user_id();
    // ok: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie($uid);
}

function ok_signon_flow() {
    $user = wp_signon(['user_login' => 'admin', 'user_password' => 'pass']);
    // ok: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie($user->ID);
}

function ok_hardcoded_uid() {
    // ok: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie(1);
}

function ok_transient_bound_record( $record_id = null ) {
    if ( ! empty( $_GET['record_id'] ) )
        $record_id = absint( $_GET['record_id'] );

    if ( empty( $record_id ) )
        return;

    // Guarded by a value stored server-side when the flow was first
    // initiated, not supplied by the current request — binds the resolved
    // record to the party that actually started it.
    if ( false !== ( $flow_data = get_transient( 'flow_' . $record_id ) ) ) {
        $record = get_record_by_id( $record_id );

        if ( ! empty( $record->user_id ) && ! empty( $flow_data['user_id'] ) && $record->user_id == $flow_data['user_id'] ) {
            // ok: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
            wp_set_auth_cookie( $record->user_id );
        }
    }
}

function ok_strict_mismatch_rejects() {
    // The actual fix shape (sms-alert 3.9.8): an unconditional strict
    // inequality check rejects on mismatch instead of being skippable.
    $phone = sanitize_text_field( wp_unslash( $_REQUEST['billing_phone'] ) );
    if ( $phone !== $_SESSION['verified_mobile'] ) {
        wp_send_json_error( 'mismatch' );
        exit();
    }
    $user_info = get_user_by_phone( $phone );
    // ok: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie( $user_info->ID );
}

function ok_loose_mismatch_rejects() {
    $phone = sanitize_text_field( wp_unslash( $_REQUEST['billing_phone'] ) );
    if ( $_SESSION['verified_mobile'] != $phone ) {
        return;
    }
    $user_info = get_user_by_phone( $phone );
    // ok: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
    wp_set_auth_cookie( $user_info->ID );
}

function ok_session_bound_record( $record_id = null ) {
    if ( ! empty( $_GET['record_id'] ) )
        $record_id = absint( $_GET['record_id'] );

    if ( empty( $record_id ) )
        return;

    $record = get_record_by_id( $record_id );

    if ( ! empty( $_SESSION['owner_id'] ) && ! empty( $record->user_id ) && $record->user_id == $_SESSION['owner_id'] ) {
        // ok: claude.php.wordpress.access.user-input-to-wp-set-auth-cookie
        wp_set_auth_cookie( $record->user_id );
    }
}
