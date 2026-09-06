<?php
// Test cases for claude.php.wordpress.access-control.recovery-code-validation-skipped-in-sink-branch

// Real-world pre-fix shape (CVE-2025-31095): the validator call lives ONLY in
// the sibling "else" branch (no new_password supplied). Supplying vCode +
// new_password together in one request reaches the sink with zero validation.
function amd_reset_password_vulnerable( $data ) {
    $user = amd_get_user_by_email( $data["email"] );
    $vCode = $data["vcode"] ?? "";
    $new_password = $data["new_password"] ?? "";

    // ruleid: claude.php.wordpress.access-control.recovery-code-validation-skipped-in-sink-branch
    if ( !empty( $vCode ) ) {
        if ( !empty( $new_password ) ) {
            if ( strlen( $new_password ) < 8 )
                wp_send_json_error( [ "msg" => "Password must contain at least 8 characters" ] );
            $success = amd_change_password( $user->ID, $new_password, true );
            if ( $success )
                wp_send_json_success( [ "msg" => "Your password has been changed" ] );
        } else {
            $valid = amd_is_verification_code_valid( $user->ID, $vCode );
            if ( !$valid )
                wp_send_json_error( [ "msg" => "Entered verification code is not correct or has been expired" ] );
            wp_send_json_success( [ "msg" => "Please enter your new password" ] );
        }
    }
}

// Same class, different sink/validator naming, no intermediate else branch at all.
function custom_recovery_reset_password( $request ) {
    $user_id = resolve_account_by_phone( $request["phone"] );
    $code = $request["recovery_code"] ?? "";
    $new_pass = $request["new_pass"] ?? "";

    // ruleid: claude.php.wordpress.access-control.recovery-code-validation-skipped-in-sink-branch
    if ( !empty( $code ) ) {
        if ( !empty( $new_pass ) ) {
            update_password_for_user( $user_id, $new_pass, true );
            wp_send_json_success( [ "msg" => "done" ] );
        }
    }
}

// Real-world FIX shape (1.4.6): validator call hoisted to run unconditionally
// once the code is present, BEFORE branching on whether new_password exists.
function amd_reset_password_fixed( $data ) {
    $user = amd_get_user_by_email( $data["email"] );
    $vCode = $data["vcode"] ?? "";
    $new_password = $data["new_password"] ?? "";

    // ok: claude.php.wordpress.access-control.recovery-code-validation-skipped-in-sink-branch
    if ( !empty( $vCode ) ) {
        $valid = amd_is_verification_code_valid( $user->ID, $vCode );

        if ( !$valid )
            wp_send_json_error( [ "msg" => "Entered verification code is not correct or has been expired" ] );

        if ( !empty( $new_password ) ) {
            if ( strlen( $new_password ) < 8 )
                wp_send_json_error( [ "msg" => "Password must contain at least 8 characters" ] );
            $success = amd_change_password( $user->ID, $new_password, true );
            if ( $success )
                wp_send_json_success( [ "msg" => "Your password has been changed" ] );
        } else {
            wp_send_json_success( [ "msg" => "Please enter your new password" ] );
        }
    }
}

// Alternative secure ordering: validator called inline, inside the mutating
// branch itself, before the sink.
function custom_recovery_reset_password_inline_check( $request ) {
    $user_id = resolve_account_by_phone( $request["phone"] );
    $code = $request["recovery_code"] ?? "";
    $new_pass = $request["new_pass"] ?? "";

    // ok: claude.php.wordpress.access-control.recovery-code-validation-skipped-in-sink-branch
    if ( !empty( $code ) ) {
        if ( !empty( $new_pass ) ) {
            $valid = is_recovery_code_valid( $user_id, $code );
            if ( !$valid )
                wp_send_json_error( [ "msg" => "invalid code" ] );
            update_password_for_user( $user_id, $new_pass, true );
            wp_send_json_success( [ "msg" => "done" ] );
        }
    }
}

// Standard WP core reset flow — not this pattern at all (no custom sink name match).
// ok: claude.php.wordpress.access-control.recovery-code-validation-skipped-in-sink-branch
function wp_core_style_reset( $key, $login, $new_password ) {
    $user = check_password_reset_key( $key, $login );
    if ( is_wp_error( $user ) )
        wp_send_json_error( [ "msg" => "invalid key" ] );
    reset_password( $user, $new_password );
    wp_send_json_success( [ "msg" => "done" ] );
}

// Self-service authenticated change of own password — not a recovery flow.
function amd_account_settings_change_own_password( $data ) {
    $vCode = $data["vcode"] ?? "";
    $new_password = $data["new_password"] ?? "";

    // ok: claude.php.wordpress.access-control.recovery-code-validation-skipped-in-sink-branch
    if ( !empty( $vCode ) ) {
        if ( !empty( $new_password ) ) {
            amd_change_password( get_current_user_id(), $new_password, true );
            wp_send_json_success( [ "msg" => "done" ] );
        }
    }
}
