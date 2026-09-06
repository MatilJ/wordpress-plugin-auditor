<?php
// Test cases for claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
// Confirmed TP source: CVE-2026-42731 (miniorange-otp-verification <= 5.4.9, unauthenticated privesc)
// Extended: session-grant sink (wp_set_auth_cookie()/wp_set_current_user()) variant — a
// third-party verification API response gated only on its own token field, with no check
// that the identity it returned matches the request-controlled account identifier.

// === TRUE POSITIVES — OTP-verified flag + request-resolved user + unguarded credential write ===

// Vulnerable: real pre-fix shape. A generic "OTP verified" transaction flag gates the
// function, but the account written to is resolved from a request-controlled username
// field rather than the identity the OTP was actually issued to — no password recheck.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function complete_otp_login( $post_data ) {
    if ( ! otp_txn_is_validated() ) {
        return;
    }

    $resolve_user = function ( $post_data ) {
        $username = get_session_var( 'login_user' );
        if ( ! $username && isset( $post_data['username'] ) ) {
            $username = $post_data['username'];
        }
        return is_email( $username ) ? get_user_by( 'email', $username ) : get_user_by( 'login', $username );
    };

    $user  = $resolve_user( $post_data );
    $phone = get_session_var( 'phone_number' );
    update_user_meta( $user->data->ID, 'account_phone', $phone );
    wp_set_auth_cookie( $user->data->ID, true );
}

// Vulnerable: same class using add_user_meta() for first-time enrollment and a flat
// (non-closure) resolution of the target account straight from $_POST.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function otp_enroll_and_login() {
    if ( ! otp_txn_is_validated() ) {
        return;
    }
    $login = sanitize_text_field( $_POST['login'] );
    $user  = get_user_by( 'login', $login );
    add_user_meta( $user->data->ID, 'backup_phone', sanitize_text_field( $_POST['phone'] ) );
    wp_set_auth_cookie( $user->data->ID, true );
}

// === FALSE POSITIVES ===

// Safe (the actual fix): an explicit ownership gate exits the request before the
// account is resolved from request data and the credential is written.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function complete_otp_login_fixed( $post_data ) {
    if ( ! otp_txn_is_validated() ) {
        return;
    }

    if ( (string) get_session_var( 'enrollment_ownership_ok' ) !== '1' ) {
        wp_die( 'Please sign in with your password first.', 'Login error', array( 'response' => 403 ) );
    }

    $resolve_user = function ( $post_data ) {
        $username = get_session_var( 'login_user' );
        if ( ! $username && isset( $post_data['username'] ) ) {
            $username = $post_data['username'];
        }
        return is_email( $username ) ? get_user_by( 'email', $username ) : get_user_by( 'login', $username );
    };

    $user  = $resolve_user( $post_data );
    $phone = get_session_var( 'phone_number' );
    update_user_meta( $user->data->ID, 'account_phone', $phone );
    wp_set_auth_cookie( $user->data->ID, true );
}

// Safe: the account's password is explicitly re-verified before the credential
// write and login grant — ownership of the target account is actually proven.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function otp_enroll_and_login_password_checked() {
    if ( ! otp_txn_is_validated() ) {
        return;
    }
    $login    = sanitize_text_field( $_POST['login'] );
    $password = isset( $_POST['password'] ) ? (string) $_POST['password'] : '';
    $user     = get_user_by( 'login', $login );
    if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
        wp_die( 'Invalid credentials.' );
    }
    add_user_meta( $user->data->ID, 'backup_phone', sanitize_text_field( $_POST['phone'] ) );
    wp_set_auth_cookie( $user->data->ID, true );
}

// Safe: ordinary read-only lookup used for display — no credential write follows,
// so this is not the account-takeover write/login sequence the rule targets.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function show_profile_snippet( $username ) {
    $user = get_user_by( 'login', $username );
    if ( ! $user ) {
        return '';
    }
    return esc_html( $user->display_name );
}

// === TRUE POSITIVES — third-party verification response gated on its own token
// field only, granting a live session to a request-resolved account ===

// Vulnerable: real pre-fix shape. A third-party OTP-provider response is only checked
// for the presence of its own token field ("idToken") — never compared against the
// phone/identifier used to resolve which account gets logged in.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function complete_phone_verification( $account_id ) {
    $response = verify_with_identity_provider( $_GET['verificationId'], $_GET['code'] );

    if ( empty( $response ) || isset( $response->error ) || ! isset( $response->idToken ) ) {
        wp_send_json( array( 'success' => false, 'message' => 'verification failed' ) );
    } else {
        $user = get_user_by( 'ID', $account_id );
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID, true );
        wp_send_json( array( 'success' => true ) );
    }
}

// Vulnerable: same class, session granted with wp_set_current_user() alone (no
// wp_set_auth_cookie()) — still logs the visitor in as the resolved account.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function complete_email_verification( $requested_user_id ) {
    $response = verify_with_identity_provider( $_GET['sessionInfo'], $_GET['code'] );

    if ( empty( $response ) || isset( $response->error ) || ! isset( $response->idToken ) ) {
        wp_send_json( array( 'success' => false, 'message' => 'verification failed' ) );
    } else {
        $user = get_user_by( 'ID', $requested_user_id );
        wp_set_current_user( $user->ID );
        wp_send_json( array( 'success' => true ) );
    }
}

// === FALSE POSITIVES ===

// Safe (the actual fix): the identity field the response itself returned is
// compared against the requested identifier before the account is resolved.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function complete_phone_verification_fixed( $account_id, $requested_phone ) {
    $response = verify_with_identity_provider( $_GET['verificationId'], $_GET['code'] );

    if ( empty( $response ) || isset( $response->error ) || ! isset( $response->idToken ) ) {
        wp_send_json( array( 'success' => false, 'message' => 'verification failed' ) );
    } else {
        $verified_phone = isset( $response->phoneNumber ) ? ltrim( $response->phoneNumber, '+' ) : '';
        if ( $verified_phone !== $requested_phone ) {
            wp_send_json( array( 'success' => false, 'message' => 'phone mismatch' ) );
        }

        $user = get_user_by( 'ID', $account_id );
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID, true );
        wp_send_json( array( 'success' => true ) );
    }
}

// Safe: the response's own identity field is compared via a timing-safe exact
// match before the account resolved from the request is granted a session.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function complete_email_verification_hash_checked( $requested_user_id, $requested_email ) {
    $response = verify_with_identity_provider( $_GET['sessionInfo'], $_GET['code'] );

    if ( empty( $response ) || isset( $response->error ) || ! isset( $response->idToken ) ) {
        wp_send_json( array( 'success' => false, 'message' => 'verification failed' ) );
    } else {
        if ( ! hash_equals( $response->email, $requested_email ) ) {
            wp_send_json( array( 'success' => false, 'message' => 'email mismatch' ) );
        }

        $user = get_user_by( 'ID', $requested_user_id );
        wp_set_current_user( $user->ID );
        wp_send_json( array( 'success' => true ) );
    }
}

// === TRUE POSITIVES — local OTP/token validator reads its own prior-challenge
// state back from $_SESSION but never binds that state to the caller-supplied
// identifier at verification time ===

// Vulnerable: real pre-fix shape. The transaction id is a hash of a static,
// site-wide secret plus the OTP value — self-consistent, but never checked
// against which identifier the OTP was actually sent to.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function validate_login_otp_token( $transactionId, $otpToken ) {
    start_verification_session();
    $siteSecret = get_option( 'my_plugin_site_secret' );
    if ( $_SESSION['otp_pending'] ) {
        $pass = check_transaction_id( $siteSecret, $otpToken, $transactionId );
        if ( $pass ) {
            $result = array( 'status' => 'SUCCESS' );
        } else {
            $result = array( 'status' => 'FAILURE' );
        }
        unset( $_SESSION['otp_pending'] );
    } else {
        $result = array( 'status' => 'FAILURE' );
    }
    return $result;
}

// Vulnerable: same class — a 2FA transaction check reads its own session-
// stored pending flag but the success branch never re-binds the code to the
// identifier the caller is now asserting.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function verify_2fa_transaction( $code, $transactionId ) {
    start_verification_session();
    $siteSecret = get_option( 'my_plugin_mfa_secret' );
    if ( $_SESSION['mfa_pending'] ) {
        $pass = check_mfa_signature( $siteSecret, $code, $transactionId );
        if ( $pass ) {
            $result = array( 'status' => 'SUCCESS' );
        } else {
            $result = array( 'status' => 'FAILURE' );
        }
    } else {
        $result = array( 'status' => 'FAILURE' );
    }
    return $result;
}

// === FALSE POSITIVES ===

// Safe (the actual fix): the validator takes the caller's asserted identifier
// as a parameter and requires it to match the identifier the challenge was
// actually issued for, stored server-side, before accepting the code.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function validate_login_otp_token_fixed( $otpToken, $email ) {
    start_verification_session();
    if ( empty( $_SESSION['otp_pending'] ) || ! isset( $_SESSION['otp_value'] ) || ! isset( $_SESSION['otp_email'] ) ) {
        return array( 'status' => 'FAILURE' );
    }
    $email_ok = hash_equals( $_SESSION['otp_email'], sanitize_email( $email ) );
    $otp_ok   = $email_ok && hash_equals( $_SESSION['otp_value'], (string) $otpToken );
    if ( $otp_ok ) {
        return array( 'status' => 'SUCCESS' );
    }
    return array( 'status' => 'FAILURE' );
}

// Safe: an ordinary WP option/meta read used to build a display value — no
// session-based OTP challenge state and no identity decision involved.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function get_otp_notice_text( $user_id ) {
    $custom_notice = get_option( 'otp_notice_text' );
    $display_name  = get_user_meta( $user_id, 'display_name', true );
    return sprintf( '%s: %s', $display_name, $custom_notice );
}

// === TRUE POSITIVES — get_users() meta-value lookup on a request-controlled
// identifier grants a live session with no in-function code/OTP check ===

// Vulnerable: real pre-fix shape. A generic multi-purpose form validator's
// boolean result is trusted as proof an SMS/OTP code was checked for this
// phone number — no dedicated code-verification routine is ever called here.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function ajax_phone_login() {
    $phone = sanitize_text_field( wp_unslash( $_POST['user_phone'] ) );
    $res   = generic_form_validate( array( 'result' => 1 ), 'login_nonce', 'login_items' );

    if ( $res['result'] == 1 ) {
        $args  = array( 'meta_key' => 'mobile_phone', 'meta_value' => $phone );
        $users = get_users( $args );
        if ( $users && $users[0]->ID ) {
            $user = $users[0];
            wp_set_auth_cookie( $user->ID, true );
            wp_set_current_user( $user->ID );
        }
    }
}

// Vulnerable: same class, session granted with wp_set_current_user() alone.
// ruleid: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function ajax_email_login() {
    $email = sanitize_email( wp_unslash( $_POST['user_email'] ) );
    $args  = array( 'meta_key' => 'alt_email', 'meta_value' => $email );
    $users = get_users( $args );
    if ( $users && $users[0]->ID ) {
        $user = $users[0];
        wp_set_current_user( $user->ID );
    }
}

// === FALSE POSITIVES ===

// Safe (the actual fix): the handler directly calls a dedicated code-check
// routine against the same identifier before the session is granted.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function ajax_phone_login_fixed() {
    $phone = sanitize_text_field( wp_unslash( $_POST['user_phone'] ) );
    if ( $phone === '' || ! isset( $_POST['sms_code'] ) || ! check_sms_code( $phone, sanitize_text_field( $_POST['sms_code'] ) ) ) {
        return;
    }
    $args  = array( 'meta_key' => 'mobile_phone', 'meta_value' => $phone );
    $users = get_users( $args );
    if ( $users && $users[0]->ID ) {
        $user = $users[0];
        wp_set_auth_cookie( $user->ID, true );
        wp_set_current_user( $user->ID );
    }
}

// Safe: the lookup result is only used for a read-only listing, no session
// is granted from it.
// ok: claude.php.wordpress.access-control.otp-verified-flag-binds-request-controlled-user
function list_users_by_phone_prefix( $prefix ) {
    $args  = array( 'meta_key' => 'mobile_phone', 'meta_value' => $prefix, 'meta_compare' => 'LIKE' );
    $users = get_users( $args );
    if ( $users && $users[0]->ID ) {
        $user = $users[0];
        return esc_html( $user->display_name );
    }
    return '';
}
