<?php

// ruleid: claude.php.wordpress.access-control.stored-secret-loose-compare-no-empty-guard
function handle_otp_login_step2($request) {
    $email = $request->get_param('email');
    $otp_code = $request->get_param('otp');

    $user = get_user_by('email', $email);
    if (!$user) {
        return ['errors' => 'no user'];
    }
    $user_id = $user->ID;

    $saved_otp = get_user_meta($user_id, 'uv_otp', true);

    if ($saved_otp != $otp_code) {
        return ['errors' => 'wrong otp'];
    }

    wp_set_current_user($user_id, $user->user_login);
    wp_set_auth_cookie($user_id);
    return ['success' => true];
}

// ruleid: claude.php.wordpress.access-control.stored-secret-loose-compare-no-empty-guard
function handle_magic_link_reversed_order($request) {
    $user_id = (int) $request->get_param('uid');
    $saved_token = get_transient('magic_login_' . $user_id);
    $submitted_token = $_GET['token'];

    if ($submitted_token != $saved_token) {
        return false;
    }

    wp_set_auth_cookie($user_id);
    return true;
}

// ok: claude.php.wordpress.access-control.stored-secret-loose-compare-no-empty-guard
function handle_otp_login_step2_fixed($request) {
    $email = $request->get_param('email');
    $otp_code = $request->get_param('otp');

    $user = get_user_by('email', $email);
    if (!$user) {
        return ['errors' => 'no user'];
    }
    $user_id = $user->ID;

    $saved_otp = get_user_meta($user_id, 'uv_otp', true);

    if (empty($otp_code)) {
        return ['errors' => 'wrong otp'];
    }

    if (empty($saved_otp)) {
        return ['errors' => 'wrong otp'];
    }

    if ($saved_otp != $otp_code) {
        return ['errors' => 'wrong otp'];
    }

    wp_set_current_user($user_id, $user->user_login);
    wp_set_auth_cookie($user_id);
    return ['success' => true];
}

// ok: claude.php.wordpress.access-control.stored-secret-loose-compare-no-empty-guard
function handle_otp_login_hash_equals($request) {
    $email = $request->get_param('email');
    $otp_code = $request->get_param('otp');

    $user = get_user_by('email', $email);
    $user_id = $user->ID;

    $saved_otp = get_user_meta($user_id, 'uv_otp', true);

    if (!hash_equals((string) $saved_otp, (string) $otp_code)) {
        return ['errors' => 'wrong otp'];
    }

    wp_set_current_user($user_id, $user->user_login);
    wp_set_auth_cookie($user_id);
    return ['success' => true];
}
