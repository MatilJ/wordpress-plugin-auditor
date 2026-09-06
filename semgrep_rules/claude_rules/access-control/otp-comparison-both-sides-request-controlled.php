<?php

function handle_2fa_submit_inline() {
    if (isset($_POST['submit_code'])) {
        // ruleid: claude.php.wordpress.access-control.otp-comparison-both-sides-request-controlled
        if ($_POST['entered_code'] == $_POST['expected_code']) {
            $user = get_user_by('login', $_POST['log']);
            wp_set_auth_cookie($user->ID, false);
            wp_safe_redirect(admin_url());
            exit;
        }
    }
}

function handle_2fa_submit_assigned() {
    // ruleid: claude.php.wordpress.access-control.otp-comparison-both-sides-request-controlled
    $entered = $_POST['ringcentral_2fa_code'];
    $expected = $_POST['validation_code'];
    if ($entered == $expected) {
        $user = get_user_by('login', $_POST['log']);
        wp_set_current_user($user->ID);
    }
}

// ok: claude.php.wordpress.access-control.otp-comparison-both-sides-request-controlled
function handle_2fa_submit_fixed() {
    $username = $_POST['log'] ?? '';
    $enteredPIN = $_POST['entered_2fa_code'] ?? '';

    $user = get_user_by('login', $username);
    if (!$user) {
        return;
    }

    $sms_sentPIN = get_user_meta($user->ID, 'RingCentral_2fa_user_2fa_code', true);

    if ($enteredPIN == $sms_sentPIN) {
        wp_set_auth_cookie($user->ID, false);
        wp_safe_redirect(admin_url());
        exit;
    }
}

// ok: claude.php.wordpress.access-control.otp-comparison-both-sides-request-controlled
function handle_2fa_submit_transient() {
    $entered_code = sanitize_text_field($_POST['code']);
    $stored_code = get_transient('2fa_code_' . get_current_user_id());
    if (hash_equals((string) $stored_code, $entered_code)) {
        wp_set_auth_cookie(get_current_user_id(), false);
    }
}
