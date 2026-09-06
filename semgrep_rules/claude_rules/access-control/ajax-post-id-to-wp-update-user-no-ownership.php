<?php
// Test file: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// VULNERABLE: $_POST user_id flows to wp_update_user array
function vuln_update_email() {
    check_ajax_referer('my_nonce', 'nonce');
    $user_id = (int) $_POST['user_id'];
    $email = sanitize_email($_POST['email']);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_update_user(array('ID' => $user_id, 'user_email' => $email));
    wp_send_json_success();
}

// VULNERABLE: $_REQUEST user_id flows to wp_update_user with role change
function vuln_update_role() {
    $uid = absint($_REQUEST['uid']);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_update_user(array('ID' => $uid, 'role' => 'administrator'));
}

// VULNERABLE: $_POST user_id flows to wp_set_password
function vuln_reset_password() {
    check_ajax_referer('reset_nonce', 'nonce');
    $user_id = (int) $_POST['user_id'];
    $password = $_POST['new_password'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_set_password($password, $user_id);
    wp_send_json_success();
}

// VULNERABLE: REST request param flows to wp_set_auth_cookie
function vuln_auth_cookie($request) {
    $user_id = $request->get_param('user_id');
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_set_auth_cookie((int) $user_id, true);
}

// VULNERABLE: filter_input flows to wp_update_user
function vuln_filter_input() {
    $user_id = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_update_user(array('ID' => $user_id, 'display_name' => 'hacked'));
}

// VULNERABLE: REST get_json_params flows to wp_set_password
function vuln_rest_json($request) {
    $params = $request->get_json_params();
    $user_id = $params['user_id'];
    $pass = $params['password'];
    // ruleid: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_set_password($pass, $user_id);
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: user_id comes from get_current_user_id() — no tainted source
function safe_update_own_profile() {
    $user_id = get_current_user_id();
    $email = sanitize_email($_POST['email']);
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_update_user(array('ID' => $user_id, 'user_email' => $email));
}

// SAFE: hardcoded user ID — no tainted source
function safe_hardcoded_id() {
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_update_user(array('ID' => 1, 'display_name' => 'Admin'));
}

// SAFE: user_id from DB query — taint broken by server-sourced read
function safe_db_sourced() {
    global $wpdb;
    $user_id = $wpdb->get_var("SELECT user_id FROM {$wpdb->prefix}members WHERE active = 1 LIMIT 1");
    // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
    wp_set_password('newpass123', $user_id);
}

// SAFE: wp_set_auth_cookie with wp_signon return — legitimate login flow
function safe_login_flow() {
    $creds = array(
        'user_login'    => sanitize_user($_POST['username']),
        'user_password' => $_POST['password'],
    );
    $user = wp_signon($creds, false);
    if (!is_wp_error($user)) {
        // ok: claude.php.wordpress.access-control.ajax-post-id-to-wp-update-user-no-ownership
        wp_set_auth_cookie($user->ID, true);
    }
}
