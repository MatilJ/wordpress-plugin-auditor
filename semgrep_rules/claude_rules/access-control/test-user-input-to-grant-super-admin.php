<?php

// ---- TRUE POSITIVES ----

function tp_direct_post_uid() {
    $uid = $_POST['user_id'];
    // ruleid: claude.php.wordpress.access.user-input-to-grant-super-admin
    grant_super_admin($uid);
}

function tp_get_uid() {
    // ruleid: claude.php.wordpress.access.user-input-to-grant-super-admin
    grant_super_admin($_GET['user_id']);
}

function tp_rest_param_uid($request) {
    $uid = $request->get_param('user_id');
    // ruleid: claude.php.wordpress.access.user-input-to-grant-super-admin
    grant_super_admin($uid);
}

// ---- FALSE POSITIVES ----

function ok_hardcoded_uid() {
    // ok: claude.php.wordpress.access.user-input-to-grant-super-admin
    grant_super_admin(1);
}

function ok_current_user() {
    $uid = get_current_user_id();
    // ok: claude.php.wordpress.access.user-input-to-grant-super-admin
    grant_super_admin($uid);
}
