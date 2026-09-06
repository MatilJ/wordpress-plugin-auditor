<?php

// ---- TRUE POSITIVES ----

function tp_direct_post_cap($user) {
    // ruleid: claude.php.wordpress.access.user-input-to-add-cap
    $user->add_cap($_POST['capability']);
}

function tp_variable_cap() {
    $cap = $_REQUEST['cap'];
    $user = wp_get_current_user();
    // ruleid: claude.php.wordpress.access.user-input-to-add-cap
    $user->add_cap($cap);
}

function tp_rest_param_cap($request) {
    $cap = $request->get_param('capability');
    $user = get_user_by('id', $request->get_param('user_id'));
    // ruleid: claude.php.wordpress.access.user-input-to-add-cap
    $user->add_cap($cap, true);
}

// ---- FALSE POSITIVES ----

function ok_hardcoded_cap($user) {
    // ok: claude.php.wordpress.access.user-input-to-add-cap
    $user->add_cap('read');
}

function ok_hardcoded_manage($user) {
    // ok: claude.php.wordpress.access.user-input-to-add-cap
    $user->add_cap('manage_options');
}
