<?php

function plugin_create_roles() {
    global $wp_roles;

    if (!isset($wp_roles)) {
        $wp_roles = new WP_Roles();
    }

    add_role('member_user', 'Member', array('read' => false));

    $capabilities = array('manage_member_plugin');

    foreach ($capabilities as $cap) {
        // ruleid: claude.php.wordpress.access-control.custom-role-admin-capability-parity
        $wp_roles->add_cap('member_user', $cap);
        $wp_roles->add_cap('administrator', $cap);
    }
}

function plugin_setup_roles_via_objects() {
    add_role('affiliate_user', 'Affiliate', array('read' => false));

    // ruleid: claude.php.wordpress.access-control.custom-role-admin-capability-parity
    get_role('administrator')->add_cap('manage_affiliate');
    get_role('affiliate_user')->add_cap('manage_affiliate');
}

// ok: claude.php.wordpress.access-control.custom-role-admin-capability-parity
function plugin_create_roles_fixed() {
    global $wp_roles;

    if (!isset($wp_roles)) {
        $wp_roles = new WP_Roles();
    }

    add_role('member_user', 'Member', array('read' => false));

    $role = get_role('administrator');
    if ($role && !$role->has_cap('manage_member_plugin')) {
        $role->add_cap('manage_member_plugin');
    }
}

// ok: claude.php.wordpress.access-control.custom-role-admin-capability-parity
function plugin_grants_custom_role_only_no_admin_parity() {
    add_role('subscriber_plus', 'Subscriber Plus', array('read' => true));

    global $wp_roles;
    $wp_roles->add_cap('subscriber_plus', 'view_own_reports');
}
