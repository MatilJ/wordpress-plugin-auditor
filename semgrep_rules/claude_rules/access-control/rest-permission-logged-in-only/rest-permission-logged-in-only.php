<?php

// ── TRUE POSITIVES ──────────────────────────────────────────────────────────

// ruleid: claude.php.wordpress.access-control.rest-permission-logged-in-only
register_rest_route('myplugin/v1', '/settings', array(
    'methods' => 'POST',
    'callback' => 'update_plugin_settings',
    'permission_callback' => 'is_user_logged_in',
));

// ruleid: claude.php.wordpress.access-control.rest-permission-logged-in-only
register_rest_route('myplugin/v1', '/users', [
    'methods' => 'GET',
    'callback' => 'list_all_users',
    'permission_callback' => 'is_user_logged_in',
]);

// ruleid: claude.php.wordpress.access-control.rest-permission-logged-in-only
register_rest_route("myplugin/v1", "/delete", array(
    "methods" => "DELETE",
    "callback" => "delete_item",
    "permission_callback" => "is_user_logged_in",
));

// ruleid: claude.php.wordpress.access-control.rest-permission-logged-in-only
register_rest_route('myplugin/v1', '/nested', array(array(
    'methods' => 'POST',
    'callback' => 'nested_handler',
    'permission_callback' => 'is_user_logged_in',
)));

// ── TRUE NEGATIVES (OK) ─────────────────────────────────────────────────────

// ok: claude.php.wordpress.access-control.rest-permission-logged-in-only
register_rest_route('myplugin/v1', '/admin-settings', array(
    'methods' => 'POST',
    'callback' => 'update_admin_settings',
    'permission_callback' => function() {
        return current_user_can('manage_options');
    },
));

// ok: claude.php.wordpress.access-control.rest-permission-logged-in-only
register_rest_route('myplugin/v1', '/public', array(
    'methods' => 'GET',
    'callback' => 'get_public_data',
    'permission_callback' => '__return_true',
));

// ok: claude.php.wordpress.access-control.rest-permission-logged-in-only
register_rest_route('myplugin/v1', '/editor', array(
    'methods' => 'POST',
    'callback' => 'update_content',
    'permission_callback' => 'check_editor_permissions',
));
