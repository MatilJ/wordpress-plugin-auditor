<?php
// Test cases for claude.php.wordpress.access-control.rest-shared-permission-callback-credential-route
// Seeded by CVE-2026-39583 (Datalogics Ecommerce Delivery <= 2.6.62, unauthenticated
// privilege escalation): the /update-token/ route (writes the plugin's shared secret
// via update_option()) reused the same generic permission_callback as every other
// route, and that callback authenticates by comparing input to get_option() of the
// same secret — empty by default on a fresh install.

// === TRUE POSITIVES — credential-writing route shares its permission_callback
// with another, unrelated route ===

// Vulnerable: array() syntax, credential route registered last, shared callback
// also gates an unrelated settings route (real pre-fix shape).
function acme_register_routes() {
    // ruleid: claude.php.wordpress.access-control.rest-shared-permission-callback-credential-route
    register_rest_route('acme/v1', '/update-settings/', array(
        'methods'  => 'POST',
        'callback' => 'acme_update_settings',
        'permission_callback' => 'acme_permission_check',
    ));

    register_rest_route('acme/v1', '/update-token/', array(
        'methods'  => 'POST',
        'callback' => 'acme_update_token',
        'permission_callback' => 'acme_permission_check',
    ));
}
add_action('rest_api_init', 'acme_register_routes');

function acme_update_token(WP_REST_Request $request) {
    $token = $request->get_param('token');
    if (empty($token)) {
        return new WP_Error('no_token', 'Token missing', array('status' => 400));
    }
    update_option('acme_api_token', sanitize_text_field($token));
    return new WP_REST_Response(array('success' => true), 200);
}

function acme_permission_check(WP_REST_Request $request) {
    $token = $request->get_param('token');
    $valid = get_option('acme_api_token', '');
    return $token === $valid;
}

// Vulnerable: bracket [] array syntax, credential route registered first.
function widget_register_routes() {
    // ruleid: claude.php.wordpress.access-control.rest-shared-permission-callback-credential-route
    register_rest_route('widget/v1', '/set-api-key/', [
        'methods'  => 'POST',
        'callback' => 'widget_set_api_key',
        'permission_callback' => 'widget_check_auth',
    ]);

    register_rest_route('widget/v1', '/sync-orders/', [
        'methods'  => 'POST',
        'callback' => 'widget_sync_orders',
        'permission_callback' => 'widget_check_auth',
    ]);
}

// === FALSE POSITIVES ===

// Safe (the real fix): credential route gets its own dedicated permission_callback,
// no longer shared with the other route.
function acme_register_routes_fixed() {
    // ok: claude.php.wordpress.access-control.rest-shared-permission-callback-credential-route
    register_rest_route('acme/v1', '/update-settings/', array(
        'methods'  => 'POST',
        'callback' => 'acme_update_settings',
        'permission_callback' => 'acme_permission_check',
    ));

    register_rest_route('acme/v1', '/update-token/', array(
        'methods'  => 'POST',
        'callback' => 'acme_update_token',
        'permission_callback' => 'acme_permission_check_update_token',
    ));
}

// Safe: the same permission_callback is shared, but neither route sets a
// token/secret/credential — ordinary admin-gated write endpoints.
function acme_register_other_routes() {
    // ok: claude.php.wordpress.access-control.rest-shared-permission-callback-credential-route
    register_rest_route('acme/v1', '/sync-orders/', array(
        'methods'  => 'POST',
        'callback' => 'acme_sync_orders',
        'permission_callback' => 'acme_permission_check',
    ));

    register_rest_route('acme/v1', '/update-shipping-status/', array(
        'methods'  => 'POST',
        'callback' => 'acme_update_shipping_status',
        'permission_callback' => 'acme_permission_check',
    ));
}

// Safe: only one route registered — no reuse across routes to speak of.
function acme_register_single_route() {
    // ok: claude.php.wordpress.access-control.rest-shared-permission-callback-credential-route
    register_rest_route('acme/v1', '/update-token/', array(
        'methods'  => 'POST',
        'callback' => 'acme_update_token',
        'permission_callback' => 'acme_require_manage_options',
    ));
}
