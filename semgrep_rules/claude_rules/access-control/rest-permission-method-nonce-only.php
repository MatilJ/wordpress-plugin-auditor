<?php

class ApiRouteV1
{
    // ruleid: claude.php.wordpress.access-control.rest-permission-method-nonce-only
    public function permissionValidation(WP_REST_Request $request)
    {
        $nonce = $request->get_header('X-WP-Nonce');

        if (! wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_Error('rest_forbidden', 'Invalid Access.', ['status' => 403]);
        }

        return true;
    }
}

class SomeOtherRoute
{
    // ruleid: claude.php.wordpress.access-control.rest-permission-method-nonce-only
    public function checkPermission(WP_REST_Request $request)
    {
        return wp_verify_nonce($request->get_header('X-WP-Nonce'), 'wp_rest');
    }
}

class FixedRoute
{
    // ok: claude.php.wordpress.access-control.rest-permission-method-nonce-only
    public function permissionValidation(WP_REST_Request $request)
    {
        $nonce = $request->get_header('X-WP-Nonce');

        if (! wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_Error('rest_forbidden', 'Invalid Access.', ['status' => 403]);
        }

        if (! current_user_can('manage_options')) {
            return new WP_Error('rest_forbidden', 'Insufficient permissions.', ['status' => 403]);
        }

        return true;
    }
}

class AssignThenReturnRoute
{
    // ruleid: claude.php.wordpress.access-control.rest-permission-method-nonce-only
    public function checkRestNonce($request)
    {
        $nonce = $request->get_header('X-WP-Nonce');
        $restNonce = wp_verify_nonce($nonce, 'wp_rest');
        return $restNonce;
    }
}

class AssignThenFilterThenReturnRoute
{
    // ruleid: claude.php.wordpress.access-control.rest-permission-method-nonce-only
    public function checkRestNonce($request)
    {
        $nonce = $request->get_header('X-WP-Nonce');
        $restNonce = wp_verify_nonce($nonce, 'wp_rest');
        return apply_filters('my_rest_authorized', $restNonce, $request);
    }
}

class AssignThenReturnWithCapRoute
{
    // ok: claude.php.wordpress.access-control.rest-permission-method-nonce-only
    public function checkRestNonce($request)
    {
        if (! current_user_can('edit_posts')) {
            return false;
        }
        $nonce = $request->get_header('X-WP-Nonce');
        $restNonce = wp_verify_nonce($nonce, 'wp_rest');
        return $restNonce;
    }
}

class RouteHandlerBody
{
    // ok: claude.php.wordpress.access-control.rest-permission-method-nonce-only
    public function processRequest(WP_REST_Request $request)
    {
        global $wpdb;

        $nonce = $request->get_header('X-WP-Nonce');

        if (! wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_Error('rest_forbidden', 'Invalid Access.', ['status' => 403]);
        }

        $data = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items");

        return rest_ensure_response($data);
    }
}
