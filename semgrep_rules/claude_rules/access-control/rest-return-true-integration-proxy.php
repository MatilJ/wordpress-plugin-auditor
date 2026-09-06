<?php
// Test cases: claude.php.wordpress.access-control.rest-return-true-integration-proxy

// ---- Vulnerable patterns ----

// Vulnerable: array() syntax, provider keyword in route path, GET method.
class Marketing_Integration_Routes_A {
    public function register_routes() {
        // ruleid: claude.php.wordpress.access-control.rest-return-true-integration-proxy
        register_rest_route(
            'myplugin/v1',
            '/mailchimp/get/lists',
            array(
                'methods' => 'GET',
                'callback' => array( $this, 'get_lists' ),
                'permission_callback' => '__return_true',
            )
        );
    }

    public function get_lists() {
        $settings = get_option( 'myplugin_settings_list' );
        $api_key  = !empty( $settings ) ? $settings['mailchimp']['fields']['api_key']['value'] : '';
        $response = wp_remote_get( 'https://example.api.mailchimp.com/3.0/lists', array(
            'headers' => array( 'Authorization' => 'apikey ' . $api_key ),
        ) );
        return json_decode( $response['body'], true );
    }
}

// Vulnerable: short-array syntax, provider keyword only in the callback name,
// READABLE constant instead of the 'GET' string.
class Marketing_Integration_Routes_B {
    public function register_routes() {
        // ruleid: claude.php.wordpress.access-control.rest-return-true-integration-proxy
        register_rest_route(
            'myplugin/v1',
            '/lists',
            [
                'methods' => \WP_REST_Server::READABLE,
                'callback' => [ $this, 'sendgrid_get_contacts' ],
                'permission_callback' => '__return_true',
            ]
        );
    }
}

// ---- Safe patterns ----

// Safe: the fix — a real capability check replaces the literal '__return_true'.
// ok: claude.php.wordpress.access-control.rest-return-true-integration-proxy
class Marketing_Integration_Routes_Fixed {
    public function register_routes() {
        register_rest_route(
            'myplugin/v1',
            '/mailchimp/get/lists',
            array(
                'methods' => 'GET',
                'callback' => array( $this, 'get_lists' ),
                'permission_callback' => array( $this, 'editor_permission_check' ),
            )
        );
    }

    public function editor_permission_check() {
        return current_user_can( 'edit_posts' );
    }
}

// Safe: '__return_true' on a GET route, but no third-party integration
// naming — a public content listing, not a credential-proxy route.
// ok: claude.php.wordpress.access-control.rest-return-true-integration-proxy
class Public_Listing_Routes {
    public function register_routes() {
        register_rest_route(
            'myplugin/v1',
            '/products',
            array(
                'methods' => 'GET',
                'callback' => array( $this, 'get_products' ),
                'permission_callback' => '__return_true',
            )
        );
    }
}

// Safe: POST-only public form submission on the same integration namespace —
// intentionally unauthenticated, no account data returned.
// ok: claude.php.wordpress.access-control.rest-return-true-integration-proxy
class Marketing_Integration_Form_Submit {
    public function register_routes() {
        register_rest_route(
            'myplugin/v1',
            '/mailchimp/post/form',
            array(
                'methods' => 'POST',
                'callback' => array( $this, 'submit_form' ),
                'permission_callback' => '__return_true',
            )
        );
    }
}
