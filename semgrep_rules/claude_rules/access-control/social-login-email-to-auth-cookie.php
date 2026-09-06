<?php
// Test cases for claude.php.wordpress.access-control.social-login-email-to-auth-cookie
// Confirmed TP sources: CVE-2024-7781, CVE-2025-34077, CVE-2025-7444

// === TRUE POSITIVES — get_user_by('email') → wp_set_auth_cookie() without token verification ===

// Vulnerable: looks up user by email from POST data and sets auth cookie — no provider verification
// ruleid: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
function handle_social_login_no_verify() {
    $email = sanitize_email( $_POST['email'] );
    $token = sanitize_text_field( $_POST['access_token'] );

    // No server-side verification of the token against the OAuth provider
    $user = get_user_by( "email", $email );
    if ( $user ) {
        wp_set_auth_cookie( $user->ID, true );
        wp_redirect( home_url() );
        exit;
    }
}

// Vulnerable: REST endpoint that trusts email from request body
// ruleid: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
function rest_social_auth_callback( $request ) {
    $email = sanitize_email( $request->get_param( 'email' ) );
    $provider = sanitize_text_field( $request->get_param( 'provider' ) );

    $user = get_user_by( "email", $email );
    if ( $user ) {
        wp_set_auth_cookie( $user->ID );
        return new WP_REST_Response( array( 'success' => true ), 200 );
    }
    return new WP_Error( 'no_user', 'User not found' );
}

// === FALSE POSITIVES — token verified via wp_remote_get/wp_remote_post ===

// Safe: verifies token with Google before looking up user by email
// ok: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
function handle_google_login_verified() {
    $token = sanitize_text_field( $_POST['id_token'] );

    // Verify the token against Google's endpoint
    $response = wp_remote_get( 'https://oauth2.googleapis.com/tokeninfo?id_token=' . $token );
    $body = json_decode( wp_remote_retrieve_body( $response ), true );
    $email = sanitize_email( $body['email'] );

    $user = get_user_by( "email", $email );
    if ( $user ) {
        wp_set_auth_cookie( $user->ID, true );
        wp_redirect( home_url() );
        exit;
    }
}

// Safe: verifies token with Facebook via wp_remote_post before user lookup
// ok: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
function handle_facebook_login_verified() {
    $access_token = sanitize_text_field( $_POST['access_token'] );

    $response = wp_remote_post( 'https://graph.facebook.com/me', array(
        'body' => array( 'access_token' => $access_token, 'fields' => 'email' ),
    ) );
    $body = json_decode( wp_remote_retrieve_body( $response ), true );
    $email = sanitize_email( $body['email'] );

    $user = get_user_by( "email", $email );
    if ( $user ) {
        wp_set_auth_cookie( $user->ID );
        return true;
    }
    return false;
}

// Safe: verifies token via wp_remote_get between user lookup and cookie setting
// ok: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
function handle_oauth_verified_between() {
    $email = sanitize_email( $_POST['email'] );
    $token = sanitize_text_field( $_POST['token'] );

    $user = get_user_by( "email", $email );
    if ( ! $user ) {
        return false;
    }

    // Verify token after lookup but before auth
    $verify = wp_remote_get( 'https://provider.example.com/verify?token=' . $token );
    $result = json_decode( wp_remote_retrieve_body( $verify ), true );
    if ( empty( $result['valid'] ) ) {
        return false;
    }

    wp_set_auth_cookie( $user->ID, true );
    return true;
}

// === TRUE POSITIVES (class variant) — lookup and cookie-set split across two methods ===

// Vulnerable: a "find member" method matches by email and stashes the user on
// $this, a separate "login" method sets the auth cookie from that property —
// no provider-token verification anywhere in the class.
// ruleid: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
class Social_Login_Handler {
    private $user;

    public function is_member( string $email ): bool {
        $this->user = get_user_by( "email", $email );
        return (bool) $this->user;
    }

    public function login(): void {
        if ( ! is_user_logged_in() ) {
            wp_set_auth_cookie( $this->user->ID, true );
        }
    }
}

// Vulnerable: same split-method shape, oauth callback wiring calls both.
// ruleid: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
class Line_Oauth_User {
    private $matched_user;

    public function find_by_provider_email( string $provider_email ): bool {
        $this->matched_user = get_user_by( "email", $provider_email );
        return ! empty( $this->matched_user );
    }

    public function complete_login( string $raw_id ): void {
        wp_clear_auth_cookie();
        wp_set_current_user( $this->matched_user->ID );
        wp_set_auth_cookie( $this->matched_user->ID, true );
    }
}

// === FALSE POSITIVES (class variant) — token verified somewhere in the class ===

// Safe: the class verifies the id_token against the provider (wp_remote_post)
// in a helper method before the email lookup is ever trusted.
// ok: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
class Verified_Social_Login_Handler {
    private $user;

    private function verify_token( string $token ): array {
        $response = wp_remote_post( 'https://provider.example.com/oauth2/verify', array( 'body' => array( 'token' => $token ) ) );
        return json_decode( wp_remote_retrieve_body( $response ), true );
    }

    public function is_member( string $email ): bool {
        $this->user = get_user_by( "email", $email );
        return (bool) $this->user;
    }

    public function login(): void {
        if ( ! is_user_logged_in() ) {
            wp_set_auth_cookie( $this->user->ID, true );
        }
    }
}

// Safe: identity is looked up by a stable provider id stored in user meta,
// not by trusting the email claim directly.
// ok: claude.php.wordpress.access-control.social-login-email-to-auth-cookie
class Meta_Keyed_Login_Handler {
    private $user;

    public function is_member( string $provider_raw_id ): bool {
        $query = new WP_User_Query( array( 'meta_key' => 'provider_user_id', 'meta_value' => $provider_raw_id ) );
        $results = $query->get_results();
        $this->user = $results ? $results[0] : false;
        return (bool) $this->user;
    }

    public function login(): void {
        if ( ! is_user_logged_in() ) {
            wp_set_auth_cookie( $this->user->ID, true );
        }
    }
}
