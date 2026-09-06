<?php
// Test cases for claude.php.wordpress.access-control.conditional-nonce-post-only-auth-cookie

// OAuth/social-login callback shape (simplified/inlined variant of
// wpdiscuz 7.6.62 SocialLogin::loginCallBack()): the nonce check only runs
// on the POST branch, but every real OAuth provider redirect is a GET, so
// wp_set_auth_cookie() below is reachable with zero nonce/state verification.
class SocialLoginCallbackVulnerable {
    public function loginCallBack() {
        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            wp_verify_nonce( $_POST['nonce'], 'wpd-login' );
        }
        $userID = $this->resolveUserFromProvider( $_GET['code'], $_GET['state'] );
        // ruleid: claude.php.wordpress.access-control.conditional-nonce-post-only-auth-cookie
        wp_set_auth_cookie( $userID );
    }
}

// Same shape using wp_set_current_user() as the session-establishing sink.
class LegacyAutoLoginVulnerable {
    public function handleCallback() {
        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            check_ajax_referer( 'legacy-login', 'nonce' );
        }
        $userID = $this->lookupUserFromToken( $_GET['token'] );
        // ruleid: claude.php.wordpress.access-control.conditional-nonce-post-only-auth-cookie
        wp_set_current_user( $userID );
    }
}

// ---- SAFE: the session-establishing call is itself inside the POST-only
// conditional (properly gated — the endpoint really is POST-only) ----

class SocialLoginCallbackFixedGated {
    public function loginCallBack() {
        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            wp_verify_nonce( $_POST['nonce'], 'wpd-login' );
            $userID = $this->resolveUserFromProvider( $_POST['code'], $_POST['state'] );
            // ok: claude.php.wordpress.access-control.conditional-nonce-post-only-auth-cookie
            wp_set_auth_cookie( $userID );
        }
    }
}

// ---- SAFE: an unconditional wp_verify_nonce() check (outside the POST-only
// conditional) also exists — the nonce check now runs regardless of method ----

class SocialLoginCallbackFixedUnconditional {
    public function loginCallBack() {
        wp_verify_nonce( $_REQUEST['nonce'], 'wpd-login' );
        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            $this->logPostAttempt();
        }
        $userID = $this->resolveUserFromProvider( $_GET['code'], $_GET['state'] );
        // ok: claude.php.wordpress.access-control.conditional-nonce-post-only-auth-cookie
        wp_set_auth_cookie( $userID );
    }
}

// ---- SAFE: an unconditional custom nonce-wrapper method call (outside the
// POST-only conditional) gates the function — the real wpdiscuz 7.6.62 fix
// shape (a requester-binding check added unconditionally, independent of
// REQUEST_METHOD) ----

class SocialLoginCallbackFixedCustomWrapper {
    public function loginCallBack() {
        $this->helper->validateNonce();
        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            $this->logPostAttempt();
        }
        $userID = $this->resolveUserFromProvider( $_GET['code'], $_GET['state'] );
        // ok: claude.php.wordpress.access-control.conditional-nonce-post-only-auth-cookie
        wp_set_auth_cookie( $userID );
    }
}

// ---- SAFE: unrelated function containing a POST-conditional but no
// session-establishing call at all — should not fire ----

class SettingsFormHandler {
    public function save() {
        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            check_admin_referer( 'save-settings' );
        }
        update_option( 'plugin_setting', sanitize_text_field( $_POST['value'] ) );
    }
}
