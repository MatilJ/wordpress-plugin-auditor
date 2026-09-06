<?php

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// Bare-function-call sink, stored value on the left of the comparison.
// Match is reported at the enclosing function's declaration line (the
// rule's pattern spans the whole "function $FUNC(...) { ... }" template).
class ConnectController {
    // ruleid: claude.php.wordpress.access-control.self-minted-option-token-credential-sink
    public function connect_from_core( $request ) {
        $parameters = $request->get_body_params();
        if ( isset( $parameters['nonce'] ) ) {
            $saved_nonce = get_site_option( 'plugin_saved_nonce' );
            if ( $parameters['nonce'] === $saved_nonce ) {
                connect_to_remote_account( $parameters );
            }
        }
    }
}

// Method/chained-call sink, stored value on the right of the comparison.
class AccountLinker {
    public static function get_instance() {
        return new self();
    }

    public function link_account( $parameters ) {
        \Vendor\Auth\Login::login( $parameters['email'], $parameters['token'] );
    }
}

// ruleid: claude.php.wordpress.access-control.self-minted-option-token-credential-sink
function handle_connect_callback( $request ) {
    $parameters = $request->get_body_params();
    $saved_token = get_option( 'connect_verify_token' );
    if ( $parameters['token'] === $saved_token ) {
        AccountLinker::get_instance()->link_account( $parameters );
    }
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// Real wp_verify_nonce() gate present elsewhere in the function.
function handle_connect_with_real_nonce( $request ) {
    $parameters = $request->get_body_params();
    // ok: claude.php.wordpress.access-control.self-minted-option-token-credential-sink
    $saved_token = get_option( 'connect_verify_token' );
    if ( wp_verify_nonce( $parameters['nonce'], 'connect_action' ) && $parameters['token'] === $saved_token ) {
        connect_to_remote_account( $parameters );
    }
}

// current_user_can() gate present — real capability check, not a bare
// stored-option comparison.
function handle_connect_with_capability( $request ) {
    $parameters = $request->get_body_params();
    if ( ! current_user_can( 'manage_options' ) ) {
        return new WP_Error( 'forbidden', 'Not allowed.' );
    }
    // ok: claude.php.wordpress.access-control.self-minted-option-token-credential-sink
    $saved_token = get_option( 'connect_verify_token' );
    if ( $parameters['token'] === $saved_token ) {
        connect_to_remote_account( $parameters );
    }
}

// Stored option key does not look like a self-service verification token —
// an unrelated cached-value comparison feeding a login-shaped sink name is
// not this bug class.
function refresh_cached_display_name( $request ) {
    // ok: claude.php.wordpress.access-control.self-minted-option-token-credential-sink
    $cached_label = get_option( 'display_label_cache' );
    if ( $request['label'] === $cached_label ) {
        AccountLinker::get_instance()->link_account( $request );
    }
}
