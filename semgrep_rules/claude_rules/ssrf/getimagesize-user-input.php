<?php

// Test cases for claude.php.wordpress.ssrf.getimagesize-user-input

function vulnerable_ajax_getimagesize() {
    $url = wp_unslash( $_POST['image_url'] );
    // ruleid: claude.php.wordpress.ssrf.getimagesize-user-input
    $info = getimagesize( $url );
}

function vulnerable_rest_getimagesize( $request ) {
    $url = $request->get_param( 'url' );
    // ruleid: claude.php.wordpress.ssrf.getimagesize-user-input
    $dimensions = getimagesize( $url );
}

function safe_local_file_getimagesize() {
    // ok: claude.php.wordpress.ssrf.getimagesize-user-input
    $info = getimagesize( '/tmp/uploaded_image.jpg' );
}

function safe_validated_getimagesize() {
    $url = wp_http_validate_url( $_POST['image_url'] );
    if ( ! $url ) {
        return;
    }
    // ok: claude.php.wordpress.ssrf.getimagesize-user-input
    $info = getimagesize( $url );
}

function safe_integer_getimagesize() {
    $id = absint( $_GET['attachment_id'] );
    $file = get_attached_file( $id );
    // ok: claude.php.wordpress.ssrf.getimagesize-user-input
    $info = getimagesize( $file );
}

class Media_Server_Safe {
    // SAFE: the attacker-controlled context ID only selects WHICH avatar/
    // attachment is resolved (via WP's own accessors) — never an arbitrary
    // attacker-chosen host.
    public function get_avatar( $request ) {
        $author = $request->get_param( 'author' );
        // ok: claude.php.wordpress.ssrf.getimagesize-user-input
        $path = get_avatar_url( $author );
        $info = getimagesize( $path );
    }

    public static function get_safe_fallback_path( $fallback ) {
        $full_path = realpath( sanitize_text_field( $fallback ) );
        return false === $full_path ? '' : $full_path;
    }

    // SAFE: sentinel-substitution idiom — only the resolver's own validated
    // return value is trusted.
    public function get( $request ) {
        $fallback      = $request->get_param( 'fallback' );
        $path          = OTTER_BLOCKS_PATH . '/assets/images/placeholder.jpg';
        $safe_fallback = self::get_safe_fallback_path( $fallback );

        if ( '' !== $safe_fallback ) {
            $path = $safe_fallback;
        }

        // ok: claude.php.wordpress.ssrf.getimagesize-user-input
        $info = getimagesize( $path );
    }

    // VULNERABLE: same sentinel-substitution idiom, but a separate later
    // branch reassigns $path directly from raw request data.
    public function get_mixed_safety( $request ) {
        $fallback      = $request->get_param( 'fallback' );
        $path          = 'default.jpg';
        $safe_fallback = self::get_safe_fallback_path( $fallback );

        if ( '' !== $safe_fallback ) {
            $path = $safe_fallback;
        }

        if ( isset( $_GET['debug_url'] ) ) {
            $path = $_GET['debug_url'];
        }

        // ruleid: claude.php.wordpress.ssrf.getimagesize-user-input
        $info = getimagesize( $path );
    }
}
