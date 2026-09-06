<?php
// Test cases for claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate

function handle_import() {
    // ruleid: claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate
    if ( isset( $_REQUEST['nonce'] ) && sanitize_input( $_REQUEST['nonce'] ) === md5( 'import_action' ) ) {
        move_uploaded_file( $_FILES['file']['tmp_name'], $dest );
    }
}

function handle_export() {
    // ruleid: claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate
    if ( $_GET['token'] == sha1( 'static_secret' ) ) {
        file_put_contents( $path, $data );
    }
}

class Widget_Import {
    public function process() {
        // ruleid: claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate
        if ( md5( 'widget_import' ) === $this->clean( $_POST['nonce'] ) ) {
            update_option( 'widget_data', $_POST['data'] );
        }
    }

    private function clean( $v ) {
        return htmlspecialchars( $v, ENT_QUOTES );
    }
}

function handle_import_fixed() {
    // ok: claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate
    if ( wp_verify_nonce( sanitize_key( $_REQUEST['nonce'] ), 'my_action_' . $GLOBALS['opt_name'] ) ) {
        move_uploaded_file( $_FILES['file']['tmp_name'], $dest );
    }
}

function get_cache_key() {
    // ok: claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate
    $key = md5( 'cache_prefix' );
    return get_transient( $key );
}

function handle_import_redundant_check() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die();
    }

    // ok: claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate
    if ( $_REQUEST['nonce'] === md5( 'import_action' ) ) {
        move_uploaded_file( $_FILES['file']['tmp_name'], $dest );
    }
}

function verify_signature( $secret, $data ) {
    // Not a literal — the hash input is a variable, so the value is not
    // statically knowable from source code alone.
    // ok: claude.php.wordpress.access-control.hardcoded-hash-literal-nonce-gate
    if ( $_POST['sig'] === md5( $secret . $data ) ) {
        do_privileged_action();
    }
}
