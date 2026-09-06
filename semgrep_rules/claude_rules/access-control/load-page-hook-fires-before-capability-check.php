<?php
// Test file for load-page-hook-fires-before-capability-check rule

// --- TRUE POSITIVES (registration on a load-{page}.php hook) ---

class Post_Republisher {
    public function register_hooks() {
        // ruleid: claude.php.wordpress.access-control.load-page-hook-fires-before-capability-check
        add_action( 'load-post.php', [ $this, 'clean_up_orphaned_copy' ], 11 );
    }

    public function clean_up_orphaned_copy() {
        if ( empty( $_GET['post'] ) || empty( $_GET['action'] ) ) {
            return;
        }
        $post_id = intval( wp_unslash( $_GET['post'] ) );
        $copy_id = get_post_meta( $post_id, '_has_copy', true );
        wp_delete_post( $copy_id, true );
    }
}

function register_upload_cleanup() {
    // ruleid: claude.php.wordpress.access-control.load-page-hook-fires-before-capability-check
    \add_action( 'load-upload.php', 'my_plugin_cleanup_upload_request' );
}

// --- TRUE NEGATIVES ---

class Safe_Handler {
    public function register_hooks() {
        // ok: claude.php.wordpress.access-control.load-page-hook-fires-before-capability-check
        add_action( 'admin_init', [ $this, 'maybe_run' ] );
    }

    public function register_save_hook() {
        // ok: claude.php.wordpress.access-control.load-page-hook-fires-before-capability-check
        add_action( 'save_post', [ $this, 'on_save' ] );
    }
}
