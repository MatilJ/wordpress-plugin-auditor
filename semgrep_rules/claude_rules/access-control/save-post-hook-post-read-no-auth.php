<?php
/**
 * Test cases for claude.php.wordpress.access.save-post-hook-post-read-no-auth
 *
 * Detects save_post hook callbacks that read $_POST without calling
 * current_user_can() or verifying a nonce.
 *
 * Motivating real-world pattern (post-expirator 4.10.1):
 *   ManualPostTrigger::processQuickEditUpdate() — hooked on save_post,
 *   reads $_POST['future_workflow_view'] and triggers workflow execution
 *   without any capability check. Contributor can publish their own posts.
 */

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// Classic save_post callback: autosave guard + $_POST read, no auth at all.
// Confirmed TP pattern from post-expirator 4.10.1 ManualPostTrigger.php:149.
function processQuickEditUpdate( $postId ) {
    try {
        // phpcs:disable WordPress.Security.NonceVerification.Missing
        if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
            return;
        }
        // ruleid: claude.php.wordpress.access.save-post-hook-post-read-no-auth
        $view = $_POST['future_workflow_view'] ?? '';
        if ( empty( $view ) || $view !== 'quick-edit' ) {
            return;
        }
        // ruleid: claude.php.wordpress.access.save-post-hook-post-read-no-auth
        $manuallyEnabledWorkflows = $_POST['future_workflow_manual_trigger'] ?? [];
        update_post_meta( $postId, '_workflow_enabled', $manuallyEnabledWorkflows );
    } catch ( \Throwable $th ) {
        error_log( $th->getMessage() );
    }
}

// Variant: nonce is read but not verified — still no auth.
function save_post_nonce_read_not_verified( $postId ) {
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    $nonce = $_POST['_wpnonce']; // reading nonce value but not calling wp_verify_nonce
    // ruleid: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $custom_field = $_POST['my_plugin_field'] ?? '';
    update_post_meta( $postId, '_my_plugin_field', sanitize_text_field( $custom_field ) );
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// Safe: nonce is verified before reading POST data.
function save_post_with_nonce( $postId ) {
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    if ( ! isset( $_POST['my_nonce'] ) || ! wp_verify_nonce( $_POST['my_nonce'], 'save_my_meta_' . $postId ) ) {
        return;
    }
    // ok: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $value = $_POST['my_plugin_field'] ?? '';
    update_post_meta( $postId, '_my_plugin_field', sanitize_text_field( $value ) );
}

// Safe: capability check present before reading POST data.
function save_post_with_capability( $postId ) {
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    if ( ! current_user_can( 'edit_post', $postId ) ) {
        return;
    }
    // ok: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $value = $_POST['my_plugin_field'] ?? '';
    update_post_meta( $postId, '_my_plugin_field', sanitize_text_field( $value ) );
}

// Safe: both nonce and capability check present.
function save_post_fully_protected( $postId ) {
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    if ( ! isset( $_POST['my_nonce'] ) || ! wp_verify_nonce( $_POST['my_nonce'], 'my_action' ) ) {
        return;
    }
    if ( ! current_user_can( 'edit_posts' ) ) {
        return;
    }
    // ok: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $value = $_POST['my_plugin_field'] ?? '';
    update_post_meta( $postId, '_my_plugin_field', sanitize_text_field( $value ) );
}

// Safe: uses OOP userCan* capability wrapper — delegates to current_user_can().
function save_post_with_usercan_wrapper( $postId ) {
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    if ( ! $this->currentUserModel->userCanExpirePosts() ) {
        return;
    }
    // ok: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $value = $_POST['expiration_date'] ?? '';
    update_post_meta( $postId, '_expiration_date', sanitize_text_field( $value ) );
}

// Safe: no DOING_AUTOSAVE check — function is not a save_post callback pattern.
function not_a_save_post_callback() {
    // ok: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $value = $_POST['my_plugin_field'] ?? '';
    update_option( 'my_plugin_setting', sanitize_text_field( $value ) );
}

// Safe: check_admin_referer() verifies nonce and wp_die()s on failure.
// Standard protection for admin form-based save_post callbacks (non-AJAX).
// Parity with check_ajax_referer() exclusion already present in the rule.
function save_post_with_check_admin_referer( $postId ) {
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    check_admin_referer( 'save_gallery_' . $postId, '_gallery_nonce' );
    // ok: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $value = $_POST['gallery_title'] ?? '';
    update_post_meta( $postId, '_gallery_title', sanitize_text_field( $value ) );
}

// Safe: reads the _wpnonce key (the nonce value read itself, not a missing check).
function save_post_nonce_fetch( $postId ) {
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    // ok: claude.php.wordpress.access.save-post-hook-post-read-no-auth
    $nonce = $_POST['_wpnonce'];
    if ( ! wp_verify_nonce( $nonce, 'save_post_' . $postId ) ) {
        return;
    }
    $value = $_POST['my_field'] ?? '';
    update_post_meta( $postId, '_my_field', sanitize_text_field( $value ) );
}
