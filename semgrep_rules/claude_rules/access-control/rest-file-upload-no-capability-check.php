<?php
/**
 * Test cases for claude.php.wordpress.access.rest-file-upload-no-capability-check
 *
 * Rule catches: $_FILES reads or wp_handle_upload() calls that are NOT inside a
 * function with current_user_can() or is_user_logged_in() in the same scope.
 *
 * Motivating real-world TP: ai-engine 3.4.7 classes/modules/files.php:787
 *   rest_upload() reads $_FILES['file'] with permission_callback => check_rest_nonce only.
 *   A companion /start_session endpoint (__return_true) returns a valid wp_rest nonce to
 *   any unauthenticated visitor, enabling unauthenticated upload.
 */

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// $_FILES read + wp_handle_upload, no auth check — AI Engine rest_upload() pattern
function rest_upload_no_auth( $request ) {
    // ruleid: claude.php.wordpress.access.rest-file-upload-no-capability-check
    $file = $_FILES['file'];
    // ruleid: claude.php.wordpress.access.rest-file-upload-no-capability-check
    $result = wp_handle_upload( $file, array( 'test_form' => false ) );
    return new WP_REST_Response( array( 'url' => $result['url'] ), 200 );
}

// wp_handle_upload() without auth — direct call with inline $_FILES
function handle_upload_no_auth() {
    $overrides = array( 'test_form' => false );
    // ruleid: claude.php.wordpress.access.rest-file-upload-no-capability-check
    wp_handle_upload( $_FILES['attachment'], $overrides );
}

// isset($_FILES[...]) check + wp_handle_upload, no auth
function check_file_no_auth() {
    // ruleid: claude.php.wordpress.access.rest-file-upload-no-capability-check
    if ( isset( $_FILES['file'] ) ) {
        // ruleid: claude.php.wordpress.access.rest-file-upload-no-capability-check
        wp_handle_upload( $_FILES['file'], array( 'test_form' => false ) );
    }
}

// Two-level $_FILES subscript + wp_handle_upload, no auth
function get_tmpname_no_auth() {
    // ruleid: claude.php.wordpress.access.rest-file-upload-no-capability-check
    $tmp = $_FILES['file']['tmp_name'];
    // ruleid: claude.php.wordpress.access.rest-file-upload-no-capability-check
    wp_handle_upload( $_FILES['file'], array( 'test_form' => false ) );
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// current_user_can('upload_files') guard — correct pattern
// Note: current_user_can() is inside if (!current_user_can(...)), so the rule must
// use deep-expression matching <... current_user_can(...) ...> to catch this.
function rest_upload_with_capability( $request ) {
    if ( !current_user_can( 'upload_files' ) ) {
        return new WP_Error( 'forbidden', 'You cannot upload files.', array( 'status' => 403 ) );
    }
    // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
    $file = $_FILES['file'] ?? null;
    // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
    wp_handle_upload( $file, array( 'test_form' => false ) );
}

// is_user_logged_in() guard — prevents unauthenticated access
function rest_upload_logged_in_only( $request ) {
    if ( !is_user_logged_in() ) {
        return new WP_Error( 'login_required', 'Login required.', array( 'status' => 401 ) );
    }
    // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
    $file = $_FILES['file'] ?? null;
    // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
    wp_handle_upload( $file, array( 'test_form' => false ) );
}

// manage_options capability — admin-only import handler, PR:H (OOS for bounty)
function admin_import_handler() {
    if ( !current_user_can( 'manage_options' ) ) {
        wp_die( 'Insufficient permissions.' );
    }
    // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
    $file = $_FILES['import_file'];
    // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
    wp_handle_upload( $file, array( 'test_form' => false ) );
}

// Per-item stored option/transient token compared against request input as
// an early guard — the route-level gate is intentional (__return_true /
// nonce-only); the real auth is this per-item stored secret, not a WP
// capability. TRIAGE GUIDANCE #1 documents this class; this codifies it.
function set_critical_css_upload() {
    if ( isset( $_POST['token'], $_POST['page_id'] )
        && get_option( 'critical_token_' . sanitize_text_field( $_POST['page_id'] ) ) === $_POST['token'] ) {
        // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
        $uploadfile = $_FILES['covered_css']['tmp_name'];
        echo '{"status":"ok"}';
    }
}

// check_role_access()/check_write_access()-style naming-convention wrappers
// around current_user_can() — the nonce check alone doesn't gate the $_FILES
// read, but the sibling static wrapper call does.
class Import_Settings_Handler {
    public function wt_pklist_import_settings() {
        if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'import_settings' ) || ! self::check_role_access() ) {
            wp_die( 'You are not allowed to do this action' );
        }
        // ok: claude.php.wordpress.access.rest-file-upload-no-capability-check
        $file = $_FILES['import_setting_file']['tmp_name'];
        return $file;
    }

    public static function check_role_access() {
        return current_user_can( 'manage_options' ) || current_user_can( 'manage_woocommerce' );
    }
}
