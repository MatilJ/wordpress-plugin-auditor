<?php
/**
 * Test cases for claude.php.wordpress.upload.filetype-check-before-rename-no-exit
 *
 * Vulnerable: wp_check_filetype_and_ext() result stored but execution reaches
 *             rename() without a conditional return/die on filetype failure.
 *
 * Safe: a conditional return or wp_die() gates the rename — invalid files
 *       never reach the rename() call.
 */

// -------------------------------------------------------------------------
// VULNERABLE patterns — rule MUST fire
// -------------------------------------------------------------------------

// Exact EVF pattern: error recorded in task->errors but no return/continue.
// ruleid: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
function format_no_exit( $file, $form_data, $field_id ) {
    $wp_filetype     = wp_check_filetype_and_ext( $file['tmp_path'], $file['name'] );
    $ext             = empty( $wp_filetype['ext'] ) ? '' : $wp_filetype['ext'];
    $type            = empty( $wp_filetype['type'] ) ? '' : $wp_filetype['type'];
    $proper_filename = empty( $wp_filetype['proper_filename'] ) ? '' : $wp_filetype['proper_filename'];

    if ( $proper_filename || ! $ext || ! $type ) {
        task_errors_set( $form_data['id'], $field_id, 'File type is not allowed.' );
        update_option( 'evf_validation_error', 'yes' );
        // BUG: no return/continue — rename runs regardless
    }

    rename( $file['tmp_path'], $file['path'] );
}

// Variant: error pushed into $errors array but no exit before rename.
// ruleid: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
function move_upload_errors_array( $tmp, $dest, $name ) {
    $result = wp_check_filetype_and_ext( $tmp, $name );
    $errors = array();

    if ( empty( $result['ext'] ) || empty( $result['type'] ) ) {
        $errors[] = 'File type is not allowed.';
        // BUG: $errors collected but rename still runs
    }

    rename( $tmp, $dest );
}

// Variant: @rename() (error-suppressed) — Semgrep normalises @ away, still caught.
// ruleid: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
function format_at_rename_no_exit( $file, $form_data, $field_id ) {
    $wp_filetype = wp_check_filetype_and_ext( $file['tmp_path'], $file['name'] );
    $ext         = empty( $wp_filetype['ext'] ) ? '' : $wp_filetype['ext'];
    $type        = empty( $wp_filetype['type'] ) ? '' : $wp_filetype['type'];

    if ( ! $ext || ! $type ) {
        task_errors_set( $form_data['id'], $field_id, 'File type is not allowed.' );
        update_option( 'evf_validation_error', 'yes' );
        // BUG: no return/continue
    }

    @rename( $file['tmp_path'], $file['path'] ); // @ suppresses error but file still moves
}

// -------------------------------------------------------------------------
// SAFE patterns — rule must NOT fire
// -------------------------------------------------------------------------

// Proper pattern: conditional return on bad filetype — rename is never reached.
// ok: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
function move_upload_with_return( $tmp, $dest, $name ) {
    $filetype = wp_check_filetype_and_ext( $tmp, $name );

    if ( empty( $filetype['ext'] ) || empty( $filetype['type'] ) ) {
        return false; // early exit — rename is unreachable
    }

    rename( $tmp, $dest );
}

// Proper pattern: wp_die() on bad filetype — rename is never reached.
// ok: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
function move_upload_with_die( $tmp, $dest, $name ) {
    $filetype = wp_check_filetype_and_ext( $tmp, $name );

    if ( empty( $filetype['ext'] ) || empty( $filetype['type'] ) ) {
        wp_die( esc_html__( 'File type not allowed.', 'plugin' ) );
    }

    rename( $tmp, $dest );
}

// -------------------------------------------------------------------------
// Variant B — try/catch swallow: validation throws, catch only logs.
// -------------------------------------------------------------------------

// Vulnerable: catch logs the validation-failure exception but never returns —
// move_uploaded_file() still runs even though the type check failed.
function handle_single_file_upload( $form_id, $name, $file ) {
    // ruleid: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
    try {
        if ( ! check_file_type( $file['tmp_name'], $file['name'] ) ) {
            throw new \RuntimeException( 'File type is not allowed.' );
        }
    } catch ( \Exception $e ) {
        error_log( $e->getMessage() );
        // BUG: no return — move_uploaded_file() below still executes
    }

    $filepath = sanitize_file_name( $file['name'] );
    move_uploaded_file( $file['tmp_name'], $filepath );
}

// Vulnerable: same swallow shape gating a size/error-status check instead of
// a pure type check — the missing halt still lets an invalid file persist.
function process_upload_field( $form_id, $name, $file ) {
    // ruleid: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
    try {
        if ( UPLOAD_ERR_OK !== $file['error'] ) {
            throw new \RuntimeException( 'Upload error.' );
        }
    } catch ( \Exception $e ) {
        error_log( $e->getMessage() );
    }

    move_uploaded_file( $file['tmp_name'], sanitize_file_name( $file['name'] ) );
}

// Safe: catch returns false immediately after logging — move_uploaded_file()
// is unreachable when validation fails.
function handle_upload_with_catch_return( $form_id, $name, $file ) {
    // ok: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
    try {
        if ( ! check_file_type( $file['tmp_name'], $file['name'] ) ) {
            throw new \RuntimeException( 'File type is not allowed.' );
        }
    } catch ( \Exception $e ) {
        error_log( $e->getMessage() );
        return false;
    }

    move_uploaded_file( $file['tmp_name'], sanitize_file_name( $file['name'] ) );
}

// Safe: catch calls wp_die() — execution never reaches move_uploaded_file().
function handle_upload_with_catch_wpdie( $form_id, $name, $file ) {
    // ok: claude.php.wordpress.upload.filetype-check-before-rename-no-exit
    try {
        if ( ! check_file_type( $file['tmp_name'], $file['name'] ) ) {
            throw new \RuntimeException( 'File type is not allowed.' );
        }
    } catch ( \Exception $e ) {
        error_log( $e->getMessage() );
        wp_die( esc_html( $e->getMessage() ) );
    }

    move_uploaded_file( $file['tmp_name'], sanitize_file_name( $file['name'] ) );
}
