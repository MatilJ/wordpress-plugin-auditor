<?php
/**
 * Test cases for claude.php.wordpress.access-control.nonce-id-export-no-ownership-check
 *
 * Rule fires at the nonce-check line inside functions that:
 *  1. Call wp_verify_nonce() / check_ajax_referer() / check_admin_referer()
 *  2. Read an integer ID via filter_input(FILTER_VALIDATE_INT)
 *  3. Send a file download response: explicit header()+die() or readfile()
 *  4. Do NOT call current_user_can() or a known ownership wrapper
 */

// ── MATCH: nonce present, int ID from input, file download, no ownership check ──

// TP1: wp_verify_nonce + filter_input(INT) from POST + header+die export
function export_module_tp1() {
    $nonce = filter_input( INPUT_POST, '_wpnonce', FILTER_SANITIZE_SPECIAL_CHARS );
    // ruleid: claude.php.wordpress.access-control.nonce-id-export-no-ownership-check
    if ( ! wp_verify_nonce( $nonce, 'plugin_export_module' ) ) {
        return;
    }
    $id = filter_input( INPUT_POST, 'id', FILTER_VALIDATE_INT );
    if ( ! $id ) {
        return;
    }
    $module = SomeModel::get( $id );
    $result = json_encode( $module );
    header( 'Content-Type: application/json' );
    header( 'Content-Disposition: attachment; filename=module-' . $id . '.json' );
    die( $result );
}

// TP2: check_admin_referer + filter_input(INT) from GET + readfile download
function download_report_tp2() {
    // ruleid: claude.php.wordpress.access-control.nonce-id-export-no-ownership-check
    if ( ! check_admin_referer( 'generate_report' ) ) {
        return;
    }
    $report_id = filter_input( INPUT_GET, 'id', FILTER_VALIDATE_INT );
    if ( ! $report_id ) {
        wp_die( 'Invalid ID' );
    }
    $path = get_report_path( $report_id );
    header( 'Content-Type: application/octet-stream' );
    header( 'Content-Disposition: attachment; filename=report.pdf' );
    readfile( $path );
}

// TP3: wp_verify_nonce + filter_input(INT) from POST + header+echo+exit — real-world pattern.
function export_module_tp3() {
    $nonce = filter_input( INPUT_POST, '_wpnonce', FILTER_SANITIZE_SPECIAL_CHARS );
    // ruleid: claude.php.wordpress.access-control.nonce-id-export-no-ownership-check
    if ( ! wp_verify_nonce( $nonce, 'hustle_module_export' ) ) {
        return;
    }
    $id = filter_input( INPUT_POST, 'id', FILTER_VALIDATE_INT );
    if ( ! $id ) {
        return;
    }
    $module  = SomeModel::get( $id );
    $result  = wp_json_encode( $module );
    $filename = 'export-' . $id . '.json';
    header( 'Content-Description: File Transfer' );
    header( 'Content-Disposition: attachment; filename=' . $filename );
    header( 'Content-Type: application/bin; charset=UTF-8', true );
    echo $result;
    exit;
}

// ── NO MATCH: ownership check present ─────────────────────────────────────────

// OK1: current_user_can() inside if-guard — exclusion must suppress firing.
function export_module_safe_ok1() {
    $nonce = filter_input( INPUT_POST, '_wpnonce', FILTER_SANITIZE_SPECIAL_CHARS );
    // ok: claude.php.wordpress.access-control.nonce-id-export-no-ownership-check
    if ( ! wp_verify_nonce( $nonce, 'plugin_export_module' ) ) {
        return;
    }
    $id = filter_input( INPUT_POST, 'id', FILTER_VALIDATE_INT );
    if ( ! $id ) {
        return;
    }
    if ( ! current_user_can( 'edit_post', $id ) ) {
        wp_die( 'Unauthorized' );
    }
    $module = SomeModel::get( $id );
    $result = json_encode( $module );
    header( 'Content-Disposition: attachment; filename=module-' . $id . '.json' );
    die( $result );
}

// OK2: current_user_can() as standalone capability gate (no if-condition).
function export_with_cap_ok2() {
    $nonce = filter_input( INPUT_POST, '_wpnonce', FILTER_SANITIZE_SPECIAL_CHARS );
    // ok: claude.php.wordpress.access-control.nonce-id-export-no-ownership-check
    if ( ! wp_verify_nonce( $nonce, 'plugin_export' ) ) {
        return;
    }
    $id    = filter_input( INPUT_POST, 'id', FILTER_VALIDATE_INT );
    $cap   = current_user_can( 'export' );
    if ( ! $cap || ! $id ) {
        return;
    }
    $data = get_data( $id );
    header( 'Content-Disposition: attachment; filename=data.json' );
    die( json_encode( $data ) );
}
