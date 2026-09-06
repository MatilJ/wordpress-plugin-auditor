<?php

// Test cases for claude.php.wordpress.xss.stored-meta-keyvalue-foreach-unescaped-echo

// --- TRUE POSITIVES ---

function ajax_inspect_log_entry_tp1() {
    $entry_meta = get_stored_entry_meta( (int) $_GET['occurrence'] );

    echo '<div class="event-content-wrapper">';
    foreach ( $entry_meta as $item => $value ) {
        if ( $value ) {
            // ruleid: claude.php.wordpress.xss.stored-meta-keyvalue-foreach-unescaped-echo
            echo '<strong>' . $item . ':</strong> <span><pre>' . $value . '</pre></span></br>';
        }
    }
    echo '</div>';
    wp_die();
}

function ajax_inspect_log_entry_namespaced_tp2() {
    $entry_meta = get_stored_entry_meta( (int) $_GET['occurrence'] );

    foreach ( $entry_meta as $item => $value ) {
        if ( is_array( $value ) || is_object( $value ) ) {
            $value = var_export( $value, true );
        }
        // ruleid: claude.php.wordpress.xss.stored-meta-keyvalue-foreach-unescaped-echo
        echo '<strong>' . $item . ':</strong> <span style="opacity: 0.7;"><pre style="display:inline">' . $value . '</pre></span></br>';
    }
    wp_die();
}

function render_debug_meta_dump_tp3( $meta ) {
    foreach ( $meta as $key => $val ) {
        // ruleid: claude.php.wordpress.xss.stored-meta-keyvalue-foreach-unescaped-echo
        print( $key . ': ' . $val . "<br>" );
    }
}

// --- FALSE POSITIVES (properly escaped / not an HTML output sink) ---

function ajax_inspect_log_entry_fp1() {
    $entry_meta = get_stored_entry_meta( (int) $_GET['occurrence'] );

    echo '<div class="event-content-wrapper">';
    foreach ( $entry_meta as $item => $value ) {
        if ( $value ) {
            // ok: claude.php.wordpress.xss.stored-meta-keyvalue-foreach-unescaped-echo
            echo '<strong>' . \esc_html( $item ) . ':</strong> <span><pre>' . \esc_html( $value ) . '</pre></span></br>';
        }
    }
    echo '</div>';
    wp_die();
}

function render_debug_meta_dump_fp2( $meta ) {
    foreach ( $meta as $key => $val ) {
        // ok: claude.php.wordpress.xss.stored-meta-keyvalue-foreach-unescaped-echo
        print( esc_html( $key ) . ': ' . esc_html( $val ) . "<br>" );
    }
}

function ajax_inspect_log_entry_json_fp3() {
    $entry_meta = get_stored_entry_meta( (int) $_GET['occurrence'] );
    $out        = array();

    foreach ( $entry_meta as $item => $value ) {
        $out[ $item ] = $value;
    }
    // ok: claude.php.wordpress.xss.stored-meta-keyvalue-foreach-unescaped-echo
    wp_send_json_success( $out );
}
