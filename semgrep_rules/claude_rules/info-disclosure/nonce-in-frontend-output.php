<?php

function enqueue_plugin_scripts() {
    // ruleid: claude.php.wordpress.info-disclosure.nonce-in-frontend-output
    wp_localize_script( 'plugin-js', 'PluginAjax', array(
        'ajax_url' => admin_url( 'admin-ajax.php' ),
        'nonce'    => wp_create_nonce( 'plugin_delete_action' ),
    ) );
}

function enqueue_with_variable() {
    // ruleid: claude.php.wordpress.info-disclosure.nonce-in-frontend-output
    $nonce = wp_create_nonce( 'my_sensitive_action' );
    wp_localize_script( 'my-script', 'MyObj', array(
        'url'   => admin_url( 'admin-ajax.php' ),
        'nonce' => $nonce,
    ) );
}

function enqueue_rest_nonce() {
    // ok: claude.php.wordpress.info-disclosure.nonce-in-frontend-output
    wp_localize_script( 'plugin-js', 'PluginRest', array(
        'root'  => rest_url( 'plugin/v1/' ),
        'nonce' => wp_create_nonce( 'wp_rest' ),
    ) );
}
