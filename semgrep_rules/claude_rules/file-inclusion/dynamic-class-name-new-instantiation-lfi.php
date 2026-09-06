<?php

// Test cases for claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi

// Real-world shape: a namespace prefix concatenated with a raw $_POST value,
// then instantiated — triggers the plugin's own spl_autoload_register()
// callback with the attacker-controlled suffix.
function run_social_login_action( $ajax_handler ) {
    $social      = $_POST['social_network'];
    $social_ajax = '\MyPlugin\Modules\Forms\Classes\Social_Login_Handler\\' . $social;
    // ruleid: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $network     = new $social_ajax();
    $network->ajax_handler( $ajax_handler );
}

// Real-world shape: taint flows through a dispatcher object's request-data-bag
// property (populated from $_POST elsewhere, e.g. in the constructor of the
// class that owns $ajax_handler) rather than a direct superglobal read in
// this function — the common Elementor-ecosystem AJAX-handler idiom.
function run_social_login_action_via_record_bag( $ajax_handler ) {
    $social      = $ajax_handler->record['social_network'];
    $social_ajax = '\MyPlugin\Modules\Forms\Classes\Social_Login_Handler\\' . $social;
    // ruleid: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $network     = new $social_ajax();
    $network->ajax_handler( $ajax_handler );
}

function run_handler_from_get() {
    $handler_class = 'MyPlugin_Handler_' . $_GET['type'];
    // ruleid: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $obj = new $handler_class();
    return $obj;
}

function run_handler_direct_request() {
    // ruleid: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $obj = new $_REQUEST['class']();
    return $obj;
}

// --- TRUE NEGATIVES ---

function run_handler_with_key_allowlist() {
    $type = sanitize_key( $_GET['type'] );
    $handler_class = 'MyPlugin_Handler_' . $type;
    // ok: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $obj = new $handler_class();
    return $obj;
}

function run_handler_with_hardcoded_allowlist() {
    $allowed = array( 'facebook', 'google', 'twitter' );
    $requested = $_POST['social_network'];
    $type = in_array( $requested, $allowed, true ) ? $requested : 'facebook';
    $handler_class = 'MyPlugin\\Social_Login_Handler\\' . $type;
    // ok: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $obj = new $handler_class();
    return $obj;
}

function run_handler_with_traversal_and_separator_strip() {
    $type = $_GET['type'];
    $type = str_replace( '..', '', $type );
    $type = str_replace( '/', '', $type );
    $handler_class = 'MyPlugin_Handler_' . $type;
    // ok: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $obj = new $handler_class();
    return $obj;
}

function run_handler_hardcoded_class_only() {
    $class_name = 'MyPlugin_Default_Handler';
    // ok: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $obj = new $class_name();
    return $obj;
}

function run_handler_constructor_arg_tainted_not_class_name() {
    // Tainted value passed as a CONSTRUCTOR ARGUMENT, not the class name
    // itself — different bug class, not this rule's target shape.
    // ok: claude.php.wordpress.file-inclusion.dynamic-class-name-new-instantiation-lfi
    $obj = new MyPlugin_Request_Context( $_GET['id'] );
    return $obj;
}
