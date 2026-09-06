<?php

// Test cases for claude.php.wordpress.access-control.admin-init-conditional-request-hook

// TP: admin_init registered conditionally on $_REQUEST — canonical vulnerable pattern.
// ruleid: claude.php.wordpress.access-control.admin-init-conditional-request-hook
if ( isset( $_REQUEST['action'] ) && 'my-action' === sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) ) {
	add_action( 'admin_init', [ 'MyClass', 'handle_action' ] );
}

// TP: admin_init registered conditionally on $_GET parameter.
// ruleid: claude.php.wordpress.access-control.admin-init-conditional-request-hook
if ( isset( $_GET['page'] ) && 'my-plugin' === $_GET['page'] ) {
	add_action( 'admin_init', [ 'MyClass', 'handle_page_load' ] );
}

// TP: admin_init registered conditionally on $_POST parameter.
// ruleid: claude.php.wordpress.access-control.admin-init-conditional-request-hook
if ( 'trigger' === $_POST['task'] ) {
	add_action( 'admin_init', 'my_handler_function' );
}

// ok: claude.php.wordpress.access-control.admin-init-conditional-request-hook
add_action( 'admin_init', [ 'MyClass', 'always_registered_handler' ] );

// ok: claude.php.wordpress.access-control.admin-init-conditional-request-hook
if ( is_admin() ) {
	add_action( 'admin_init', [ 'MyClass', 'is_admin_scoped_handler' ] );
}
