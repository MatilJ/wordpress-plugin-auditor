<?php

class Login_Controller {

	public static function get_instance() {
		return new self();
	}

	public function permission_check( $request ) {
		return true;
	}

	public function login() {
		// performs the actual login/account-link write
	}
}

// Vulnerable: init-hook handler builds a WP_REST_Request and calls the
// controller method directly — register_rest_route()'s own
// permission_callback (bound only when WP itself routes a matching HTTP
// request) never runs for this call path.
function my_plugin_google_login_handler() {
	if ( empty( $_GET['my_plugin_login'] ) || empty( $_GET['api_key'] ) ) {
		return;
	}

	// ruleid: claude.php.wordpress.access-control.manual-rest-request-direct-controller-call
	$request = new WP_REST_Request( 'POST', '/my-plugin/v1/login' );
	$request->set_param( 'api_key', sanitize_text_field( $_GET['api_key'] ) );

	Login_Controller::get_instance()->permission_check( $request );
	Login_Controller::get_instance()->login();
}
add_action( 'init', 'my_plugin_google_login_handler' );

// Vulnerable: same shape, single-argument direct method call, fully
// namespace-qualified WP_REST_Request.
function my_plugin_alt_login_handler() {
	// ruleid: claude.php.wordpress.access-control.manual-rest-request-direct-controller-call
	$request = new \WP_REST_Request( 'POST', '/my-plugin/v1/login' );
	$controller = Login_Controller::get_instance();
	$controller->login( $request );
}
add_action( 'init', 'my_plugin_alt_login_handler' );

// Safe: the manually built request is dispatched via rest_do_request(),
// which DOES run the route's own permission_callback before the handler.
function my_plugin_internal_login_dispatch() {
	// ok: claude.php.wordpress.access-control.manual-rest-request-direct-controller-call
	$request = new WP_REST_Request( 'POST', '/my-plugin/v1/login' );
	$request->set_param( 'api_key', sanitize_text_field( $_GET['api_key'] ) );
	$response = rest_do_request( $request );
	return $response;
}

// Safe: dispatched via the REST server's own dispatch() method — same
// permission-enforcing code path WordPress itself uses for a real HTTP
// request.
function my_plugin_server_dispatch_login() {
	global $wp_rest_server;
	// ok: claude.php.wordpress.access-control.manual-rest-request-direct-controller-call
	$request = new WP_REST_Request( 'POST', '/my-plugin/v1/login' );
	$response = $wp_rest_server->dispatch( $request );
	return $response;
}

// Safe: this IS the route's own registered permission_callback / handler
// pair, invoked directly with an already-authorized $request object passed
// in as a parameter — no WP_REST_Request is constructed here at all.
function my_plugin_route_handler( WP_REST_Request $request ) {
	// ok: claude.php.wordpress.access-control.manual-rest-request-direct-controller-call
	$controller = Login_Controller::get_instance();
	if ( ! $controller->permission_check( $request ) ) {
		return new WP_Error( 'forbidden', 'Forbidden', [ 'status' => 403 ] );
	}
	return $controller->login();
}
