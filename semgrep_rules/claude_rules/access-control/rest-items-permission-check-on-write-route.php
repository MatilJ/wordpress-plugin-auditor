<?php
// Test cases for claude.php.wordpress.access-control.rest-items-permission-check-on-write-route

class Example_Group_Model {

	public function register_routes() {
		$namespace = 'example/v1';
		$base      = 'widgets';

		// ruleid: claude.php.wordpress.access-control.rest-items-permission-check-on-write-route
		register_rest_route(
			$namespace,
			'/' . $base . '/groups/(?P<id>[\d]+)/cancel',
			array(
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'group_cancel' ),
					'permission_callback' => array( $this, 'get_items_permissions_check' ),
					'args'                => array(),
				),
			)
		);

		// ruleid: claude.php.wordpress.access-control.rest-items-permission-check-on-write-route
		register_rest_route(
			$namespace,
			'/' . $base . '/(?P<id>[\d]+)',
			array(
				array(
					'methods'             => 'DELETE',
					'callback'            => array( $this, 'delete_widget' ),
					'permission_callback' => array( $this, 'get_items_permissions_check' ),
				),
			)
		);

		// ok: claude.php.wordpress.access-control.rest-items-permission-check-on-write-route
		register_rest_route(
			$namespace,
			'/' . $base . '/groups/(?P<id>[\d]+)/cancel',
			array(
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'group_cancel' ),
					'permission_callback' => array( $this, 'group_cancel_permissions_check' ),
					'args'                => array(),
				),
			)
		);

		// ok: claude.php.wordpress.access-control.rest-items-permission-check-on-write-route
		// Plugin's own dedicated bulk-tier check — purpose-built for this route,
		// not the generic WP_REST_Controller list-tier fallback.
		register_rest_route(
			$namespace,
			'/' . $base . '/bulk',
			array(
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'update_items' ),
					'permission_callback' => array( $this, 'update_items_permissions_check' ),
					'args'                => array(),
				),
			)
		);

		// ok: claude.php.wordpress.access-control.rest-items-permission-check-on-write-route
		register_rest_route(
			$namespace,
			'/' . $base,
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_items' ),
					'permission_callback' => array( $this, 'get_items_permissions_check' ),
					'args'                => array(),
				),
			)
		);

		// ok: claude.php.wordpress.access-control.rest-items-permission-check-on-write-route
		register_rest_route(
			$namespace,
			'/' . $base . '/(?P<id>[\d]+)',
			array(
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'update_item' ),
					'permission_callback' => array( $this, 'update_item_permissions_check' ),
				),
			)
		);
	}

	public function get_items_permissions_check( $request ) {
		if ( current_user_can( 'manage_widgets' ) ) {
			return true;
		}

		$settings = get_option( 'example_settings' );
		$token    = isset( $settings['public_read_token'] ) ? (string) $settings['public_read_token'] : '';
		$params   = $request->get_params();
		if ( ! empty( $params['token'] ) && '' !== $token && hash_equals( $token, $params['token'] ) ) {
			return true;
		}

		return false;
	}
}
