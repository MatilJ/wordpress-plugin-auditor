<?php
// Tests for claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
// TP cases: (1) single-item GET route delegates to an inherited, undefined-in-class
// get_item_permissions_check(); (2) current_user_can('read', $id) / ->cap->read
// misuse as a per-object gate.
// FP cases: real per-object override, real read_post meta cap, coarse no-id check,
// and inheriting a known-safe WP-core REST base class without overriding.

class RuleidWebhooksController extends PluginPostsController {
	public function register_routes() {
		register_rest_route( $this->namespace, '/webhooks/(?P<id>[\d]+)',
		// ruleid: claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
		array(
			'methods'             => \WP_REST_Server::READABLE,
			'callback'            => array( $this, 'get_item' ),
			'permission_callback' => array( $this, 'get_item_permissions_check' ),
			'args'                => array(),
		)
		);
	}
}

function ruleid_get_item_permissions_check( $request ) {
	// ruleid: claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
	if ( ! current_user_can( 'read', $request['id'] ) ) {
		return new WP_Error( 'cannot_read', 'Sorry, you are not allowed to read this resource.' );
	}

	return true;
}

function ruleid_check_post_permissions( $post_type, $context, $object_id = 0 ) {
	$post_type_object = get_post_type_object( $post_type );

	// ruleid: claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
	return current_user_can( $post_type_object->cap->read, $object_id );
}

class OkWebhooksController extends PluginPostsController {
	public function register_routes() {
		register_rest_route( $this->namespace, '/webhooks/(?P<id>[\d]+)',
		// ok: claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
		array(
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_item' ),
				'permission_callback' => array( $this, 'get_item_permissions_check' ),
				'args'                => array(),
			),
		) );
	}

	// Real per-object override defined in this class — the inherited base
	// method (whatever it does) is never reached.
	public function get_item_permissions_check( $request ) {
		$post = get_post( (int) $request['id'] );

		if ( ! $post ) {
			return new WP_Error( 'invalid_id', 'Invalid ID', array( 'status' => 404 ) );
		}

		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		if ( get_current_user_id() === (int) $post->post_author ) {
			return true;
		}

		return new WP_Error( 'cannot_read', 'Sorry, you are not allowed to read this resource.' );
	}
}

function ok_get_item_permissions_check( $request ) {
	// ok: claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
	// Real per-object meta capability, read_post, used instead of the coarse primitive.
	if ( ! current_user_can( 'read_post', $request['id'] ) ) {
		return new WP_Error( 'cannot_read', 'Sorry, you are not allowed to read this resource.' );
	}

	return true;
}

function ok_dashboard_widget_check() {
	// ok: claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
	// Legitimate coarse check: no object id argument, just "can this user
	// access wp-admin at all".
	if ( ! current_user_can( 'read' ) ) {
		return false;
	}

	return true;
}

class OkCoreController extends WP_REST_Posts_Controller {
	// Inheriting a known-safe WordPress core REST base class without
	// overriding get_item_permissions_check() is normal, safe reuse of a
	// correct base implementation.
	public function register_routes() {
		register_rest_route( $this->namespace, '/items/(?P<id>[\d]+)',
		// ok: claude.php.wordpress.access-control.rest-read-permission-primitive-cap-no-ownership
		array(
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_item' ),
				'permission_callback' => array( $this, 'get_item_permissions_check' ),
				'args'                => array(),
			),
		) );
	}
}
