<?php

class Vulnerable_Parameter_Schema {

	public function to_array(): array {
		return array_filter(
			// ruleid: claude.php.wordpress.sqli.rest-validate-callback-returns-closure
			[
				'type'              => $this->get_type(),
				'enum'              => $this->get_enum(),
				'validate_callback' => function () {
					return function ( $value ) {
						try {
							return $this->get_validator()( $value );
						} catch ( InvalidRestArgumentException $e ) {
							return $e->to_wp_error();
						}
					};
				},
				'sanitize_callback' => $this->get_sanitizer(),
			],
			static fn( $value ) => null !== $value
		);
	}

	public function register_routes() {
		$args = [
			'per_page' => [
				'type' => 'integer',
			],
			// ruleid: claude.php.wordpress.sqli.rest-validate-callback-returns-closure
			'orderby'  => [
				'type'              => 'string',
				'validate_callback' => function () {
					return function ( $value ) {
						return in_array( $value, $this->get_allowed_orderby_keys(), true );
					};
				},
			],
		];

		register_rest_route(
			'my-plugin/v1',
			'/items',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_items' ],
				'permission_callback' => '__return_true',
				'args'                => $args,
			]
		);
	}

	public function build_args_via_assignment() {
		$args = [];

		// ruleid: claude.php.wordpress.sqli.rest-validate-callback-returns-closure
		$args['validate_callback'] = function () {
			return function ( $value ) {
				return is_string( $value );
			};
		};

		return $args;
	}

	public function to_array_fixed(): array {
		return array_filter(
			// ok: claude.php.wordpress.sqli.rest-validate-callback-returns-closure
			[
				'type'              => $this->get_type(),
				'enum'              => $this->get_enum(),
				'validate_callback' => function ( $value ) {
					try {
						return $this->get_validator()( $value );
					} catch ( InvalidRestArgumentException $e ) {
						return $e->to_wp_error();
					}
				},
				'sanitize_callback' => $this->get_sanitizer(),
			],
			static fn( $value ) => null !== $value
		);
	}

	public function register_routes_safe() {
		$args = [
			// ok: claude.php.wordpress.sqli.rest-validate-callback-returns-closure
			'orderby' => [
				'type'              => 'string',
				'validate_callback' => function ( $value ) {
					return in_array( $value, [ 'title', 'date', 'id' ], true );
				},
			],
		];

		register_rest_route(
			'my-plugin/v1',
			'/items',
			[
				'methods'  => 'GET',
				'callback' => [ $this, 'get_items' ],
				'args'     => $args,
			]
		);
	}

	public function get_items_by_order( $orderby ) {
		global $wpdb;

		// ok: claude.php.wordpress.sqli.rest-validate-callback-returns-closure
		$results = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$wpdb->posts} ORDER BY %i", $orderby )
		);

		return $results;
	}
}
