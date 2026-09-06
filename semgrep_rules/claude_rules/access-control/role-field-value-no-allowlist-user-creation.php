<?php

class Registration_Handler_A {
	private $valid_data = array();

	public function process_fields() {
		foreach ( $this->fields as $field ) {
			$type  = $field['blockName'];
			$value = sanitize_text_field( wp_unslash( $_POST[ $field['name'] ] ) );
			$this->valid_data[ $field['name'] ] = array(
				'type'  => $type,
				'value' => $value,
			);
		}
	}

	// ruleid: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function create_user() {
		$role = 'customer';
		if ( ! empty( $this->valid_data['user_roles']['value'] ) ) {
			$role = $this->valid_data['user_roles']['value'];
		}
		add_filter(
			'woocommerce_new_customer_data',
			function ( $user_data ) use ( $role ) {
				$user_data['role'] = sanitize_text_field( $role );
				return $user_data;
			}
		);
	}
}

class Registration_Handler_B {
	private $submitted = array();

	public function collect() {
		foreach ( $this->fields as $field ) {
			$this->submitted[ $field['key'] ] = array(
				'value' => sanitize_text_field( wp_unslash( $_POST[ $field['key'] ] ) ),
			);
		}
	}

	// ruleid: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function register_new_user() {
		$role = $this->submitted['selected_role']['value'];
		wp_insert_user(
			array(
				'user_login' => $this->username,
				'user_email' => $this->email,
				'role'       => trim( $role ),
			)
		);
	}
}

class Registration_Handler_Fixed {
	private $valid_data = array();

	public function process_fields() {
		foreach ( $this->fields as $field ) {
			$type  = $field['blockName'];
			$value = sanitize_text_field( wp_unslash( $_POST[ $field['name'] ] ) );

			if ( 'my/user-roles' === $type && ! empty( $value ) ) {
				$allowed_roles = isset( $field['attrs']['roles'] ) ? array_keys( (array) $field['attrs']['roles'] ) : array();
				if ( ! in_array( $value, $allowed_roles, true ) ) {
					$value = '';
				}
			}

			$this->valid_data[ $field['name'] ] = array(
				'type'  => $type,
				'value' => $value,
			);
		}
	}

	// ok: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function create_user() {
		$role = 'customer';
		if ( ! empty( $this->valid_data['user_roles']['value'] ) ) {
			$role = $this->valid_data['user_roles']['value'];
		}
		add_filter(
			'woocommerce_new_customer_data',
			function ( $user_data ) use ( $role ) {
				$user_data['role'] = sanitize_text_field( $role );
				return $user_data;
			}
		);
	}
}

class Wpdb_Read_Example {
	// ok: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function get_row_by_key( $key ) {
		global $wpdb;
		return $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}my_table WHERE meta_key = %s", $key )
		);
	}
}

class Members_Update_Vulnerable {
	// ruleid: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function update( $data, $type = 'full' ) {
		$user          = $data['member'];
		$custom_fields = $data['data'];
		$user          = array_merge( $custom_fields, $user );

		$result = $this->form->validate( $user, $this->form_fields );
		$user   = $this->form->sanitize( $user, $this->form_fields );

		$result_profile = $this->update_profile_fields( $userid, $user, false );

		return $result_profile;
	}
}

class Community_Profile_Handler {
	// ruleid: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function save_profile( $request ) {
		$account       = $request['account'];
		$dynamic_field = $request['dynamic'];
		$account       = array_merge( $dynamic_field, $account );

		$account = $this->sanitize_fields( $account );

		$this->members->update_member_fields( $member_id, $account, false );
	}
}

class Members_Update_Fixed {
	// ok: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function update( $data, $type = 'full' ) {
		$user          = $data['member'];
		$custom_fields = $data['data'];
		$user          = array_merge( $custom_fields, $user );

		if ( $gid = (int) $user['groupid'] ) {
			if ( in_array( $gid, array( 1, 2, 4 ), true ) ) {
				unset( $user['groupid'] );
			}
		}

		$result = $this->form->validate( $user, $this->form_fields );
		$user   = $this->form->sanitize( $user, $this->form_fields );

		$result_profile = $this->update_profile_fields( $userid, $user, false );

		return $result_profile;
	}
}

class Settings_Cache_Merge_Example {
	// ok: claude.php.wordpress.access-control.role-field-value-no-allowlist-user-creation
	public function refresh_cache( $overrides ) {
		$config = $this->defaults;
		$config = array_merge( $overrides, $config );

		$this->cache->store( $cache_id, $config, false );
	}
}
