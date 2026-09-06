<?php

class Vulnerable_Upload_Handler_A {
	// ruleid: claude.php.wordpress.xss.file-upload-name-only-mime-check
	public function handle_file_upload( $field, $file_object ) {
		$mime_types = array( '3gp' => 'video/3gpp', 'jpg' => 'image/jpeg' );
		$valid      = wp_check_filetype( $file_object['name'], $mime_types );

		if ( false === $valid['ext'] ) {
			return array( 'success' => false, 'message' => 'Extension not allowed.' );
		}

		$file_path = '/var/www/wp-content/uploads/forms/' . $file_object['name'];

		if ( false !== move_uploaded_file( $file_object['tmp_name'], $file_path ) ) {
			return array( 'success' => true, 'file_path' => $file_path );
		}

		return array( 'success' => false );
	}
}

class Vulnerable_Upload_Handler_B {
	// ruleid: claude.php.wordpress.xss.file-upload-name-only-mime-check
	public function save_attachment( $post_data ) {
		$name  = $post_data['name'];
		$check = wp_check_filetype( $name );
		if ( ! $check['ext'] ) {
			return false;
		}
		$dest = forminator_get_upload_path( $post_data['form_id'] ) . '/' . $name;
		move_uploaded_file( $post_data['tmp_name'], $dest );
		return $dest;
	}
}

// ok: claude.php.wordpress.xss.file-upload-name-only-mime-check
class Safe_Upload_Handler_Inline {
	public function handle_file_upload( $field, $file_object ) {
		$valid = wp_check_filetype( $file_object['name'] );
		if ( false === $valid['ext'] ) {
			return array( 'success' => false );
		}

		$wp_filetype = wp_check_filetype_and_ext( $file_object['tmp_name'], $file_object['name'] );
		if ( empty( $wp_filetype['ext'] ) || empty( $wp_filetype['type'] ) ) {
			return array( 'success' => false, 'message' => 'Type mismatch.' );
		}

		$file_path = '/var/www/wp-content/uploads/forms/' . $file_object['name'];
		move_uploaded_file( $file_object['tmp_name'], $file_path );
		return array( 'success' => true );
	}
}

// ok: claude.php.wordpress.xss.file-upload-name-only-mime-check
class Safe_Upload_Handler_Sibling_Method {
	public function handle_file_upload( $field, $file_object ) {
		$valid = wp_check_filetype( $file_object['name'] );
		if ( false === $valid['ext'] ) {
			return array( 'success' => false );
		}

		$valid_mime = self::check_mime_type( $file_object['tmp_name'], $file_object['name'] );
		if ( ! $valid_mime ) {
			return array( 'success' => false, 'message' => 'Type not allowed.' );
		}

		$file_path = '/var/www/wp-content/uploads/forms/' . $file_object['name'];
		move_uploaded_file( $file_object['tmp_name'], $file_path );
		return array( 'success' => true );
	}

	private static function check_mime_type( $file, $file_name ) {
		$wp_filetype = wp_check_filetype_and_ext( $file, $file_name );
		return ! empty( $wp_filetype['ext'] ) && ! empty( $wp_filetype['type'] );
	}
}

// ok: claude.php.wordpress.xss.file-upload-name-only-mime-check
class Safe_Standard_Wp_Handle_Upload {
	public function process_submission( $file_object ) {
		global $wpdb;
		$overrides = array( 'test_form' => false );
		$result    = wp_handle_upload( $file_object, $overrides );
		$row       = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE id = %d', $wpdb->prefix . 'forms', 1 ) );
		return $result;
	}
}
