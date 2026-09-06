<?php

class Vulnerable_Template_Loader {

	// ruleid: claude.php.wordpress.lfi.extract-before-template-path-resolve
	public static function get_template( $template_name, $args = array(), $template_path = '', $default_path = '' ) {
		if ( ! empty( $args ) && is_array( $args ) ) {
			extract( $args );
		}

		$located = self::locate_template( $template_name, $template_path, $default_path );

		if ( file_exists( $located ) ) {
			include $located;
		}
	}

	public static function locate_template( $name, $template_path, $default_path ) {
		return $default_path . $name;
	}
}

class Vulnerable_View_Loader {

	// ruleid: claude.php.wordpress.lfi.extract-before-template-path-resolve
	function render_view( $view, $data = array(), $path = '' ) {
		extract( $data );

		$located = static::resolve_view( $view, $path );

		if ( file_exists( $located ) ) {
			require $located;
		}
	}

	static function resolve_view( $name, $path ) {
		return $path . $name . '.php';
	}
}

class Patched_Template_Loader {

	// ok: claude.php.wordpress.lfi.extract-before-template-path-resolve
	public static function get_template( $template_name, $args = array(), $template_path = '', $default_path = '' ) {
		// Path resolved BEFORE extract() runs, so extract() cannot
		// clobber $template_name with an attacker-supplied value.
		$located = self::locate_template( $template_name, $template_path, $default_path );

		if ( ! empty( $args ) && is_array( $args ) ) {
			extract( $args );
		}

		if ( file_exists( $located ) ) {
			include $located;
		}
	}

	public static function locate_template( $name, $template_path, $default_path ) {
		return $default_path . $name;
	}
}

class Patched_With_Extr_Skip {

	// ok: claude.php.wordpress.lfi.extract-before-template-path-resolve
	public static function get_template( $template_name, $args = array(), $template_path = '', $default_path = '' ) {
		// EXTR_SKIP refuses to overwrite an existing variable, so
		// $template_name cannot be clobbered even though extract()
		// still runs before the path is resolved.
		if ( ! empty( $args ) && is_array( $args ) ) {
			extract( $args, EXTR_SKIP );
		}

		$located = self::locate_template( $template_name, $template_path, $default_path );

		if ( file_exists( $located ) ) {
			include $located;
		}
	}

	public static function locate_template( $name, $template_path, $default_path ) {
		return $default_path . $name;
	}
}

class Unrelated_Db_Read {

	// ok: claude.php.wordpress.lfi.extract-before-template-path-resolve
	public static function get_widget( $widget_id, $args = array() ) {
		global $wpdb;
		extract( $args );

		$row = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}widgets WHERE id = %d", $widget_id )
		);

		return $row;
	}
}
