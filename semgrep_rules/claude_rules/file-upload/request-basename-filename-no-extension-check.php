<?php

// Vulnerable shape (CVE-2021-4443 class): an unauthenticated-reachable
// "compiler/cache save" AJAX action passes basename() of a request-supplied
// import path directly into a custom save delegate, with no extension
// allow-list anywhere in the function, and writes request-supplied content.
class Style_Compiler {
	public function compiler_save() {
		if ( ! isset( $_REQUEST['output']['imports'][0] ) || ! isset( $_REQUEST['output']['css'] ) ) {
			wp_die();
		}
		// ruleid: claude.php.wordpress.file-upload.request-basename-filename-no-extension-check
		$this->save_generated_file( str_replace( '.less', '.css', basename( $_REQUEST['output']['imports'][0] ) ), UPLOAD_DIR, stripslashes( $_REQUEST['output']['css'] ) );
		wp_die();
	}

	public function save_generated_file( $name, $dir, $content ) {
		if ( ! $name || ! $dir || ! $content ) {
			return;
		}
		global $wp_filesystem;
		$wp_filesystem->put_contents( trailingslashit( $dir ) . $name, $content );
	}
}

// Vulnerable shape: a direct file_put_contents() call with the destination
// built from basename() of a $_POST field concatenated onto a fixed
// directory -- no extension check anywhere in the function.
function save_uploaded_snippet() {
	$dest_dir = get_snippet_dir();
	// ruleid: claude.php.wordpress.file-upload.request-basename-filename-no-extension-check
	file_put_contents( trailingslashit( $dest_dir ) . basename( $_POST['snippet_name'] ), $_POST['snippet_body'] );
}

// Fixed shape (the real patch): an extension allow-list gates the write --
// only 'less'/'css' extensions are accepted before the save delegate runs.
class Style_Compiler_Fixed {
	public function compiler_save() {
		if ( ! isset( $_REQUEST['output']['imports'][0] ) || ! isset( $_REQUEST['output']['css'] ) ) {
			wp_die();
		}
		$file_ext = pathinfo( $_REQUEST['output']['imports'][0], PATHINFO_EXTENSION );
		if ( ! in_array( $file_ext, array( 'less', 'css' ) ) ) {
			wp_die( 'Cheating?' );
		}
		$file_name = str_replace( ".{$file_ext}", '.css', basename( $_REQUEST['output']['imports'][0] ) );
		// ok: claude.php.wordpress.file-upload.request-basename-filename-no-extension-check
		$this->save_generated_file( $file_name, UPLOAD_DIR, stripslashes( $_REQUEST['output']['css'] ) );
		wp_die();
	}

	public function save_generated_file( $name, $dir, $content ) {
		global $wp_filesystem;
		$wp_filesystem->put_contents( trailingslashit( $dir ) . $name, $content );
	}
}

// Unrelated WP DB-read pattern -- must not be flagged.
function get_snippet_by_id( $id ) {
	global $wpdb;
	// ok: claude.php.wordpress.file-upload.request-basename-filename-no-extension-check
	$row = $wpdb->get_row( "SELECT body FROM {$wpdb->prefix}snippets WHERE id = " . intval( $id ), ARRAY_A );
	return $row;
}
