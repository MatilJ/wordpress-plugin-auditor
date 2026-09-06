<?php

// Vulnerable shape (CVE-2021-38346 class): a low-level "store bytes to path"
// helper takes the raw content and a fixed-extension destination as its own
// two parameters and writes them directly, with no content-type validation
// anywhere in the enclosing class. The decode step lives in a public entry
// method several delegate calls away from the actual write.
class Screenshot_Manager {
	public function saveScreenshot( $uid, $imageContent, $postId ) {
		$path = $this->getPath( $uid, $postId );
		return $this->storeThumbnail( $imageContent, $path );
	}

	private function storeThumbnail( $content, $path ) {
		return $this->storeFile( $content, $path . '/' . 'screen.jpeg' );
	}

	private function storeFile( $content, $thumbnailFullPath ) {
		if ( ! file_exists( dirname( $thumbnailFullPath ) ) ) {
			@mkdir( dirname( $thumbnailFullPath ), 0755, true );
		}
		// ruleid: claude.php.wordpress.file-upload.content-param-write-helper-no-mime-check
		return file_put_contents( $thumbnailFullPath, $content ) !== false;
	}

	private function getPath( $uid, $postId ) {
		return get_upload_folder() . '/' . $postId;
	}
}

// Vulnerable shape: a different class/naming convention, same structural
// bug -- a thin write helper receiving (content, destination) with zero
// type validation anywhere in the class, reached from a public "persist"
// entry point one hop away.
class Media_Writer {
	public function persist( $bytes, $target ) {
		return $this->flush( $bytes, $target );
	}

	protected function flush( $data, $dest ) {
		// ruleid: claude.php.wordpress.file-upload.content-param-write-helper-no-mime-check
		file_put_contents( $dest, $data );
		return true;
	}
}

// Fixed shape (the real patch): the class now also defines a validator that
// calls mime_content_type() on the decoded bytes before the write is ever
// reached -- the check lives in a sibling method, not inside the low-level
// write helper itself, which is exactly the class-wide guard this rule uses.
class Screenshot_Manager_Fixed {
	public function saveScreenshot( $uid, $imageContent, $postId ) {
		if ( ! $this->validateImageContent( $imageContent ) ) {
			throw new Exception( 'Invalid image content' );
		}
		$path = $this->getPath( $uid, $postId );
		return $this->storeThumbnail( $imageContent, $path );
	}

	protected function validateImageContent( $imageContent ) {
		$tmp  = tempnam( get_temp_dir(), 'screen' );
		file_put_contents( $tmp, $imageContent );
		$mime = mime_content_type( $tmp );
		unlink( $tmp );
		return 'image/jpeg' === $mime;
	}

	private function storeThumbnail( $content, $path ) {
		return $this->storeFile( $content, $path . '/' . 'screen.jpeg' );
	}

	private function storeFile( $content, $thumbnailFullPath ) {
		// ok: claude.php.wordpress.file-upload.content-param-write-helper-no-mime-check
		return file_put_contents( $thumbnailFullPath, $content ) !== false;
	}

	private function getPath( $uid, $postId ) {
		return get_upload_folder() . '/' . $postId;
	}
}

// Fixed shape: WordPress-native content-type validation (wp_check_filetype_
// and_ext()) called from the public entry point before the thin write helper
// runs -- proves the class-wide guard also recognizes the standard WP check.
class Import_Attachment_Handler {
	public function importFile( $content, $originalName, $destPath ) {
		$filetype = wp_check_filetype_and_ext( $destPath, $originalName );
		if ( empty( $filetype['ext'] ) ) {
			return false;
		}
		return $this->writeToDisk( $content, $destPath );
	}

	private function writeToDisk( $data, $dest ) {
		// ok: claude.php.wordpress.file-upload.content-param-write-helper-no-mime-check
		file_put_contents( $dest, $data );
		return true;
	}
}

// Unrelated DB read, no file write at all -- confirms the rule stays
// silent on ordinary WordPress data-access code.
function log_screenshot_record( $post_id ) {
	global $wpdb;
	// ok: claude.php.wordpress.file-upload.content-param-write-helper-no-mime-check
	$row = $wpdb->get_row( "SELECT id FROM {$wpdb->prefix}brizy_screenshots WHERE post_id = " . intval( $post_id ), ARRAY_A );
	return $row;
}
