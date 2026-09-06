<?php

/**
 * TP 1: base wp_upload_dir() directory + hardcoded filename, write happens
 * in a different method than the one that resolved the directory (mirrors
 * the real-world construct()-then-method() split).
 */
class QrLoginHandler {

	private $upload_dir;

	public function __construct() {
		$wp_uploads = wp_upload_dir();
		$this->upload_dir = untrailingslashit( wp_normalize_path( $wp_uploads['basedir'] ) ) . '/';
	}

	public function send_login_qr( $unique_url ) {
		$generator = new QrGenerator( $unique_url );
		$image = $generator->render_image();
		// ruleid: claude.php.wordpress.access-control.predictable-filename-image-write-web-accessible-dir
		imagepng( $image, $this->upload_dir . 'QR_Code.png' );
		wp_mail( 'user@example.com', 'Login', 'see attached', '', $this->upload_dir . 'QR_Code.png' );
		wp_delete_file( $this->upload_dir . 'QR_Code.png' );
	}
}

/**
 * TP 2: WP_CONTENT_DIR-derived property, imagejpeg with an explicit quality
 * argument (3-arg form), still a bare string-literal filename.
 */
class TwoFactorQrExporter {

	private $export_dir;

	public function init() {
		$this->export_dir = WP_CONTENT_DIR . '/2fa-exports/';
	}

	public function export( $image ) {
		// ruleid: claude.php.wordpress.access-control.predictable-filename-image-write-web-accessible-dir
		imagejpeg( $image, $this->export_dir . 'totp-secret.jpg', 90 );
	}
}

/**
 * OK 1: the real fix for this class of bug — render in memory only (no
 * path argument at all) and hand the bytes to the caller instead of
 * touching disk.
 */
class QrLoginHandlerFixed {

	public function send_login_qr( $unique_url ) {
		$generator = new QrGenerator( $unique_url );
		$image = $generator->render_image();
		ob_start();
		// ok: claude.php.wordpress.access-control.predictable-filename-image-write-web-accessible-dir
		imagepng( $image );
		$imagedata = ob_get_clean();
		return base64_encode( $imagedata );
	}
}

/**
 * OK 2: property-derived path, but the filename is per-user/unique rather
 * than a bare literal, so the guessable-static-name shape does not apply.
 */
class PerUserQrExporter {

	private $export_dir;

	public function init() {
		$this->export_dir = WP_CONTENT_DIR . '/qr-exports/';
	}

	public function export( $image, $user_id ) {
		$unique_name = $user_id . '-' . wp_generate_password( 12, false ) . '.png';
		// ok: claude.php.wordpress.access-control.predictable-filename-image-write-web-accessible-dir
		imagepng( $image, $this->export_dir . $unique_name );
	}
}

/**
 * OK 3: same web-accessible directory helper is used somewhere in the
 * class, but the actual write is a plain local variable, not a class
 * property, so it doesn't match the construct()-then-method() property
 * shape this rule targets.
 */
class LocalPathQrExporter {

	public function init() {
		$dir = wp_upload_dir();
		return $dir;
	}

	public function export( $image, $dir ) {
		$path = $dir['basedir'] . '/qr.png';
		// ok: claude.php.wordpress.access-control.predictable-filename-image-write-web-accessible-dir
		imagepng( $image, $path );
	}
}
