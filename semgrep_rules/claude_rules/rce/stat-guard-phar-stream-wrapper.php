<?php

function entry_delete_upload_files( $entry_model ) {
	foreach ( $entry_model->meta_data as $meta_data ) {
		$meta_value = $meta_data['value'];
		$path       = $meta_value['file']['file_path'];
		// ruleid: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
		if ( ! empty( $path ) && file_exists( $path ) ) {
			wp_delete_file( $path );
		}
	}
}

function cleanup_submission_attachment( $file_data ) {
	// ruleid: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	if ( is_file( $file_data['path'] ) ) {
		@unlink( $file_data['path'] );
	}
}

function entry_delete_upload_files_fixed( $entry_model, $upload_root ) {
	foreach ( $entry_model->meta_data as $meta_data ) {
		$meta_value = $meta_data['value'];
		$path       = $meta_value['file']['file_path'];
		$path       = realpath( $path );
		// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
		if ( ! $path || ! file_exists( $path ) ) {
			continue;
		}
		wp_delete_file( $path );
	}
}

function cleanup_cached_report() {
	// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	if ( file_exists( PLUGIN_DIR . '/cache/report.json' ) ) {
		unlink( PLUGIN_DIR . '/cache/report.json' );
	}
}

function cleanup_from_request_direct() {
	// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	if ( file_exists( $_POST['path'] ) ) {
		unlink( $_POST['path'] );
	}
}

function cleanup_validated_path( $path ) {
	validate_file( $path );
	// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	if ( file_exists( $path ) ) {
		unlink( $path );
	}
}

// The real CVE-2025-2105 pre-fix shape — naive scheme blacklist via a
// single non-recursive str_replace(), guard call is the trigger itself
// (no later sink needed), containment check present but too late.
function handle_file_download_vuln() {
	$file = filter_input( INPUT_GET, 'file' );
	// ruleid: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	$file = str_replace( [ 'phar://', 'zip://', 'ftp://', 'data://' ], '', base64_decode( $file ) );
	$upload_dir = wp_get_upload_dir();

	if ( empty( $file ) || ! file_exists( $file ) ) {
		wp_die();
	}

	$real_file_path = realpath( $file );

	if (
		false === $real_file_path ||
		0 !== strpos( wp_normalize_path( $file ), wp_normalize_path( $upload_dir['basedir'] ) )
	) {
		wp_die();
	}

	readfile( $file );
}

// Same naive-blacklist shape via preg_replace() instead of str_replace().
function handle_download_preg_variant() {
	$path = filter_input( INPUT_GET, 'path' );
	// ruleid: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	$path = preg_replace( [ '#phar://#', '#zip://#' ], '', base64_decode( $path ) );

	if ( ! is_readable( $path ) ) {
		wp_die();
	}

	echo file_get_contents( $path );
}

// The real fix — containment check runs BEFORE the guard call, not after.
function handle_file_download_fixed() {
	$file       = base64_decode( filter_input( INPUT_GET, 'file' ) );
	$upload_dir = wp_get_upload_dir();
	$root_path  = wp_normalize_path( $upload_dir['basedir'] );
	$file       = wp_normalize_path( $file );

	if ( strpos( $file, $root_path ) !== 0 ) {
		wp_die();
	}

	// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	if ( empty( $file ) || ! file_exists( $file ) ) {
		wp_die();
	}

	readfile( $file );
}

// str_replace() with needles unrelated to stream wrappers — out of scope.
function trim_label_prefix( $label ) {
	$label = str_replace( [ 'Mr. ', 'Mrs. ' ], '', $label );

	// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	if ( file_exists( $label ) ) {
		echo 'exists';
	}
}

class CacheIndexReader {
	public $cachedir;

	// $cacheFile is built by concatenating an internal property with a
	// FIXED STRING LITERAL suffix -- no request-derived remainder can ever
	// carry a phar:// scheme into this guard, regardless of $cacheFile's
	// own variable-rooted shape.
	public function read_index() {
		$cacheFile = $this->cachedir . '_cached.json';
		// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
		if ( file_exists( $cacheFile ) ) {
			return json_decode( file_get_contents( $cacheFile ), true );
		}
		return [];
	}
}

function read_fixed_cache_index() {
	$cacheFile = CACHE_DIR_CONST . '_cached.json';
	// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
	if ( file_exists( $cacheFile ) ) {
		return json_decode( file_get_contents( $cacheFile ), true );
	}
	return [];
}

class PluginLogReader {
	protected $filepath;

	// $filepath is assigned once, in the constructor, from a plugin-defined
	// path constant concatenated with a fixed string literal -- never
	// reassigned elsewhere in the class, regardless of which method later
	// reads the property.
	private function __construct() {
		$this->filepath = PLUGIN_DIR . '/logs.txt';
	}

	public function printLogs() {
		// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
		if ( is_file( $this->filepath ) ) {
			echo htmlspecialchars( file_get_contents( $this->filepath ) );
		}
	}
}

class PluginLogReaderTwoConcat {
	const FILENAME = 'logs.txt';
	protected $filepath;

	// $filepath is assigned once, in the constructor, from a path constant
	// concatenated with TWO fixed components -- a literal separator and a
	// class constant -- neither of which can carry a request-derived scheme.
	private function __construct() {
		$this->filepath = PLUGIN_DIR . '/' . self::FILENAME;
	}

	public function printLogs() {
		// ok: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
		if ( is_file( $this->filepath ) ) {
			echo htmlspecialchars( file_get_contents( $this->filepath ) );
		}
	}
}

class PluginImportReader {
	protected $importPath;

	// $importPath is assigned once, in the constructor, from request-derived
	// input with no literal-suffix guarantee -- must still fire.
	public function __construct() {
		$this->importPath = $_POST['import_path'];
	}

	public function readImport() {
		// ruleid: claude.php.wordpress.rce.stat-guard-phar-stream-wrapper
		if ( is_file( $this->importPath ) ) {
			echo file_get_contents( $this->importPath );
		}
	}
}
