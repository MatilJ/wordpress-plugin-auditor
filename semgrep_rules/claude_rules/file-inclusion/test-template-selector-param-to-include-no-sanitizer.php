<?php
// Test file for lfi template-selector-param-to-include-no-sanitizer rule

class RendererBad {
	const LAYOUTS_DIR = '/plugin/views/layouts/';

	function add_extension($string = '', $extension = '.php') {
		if (substr($string, -strlen($extension)) === $extension) return $string;
		return $string . $extension;
	}

	function render($view, $layout = 'none', $extra_vars = array()) {
		if ($layout != 'none') {
			// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
			include self::LAYOUTS_DIR . $this->add_extension($layout, '.php');
		} else {
			include $this->add_extension($view, '.php');
		}
	}
}

function bad_direct_concat_include($template) {
	// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	require '/plugin/templates/' . $template . '.php';
}

class RendererGoodAllowlist {
	const LAYOUTS_DIR = '/plugin/views/layouts/';

	function render($view, $layout = 'none', $extra_vars = array()) {
		$layout = preg_replace('/[^a-zA-Z0-9_-]/', '', $layout);
		if ($layout != 'none') {
			// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
			include self::LAYOUTS_DIR . $layout . '.php';
		}
	}
}

function good_sanitize_file_name($template) {
	$template = sanitize_file_name($template);
	// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	require '/plugin/templates/' . $template . '.php';
}

// Pluggable-backend-by-name shape (CVE-2025-47672, miniOrange Discord
// Integration): an "app" selector picks which social/OAuth backend class
// file to load, concatenated straight into require with no charset/
// allow-list restriction anywhere in the function body.
function bad_oauth_app_dispatch($appname) {
	// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	require 'social_apps/class-mo-' . $appname . '.php';
}

function good_oauth_app_hardcoded($appname) {
	// Fix shape: the selector is no longer dynamic — the value is
	// discarded and replaced with a fixed literal before the require, so
	// no concatenation with a variable selector remains at the sink.
	$appname = 'discord';
	// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	require 'social_apps/class-discord.php';
}

// Resolver-returns-path shape (CVE-2025-12493, ShopLentor/WooLentor
// load_template): the concat lives in a sibling resolver method, the loader
// only checks file_exists() before including the resolved variable.
class GridLoaderBad {
	public function get_style_path( $style, $layout = 'grid' ) {
		return WOOLENTOR_DIR . 'templates/product-grid/' . $style . '.php';
	}

	public function load_template( $style, $layout, $products, $settings ) {
		// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
		$template_path = $this->get_style_path( $style, $layout );
		if ( file_exists( $template_path ) ) {
			include $template_path;
		}
	}
}

class GridLoaderGood {
	private function get_allowed_styles() {
		return [ 'modern' ];
	}

	public function get_style_path( $style ) {
		$base_dir = wp_normalize_path( WOOLENTOR_DIR . 'templates/product-grid/' );
		$candidate = wp_normalize_path( $base_dir . $style . '.php' );
		$real_base = wp_normalize_path( realpath( $base_dir ) );
		$real_target = wp_normalize_path( realpath( $candidate ) );
		if ( ! $real_target || strpos( $real_target, $real_base ) !== 0 ) {
			return '';
		}
		return $real_target;
	}

	public function load_template( $style, $layout, $products, $settings ) {
		$style = sanitize_key( $style );
		if ( ! in_array( $style, $this->get_allowed_styles(), true ) ) {
			$style = 'modern';
		}
		$template_path = $this->get_style_path( $style );
		// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
		if ( file_exists( $template_path ) ) {
			include $template_path;
		}
	}
}

// Shortcode-callback shape: the selector is not a formal parameter but a
// local variable produced by extract(shortcode_atts(...)) — the value is
// whatever renders the shortcode, and when another handler rebuilds and
// executes a shortcode string from request data this is unauthenticated LFI.
class ShortcodeTemplateBad {
	public static function custom_block( $atts ) {
		extract( shortcode_atts( array(
			'template' => '',
			'post_type' => 'post',
				), $atts ) );

		if ( empty( $template ) ) {
			return '';
		}
		ob_start();
		// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
		get_template_part( 'custom-templates/' . $template . '/index' );
		return ob_get_clean();
	}
}

class ShortcodeTemplateGood {
	public static function custom_block( $atts ) {
		extract( shortcode_atts( array(
			'template' => '',
			'post_type' => 'post',
				), $atts ) );

		if ( empty( $template ) ) {
			return '';
		}
		$template = basename( $template );
		ob_start();
		// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
		get_template_part( 'custom-templates/' . $template . '/index' );
		return ob_get_clean();
	}
}

// Allow-list validator function shape (CVE-2025-47670, miniOrange
// WordPress Social Login): the fix adds a helper that checks the selector
// against a static whitelist (in_array) and calls it as an early guard
// clause, wp_die()-ing on failure, instead of sanitizing the string itself.
function mo_validate_social_app_test($appname) {
	$allowed = array('google', 'facebook', 'twitter');
	return in_array(strtolower($appname), $allowed);
}

function good_oauth_app_allowlist_guard($appname) {
	if (!mo_validate_social_app_test($appname)) {
		wp_die('Invalid social app specified.');
	}
	// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	require 'social_apps/' . $appname . '.php';
}

// Same call site, but the guard never terminates execution on failure — the
// invalid value is still reachable at the sink, so this must still fire.
function bad_oauth_app_nonterminating_guard($appname) {
	if (!mo_validate_social_app_test($appname)) {
		error_log('invalid app: ' . $appname);
	}
	// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	require 'social_apps/' . $appname . '.php';
}

// Case-normalized selector shape (CVE-2025-62075, Simple Payment): a
// payment-"engine" dispatch selector is lowercased in place immediately
// before concatenation, guarded only by file_exists() (not a containment
// check), with no basename()/sanitize_file_name() anywhere in the function.
class EngineDispatchBad {
	function setEngine( $engine ) {
		if ( file_exists( PLUGIN_DIR . '/engines/' . strtolower( $engine ) . '.php' ) )
			// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
			require_once( PLUGIN_DIR . '/engines/' . strtolower( $engine ) . '.php' );
	}
}

// Same shape, uppercased selector + include_once, to confirm the
// strtoupper() variant is caught too.
function bad_driver_dispatch_strtoupper( $driver ) {
	// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	include_once( PLUGIN_DIR . '/drivers/' . strtoupper( $driver ) . '.php' );
}

// Fix shape (matches the real CVE-2025-62075 patch): the selector is reduced
// to a safe basename via wp_basename()+sanitize_file_name() BEFORE the
// strtolower()/concatenation, stripping any path-traversal segments.
class EngineDispatchGood {
	function setEngine( $engine ) {
		$filename = strtolower( sanitize_file_name( wp_basename( $engine, '.php' ) ) );
		// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
		if ( file_exists( PLUGIN_DIR . '/engines/' . $filename . '.php' ) )
			require_once( PLUGIN_DIR . '/engines/' . $filename . '.php' );
	}
}

// Fix shape variant: basename() alone (no sanitize_file_name()) applied to
// the selector before the case-normalization + concatenation.
function good_driver_dispatch_basename( $driver ) {
	$driver = basename( $driver );
	// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
	include_once( PLUGIN_DIR . '/drivers/' . strtoupper( $driver ) . '.php' );
}

// Template-partial-file shape: extract(shortcode_atts(...)) runs directly at
// file scope (no enclosing function - the file itself is the include target,
// loaded by a caller's template-loading wrapper), and the extracted selector
// reaches a second, custom (non-core) template-loading wrapper function.
// NOTE: kept as the LAST statements in this file — the file-scope (not
// function-scoped) pattern-not-inside FP-suppression clauses for this shape
// use an unanchored "..." that can match a sanitize_file_name()/basename()
// call anywhere later in the file, even inside an unrelated function/class;
// placing any later test case containing those calls after this block would
// wrongly suppress this true positive (and any true positive between here
// and that later call).
extract(shortcode_atts(array(
    'layout_style' => 'grid',
), $atts));
// ruleid: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
my_get_template('widget/layout/' . $layout_style . '.php', array('layout_style' => $layout_style));
