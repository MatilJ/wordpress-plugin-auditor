<?php
// Test cases for style-tag-concat-unsanitized-css

// ---- VULNERABLE: direct 3-term concat, the real pre-fix shape (external/
// notified content returned raw inside a <style> wrapper, no sanitizer) ----

function prepare_ccss_test( $rules, $error_tag ) {
	// ruleid: claude.php.wordpress.xss.style-tag-concat-unsanitized-css
	return '<style id="my-ccss"' . $error_tag . '>' . $rules . '</style>';
}

// ---- VULNERABLE: 4-term trailing-tail shape — content appended after the
// closing tag, a common head-buffer accumulator idiom ----

function build_head_test( $ucss, $html_head ) {
	// ruleid: claude.php.wordpress.xss.style-tag-concat-unsanitized-css
	$html_head = '<style id="my-ucss">' . $ucss . '</style>' . $html_head;
	return $html_head;
}

// ---- VULNERABLE: double-quoted interpolation shape ----

function build_head_interpolated_test( $ucss ) {
	// ruleid: claude.php.wordpress.xss.style-tag-concat-unsanitized-css
	$out = "<style id=\"my-ucss\">$ucss</style>";
	return $out;
}

// ---- SAFE: the actual fix — sanitize with wp_strip_all_tags() before the
// value is persisted/concatenated into the <style> wrapper ----

function prepare_ccss_fixed_test( $rules, $error_tag ) {
	$rules = wp_strip_all_tags( $rules );
	// ok: claude.php.wordpress.xss.style-tag-concat-unsanitized-css
	return '<style id="my-ccss"' . $error_tag . '>' . $rules . '</style>';
}

// ---- SAFE: value sourced from a WP option/DB read, escaped with
// esc_html() directly at the concat site before being wrapped in <style> ----

function build_head_from_option_test() {
	$custom_css = get_option( 'my_plugin_custom_css' );
	// ok: claude.php.wordpress.xss.style-tag-concat-unsanitized-css
	$html_head = '<style id="my-custom">' . esc_html( $custom_css ) . '</style>';
	return $html_head;
}

// ---- VULNERABLE: persistence-side shape — apply_filters() output written
// to a static file with no tag-stripping sanitizer, the real pre-fix shape ----

function save_con_test( $type, $css, $queue_k ) {
	$css = apply_filters( 'my_plugin_' . $type, $css, $queue_k );
	$static_file = '/cache/' . md5( $css ) . '.css';
	// ruleid: claude.php.wordpress.xss.style-tag-concat-unsanitized-css
	File::save( $static_file, $css, true );
}

// ---- SAFE: persistence-side fix — wp_strip_all_tags() applied to the
// apply_filters() output before the file write ----

function save_con_fixed_test( $type, $css, $queue_k ) {
	$css = apply_filters( 'my_plugin_' . $type, $css, $queue_k );
	$css = wp_strip_all_tags( $css );
	$static_file = '/cache/' . md5( $css ) . '.css';
	// ok: claude.php.wordpress.xss.style-tag-concat-unsanitized-css
	File::save( $static_file, $css, true );
}
