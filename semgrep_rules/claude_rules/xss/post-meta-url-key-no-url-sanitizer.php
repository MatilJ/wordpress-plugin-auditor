<?php
global $post_id, $user_id;

// sanitize_text_field preserves javascript:; key "link" matches URL pattern
// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_post_meta( $post_id, '_popup_button_link', sanitize_text_field( $_POST['button_link'] ) );

// update_option with URL-named key
// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_option( 'plugin_homepage_url', sanitize_text_field( $_POST['homepage'] ) );

// user meta with website-named key
// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_user_meta( $user_id, 'profile_website', sanitize_text_field( $_POST['website'] ) );

// split-assignment form: $VAL = sanitize_text_field(...); update_post_meta($id, url-key, $VAL)
// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
$redirect_url = sanitize_text_field( $_POST['redirect'] );
update_post_meta( $post_id, '_redirect_url', $redirect_url );

// esc_url_raw strips javascript: at write time
// ok: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_post_meta( $post_id, '_popup_button_link', esc_url_raw( $_POST['button_link'] ) );

// key "_popup_type" does not match any URL pattern term
// ok: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_post_meta( $post_id, '_popup_type', sanitize_text_field( $_POST['popup_type'] ) );

// key "_popup_open_trigger" has no URL term
// ok: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_post_meta( $post_id, '_popup_open_trigger', sanitize_text_field( $_POST['trigger'] ) );

// key matches "src" but value is absint — numeric, cannot be javascript: URI
// ok: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_post_meta( $post_id, '_hero_image_src_id', absint( $_POST['image_id'] ) );

// esc_attr() used directly as the (wrong) sanitizer on a literal URL-named key
// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
update_post_meta( $post_id, '_callback_endpoint', esc_attr( $_POST['endpoint'] ) );

// split-assignment with esc_attr()
// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
$profile_uri = esc_attr( $_POST['profile'] );
update_post_meta( $post_id, '_author_uri', $profile_uri );

// generic bulk meta-update loop: every field's value is blindly esc_attr()'d
// with no per-key type branching, so a URL-typed field never gets esc_url()
function bulk_update_meta( $item_id, array $fields ) {
	$sanitized = array();
	foreach ( $fields as $key => $value ) {
		// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
		$sanitized[ $key ] = esc_attr( trim( $value ) );
	}
	my_custom_meta_model_update( $item_id, $sanitized );
}

// same generic loop shape, but a different unrelated field name — still a TP
// because the loop itself has no per-key type branching
function bulk_update_settings( $id, array $fields ) {
	$out = array();
	foreach ( $fields as $key => $value ) {
		// ruleid: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
		$out[ $key ] = esc_attr( $value );
	}
	save_settings( $id, $out );
}

// fixed: the loop now branches per key via an allow-list before choosing the
// sanitizer, so URL-typed fields get esc_url_raw() instead of esc_attr()
function bulk_update_meta_fixed( $item_id, array $fields ) {
	$url_keys  = array( 'booking_url', 'profile_link' );
	$sanitized = array();
	foreach ( $fields as $key => $value ) {
		if ( in_array( $key, $url_keys, true ) ) {
			$sanitized[ $key ] = esc_url_raw( trim( $value ) );
		} else {
			// ok: claude.php.wordpress.xss.post-meta-url-key-no-url-sanitizer
			$sanitized[ $key ] = esc_attr( trim( $value ) );
		}
	}
	my_custom_meta_model_update( $item_id, $sanitized );
}
