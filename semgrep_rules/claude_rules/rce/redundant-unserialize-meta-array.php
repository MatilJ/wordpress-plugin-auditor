<?php

function get_lead_fields_vulnerable( $post_id, $field_key ) {
	$custom_meta_fields = get_post_custom( $post_id );
	// ruleid: claude.php.wordpress.rce.redundant-unserialize-meta-array
	$value = maybe_unserialize( $custom_meta_fields[ $field_key ][0] );
	return $value;
}

function get_user_field_vulnerable( $user_id, $field_key ) {
	$all_meta = get_user_meta( $user_id );
	// ruleid: claude.php.wordpress.rce.redundant-unserialize-meta-array
	$value = unserialize( $all_meta[ $field_key ][0] );
	return $value;
}

function export_field_vulnerable( $post_id, $field_key ) {
	$custom_meta_fields = get_post_custom( $post_id );
	// ruleid: claude.php.wordpress.rce.redundant-unserialize-meta-array
	$field_value = maybe_unserialize( reset( $custom_meta_fields[ $field_key ] ) );
	return $field_value;
}

function get_lead_fields_fixed( $post_id, $field_key ) {
	$custom_meta_fields = get_post_custom( $post_id );
	// ok: claude.php.wordpress.rce.redundant-unserialize-meta-array
	$value = unserialize( $custom_meta_fields[ $field_key ][0], array( 'allowed_classes' => false ) );
	return $value;
}

function get_lead_fields_safe_direct_read( $post_id, $field_key ) {
	// ok: claude.php.wordpress.rce.redundant-unserialize-meta-array
	$value = get_post_meta( $post_id, $field_key, true );
	return $value;
}
