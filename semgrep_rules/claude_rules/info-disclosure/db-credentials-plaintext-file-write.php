<?php

function generate_backup_payload_a( $migrate_key ) {
	$data = array(
		'db_password' => DB_PASSWORD,
		'db_host'     => DB_HOST,
	);
	$json = wp_json_encode( $data );
	$path = WP_CONTENT_DIR . '/instawpbackups/creds-' . substr( $migrate_key, 0, 5 ) . '.json';

	// ruleid: claude.php.wordpress.info-disclosure.db-credentials-plaintext-file-write
	file_put_contents( $path, $json );
}

function generate_backup_payload_b( $migrate_key ) {
	global $wp_filesystem;

	$data = array(
		'db_password' => DB_PASSWORD,
		'db_name'     => DB_NAME,
	);
	$json = wp_json_encode( $data );
	$path = WP_CONTENT_DIR . '/instawpbackups/creds-' . substr( $migrate_key, 0, 5 ) . '.txt';

	// ruleid: claude.php.wordpress.info-disclosure.db-credentials-plaintext-file-write
	$wp_filesystem->put_contents( $path, $json );
}

function generate_backup_payload_encrypted( $migrate_key ) {
	$data = array(
		'db_password' => DB_PASSWORD,
		'db_host'     => DB_HOST,
	);
	$json       = wp_json_encode( $data );
	$passphrase = openssl_digest( $migrate_key, 'SHA256', true );
	$encrypted  = openssl_encrypt( $json, 'AES-256-CBC', $passphrase );
	$path       = WP_CONTENT_DIR . '/instawpbackups/creds-' . substr( $migrate_key, 0, 5 ) . '.txt';

	// ok: claude.php.wordpress.info-disclosure.db-credentials-plaintext-file-write
	file_put_contents( $path, $encrypted );
}

function export_public_settings() {
	$data = array(
		'site_url'   => site_url(),
		'wp_version' => get_bloginfo( 'version' ),
	);
	$json = wp_json_encode( $data );
	$path = WP_CONTENT_DIR . '/instawpbackups/settings.json';

	// ok: claude.php.wordpress.info-disclosure.db-credentials-plaintext-file-write
	file_put_contents( $path, $json );
}
