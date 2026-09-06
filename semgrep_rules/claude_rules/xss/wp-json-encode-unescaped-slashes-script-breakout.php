<?php
// Test cases for claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
// Targets echo wp_json_encode(..., JSON_UNESCAPED_SLASHES) without JSON_HEX_TAG.
// JSON_UNESCAPED_SLASHES removes the / -> \/ escaping that prevents </script> breakout.

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// Form A: direct echo — JSON_UNESCAPED_SLASHES alone (actual audit pattern).
// inject_data_layer() echo in <script> block — confirmed TP from audit.
$data = [];
$data['shop']['list_name'] = 'Blog Post | ' . wp_specialchars_decode( get_the_title() );
// ruleid: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo wp_json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

// Form A variant: JSON_UNESCAPED_SLASHES as only flag.
$settings = get_option( 'plugin_settings' );
$settings['label'] = wp_specialchars_decode( get_post_meta( $post_id, 'custom_title', true ) );
// ruleid: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo wp_json_encode( $settings, JSON_UNESCAPED_SLASHES );

// Form B: concatenation echo with JSON_UNESCAPED_SLASHES.
$layer = [];
$layer['page'] = wp_specialchars_decode( get_the_title() );
// ruleid: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo 'window.dataLayer = ' . wp_json_encode( $layer, JSON_UNESCAPED_SLASHES ) . ';';

// Form C: assigned variable echoed later.
$datalayer = [ 'name' => wp_specialchars_decode( get_the_title() ) ];
// ruleid: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
$encoded = wp_json_encode( $datalayer, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
echo 'window.pmwDataLayer = Object.assign(window.pmwDataLayer, ' . $encoded . ');';

// Form D: flags stored in a variable then passed to wp_json_encode (actual audit pattern).
// inject_data_layer() at class-pixel-manager.php:1015+1030 uses this exact form.
// ruleid: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
$json_encode_options = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
$datalayer2 = $this->get_data_for_data_layer();
echo wp_json_encode( $datalayer2, $json_encode_options );

// Form E: flags-variable, concatenation echo form.
// ruleid: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
$opts = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
$layer2 = [ 'shop' => [ 'list_name' => wp_specialchars_decode( get_the_title() ) ] ];
echo 'window.pmwDataLayer = Object.assign(window.pmwDataLayer, ' . wp_json_encode( $layer2, $opts ) . ');';

// ─── Safe patterns ────────────────────────────────────────────────────────────

// JSON_HEX_TAG hex-encodes < and > — literal angle brackets cannot appear.
$safe_data = [ 'title' => wp_specialchars_decode( get_the_title() ) ];
// ok: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo wp_json_encode( $safe_data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );

// JSON_UNESCAPED_SLASHES combined with JSON_HEX_TAG — HEX_TAG takes precedence for <>.
$safe_data2 = [ 'url' => 'https://example.com/path' ];
// ok: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo wp_json_encode( $safe_data2, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG );

// Form D safe: flags variable includes JSON_HEX_TAG — < > are hex-encoded.
$safe_opts = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG;
$safe_layer = [ 'product' => [ 'id' => 42 ] ];
// ok: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo wp_json_encode( $safe_layer, $safe_opts );

// No JSON_UNESCAPED_SLASHES — PHP default escapes / to \/ (</script> blocked).
$safe_data3 = [ 'product' => [ 'id' => 42, 'sku' => 'ABC' ] ];
// ok: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo wp_json_encode( $safe_data3 );

// No JSON_UNESCAPED_SLASHES — JSON_UNESCAPED_UNICODE only (no slash impact).
$safe_data4 = [ 'title' => get_the_title() ];
// ok: claude.php.wordpress.xss.wp-json-encode-unescaped-slashes-script-breakout
echo wp_json_encode( $safe_data4, JSON_UNESCAPED_UNICODE );
