<?php

$csp = trim( get_option( 'myplugin_csp_script_src' ) );
$rules_headers  = "<IfModule mod_headers.c>\n";
// ruleid: claude.php.wordpress.rce.webserver-directive-injection-from-option
$rules_headers .= '    Header set Content-Security-Policy "script-src ' . $csp . "\"\n";
$rules_headers .= "</IfModule>\n";
file_put_contents( ABSPATH . '.htaccess', $rules_headers, FILE_APPEND );

$origin = get_post_meta( $post_id, '_myplugin_cors_origin', true );
// ruleid: claude.php.wordpress.rce.webserver-directive-injection-from-option
$nginx_rules = "add_header Access-Control-Allow-Origin \"" . $origin . "\";\n";
file_put_contents( $nginx_conf_path, $nginx_rules, FILE_APPEND );

$referrer_policy = $config->get_string( 'security.referrer.policy.directive' );
// ruleid: claude.php.wordpress.rce.webserver-directive-injection-from-option
$rules .= '    Header always set Referrer-Policy "' . $referrer_policy . "\"\n";

$csp = sanitize_text_field( get_option( 'myplugin_csp_script_src' ) );
// ok: claude.php.wordpress.rce.webserver-directive-injection-from-option
$rules_headers .= '    Header set Content-Security-Policy "script-src ' . $csp . "\"\n";

$dir = get_option( 'myplugin_referrer_policy' );
$dir = Util_Rule::sanitize_directive_value( $dir );
// ok: claude.php.wordpress.rce.webserver-directive-injection-from-option
$rules_headers .= '    Header set Referrer-Policy "' . $dir . "\"\n";

// A stored value used in an ordinary DB read, not a directive-file write —
// the source/sink pairing itself does not apply.
$name = get_option( 'blogname' );
$greeting = 'Welcome to ' . $name;
// ok: claude.php.wordpress.rce.webserver-directive-injection-from-option
echo esc_html( $greeting );
