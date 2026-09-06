<?php
// Test fixture for claude.php.wordpress.xss.wp-user-profile-field-unescaped-output
// and claude.php.wordpress.xss.wp-user-profile-field-html-concat

// ruleid: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$tooltip = '<strong>Username: </strong>' . $user->data->user_login . '</br>';

// ruleid: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$tooltip .= '<strong>First name: </strong>' . $user->data->first_name . '</br>';

// ruleid: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$uhtml = '<a data-user="' . $user->user_login . '">' . $display_name . '</a>';

// ruleid: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$uhtml = '<a data-user="' . $user_data['display_name'] . '">' . $label . '</a>';

// ok: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$tooltip = '<strong>Username: </strong>' . esc_html( $user->data->user_login ) . '</br>';

// ok: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$uhtml = '<a data-user="' . esc_attr( $user->user_login ) . '">' . esc_html( $display_name ) . '</a>';

// direct source-to-sink for the taint rule (echo is the reported sink line)
// ruleid: claude.php.wordpress.xss.wp-user-profile-field-unescaped-output
echo $user->first_name;

// ruleid: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$line = '<em>' . $user->first_name . '</em>';
// ruleid: claude.php.wordpress.xss.wp-user-profile-field-unescaped-output
echo $line;

// ok: claude.php.wordpress.xss.wp-user-profile-field-unescaped-output
echo esc_html( $user->first_name );

// ok: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$line = '<em>' . esc_html( $user->first_name ) . '</em>';
// ok: claude.php.wordpress.xss.wp-user-profile-field-unescaped-output
echo $line;

// ok: claude.php.wordpress.xss.wp-user-profile-field-unescaped-output
$user_id = get_current_user_id();
echo esc_html( $user_id );

// ok: claude.php.wordpress.xss.wp-user-profile-field-html-concat
$label = '<option>' . \esc_html( $user->user_login . ' (' . $user->user_email . ')' ) . '</option>';
