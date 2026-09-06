<?php

// ruleid: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$html = sprintf('<a href="%2$s" target="%3$s"><h3>%1$s</h3></a>', $name, $website_url, $target);

// ruleid: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$img = sprintf('<img src="%1$s" alt="icon"/>', $this->props['custom_play_icon']);

// ruleid: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$video = sprintf('<video controls><source type="video/mp4" src="%1$s"></video>', $video);

// ruleid: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$link = sprintf('<a class="popup-trigger" href="%3$s">%1$s</a>', $text, $icon, $video_link);

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$safe_html = sprintf('<a href="%2$s"><h3>%1$s</h3></a>', $name, esc_url($website_url));

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$safe_img = sprintf('<img src="%1$s" alt="%2$s"/>', esc_url($image), esc_attr($alt));

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
echo sprintf('<div class="%1$s">%2$s</div>', $class, $content);

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
echo sprintf('<span data-id="%1$s">text</span>', $id);

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
// menu_page_url() unconditionally applies esc_url() to its return value
// before returning, regardless of the $display argument.
$settings_link = sprintf('<a href="%1$s">%2$s</a>', menu_page_url('my-plugin', false), 'Settings');

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$fqn_link = sprintf('<a href="%1$s">%2$s</a>', \menu_page_url('my-plugin', false), 'Settings');

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
// Hardcoded literal URL — cannot carry attacker-controlled bytes regardless
// of missing esc_url(). Confirmed FP source: templately 3.7.0
// FullSiteImport.php:735/819/1386 — translated support-link error messages.
$support_message = sprintf(__(" Please try again or contact <a href='%s' target='_blank'>support</a>.", 'my-plugin'), 'https://example.com/?support=open');

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$vendor_link = sprintf('<a target="_blank" href="%s">%s</a>', 'https://example.com/go/vendor', 'Vendor PRO');

// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
// Three-placeholder hardcoded form: two bare literal URLs plus a relative
// admin path built from a literal prefix concatenated with a plugin-defined
// UPPERCASE constant — none of the three arguments is request-controlled.
$notice = sprintf(
    __('Create a <a href="%s">tag</a>, add its <a href="%s">number</a>, on the <a href="%s">settings page</a>.', 'my-plugin'),
    'https://example.com/create-tag.html',
    'https://example.com/tag-id.html',
    '/wp-admin/options-general.php?page=' . MY_PLUGIN_PAGE_SLUG
);

// Single-placeholder form: the sole argument is a literal prefix
// concatenated with a plugin-defined UPPERCASE constant, not request input.
// ok: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$reminder = sprintf(
    __('Settings were migrated automatically. Review them on the <a href="%s">settings page</a>.', 'my-plugin'),
    '/wp-admin/options-general.php?page=' . MY_PLUGIN_PAGE_SLUG
);

// Same three-placeholder shape, but the third argument concatenates the
// literal prefix with a request-controlled variable, not an UPPERCASE
// constant — must still fire.
// ruleid: claude.php.wordpress.xss.sprintf-url-attr-no-esc-url
$notice_vuln = sprintf(
    __('Create a <a href="%s">tag</a>, add its <a href="%s">number</a>, on the <a href="%s">settings page</a>.', 'my-plugin'),
    'https://example.com/create-tag.html',
    'https://example.com/tag-id.html',
    '/wp-admin/options-general.php?page=' . $_GET['page']
);
