<?php
// Test cases for esc-url-raw-html-attribute-misuse

// ---- VULNERABLE: direct-inline concatenation into single-quoted href ----

$url = $_REQUEST['redirect'];
// ruleid: claude.php.wordpress.xss.esc-url-raw-html-attribute-misuse
$html .= "<a href='" . sanitize_url($url) . "'>";

// ---- VULNERABLE: direct-inline sprintf into single-quoted href ----

function render_link( $target ) {
    // ruleid: claude.php.wordpress.xss.esc-url-raw-html-attribute-misuse
    return sprintf( "<a href='%s'>link</a>", esc_url_raw( $target ) );
}

// ---- VULNERABLE: assign-then-concat, same function ----

function build_item_link( $raw_href, $link_markup ) {
    $link_href = sanitize_url( $raw_href );
    // ruleid: claude.php.wordpress.xss.esc-url-raw-html-attribute-misuse
    $link_markup = "<a href='" . $link_href . "'>" . $link_markup . '</a>';
    return $link_markup;
}

// ---- VULNERABLE: assign-then-preg_replace-replacement (merge-tag engine shape) ----

function mla_gallery_shortcode( $arguments, $item_values ) {
    $link_href = sanitize_url( self::mla_process_shortcode_parameter( $arguments['mla_link_href'], $item_values ) );
    // ruleid: claude.php.wordpress.xss.esc-url-raw-html-attribute-misuse
    $item_values['link'] = preg_replace( '# href=\'([^\']*)\'#', " href='{$link_href}'", $item_values['link'] );
    return $item_values;
}

// ---- SAFE: esc_url() default display context ----

$url = $_REQUEST['redirect'];
// ok: claude.php.wordpress.xss.esc-url-raw-html-attribute-misuse
$html .= '<a href=\'' . esc_url($url) . '\'>';

// ---- SAFE: sprintf with esc_url() ----

function render_link_safe( $target ) {
    // ok: claude.php.wordpress.xss.esc-url-raw-html-attribute-misuse
    return sprintf( '<a href=\'%s\'>link</a>', esc_url( $target ) );
}

// ---- SAFE: sanitize_url() used for db storage, not HTML output ----

function save_redirect_option( $raw_url ) {
    $clean_url = sanitize_url( $raw_url );
    update_option( 'my_plugin_redirect_url', $clean_url );
}

// ---- SAFE: sanitize_url() result re-wrapped in esc_attr() before use ----

function build_item_link_safe( $raw_href, $link_markup ) {
    $link_href = sanitize_url( $raw_href );
    // ok: claude.php.wordpress.xss.esc-url-raw-html-attribute-misuse
    $link_markup = '<a href=\'' . esc_attr( $link_href ) . '\'>' . $link_markup . '</a>';
    return $link_markup;
}
