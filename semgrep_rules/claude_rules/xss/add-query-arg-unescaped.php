<?php
/**
 * Test cases for add-query-arg-unescaped.yaml
 * Rule id: claude.php.wordpress.xss.add-query-arg-unescaped
 *
 * Classic WordPress XSS: add_query_arg() without a base URL uses
 * $_SERVER['REQUEST_URI'] implicitly, so attacker-controlled query params
 * survive into the echoed URL. Must always wrap with esc_url() before output.
 */

// TP: add_query_arg() echoed without esc_url() — URL contains raw REQUEST_URI params
function tp_direct_echo_no_base() {
    $url = add_query_arg('page', '2');
    // ruleid: claude.php.wordpress.xss.add-query-arg-unescaped
    echo $url;
}

// TP: home_url(add_query_arg()) echoed without esc_url()
function tp_home_url_no_escape() {
    $url = home_url( add_query_arg( 'tab', 'settings' ) );
    // ruleid: claude.php.wordpress.xss.add-query-arg-unescaped
    echo $url;
}

// TP: inline echo without assignment
function tp_inline_no_escape() {
    // ruleid: claude.php.wordpress.xss.add-query-arg-unescaped
    echo add_query_arg( 'action', 'delete', get_permalink() );
}

// TP: used inside an HTML attribute without escaping
function tp_href_attr_no_escape() {
    $next = add_query_arg( 'paged', 2 );
    // ruleid: claude.php.wordpress.xss.add-query-arg-unescaped
    echo '<a href="' . $next . '">Next</a>';
}

// OK: wrapped with esc_url() before echo
function ok_esc_url() {
    $url = add_query_arg( 'page', '2' );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo esc_url( $url );
}

// OK: inline esc_url()
function ok_inline_esc_url() {
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo esc_url( add_query_arg( 'tab', 'general' ) );
}

// OK: home_url(add_query_arg()) wrapped with esc_url()
function ok_home_url_esc_url() {
    $url = home_url( add_query_arg( 'tab', 'settings' ) );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo esc_url( $url );
}

// OK: esc_attr used (valid for attribute context)
function ok_esc_attr() {
    $url = add_query_arg( 'action', 'delete' );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo esc_attr( $url );
}

// OK: used in wp_redirect() — not an echo sink
function ok_wp_redirect() {
    $url = add_query_arg( 'updated', '1', admin_url('admin.php') );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    wp_redirect( $url );
    exit;
}

// OK: used in wp_safe_redirect() — not an echo sink
function ok_wp_safe_redirect() {
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    wp_safe_redirect( add_query_arg( 'saved', 'true', admin_url('options-general.php') ) );
    exit;
}

// OK: add_query_arg() passed as 'base' to paginate_links() — paginate_links()
// applies esc_url() to all generated links internally; no raw URL reaches echo.
// Confirmed FP: responsive-lightbox 2.7.6 trait-gallery-image-methods.php:610
function ok_paginate_links_base() {
    $base_args = array( 'gallery_id' => 1, 'rl_page' => '%#%' );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo paginate_links( array(
        'base'    => add_query_arg( $base_args ),
        'format'  => '',
        'current' => 1,
        'total'   => 10,
    ) );
}

// OK: add_query_arg() wrapped with wp_nonce_url() before echo — wp_nonce_url()
// applies esc_html() internally so < > " & cannot produce injection.
// Confirmed FP: yarpp 5.30.11 YARPP_Admin.php (dismiss notice URL pattern).
function ok_wp_nonce_url_wraps_query_arg() {
    $dismiss_url = add_query_arg( array( 'action' => 'dismiss', 'page' => 'my-plugin' ) );
    $nonce_url   = wp_nonce_url( $dismiss_url, 'dismiss-notice' );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo $nonce_url;
}

// OK: inline wp_nonce_url() around add_query_arg()
function ok_wp_nonce_url_inline() {
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo wp_nonce_url( add_query_arg( 'action', 'delete', admin_url('admin.php') ), 'delete-item' );
}

// OK: add_query_arg() with an explicit admin_url() base, echoed directly with
// no esc_url() wrapper — the REQUEST_URI-fallback risk this rule targets is
// structurally absent since the base URL is a WP core generator, not implicit.
// Confirmed FP: woo-cart-abandonment-recovery 2.1.3 class-cartflows-ca-tabs.php
// (admin nav-tab URL builder, array key/values are plugin constants).
function ok_admin_url_base_array_form() {
    $url = add_query_arg( array(
        'page'   => WCF_CA_PAGE_NAME,
        'action' => WCF_ACTION_REPORTS,
    ), admin_url( '/admin.php' ) );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo $url;
}

// OK: 3-arg key/value form with an explicit home_url() base, echoed directly.
function ok_home_url_base_kv_form() {
    $url = add_query_arg( 'tab', 'settings', home_url( '/account/' ) );
    // ok: claude.php.wordpress.xss.add-query-arg-unescaped
    echo $url;
}

// TP: explicit base argument, but the base itself is the REQUEST_URI fallback
// this rule targets — not one of the trusted WP URL generators, so the
// exclusion must NOT apply.
function tp_explicit_request_uri_base_still_flagged() {
    $url = add_query_arg( array( 'paged' => 2 ), $_SERVER['REQUEST_URI'] );
    // ruleid: claude.php.wordpress.xss.add-query-arg-unescaped
    echo $url;
}

// TP: explicit base argument, but it's an arbitrary plugin variable (not a
// trusted WP core URL generator) — still flagged.
function tp_explicit_custom_var_base_still_flagged() {
    $current_url = 'https://example.com' . $_SERVER['REQUEST_URI'];
    $url = add_query_arg( array( 'paged' => 2 ), $current_url );
    // ruleid: claude.php.wordpress.xss.add-query-arg-unescaped
    echo $url;
}
