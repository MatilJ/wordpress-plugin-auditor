<?php
// Test cases for
// claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass

// === TRUE POSITIVES — should match ===

function add_menus() {
    $minimum_capability = 'read';
    // ruleid: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
    if ( false === strpos( my_plugin::$settings['can_view'], (string) $GLOBALS['current_user']->user_login ) && ! empty( my_plugin::$settings['capability_can_view'] ) ) {
        $minimum_capability = my_plugin::$settings['capability_can_view'];
    }
    add_menu_page( 'My Plugin', 'My Plugin', $minimum_capability, 'my-plugin', 'render_page' );
}

function check_ajax_view_capability() {
    $minimum_capability = 'read';
    $current_user = wp_get_current_user();
    // ruleid: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
    if ( false !== strpos( get_option( 'plugin_can_view_list' ), $current_user->user_login ) ) {
        $minimum_capability = 'read';
    } else {
        $minimum_capability = get_option( 'plugin_capability_can_view', 'manage_options' );
    }
    return current_user_can( $minimum_capability );
}

class Abstract_Report {
    public function can_view(): bool {
        // ruleid: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
        if ( false !== strpos( ( my_plugin::$settings['can_view'] ?? '' ), (string) $GLOBALS['current_user']->user_login ) ) {
            return current_user_can( 'read' );
        }
        $minimum_capability = my_plugin::$settings['capability_can_view'] ?? 'manage_options';
        return current_user_can( $minimum_capability );
    }
}

function reversed_comparison_operand_order( $current_user ) {
    // ruleid: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
    if ( strpos( get_option( 'plugin_can_admin_list' ), $current_user->user_login ) === false ) {
        return false;
    }
    return true;
}

function bare_comparison_no_string_cast( $current_user ) {
    // ruleid: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
    $is_whitelisted = strpos( get_option( 'plugin_can_customize_list' ), $current_user->user_login ) !== false;
    return $is_whitelisted;
}

// === FALSE POSITIVES — should NOT match ===

// Exact, delimiter-aware membership test via in_array() on an exploded list —
// the actual fix pattern for this vulnerability class.
function add_menus_fixed() {
    $minimum_capability = 'read';
    $current_user = wp_get_current_user();
    $allowlist = array_map( 'trim', explode( ',', my_plugin::$settings['can_view'] ) );
    // ok: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
    if ( in_array( $current_user->user_login, $allowlist, true ) ) {
        $minimum_capability = 'read';
    } else {
        $minimum_capability = my_plugin::$settings['capability_can_view'];
    }
    return current_user_can( $minimum_capability );
}

// strpos() used for an unrelated, non-authorization purpose (a search/filter
// dimension over a stored dataset) — the needle is a dimension value, not the
// current user's own login, and the haystack is a per-row column, not an
// admin-configured allowlist.
function filter_visitor_rows( $rows, $search_term ) {
    $matches = array();
    foreach ( $rows as $row ) {
        // ok: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
        if ( false !== strpos( $row['username'], $search_term ) ) {
            $matches[] = $row;
        }
    }
    return $matches;
}

// strpos() against a hardcoded, developer-controlled string — not an
// admin-configurable allowlist, and the needle is not a user_login property.
function is_known_bot( $user_agent ) {
    // ok: claude.php.wordpress.access-control.strpos-username-allowlist-membership-bypass
    return false !== strpos( $user_agent, 'Googlebot' );
}
