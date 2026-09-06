<?php

class SettingsPageVulnerable {
    public function render_settings_page() {
        global $template, $page_slug, $nonce_field;

        $page_slug = $this->page_slug;
        // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $template = !empty( $_GET['page_type'] ) ? sanitize_text_field( $_GET['page_type'] ) : 'general';
        $nonce_field = wp_nonce_field( 'settings_nonce', 'settings_nonce', true, false );
        include_once PLUGIN_SETTINGS_PATH . 'templates/main-template.php';
    }
}

function render_widget_view() {
    // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $view = sanitize_textarea_field( $_REQUEST['view'] );
    do_action( 'plugin_render_view', $view );
}

class SettingsPageFixed {
    public function render_settings_page() {
        global $template, $page_slug;

        $page_slug = $this->page_slug;
        // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $template = !empty( $_GET['page_type'] ) ? sanitize_file_name( $_GET['page_type'] ) : 'general';
        include_once PLUGIN_SETTINGS_PATH . 'templates/main-template.php';
    }
}

// tab/subtab admin-page dispatch idiom (CVE-2025-48338 shape): the
// top-level file gate reads $_GET['tab'] to pick which handler runs, and
// the subtab value is what actually gets concatenated into the include
// path further down in the same handler.
if ( is_admin() && isset( $_GET['tab'] ) && $_GET['tab'] === 'events' ) {
    // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $subtab = isset( $_GET['subtab'] ) ? sanitize_text_field( $_GET['subtab'] ) : 'manage';
    render_events_tab( $subtab );
}

function render_events_tab_fixed() {
    // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $subtab = isset( $_GET['subtab'] ) ? sanitize_file_name( $_GET['subtab'] ) : 'manage';
    render_events_tab( $subtab );
}

function get_search_results() {
    // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    // Variable name does not match the template/view/layout selector
    // naming convention -- sanitize_text_field() is adequate here since
    // this value is only ever used as a $wpdb prepared-query argument,
    // never as part of a file path.
    global $wpdb;
    $search_term = sanitize_text_field( $_GET['q'] );
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM modules WHERE name LIKE %s", '%' . $wpdb->esc_like( $search_term ) . '%' ) );
}

// Object-property variant (CVE-2025-54017 shape): a settings-page class
// caches the request-derived selector on an instance property in one
// method, and a sibling render method (invoked later via a WP action)
// concatenates that property into an include path guarded only by
// file_exists() -- the sanitize_text_field()/property-assignment pair is
// the detectable smell even though the eventual include is elsewhere.
class SettingsPageTabVulnerable {
    public $active_tab = 'general';

    public function init() {
        if ( isset( $_GET['tab'] ) )
            // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
            $this->active_tab = sanitize_text_field( $_GET['tab'] );
    }

    public function output() {
        if ( file_exists( PLUGIN_SETTINGS_PATH . 'views/view-page-settings-' . $this->active_tab . '.php' ) )
            include_once 'views/view-page-settings-' . $this->active_tab . '.php';
    }
}

class WidgetCurrentViewVulnerable {
    public function set_view() {
        // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $this->current_view = sanitize_textarea_field( $_POST['view'] );
    }
}

// Real pre-fix -> fix pair for CVE-2025-54017: the patch inserts an
// allow-list check (in_array() against the plugin's own known tab keys)
// between the sanitizer call and the property assignment, resetting the
// value to a safe default when it is not recognized.
class SettingsPageTabFixed {
    public $active_tab = 'general';

    public function init() {
        if ( isset( $_GET['tab'] ) ) {
            // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
            $tab = sanitize_text_field( $_GET['tab'] );

            if ( !in_array( $tab, array_keys( $this->get_tabs() ) ) ) {
                $tab = 'general';
            }

            // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
            $this->active_tab = $tab;
        }
    }
}

// get_query_var() source variant (CVE-2026-9290 shape, generalized: a
// public query var / rewrite tag is read straight into a profile/account
// tab selector with NO sanitizer at all, then interpolated into a
// get_template_part()/locate_template() slug elsewhere).
function get_active_profile_tab_vulnerable() {
    $registered  = get_registered_profile_tabs();
    $first_tab   = key( $registered );
    // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $profile_tab = get_query_var( 'tab', $first_tab );

    return $profile_tab;
}

class WidgetCurrentTabVulnerable {
    public function set_tab() {
        // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $this->current_tab = get_query_var( 'tab' );
    }
}

// Real pre-fix -> fix pair for CVE-2026-9290: the patch inserts an
// isset()-against-the-registered-tabs-array allow-list check between the
// unsanitized get_query_var() read and the value being trusted, resetting
// it to the known-good first tab when the requested key is not registered.
function get_active_profile_tab_fixed() {
    $registered  = get_registered_profile_tabs();
    $first_tab   = key( $registered );
    // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $profile_tab = get_query_var( 'tab', $first_tab );

    if ( ! isset( $registered[ $profile_tab ] ) ) {
        $profile_tab = $first_tab;
    }

    return $profile_tab;
}

// WP core reserves 'page'/'paged' for WP_Query pagination -- a
// get_query_var('page'|'paged') read is always the native pagination page
// number, never a file/template selector, even when the destination
// variable's own name coincidentally matches this rule's naming convention.
class PostsGridPagination {
    public function render( $has_pagination ) {
        $page_number = 1;
        if ( $has_pagination ) {
            // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
            $page_number = is_front_page() ? get_query_var( 'page' ) : get_query_var( 'paged' );
        }
        return $page_number;
    }
}

// WP DB-read pattern: get_query_var() feeding a $wpdb prepared query, not
// a file-selector name -- should not fire regardless of sanitizer.
function get_orders_for_status() {
    global $wpdb;
    $status = get_query_var( 'order_status', 'pending' );
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE status = %s", $status ) );
}

// filter_input()/FILTER_SANITIZE_STRING source variant (CVE-2025-39391
// shape): a settings-page dispatcher reads the tab selector through
// filter_input() instead of $_GET[] array access -- FILTER_SANITIZE_STRING
// strips tags only, never traversal sequences, and the value is handed
// unchecked to a sibling method that require_once's
// "{settings_path}/class-settings-{$current_tab}.php".
class ZamartzSettingsVulnerable {
    public function init() {
        // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $current_tab = filter_input( INPUT_GET, 'tab', FILTER_SANITIZE_STRING );
        if ( empty( $current_tab ) ) {
            $current_tab = 'general';
        }
        $this->get_page_content( $current_tab );
    }

    public function get_page_content( $current_tab ) {
        require_once $this->settings_path . "/class-settings-{$current_tab}.php";
    }
}

class WidgetActiveTabViaFilterInputVulnerable {
    public function set_tab() {
        // ruleid: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $this->active_tab = filter_input( INPUT_POST, 'tab', FILTER_SANITIZE_STRING );
    }
}

// Real pre-fix -> fix pair for CVE-2025-39391: the patch builds an
// allow-list from the plugin's own registered tab list and adds it as a
// second OR'd clause on the existing empty() guard, rather than replacing
// filter_input()/FILTER_SANITIZE_STRING with a path-safe sanitizer.
class ZamartzSettingsFixed {
    public function init() {
        $allowed_tabs = array_map( function( $item ) { return $item['slug']; }, $this->tab_list );

        // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $current_tab = filter_input( INPUT_GET, 'tab', FILTER_SANITIZE_STRING );
        if ( empty( $current_tab ) || ! in_array( $current_tab, $allowed_tabs, true ) ) {
            $current_tab = 'general';
        }
        $this->get_page_content( $current_tab );
    }
}

// filter_input() feeding a variable whose name does not match the
// template/view/layout selector naming convention, cast to int for a
// pagination comparison -- should not fire regardless of sanitizer.
function get_page_number() {
    // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $paged = filter_input( INPUT_GET, 'paged', FILTER_SANITIZE_STRING );
    return max( 1, (int) $paged );
}

// "page_id"/"post_id" is WordPress's own standard naming convention for a
// numeric post/page identifier -- used here only as an option-key suffix
// and an outbound URL path segment, never as a local include/require path,
// even though it matches this rule's "page" keyword + "_id" suffix shape.
function ajax_delete_critical_entry() {
    // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $page_id = sanitize_text_field( $_POST['page_id'] );
    delete_option( 'critical_' . $page_id );
}

class CriticalCssFetcherFixed {
    public function download() {
        // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
        $page_id = sanitize_text_field( $_GET['page_id'] );
        return wp_remote_get( REMOTE_API_HOST . '/v1/pages/' . $page_id . '/get' );
    }
}

// WP core also reserves 'cpage' for WP_Query comment pagination (the
// "current comment page" rewrite tag) -- a get_query_var('cpage') read is
// always the native comment-pagination page number, never a file/template
// selector, even when the destination variable's own name coincidentally
// matches this rule's naming convention (e.g. "$page").
function get_comments_page_offset() {
    // ok: claude.php.wordpress.lfi.global-template-selector-weak-sanitizer
    $page = get_query_var( 'cpage' );
    return max( 1, (int) $page ) - 1;
}
