<?php
/**
 * Test cases for claude.php.wordpress.access-control.capability-check-without-nonce-verification
 *
 * The rule fires (join mode, reported on the callback function) when a callback
 * registered on admin_action_ / admin_post_ / wp_ajax_ :
 *  1. Calls current_user_can() somewhere in its body (inline or in an if-guard)
 *  2. Never calls wp_verify_nonce() / check_admin_referer() / check_ajax_referer()
 *     anywhere in its body
 */

// ── MATCH: admin_action_ handler, inline current_user_can(), no nonce check ───
// Pattern from happy-elementor-addons 3.22.0 classes/clone-handler.php:61-94 —
// Clone_Handler::duplicate_thing() reads $_GET['_wpnonce'] into a variable but
// never verifies it; only capability checks gate the state-changing clone.

add_action( 'admin_action_ha_duplicate_thing', [ Clone_Handler::class, 'duplicate_thing' ] );

class Clone_Handler {
    // ruleid: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    public static function duplicate_thing() {
        if ( ! current_user_can( 'edit_posts' ) ) {
            return;
        }

        $nonce   = isset( $_GET['_wpnonce'] ) ? $_GET['_wpnonce'] : '';
        $post_id = isset( $_GET['post_id'] ) ? absint( $_GET['post_id'] ) : 0;

        if ( ! current_user_can( 'edit_post', $post_id ) ) {
            wp_die( 'Sorry, you are not allowed to clone this item.' );
        }

        $new_id = self::duplicate_post( $post_id );
        wp_safe_redirect( admin_url( 'edit.php' ) );
        die();
    }

    private static function duplicate_post( $post_id ) {
        return wp_insert_post( [ 'post_title' => 'Clone' ] );
    }
}

// ── MATCH: wp_ajax_ handler, current_user_can() in if-guard, no nonce check ───

add_action( 'wp_ajax_reset_widget_state', 'ajax_reset_widget_state_no_nonce' );

// ruleid: claude.php.wordpress.access-control.capability-check-without-nonce-verification
function ajax_reset_widget_state_no_nonce() {
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_send_json_error( 'Unauthorized' );
    }
    $widget_id = sanitize_text_field( $_POST['widget_id'] );
    delete_option( 'widget_state_' . $widget_id );
    wp_send_json_success();
}

// ── NO MATCH: same shape but wp_verify_nonce() is present ─────────────────────

add_action( 'admin_action_ha_duplicate_thing_safe', [ Clone_Handler_Safe::class, 'duplicate_thing' ] );

class Clone_Handler_Safe {
    // ok: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    public static function duplicate_thing() {
        if ( ! current_user_can( 'edit_posts' ) ) {
            return;
        }
        if ( ! wp_verify_nonce( $_GET['_wpnonce'], 'ha_duplicate_thing' ) ) {
            wp_die( 'Invalid request.' );
        }
        $post_id = absint( $_GET['post_id'] );
        if ( ! current_user_can( 'edit_post', $post_id ) ) {
            wp_die( 'Sorry, you are not allowed to clone this item.' );
        }
        wp_safe_redirect( admin_url( 'edit.php' ) );
        die();
    }
}

// ── NO MATCH: check_admin_referer() present ────────────────────────────────────

add_action( 'admin_post_save_plugin_widget', 'save_plugin_widget_with_referer' );

// ok: claude.php.wordpress.access-control.capability-check-without-nonce-verification
function save_plugin_widget_with_referer() {
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_die( 'Unauthorized' );
    }
    check_admin_referer( 'save_plugin_widget' );
    update_option( 'plugin_widget_state', sanitize_text_field( $_POST['state'] ) );
    wp_safe_redirect( admin_url( 'edit.php' ) );
}

// ── NO MATCH: nonce check delegated to a private helper defined AFTER the
// callback in the same class, invoked via $this->helper() ────────────────────

add_action( 'admin_post_save_widget_via_helper', array( 'Widget_Controller', 'save' ) );

class Widget_Controller {
    // ok: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    public function save() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }
        $inner = function () {
            update_option( 'widget_state', sanitize_text_field( $_POST['state'] ) );
        };
        $this->create_and_update( $inner );
    }

    private function create_and_update( $closure ) {
        $nonce = isset( $_POST['_wpnonce_widget'] ) ? $_POST['_wpnonce_widget'] : '';
        if ( wp_verify_nonce( $nonce, 'widget-edit' ) ) {
            $closure();
        }
    }
}

// ── NO MATCH: nonce check delegated to a private helper defined BEFORE the
// callback in the same class ──────────────────────────────────────────────────

add_action( 'admin_post_update_condition_via_helper', array( 'Condition_Controller', 'update' ) );

class Condition_Controller {
    private function create_and_update( $closure, $action ) {
        $nonce          = isset( $_POST['_wpnonce_condition'] ) ? $_POST['_wpnonce_condition'] : '';
        $nonce_verified = wp_verify_nonce( $nonce, $action );
        if ( $nonce_verified ) {
            $closure();
        }
    }

    // ok: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    public function update() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }
        $inner = function () {
            update_option( 'condition_state', sanitize_text_field( $_POST['state'] ) );
        };
        $this->create_and_update( $inner, 'cnb-condition-edit' );
    }
}

// ── MATCH: callback delegates to a helper method, but the helper does NOT
// perform any nonce check — delegation alone must not suppress the finding ────

add_action( 'admin_post_activate_via_helper', array( 'Ott_Like_Controller', 'activate' ) );

class Ott_Like_Controller {
    // ruleid: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    public function activate() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }
        $this->parse_header();
    }

    private function parse_header() {
        $api_key = isset( $_GET['api_key'] ) ? sanitize_text_field( $_GET['api_key'] ) : '';
        update_option( 'cnb', array( 'api_key' => $api_key ) );
    }
}

// ── NO MATCH: hook is not admin_action_ / admin_post_ / wp_ajax_ / admin_init ─

add_action( 'init', 'register_plugin_post_type_no_nonce' );

// ok: claude.php.wordpress.access-control.capability-check-without-nonce-verification
function register_plugin_post_type_no_nonce() {
    if ( ! current_user_can( 'edit_posts' ) ) {
        return;
    }
    register_post_type( 'plugin_cpt' );
}

// ── MATCH: admin_init handler, own internal request-param dispatch, capability
// check present, no nonce check anywhere, write delegated to a static helper ──

add_action( 'admin_init', [ Blank_Page_Creator::class, 'handle_blank_page_request' ] );

class Blank_Page_Creator {
    const ACTION_PARAM = 'plugin_create_blank_page';

    // ruleid: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    public function handle_blank_page_request() {
        $action = isset( $_GET['action'] ) ? sanitize_text_field( $_GET['action'] ) : '';
        if ( self::ACTION_PARAM !== $action ) {
            return;
        }
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Insufficient permissions.', 403 );
        }
        $page_id = Page_Utils::create_blank_page();
        wp_safe_redirect( admin_url( 'post.php?post=' . $page_id . '&action=edit' ) );
        exit;
    }
}

// ── NO MATCH: same admin_init shape, but check_admin_referer() is present ─────

add_action( 'admin_init', [ Blank_Page_Creator_Safe::class, 'handle_blank_page_request' ] );

class Blank_Page_Creator_Safe {
    const ACTION_PARAM = 'plugin_create_blank_page_safe';

    // ok: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    public function handle_blank_page_request() {
        $action = isset( $_GET['action'] ) ? sanitize_text_field( $_GET['action'] ) : '';
        if ( self::ACTION_PARAM !== $action ) {
            return;
        }
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Insufficient permissions.', 403 );
        }
        check_admin_referer( 'plugin_create_blank_page_safe' );
        $page_id = Page_Utils::create_blank_page();
        wp_safe_redirect( admin_url( 'post.php?post=' . $page_id . '&action=edit' ) );
        exit;
    }
}

// ── NO MATCH: nonce verification performed by a custom auth-wrapper call
// (__::isAuthentic) rather than a direct wp_verify_nonce()/check_ajax_referer()
// call in the callback's own body — confirmed by source review that the wrapper
// internally calls check_ajax_referer()+wp_verify_nonce()+current_user_can(). ──

add_action( 'wp_ajax_media_make_private', array( 'Media_Access_Control', 'makeMediaPrivate' ) );

class Media_Access_Control {
    // ok: claude.php.wordpress.access-control.capability-check-without-nonce-verification
    function makeMediaPrivate() {
        __::isAuthentic( 'mmpnonce', NONCE_KEY, 'edit_posts' );
        $id = absint( $_POST['mediaid'] );
        if ( ! current_user_can( 'edit_post', $id ) ) {
            wp_send_json( array( 'success' => false ) );
        }
        update_post_meta( $id, '__wpdm_private', 1 );
        wp_send_json_success();
    }
}
