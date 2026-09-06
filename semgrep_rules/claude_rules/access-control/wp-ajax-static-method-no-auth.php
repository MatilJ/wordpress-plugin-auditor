<?php

class MyAjaxHandler {

    // ── Vulnerable: reads $_REQUEST, returns JSON, no auth gate ───────────────

    // ruleid: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function fill_compat_fields_action() {
        $query = isset( $_REQUEST['query'] ) ? $_REQUEST['query'] : array();
        $id    = isset( $_REQUEST['id'] ) ? (int) $_REQUEST['id'] : 0;
        $post  = get_post( $id );
        wp_send_json_success( array( 'title' => get_the_title( $post ) ) );
    }

    // ruleid: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function get_attachment_data_action() {
        $attachment_id = intval( $_POST['attachment_id'] );
        $data          = wp_get_attachment_metadata( $attachment_id );
        wp_send_json_success( $data );
    }

    // ── OK: nonce-checked before reading input ────────────────────────────────

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function set_parent_action() {
        check_ajax_referer( 'mla_admin_nonce_action', 'mla_admin_nonce' );
        $post_id = intval( $_REQUEST['post_ID'] );
        $updates = isset( $_REQUEST['custom_updates'] ) ? $_REQUEST['custom_updates'] : array();
        wp_send_json_success( array( 'updated' => $post_id ) );
    }

    // ── OK: check_ajax_referer() wrapped in an if(!...) condition — the standard
    //        WP AJAX nonce-fail-and-respond idiom, not a bare top-level statement ──

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function scan_action() {
        if ( ! check_ajax_referer( 'scan_form_nonce', false, false ) ) {
            wp_send_json_error( array( 'message' => 'Nonce verification failed!' ) );
        }
        $post_types = isset( $_POST['post_types'] ) ? $_POST['post_types'] : array();
        wp_send_json_success( array( 'types' => $post_types ) );
    }

    // ── OK: capability-checked before reading input ───────────────────────────

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function admin_only_action() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied', 403 );
        }
        $key = sanitize_key( $_GET['key'] );
        wp_send_json_success( get_option( $key ) );
    }

    // ── OK: admin referer nonce verified before reading input ─────────────────

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function dismiss_notice_action() {
        check_admin_referer( 'dismiss_notice_action', 'nonce' );
        $notice_id = sanitize_key( $_REQUEST['notice_id'] );
        update_user_meta( get_current_user_id(), 'dismissed_' . $notice_id, true );
        wp_send_json_success();
    }

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function dismiss_notice_conditional() {
        if ( isset( $_REQUEST['notice_index'] ) && check_admin_referer( 'dismiss_action', 'nonce' ) ) {
            $notice_id = sanitize_key( $_REQUEST['notice_index'] );
            update_user_meta( get_current_user_id(), 'dismissed_' . $notice_id, true );
            wp_send_json_success();
        }
        wp_send_json_error();
    }

    // ── OK: custom validate_nonce() wrapper internally calls check_ajax_referer()
    //        and current_user_can() — equivalent to inline nonce+cap checks.
    // Confirmed FP pattern: class with static validate_nonce($name) that wraps
    // wp_verify_nonce() + check_ajax_referer() + current_user_can('edit_posts').

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function get_redirect_url_safe() {
        $urls = ! empty( $_POST['urls'] ) ? $_POST['urls'] : null;
        self::validate_nonce( 'image' );
        $redirectUrls = array();
        foreach ( $urls as $url ) {
            $redirectUrls[ $url ] = esc_url_raw( $url );
        }
        wp_send_json_success( $redirectUrls );
    }

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function save_settings_safe() {
        $data = ! empty( $_POST['settings'] ) ? $_POST['settings'] : array();
        MyAjaxHandler::validate_nonce( 'setup' );
        wp_send_json_success( $data );
    }

    // ── OK: instance-method permission wrapper calls current_user_can() internally ──

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function fetch_items_safe() {
        $this->check_permission_nonce( 'my_action_scope' );
        $keyword = isset( $_POST['keyword'] ) ? $_POST['keyword'] : '';
        wp_send_json_success( array( 'keyword' => $keyword ) );
    }

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function refresh_tokens_safe() {
        self::check_permission_nonce( 'my_other_scope' );
        $value = isset( $_POST['value'] ) ? $_POST['value'] : '';
        wp_send_json_success( array( 'value' => $value ) );
    }

    // ── OK: class-qualified current_user_can() wrapper (e.g. Helper::current_user_can()) ──

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public static function required_plugin_activate() {
        if ( ! Helper::current_user_can() ) {
            wp_send_json_error( array( 'message' => 'Forbidden' ) );
        }
        $plugin = isset( $_POST['plugin'] ) ? $_POST['plugin'] : '';
        wp_send_json_success( array( 'plugin' => $plugin ) );
    }

    // ── Vulnerable: instance method, MVC request-wrapper property (not a raw
    //    superglobal), no nonce/capability check anywhere in the body ─────────

    // ruleid: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public function additional_user_info( $model, $service, $request, $params ) {
        $user_details = array();
        if ( ! empty( $request->req['user_ids'] ) ) {
            $user_ids     = $request->req['user_ids'];
            $user_details = $service->fetch_details( $user_ids );
        }
        wp_send_json_success( $user_details );
    }

    // ruleid: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public function export_records( $model, $service, $request, $params ) {
        $record_ids = $request->params['record_ids'];
        $records    = $service->get_records( $record_ids );
        wp_send_json_success( $records );
    }

    // ── OK: instance method, request-wrapper property, nonce + capability
    //        check combined in a single guarding if() condition ───────────────

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public function additional_user_info_fixed( $model, $service, $request, $params ) {
        if ( check_ajax_referer( 'secure_action', 'sec_nonce' ) && ( current_user_can( 'manage_options' ) || current_user_can( 'custom_manage_cap' ) ) ) {
            $user_details = array();
            if ( ! empty( $request->req['user_ids'] ) ) {
                $user_ids     = $request->req['user_ids'];
                $user_details = $service->fetch_details( $user_ids );
            }
            wp_send_json_success( $user_details );
        }
    }

    // ok: claude.php.wordpress.access.wp-ajax-static-method-no-auth
    public function export_records_fixed( $model, $service, $request, $params ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error();
        }
        $record_ids = $request->params['record_ids'];
        $records    = $service->get_records( $record_ids );
        wp_send_json_success( $records );
    }
}
