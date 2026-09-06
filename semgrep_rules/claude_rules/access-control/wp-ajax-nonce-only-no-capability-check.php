<?php
/**
 * Test cases for wp-ajax-nonce-only-no-capability-check.yaml
 * Rule id: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
 *
 * NOTE: join mode requires `semgrep login`. Run:
 *   semgrep --config <rule.yaml> <this-file.php>
 */

// ── OOP class ─────────────────────────────────────────────────────────────────

class PluginMoveHandler {

    public function setup() {
        add_action( 'wp_ajax_move_ticket_type',  [ $this, 'move_ticket_type_requests' ] );
        add_action( 'wp_ajax_move_tickets',      [ $this, 'move_tickets_request' ] );
        add_action( 'wp_ajax_secured_operation', [ $this, 'secured_handler' ] );
        add_action( 'wp_ajax_cap_gated_op',      [ $this, 'cap_gated_handler' ] );
        add_action( 'wp_ajax_seating_handler',   [ $this, 'seating_operation' ] );
    }

    // TP: verifies nonce in if-guard, no current_user_can(), delegates write to helper.
    // Mirrors the ET-001 pattern: nonce checked at handler entry, write inside called method.
    // ruleid: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function move_ticket_type_requests() {
        $args = wp_parse_args( $_POST, [
            'check'          => '',
            'ticket_type_id' => 0,
            'target_post_id' => 0,
        ] );
        if ( ! wp_verify_nonce( $args['check'], 'move_tickets' ) ) {
            wp_send_json_error();
        }
        $ticket_type_id = absint( $args['ticket_type_id'] );
        $destination_id = absint( $args['target_post_id'] );
        if ( ! $this->move_ticket_type( $ticket_type_id, $destination_id ) ) {
            wp_send_json_error( [ 'message' => 'could not be moved' ] );
        }
        wp_send_json_success( [ 'remove_ticket_type' => $ticket_type_id ] );
    }

    protected function move_ticket_type( $ticket_type_id, $destination_id ) {
        update_post_meta( $ticket_type_id, '_event_for', $destination_id );
        return true;
    }

    // TP: check_ajax_referer present, no current_user_can(), direct meta write in handler.
    // ruleid: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function move_tickets_request() {
        $check = sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) );
        check_ajax_referer( 'move_tickets', $check );
        $attendee_id  = absint( $_POST['attendee_id'] ?? 0 );
        $target_event = absint( $_POST['target_event'] ?? 0 );
        update_post_meta( $attendee_id, '_event', $target_event );
        wp_send_json_success();
    }

    // OK: nonce check AND current_user_can() present.
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function secured_handler() {
        if ( ! wp_verify_nonce( $_POST['nonce'] ?? '', 'secured_action' ) ) {
            wp_send_json_error();
        }
        if ( ! current_user_can( 'edit_others_posts' ) ) {
            wp_send_json_error( [ 'message' => 'Forbidden' ] );
        }
        $id = absint( $_POST['id'] ?? 0 );
        update_post_meta( $id, '_secured_key', sanitize_text_field( $_POST['value'] ?? '' ) );
        wp_send_json_success();
    }

    // OK: check_ajax_referer + current_user_can() in if-guard.
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function cap_gated_handler() {
        check_ajax_referer( 'cap_gated_nonce', 'security' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( -1 );
        }
        update_option( 'my_plugin_setting', sanitize_text_field( $_POST['value'] ?? '' ) );
        wp_send_json_success();
    }

    // OK: uses check_current_ajax_user_can() capability wrapper — excluded by pattern-not.
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function seating_operation() {
        if ( ! check_current_ajax_user_can( 'edit_posts' ) ) {
            wp_send_json_error( [ 'error' => 'Forbidden' ], 403 );
        }
        check_ajax_referer( 'seating_nonce', 'nonce' );
        $seat_id = absint( $_POST['seat_id'] ?? 0 );
        update_post_meta( $seat_id, '_seat_data', sanitize_text_field( $_POST['data'] ?? '' ) );
        wp_send_json_success();
    }
}

// ── Standalone functions ───────────────────────────────────────────────────────

// TP: nonce-only, no current_user_can(), option write.
// ruleid: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
function plugin_save_settings_ajax() {
    if ( false === wp_verify_nonce( $_POST['_wpnonce'] ?? '', 'plugin_save_settings' ) ) {
        wp_die( -1 );
    }
    $val = sanitize_text_field( $_POST['setting'] ?? '' );
    update_option( 'plugin_setting', $val );
    wp_send_json_success();
}

// OK: nonce + current_user_can() both present.
// ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
function plugin_save_settings_safe() {
    if ( false === wp_verify_nonce( $_POST['_wpnonce'] ?? '', 'plugin_save_settings' ) ) {
        wp_die( -1 );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( [ 'message' => 'Insufficient permissions' ] );
    }
    update_option( 'plugin_setting', sanitize_text_field( $_POST['setting'] ?? '' ) );
    wp_send_json_success();
}

// OK: static self::verify_access() wrapper encapsulates both nonce and capability checks.
// ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
function ajax_with_static_wrapper() {
    self::verify_access();
    update_post_meta( absint( $_POST['id'] ?? 0 ), '_data', sanitize_text_field( $_POST['v'] ?? '' ) );
    wp_send_json_success();
}

add_action( 'wp_ajax_plugin_save_settings',      'plugin_save_settings_ajax' );
add_action( 'wp_ajax_plugin_save_settings_safe', 'plugin_save_settings_safe' );
add_action( 'wp_ajax_static_wrapper_action',     'ajax_with_static_wrapper' );
add_action( 'wp_ajax_non_wrapper_assign_check',  'ajax_non_wrapper_assign_check' );

// ── OOP class with Helper::is_current_user_allowed() wrapper ─────────────────
// AdTribes/Rymera pattern: is_current_user_allowed() calls
// current_user_can('manage_adtribes_product_feeds').

class AdTribes_Feed_Admin {

    public function setup() {
        add_action( 'wp_ajax_adt_update_settings', [ $this, 'ajax_update_settings' ] );
        add_action( 'wp_ajax_adt_delete_feed',     [ $this, 'ajax_delete_feed' ] );
    }

    // OK: nonce + Helper::is_current_user_allowed() wrapper — excluded by pattern-not.
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function ajax_update_settings() {
        check_ajax_referer( 'woosea_ajax_nonce', 'security' );
        if ( ! Helper::is_current_user_allowed() ) {
            wp_send_json_error( 'Unauthorized' );
        }
        update_option( 'adt_pfp_setting', sanitize_text_field( $_POST['value'] ?? '' ) );
        wp_send_json_success();
    }

    // OK: nonce + standalone Helper::is_current_user_allowed() call.
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function ajax_delete_feed() {
        check_ajax_referer( 'adt_nonce', 'security' );
        Helper::is_current_user_allowed();
        $feed_id = absint( $_POST['id'] ?? 0 );
        wp_delete_post( $feed_id, true );
        wp_send_json_success();
    }
}

// ── hasCapability() static/instance wrapper ───────────────────────────────────

class PluginWithHasCapWrapper {
    public function setup() {
        add_action( 'wp_ajax_plugin_reset_all', [ $this, 'ajaxResetAll' ] );
        add_action( 'wp_ajax_plugin_save_view', [ $this, 'ajaxSaveView' ] );
    }

    // OK: nonce + static hasCapability() wrapper — wraps current_user_can()
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function ajaxResetAll() {
        check_ajax_referer( 'plugin_reset_all', 'nonce' );
        PluginUtil::hasCapability( 'export', 'throw' );
        delete_option( 'plugin_settings' );
        wp_send_json_success();
    }

    // OK: nonce + instance hasCapability() wrapper
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function ajaxSaveView() {
        check_ajax_referer( 'plugin_save_view', 'nonce' );
        $this->hasCapability( 'export' );
        update_option( 'plugin_view_state', sanitize_text_field( $_POST['state'] ?? '' ) );
        wp_send_json_success();
    }
}

// ── Generalized capability-wrapper naming convention + assign-then-check ─────
// Confirmed real-world pattern: ES_Common::ig_es_can_access('settings') result
// assigned to a variable, then negate-checked in a separate if-statement,
// rather than called bare or inlined in the if-condition — not covered by
// the hardcoded wrapper-name list above, and not covered by a bare/inline
// call shape either.

class GeneralizedWrapperAjaxHandler {
    public function setup() {
        add_action( 'wp_ajax_dismiss_promo', [ $this, 'dismiss_promo' ] );
        add_action( 'wp_ajax_save_upsell', [ $this, 'save_upsell_bare_wrapper' ] );
    }

    // OK: static wrapper matching the generalized can_access naming
    // convention, assign-then-negate-check shape.
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function dismiss_promo() {
        check_ajax_referer( 'plugin-admin-ajax-nonce', 'security' );
        $can_access_settings = ES_Common::ig_es_can_access( 'settings' );
        if ( ! $can_access_settings ) {
            return 0;
        }
        update_option( 'plugin_promotion_notice_dismissed', 'yes', false );
    }

    // OK: static wrapper matching the generalized naming convention, bare-call shape.
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function save_upsell_bare_wrapper() {
        check_ajax_referer( 'plugin-admin-ajax-nonce', 'security' );
        ES_Common::ig_es_can_access( 'settings' );
        update_option( 'plugin_upsell_flow', sanitize_text_field( $_POST['flow'] ?? '' ) );
        wp_send_json_success();
    }
}

// TP: assign-then-check shape present, but the assigned call is NOT a
// capability-wrapper name — must still fire.
// ruleid: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
function ajax_non_wrapper_assign_check() {
    check_ajax_referer( 'plugin-nonce', 'security' );
    $log_result = log_request_bare_ajax( 'save' );
    if ( ! $log_result ) {
        return;
    }
    update_option( 'my_plugin_data', sanitize_text_field( $_POST['val'] ?? '' ) );
    wp_send_json_success();
}

function log_request_bare_ajax( $action ) {
    return false;
}

// ── Class-qualified current_user_can() wrapper (e.g. Helper::current_user_can()) ──

class PluginWithHelperCapWrapper {
    public function setup() {
        add_action( 'wp_ajax_plugin_update_block', [ $this, 'update_allowed_block' ] );
    }

    // OK: check_ajax_referer + Helper::current_user_can() wrapper call in if-guard —
    // excluded by pattern-not (mirrors SureForms's Helper::current_user_can() pattern).
    // ok: claude.php.wordpress.access.wp-ajax-nonce-only-no-capability-check
    public function update_allowed_block() {
        if ( ! Helper::current_user_can() ) {
            wp_send_json_error();
        }
        if ( ! check_ajax_referer( 'plugin_ajax_nonce', 'security', false ) ) {
            wp_send_json_error();
        }
        update_option( 'plugin_allowed_blocks', sanitize_text_field( $_POST['blocks'] ?? '' ) );
        wp_send_json_success();
    }
}
