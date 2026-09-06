<?php
/**
 * Test cases for claude.php.wordpress.auth.nonce-without-capability-check
 *
 * The rule fires at the nonce check line inside functions that:
 *  1. Call wp_verify_nonce() or check_ajax_referer()
 *  2. Also perform a state-changing DB write
 *  3. Do NOT call current_user_can() (or a known wrapper)
 */

// ── MATCH: nonce present, write present, no capability check ──────────────────

// Pattern from Easy Appointments ea_update_customer_data:
// wp_verify_nonce() present, $wpdb->update() present, no current_user_can().
function handle_update_no_cap() {
    global $wpdb;
    $data = $_POST;
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    wp_verify_nonce( $data['nonce'], 'my_action' );
    $email = sanitize_email( $data['email'] );
    $name  = sanitize_text_field( $data['name'] );
    $wpdb->update(
        $wpdb->prefix . 'my_customers',
        [ 'name' => $name ],
        [ 'email' => $email ]
    );
}

// check_ajax_referer() variant — same pattern
function handle_delete_no_cap() {
    global $wpdb;
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'delete_item_action', 'nonce' );
    $id = intval( $_POST['id'] );
    $wpdb->delete( $wpdb->prefix . 'items', [ 'id' => $id ] );
}

// update_option() write without capability check
function save_settings_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'save_settings', '_nonce' );
    $color = sanitize_hex_color( $_POST['color'] );
    update_option( 'theme_color', $color );
}

// update_user_meta() write without capability check
function save_profile_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    wp_verify_nonce( $_POST['nonce'], 'save_profile' );
    $bio = sanitize_textarea_field( $_POST['bio'] );
    update_user_meta( get_current_user_id(), 'bio', $bio );
}

// ── NO MATCH: has current_user_can() — safe ───────────────────────────────────

function handle_update_with_cap() {
    global $wpdb;
    $data = $_POST;
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    wp_verify_nonce( $data['nonce'], 'my_action' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Forbidden' );
    }
    $wpdb->update( $wpdb->prefix . 'items', [ 'val' => $data['val'] ], [ 'id' => 1 ] );
}

function handle_delete_with_cap() {
    global $wpdb;
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'delete_action', 'nonce' );
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_send_json_error( 'Unauthorized' );
    }
    $id = intval( $_POST['id'] );
    $wpdb->delete( $wpdb->prefix . 'items', [ 'id' => $id ] );
}

// ── NO MATCH: uses plugin wrapper that calls current_user_can() ───────────────

class MyPlugin {
    public function handle_save() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'save_action', 'nonce' );
        $this->validate_access_rights( 'manage_options' );
        update_option( 'my_key', sanitize_text_field( $_POST['val'] ) );
    }
}

// ── NO MATCH: read-only — nonce check but no state-changing write ─────────────
// The rule requires a DB write sink; pure read endpoints are out of scope.

function handle_read_only() {
    global $wpdb;
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'read_action', 'nonce' );
    $results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}items" );
    wp_send_json_success( $results );
}

// ── NO MATCH: uses has_access() wrapper — confirmed cap check ─────────────────
// MonsterInsights pattern: has_access() calls current_user_can('monsterinsights_view_dashboard').
// Confirmed FP source: notifications.php dismiss() — check_ajax_referer() + has_access()
// where has_access() wraps current_user_can() for a plugin-specific capability.

class MonsterInsights_Notifications {
    public function has_access() {
        return current_user_can( 'monsterinsights_view_dashboard' );
    }

    public function dismiss() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'mi-admin-nonce', 'nonce' );
        if ( ! $this->has_access() || empty( $_POST['id'] ) ) {
            wp_send_json_error();
        }
        $id = sanitize_text_field( wp_unslash( $_POST['id'] ) );
        update_option( 'plugin_notices', array( $id => true ) );
        wp_send_json_success();
    }
}

// ── MATCH: uses a generic non-security method — should still fire ──────────────
// Only the specific wrapper names in the exclusion list suppress the rule.
// A call to $this->log_request() or any other unlisted method does not count.

class AnotherPlugin {
    public function log_request( $action ) {
        // ... logging only, no capability check
    }

    public function save_data() {
        // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'save_data_nonce', 'nonce' );
        $this->log_request( 'save' );
        update_option( 'my_plugin_data', sanitize_text_field( $_POST['val'] ) );
    }
}

// ── NO MATCH: sbi_current_user_can() standalone — Smash Balloon shared wrapper ─
// sbi_current_user_can() always resolves to manage_instagram_feed_options or
// manage_options (both admin-only). Confirmed FP: instagram-feed 6.10.1
// SBI_Global_Settings.php (14 hits from this pattern).

function sbi_save_settings() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'sbi-admin', 'nonce' );
    if ( ! sbi_current_user_can( 'manage_instagram_feed_options' ) ) {
        wp_send_json_error( 'Unauthorized' );
    }
    $val = sanitize_text_field( $_POST['setting'] );
    update_option( 'sbi_setting', $val );
    wp_send_json_success();
}

// ── NO MATCH: sbi_current_user_can() in if-condition form ────────────────────
function sbi_clear_cache() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'sbi-admin', 'nonce' );
    if ( ! sbi_current_user_can( 'manage_instagram_feed_options' ) ) {
        wp_send_json_error();
    }
    update_option( 'sbi_cache_cleared', time() );
    wp_send_json_success();
}

// ── MATCH: nonce + sbi_current_user_can-LIKE but different function name ──────
// sbi_user_can() is NOT the Smash Balloon wrapper — should still fire.
function sbi_unknown_wrapper() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'sbi-admin', 'nonce' );
    if ( ! sbi_user_can( 'manage_instagram_feed_options' ) ) {
        wp_send_json_error();
    }
    update_option( 'sbi_data', sanitize_text_field( $_POST['val'] ) );
}

// ── NO MATCH: Helper::is_user_allowed() — Smush plugin static wrapper ─────────
// wp-smushit 4.0.2 app/class-ajax.php pattern: check_ajax_referer() +
// if (!Helper::is_user_allowed('manage_options')) { wp_die(..., 403); }
// Helper::is_user_allowed() calls current_user_can(apply_filters(
// 'wp_smush_admin_cap', $capability)) — always admin-level.
// Confirmed FP source: wp-smushit 4.0.2 (12 hits).

class Helper {
    public static function is_user_allowed( $capability = 'manage_options' ) {
        return current_user_can( apply_filters( 'wp_smush_admin_cap', $capability ) );
    }
}

class Smush_Ajax {
    public function save_settings() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'wp-smush-ajax' );
        if ( ! Helper::is_user_allowed( 'manage_options' ) ) {
            wp_die( esc_html__( 'Unauthorized', 'wp-smushit' ), 403 );
        }
        $val = sanitize_text_field( $_POST['setting'] );
        update_option( 'smush_setting', $val );
        wp_send_json_success();
    }

    public function dismiss_notice() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'wp-smush-ajax' );
        if ( ! Helper::is_user_allowed( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
        }
        $id = sanitize_key( $_POST['notice_id'] );
        update_option( 'smush_dismissed_' . $id, true );
        wp_send_json_success();
    }
}

// ── MATCH: set_site_transient() write without capability check ────────────────
// Confirmed TP: wps-hide-login 1.9.18 dismiss_admin_notice() — check_ajax_referer()
// only, no current_user_can(); set_site_transient() with attacker-controlled key
// allows any Subscriber to overwrite update_plugins/update_core transients.

function dismiss_notice_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'wps-hide-login-dismissible-notice' );
    $option_name = sanitize_text_field( $_POST['option_name'] );
    $length      = sanitize_text_field( $_POST['dismissible_length'] );
    set_site_transient( $option_name, $length, 0 );
    wp_die();
}

// set_transient() variant — same pattern, single-site scope
function cache_result_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'my_plugin_nonce', '_nonce' );
    $key   = sanitize_key( $_POST['cache_key'] );
    $value = sanitize_text_field( $_POST['cache_value'] );
    set_transient( $key, $value, HOUR_IN_SECONDS );
    wp_send_json_success();
}

// ── NO MATCH: set_site_transient() with current_user_can() — safe ─────────────

function dismiss_notice_with_cap() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'plugin-dismissible-notice' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Forbidden' );
    }
    $option_name = sanitize_text_field( $_POST['option_name'] );
    set_site_transient( $option_name, 'forever', 0 );
    wp_die();
}

// ── MATCH: Helper::is_user_allowed() absent — nonce only, still fires ─────────
// Absence of the wrapper means no capability check — rule must still fire.
class Smush_Ajax_Missing_Cap {
    public function broken_handler() {
        global $wpdb;
        // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'wp-smush-ajax' );
        $id = intval( $_POST['id'] );
        $wpdb->delete( $wpdb->prefix . 'smush_data', array( 'id' => $id ) );
    }
}

// ── MATCH: wp_delete_attachment() without capability check ───────────────────
// Confirmed TP: meta-box 5.12.0 ajax_delete_file() — check_ajax_referer() only,
// no current_user_can(), wp_delete_attachment() with attacker-controlled object_id
// enables Contributor+ to delete files from any post (IDOR).

function ajax_delete_file_no_cap() {
    $field_id = sanitize_text_field( $_POST['field_id'] );
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( "rwmb-delete-file_{$field_id}" );
    $attachment = intval( $_POST['attachment_id'] );
    wp_delete_attachment( $attachment );
    wp_send_json_success();
}

// ── MATCH: unlink() without capability check ─────────────────────────────────

function ajax_delete_custom_file_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'delete_custom_file', 'nonce' );
    $path = sanitize_text_field( $_POST['path'] );
    $real = realpath( $path );
    unlink( $real );
    wp_send_json_success();
}

// ── NO MATCH: wp_delete_attachment() WITH capability check — safe ────────────

function ajax_delete_file_with_cap() {
    $field_id = sanitize_text_field( $_POST['field_id'] );
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( "delete-file_{$field_id}" );
    if ( ! current_user_can( 'edit_post', intval( $_POST['object_id'] ) ) ) {
        wp_send_json_error( 'Unauthorized' );
    }
    $attachment = intval( $_POST['attachment_id'] );
    wp_delete_attachment( $attachment );
    wp_send_json_success();
}

// ── MATCH: wp_delete_post() without capability check ─────────────────────────

function ajax_delete_post_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'delete_post_action', 'nonce' );
    $post_id = intval( $_POST['post_id'] );
    wp_delete_post( $post_id, true );
    wp_send_json_success();
}

// ── NO MATCH: wp_delete_post() WITH capability check — safe ──────────────────

function ajax_delete_post_with_cap() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'delete_post_action', 'nonce' );
    $post_id = intval( $_POST['post_id'] );
    if ( ! current_user_can( 'delete_post', $post_id ) ) {
        wp_die( 'Forbidden' );
    }
    wp_delete_post( $post_id, true );
    wp_send_json_success();
}

// ── NO MATCH: in_array('administrator', $user->roles) role gate ───────────────
// Confirmed FP source: check-email 2.0.13.2 helper-function.php
// checkmail_save_admin_fcm_token() — write (update_option) is inside an
// in_array('administrator', ...) block, making it administrator-only (PR:H).

function checkmail_save_admin_fcm_token() {
    if ( ! isset( $_POST['ck_mail_security_nonce'] ) ) {
        return;
    }
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['ck_mail_security_nonce'] ) ), 'ck_mail_security_nonce' ) ) {
        return;
    }
    if ( isset( $_POST['token'] ) && ! empty( $_POST['token'] ) ) {
        $current_user = wp_get_current_user();
        if ( in_array( 'administrator', (array) $current_user->roles ) ) {
            $device_tokens   = get_option( 'checkmail_admin_fcm_token' );
            $device_tokens   = is_array( $device_tokens ) ? $device_tokens : [];
            $device_tokens[] = sanitize_text_field( wp_unslash( $_POST['token'] ) );
            update_option( 'checkmail_admin_fcm_token', $device_tokens );
        }
    }
    wp_die();
}

// ── MATCH: in_array('administrator', $roles) but write is OUTSIDE the if ──────
// The write happens regardless of role — the in_array check guards only a
// secondary code path, not the update_option() call. Rule must still fire.

function broken_role_guard() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'some_nonce', 'nonce' );
    $current_user = wp_get_current_user();
    if ( in_array( 'administrator', (array) $current_user->roles ) ) {
        // only logs for admins, does not gate the write below
    }
    update_option( 'any_key', sanitize_text_field( $_POST['val'] ) );
}

// ── MATCH (KNOWN FP): self::check_edit_others_caps() static wrapper ──────────
// KNOWN FALSE POSITIVE — see rule message triage guidance.
// self::check_edit_others_caps() calls current_user_can($edit_others_cap)
// internally, making this function fully capability-gated. However, Semgrep PHP
// cannot match self:: or static:: keywords as class qualifiers inside
// pattern-not-inside function body patterns, so suppression is not possible.
// Dismiss after confirming: (1) check_edit_others_caps() exists and calls
// current_user_can(), and (2) the wrapper is called BEFORE the write sink.
// Confirmed FP source: simple-page-ordering 2.7.4 class-simple-page-ordering.php:527.

class Simple_Page_Ordering_Test {
    private static function check_edit_others_caps( $post_type ) {
        $post_type_object = get_post_type_object( $post_type );
        $edit_others_cap  = $post_type_object->cap->edit_others_posts;
        return current_user_can( $edit_others_cap );
    }

    public static function ajax_reset_simple_page_ordering() {
        global $wpdb;
        $nonce = isset( $_POST['_wpnonce'] ) ? sanitize_key( wp_unslash( $_POST['_wpnonce'] ) ) : '';
        // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
        if ( ! wp_verify_nonce( $nonce, 'simple-page-ordering-nonce' ) ) {
            die( -1 );
        }
        $post_type = isset( $_POST['post_type'] ) ? sanitize_text_field( wp_unslash( $_POST['post_type'] ) ) : '';
        if ( ! self::check_edit_others_caps( $post_type ) ) {
            die( -1 );
        }
        $wpdb->update( 'wp_posts', array( 'menu_order' => 0 ), array( 'post_type' => $post_type ), array( '%d' ), array( '%s' ) );
    }
}

// ── MATCH (KNOWN FP): static::check_edit_others_caps() — late static binding ─
// Same known FP as above. static:: is also a PHP keyword that cannot be
// matched in Semgrep PHP nested pattern-not-inside contexts.

// ── NO MATCH: wp_remote_get() with pure hardcoded string literal URL ──────────
// When the URL argument to wp_remote_get() is a single string literal (no
// variable concatenation), the destination is fully developer-controlled.

function ping_healthcheck_no_cap() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'contact_form_nonce', 'nonce' );
    $request = wp_remote_get( 'https://www.google.com/recaptcha/api/siteverify', array( 'timeout' => 15 ) );
    $body = wp_remote_retrieve_body( $request );
    wp_send_json_success( $body );
}

// ── MATCH (KNOWN FP): wp_remote_get() with string CONCATENATION URL ───────────
// When the URL is built by concatenating a string literal + variables (e.g.,
// appending a stored secret key and a user-supplied challenge response),
// Semgrep's "..." literal pattern does NOT match — the concatenation cannot be
// suppressed by pattern-not-inside. Dismiss manually after confirming:
//  1. The base URL scheme+host are hardcoded (not attacker-supplied).
//  2. The user-supplied value flows only into a query parameter (not host/path).
//  3. No stored credential is forwarded to an attacker-redirectable endpoint.
// Confirmed FP: contact-form plugin send() — nonce + wp_remote_get() to
// hardcoded https://google.com/recaptcha/api/siteverify with user challenge only.

function verify_recaptcha_concat_url() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'contact_form_nonce', 'nonce' );
    $challenge = sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) );
    $secret    = get_option( 'recaptcha_secret_key', '' );
    $request = wp_remote_get(
        'https://www.google.com/recaptcha/api/siteverify?secret=' . $secret . '&response=' . $challenge,
        array( 'timeout' => 15 )
    );
    $data = json_decode( wp_remote_retrieve_body( $request ), false );
    if ( $data && $data->success ) {
        wp_send_json_success();
    }
    wp_send_json_error( 'Invalid captcha' );
}

class Base_Page_Ordering {
    protected static function check_edit_others_caps( $post_type ) {
        $cap = get_post_type_object( $post_type )->cap->edit_others_posts;
        return current_user_can( $cap );
    }

    public static function ajax_reset() {
        global $wpdb;
        $nonce = isset( $_POST['_wpnonce'] ) ? sanitize_key( wp_unslash( $_POST['_wpnonce'] ) ) : '';
        // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
        if ( ! wp_verify_nonce( $nonce, 'page-ordering-nonce' ) ) {
            die( -1 );
        }
        $post_type = sanitize_text_field( wp_unslash( $_POST['post_type'] ?? '' ) );
        if ( ! static::check_edit_others_caps( $post_type ) ) {
            die( -1 );
        }
        $wpdb->update( 'wp_posts', array( 'menu_order' => 0 ), array( 'post_type' => $post_type ) );
    }
}

// ── MATCH: nonce-only AJAX handler proxying outbound HTTP (wp_remote_post) ───
// Pattern: stored Bearer token forwarded to external API — any subscriber
// can proxy arbitrary requests against the site's external account.
// Confirmed TP: nonce-only handler forwarding stored Bearer token to external
// GraphQL API — nonce obtained from post edit page (edit_posts capability).

function fa_query_request_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'acffa_nonce', 'nonce' );
    $query   = isset( $_POST['query'] ) ? sanitize_text_field( wp_unslash( $_POST['query'] ) ) : '';
    $token   = get_transient( 'plugin_access_token' );
    $response = wp_remote_post( 'https://api.example.com', array(
        'headers' => array(
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ),
        'body'    => json_encode( array( 'query' => $query ) ),
    ) );
    if ( ! is_wp_error( $response ) ) {
        wp_send_json_success( json_decode( wp_remote_retrieve_body( $response ) ) );
    }
    wp_send_json_error();
}

// ── MATCH: nonce-only AJAX handler using wp_remote_get (outbound fetch) ──────

function fetch_remote_data_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'plugin_nonce', 'nonce' );
    $api_key  = get_option( 'plugin_api_key' );
    $endpoint = 'https://api.example.com/data?key=' . $api_key;
    $response = wp_remote_get( $endpoint );
    if ( ! is_wp_error( $response ) ) {
        wp_send_json_success( json_decode( wp_remote_retrieve_body( $response ) ) );
    }
    wp_send_json_error();
}

// ── NO MATCH: Helper::is_current_user_allowed() — AdTribes/Rymera wrapper ────
// Helper::is_current_user_allowed() calls current_user_can('manage_adtribes_product_feeds')
// internally. Effectively admin-only unless another plugin extends via filter.

class AdTribes_Admin {
    public function ajax_update_settings() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'woosea_ajax_nonce', 'security' );
        if ( ! Helper::is_current_user_allowed() ) {
            wp_send_json_error( 'Unauthorized' );
        }
        update_option( 'adt_pfp_setting', sanitize_text_field( $_POST['val'] ) );
        wp_send_json_success();
    }

    public function ajax_delete_feed() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        wp_verify_nonce( $_POST['nonce'], 'adt_nonce' );
        Helper::is_current_user_allowed();
        $feed_id = intval( $_POST['id'] );
        wp_delete_post( $feed_id, true );
        wp_send_json_success();
    }
}

// ── NO MATCH: wp_remote_post with current_user_can() — properly gated ────────

function fa_query_request_with_cap() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'acffa_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
    }
    $query    = isset( $_POST['query'] ) ? sanitize_text_field( wp_unslash( $_POST['query'] ) ) : '';
    $token    = get_transient( 'plugin_access_token' );
    $response = wp_remote_post( 'https://api.example.com', array(
        'headers' => array(
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ),
        'body'    => json_encode( array( 'query' => $query ) ),
    ) );
    if ( ! is_wp_error( $response ) ) {
        wp_send_json_success( json_decode( wp_remote_retrieve_body( $response ) ) );
    }
    wp_send_json_error();
}

// ── MATCH: delete_option() without capability check ──────────────────────────
// Nonce-only handler calling delete_option() allows any authenticated user to
// wipe plugin configuration data.

function reset_plugin_data_no_cap() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'reset-plugin-data', 'security' );
    delete_option( 'plugin_onboarding_state' );
    delete_option( 'plugin_user_details' );
    delete_option( 'plugin_content_cache' );
    wp_send_json_success( array( 'status' => true ) );
}

// ── NO MATCH: delete_option() WITH capability check — safe ───────────────────

function reset_plugin_data_with_cap() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'reset-plugin-data', 'security' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Forbidden' );
    }
    delete_option( 'plugin_onboarding_state' );
    delete_option( 'plugin_user_details' );
    wp_send_json_success();
}

// ── NO MATCH: REST route callback verifying 'wp_rest' nonce ──────────────────
// REST routes enforce capability via permission_callback (separate method).
// The 'wp_rest' nonce action identifies a REST callback, not an AJAX handler.

function rest_set_step_data( $request ) {
    $nonce = (string) $request->get_header( 'X-WP-Nonce' );
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    if ( ! wp_verify_nonce( sanitize_text_field( $nonce ), 'wp_rest' ) ) {
        wp_send_json_error( array( 'data' => 'Nonce verification failed.' ) );
    }
    $details = $request->get_param( 'business_details' );
    update_option( 'plugin_business_details', $details );
    wp_send_json_success();
}

// ── MATCH: nonce action is NOT 'wp_rest' — AJAX handler, not REST callback ───
// Even though the code pattern looks similar, a non-REST nonce means this is
// an AJAX handler where no permission_callback is enforced.

function ajax_update_details_no_cap() {
    $nonce = $_POST['nonce'];
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    if ( ! wp_verify_nonce( sanitize_text_field( $nonce ), 'save_details_action' ) ) {
        wp_die( 'Invalid nonce' );
    }
    update_option( 'plugin_details', sanitize_text_field( $_POST['details'] ) );
    wp_send_json_success();
}

// ── NO MATCH: static hasCapability() wrapper — wraps current_user_can() ─────

function ajax_reset_settings_with_hascap() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'plugin_reset_all', 'nonce' );
    PluginUtil::hasCapability( 'export', 'throw' );
    delete_option( 'plugin_settings' );
    wp_send_json_success();
}

// ── NO MATCH: instance hasCapability() wrapper ──────────────────────────────

class AjaxServiceWithHasCap {
    public function saveViewState() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'save_view_state', 'nonce' );
        $this->hasCapability( 'export' );
        update_option( 'plugin_view_state', sanitize_text_field( $_POST['state'] ?? '' ) );
        wp_send_json_success();
    }
}

// ── NO MATCH: can_access_X() wrapper — "can_access" naming convention ────────
// A plugin-authored per-field capability delegation wrapper named
// can_access_<something>() calls current_user_can() internally. Generalizes
// the has_access()/is_allowed() naming convention to the "can_access" prefix.

class GlobalFieldsHandler {
    public function can_access_fields_page( $page ) {
        return current_user_can( 'manage_options' );
    }

    public function save_fields( $page ) {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        if ( isset( $_REQUEST['_wpnonce'] ) && wp_verify_nonce( $_REQUEST['_wpnonce'], 'save_fields' ) ) {
            if ( $this->can_access_fields_page( $page ) ) {
                update_option( 'fields_data', sanitize_text_field( $_POST['data'] ) );
            }
        }
    }
}

// ── MATCH: check_admin_referer() nonce-only in admin_init settings handler ──────
// admin_init fires for all authenticated users on any wp-admin page.
// check_admin_referer() verifies nonce intent but not privilege level.

function save_plugin_settings_no_cap() {
    if ( ! empty( $_POST['lib_options'] ) &&
        // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
        check_admin_referer( 'my_plugin_edit', 'my_nonce' ) ) {
        $options = array();
        $options['state'] = isset( $_POST['lib_options']['state'] ) ? 1 : 0;
        $options['title'] = sanitize_text_field( wp_unslash( $_POST['lib_options']['title'] ) );
        update_option( 'my_plugin_options', $options );
    }
}

// ── NO MATCH: check_admin_referer() WITH current_user_can() — safe ──────────────

function save_plugin_settings_with_cap() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Forbidden' );
    }
    if ( ! empty( $_POST['lib_options'] ) &&
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_admin_referer( 'my_plugin_edit', 'my_nonce' ) ) {
        $options = array();
        $options['title'] = sanitize_text_field( wp_unslash( $_POST['lib_options']['title'] ) );
        update_option( 'my_plugin_options', $options );
    }
}

// ── MATCH: delegated-dispatch variant — instance delegate + wp_send_json_success ─
// CWE-266/CWE-862 class: the handler never performs the privileged action
// inline — it instantiates a helper/provider object and forwards the
// delegate's result straight to the client. Nonce-only guard, no capability
// check anywhere in the handler.

class External_Api_Handler {
    public function get_api_response() {
        // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'external_api_get_response', 'nonce' );
        $api_name = sanitize_text_field( wp_unslash( $_POST['api-name'] ) );
        $provider = new Api_Provider();
        $result   = $provider->execute_request( $api_name );
        wp_send_json_success( json_decode( $result, true ) );
    }
}

// ── MATCH: delegated-dispatch variant — self:: delegate + wp_send_json ──────────

class Db_Introspection_Handler {
    public static function get_all_column_names( $table ) {
        global $wpdb;
        return $wpdb->get_col( $wpdb->prepare( 'DESCRIBE %1s', $table ), 0 );
    }

    public static function get_table_columns() {
        // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'get_columns_nonce', 'nonce' );
        $table_name   = sanitize_text_field( wp_unslash( $_GET['table'] ) );
        $column_names = self::get_all_column_names( $table_name );
        wp_send_json( $column_names );
    }
}

// ── NO MATCH: delegated-dispatch variant gated by a generalized require_capability()
// wrapper — instance-call form. The wrapper name itself (not a hardcoded plugin
// name) denotes a capability gate, so this suppresses the delegated-dispatch branch.

class Gated_External_Api_Handler {
    public function get_api_response() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        if ( $this->require_capability() ) {
            check_ajax_referer( 'external_api_get_response', 'nonce' );
            $api_name = sanitize_text_field( wp_unslash( $_POST['api-name'] ) );
            $provider = new Api_Provider();
            $result   = $provider->execute_request( $api_name );
            wp_send_json_success( json_decode( $result, true ) );
        }
    }
}

// ── NO MATCH: delegated-dispatch variant gated by a generalized require_capability()
// wrapper — static-call form (mirrors the real-world Utils::require_capability()
// fix pattern this variant was generalized from).

class Gated_Db_Introspection_Handler {
    public static function get_all_column_names( $table ) {
        global $wpdb;
        return $wpdb->get_col( $wpdb->prepare( 'DESCRIBE %1s', $table ), 0 );
    }

    public static function get_table_columns() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        if ( Utils::require_capability() ) {
            check_ajax_referer( 'get_columns_nonce', 'nonce' );
            $table_name   = sanitize_text_field( wp_unslash( $_GET['table'] ) );
            $column_names = self::get_all_column_names( $table_name );
            wp_send_json( $column_names );
        }
    }
}

// ── NO MATCH: check_ajax_view_capability() static wrapper, early-return form ──
// A view-tier capability-gate wrapper resolves and checks the caller's
// required capability internally; the early-return-on-falsy shape is a
// genuine gate from this rule's perspective even if the wrapper's own
// internal comparison logic is separately flawed (a different defect class).

class View_Tier_Handler {
    public static function check_ajax_view_capability() {
        return current_user_can( 'read' );
    }

    public static function get_online_visitors() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'meta-box-order', 'security' );
        if ( ! self::check_ajax_view_capability() ) {
            return;
        }
        update_option( 'view_tier_last_seen', time() );
        wp_send_json_success( array( 'count' => 1 ) );
    }
}

// ── NO MATCH: $report->can_view() instance wrapper, if-condition form ────────

class Report_Base {
    public function can_view(): bool {
        return current_user_can( 'read' );
    }
}

function render_report_no_cap( $report ) {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'load_report_nonce', 'security' );
    if ( ! $report->can_view() ) {
        return;
    }
    update_option( 'report_last_rendered', time() );
    wp_send_json_success( array( 'rendered' => true ) );
}

// ── NO MATCH: bare global-function capability wrapper — if-condition form ────
// Confirmed FP source: advanced-cf7-db 2.1.3 admin/class-advanced-cf7-db-admin.php
// — cf7_check_capability($cap) is a standalone function (not a class method)
// wrapping a current_user_can()-equivalent role lookup, called immediately
// after wp_verify_nonce() before the $wpdb write.

function cf7_check_capability( $capability ) {
    $user = wp_get_current_user();
    return in_array( $capability, (array) $user->allcaps, true );
}

function vsz_cf7_edit_entry_no_class() {
    global $wpdb;
    $fid   = intval( $_POST['fid'] );
    $nonce = sanitize_text_field( wp_unslash( $_POST['nonce'] ) );
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    if ( ! wp_verify_nonce( $nonce, 'vsz-cf7-edit-nonce-' . $fid ) ) {
        return;
    }
    $edit_cap = 'cf7_db_form_edit_' . $fid;
    if ( ! cf7_check_capability( $edit_cap ) ) {
        return;
    }
    $wpdb->update( $wpdb->prefix . 'cf7_vdata_entry', array( 'value' => '' ), array( 'data_id' => intval( $_POST['rid'] ) ) );
}

// ── NO MATCH: bare global-function capability wrapper — bare-call form ───────

function reset_settings_no_class() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'reset_settings_action', 'nonce' );
    cf7_check_capability( 'cf7_db_form_edit_1' );
    update_option( 'my_plugin_settings', sanitize_text_field( $_POST['val'] ) );
}

// ── NO MATCH: assign-then-negate-check wrapper variant — static receiver ─────
// The wrapper's result is stored in a variable first, then negate-checked in
// a separate if-statement, rather than being called bare or inlined in the
// if-condition. Common WP-plugin coding style not covered by the two call-
// shape variants above.

class SettingsAjaxHandler {
    public function dismiss_promotion_notice() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'plugin-admin-ajax-nonce', 'security' );
        $can_access_settings = ES_Common::can_access( 'settings' );
        if ( ! $can_access_settings ) {
            return 0;
        }
        update_option( 'plugin_promotion_notice_dismissed', 'yes', false );
    }
}

// ── NO MATCH: assign-then-negate-check wrapper variant — instance receiver ───

class InstanceGatedAjaxHandler {
    public function save_setting() {
        // ok: claude.php.wordpress.auth.nonce-without-capability-check
        check_ajax_referer( 'plugin-nonce', 'security' );
        $allowed = $this->has_access( 'settings' );
        if ( ! $allowed ) {
            wp_send_json_error();
        }
        update_option( 'plugin_setting', sanitize_text_field( $_POST['val'] ) );
    }
}

// ── NO MATCH: assign-then-negate-check wrapper variant — bare function ───────

function bare_wrapper_gated_save() {
    // ok: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'plugin-nonce', 'security' );
    $can_access = cf7_check_capability( 'cf7_db_form_edit_1' );
    if ( ! $can_access ) {
        return;
    }
    update_option( 'my_plugin_settings', sanitize_text_field( $_POST['val'] ) );
}

// ── MATCH: assign-then-check shape present, but the assigned call is NOT a
// capability-wrapper name — must still fire.

function bare_non_wrapper_assign_check() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'plugin-nonce', 'security' );
    $log_result = log_request_bare( 'save' );
    if ( ! $log_result ) {
        return;
    }
    update_option( 'my_plugin_data', sanitize_text_field( $_POST['val'] ) );
}

// ── MATCH: bare global function present but NOT a capability-wrapper name ────
// A call to an unrelated bare function (e.g. logging) must not suppress the rule.

function log_request_bare( $action ) {
    // ... logging only, no capability check
}

function save_data_no_class_wrapper() {
    // ruleid: claude.php.wordpress.auth.nonce-without-capability-check
    check_ajax_referer( 'save_data_nonce', 'nonce' );
    log_request_bare( 'save' );
    update_option( 'my_plugin_data', sanitize_text_field( $_POST['val'] ) );
}
