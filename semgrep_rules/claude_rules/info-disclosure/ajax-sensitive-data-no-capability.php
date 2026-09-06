<?php

function handle_get_apikey() {
    check_ajax_referer( 'plugin_nonce' );
    $api_key = get_option( 'plugin_api_key' );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( array( 'key' => $api_key ) );
}

function handle_get_license() {
    $license = get_option( 'my_plugin_license_token' );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json( array( 'license' => $license ) );
}

function ajax_get_all_users() {
    $users = get_users( array( 'fields' => array( 'ID', 'user_email' ) ) );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( $users );
}

function handle_get_apikey_protected() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Forbidden' );
        return;
    }
    $api_key = get_option( 'plugin_api_key' );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( array( 'key' => $api_key ) );
}

// ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
function handle_get_public_setting() {
    $setting = get_option( 'plugin_display_mode' );
    wp_send_json_success( array( 'mode' => $setting ) );
}

function admin_head_output_site_token() {
    $site_token = get_option( 'plugin_site_token', '' );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    echo json_encode( array( 'siteToken' => $site_token ) );
}

function enqueue_localize_mint_token_only() {
    $token = new Plugin_Token_Manager();
    $config = array(
        'authToken' => $token->generate(),
    );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_localize_script( 'plugin-common', 'pluginConfig', $config );
}

function admin_head_output_site_token_protected() {
    if ( ! is_user_logged_in() || ! current_user_can( 'publish_posts' ) ) {
        return;
    }
    $site_token = get_option( 'plugin_site_token', '' );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    echo json_encode( array( 'siteToken' => $site_token ) );
}

class Plugin_Feed_Widget {
    // Action verb in the method name only, no sensitive-domain noun in either the
    // method or receiver name — routine content-generation helper, not a secret source.
    private static function generate_report_data() {
        return ob_get_clean();
    }

    public static function display_report_feed() {
        $content = self::generate_report_data();
        // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
        echo $content;
    }

    // "create" verb, but the method builds a plain URL string, not a credential.
    private function create_duplicate_link() {
        return admin_url( 'post-new.php?duplicate=1' );
    }

    public function render_duplicate_link() {
        // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
        echo wp_kses_post( $this->create_duplicate_link() );
    }
}

function ajax_get_author_picker_list() {
    $authors = get_users( array( 'fields' => array( 'ID', 'display_name', 'user_nicename' ) ) );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( $authors );
}

function ajax_get_author_dropdown_options() {
    $options = array_map(
        fn( $u ) => array( 'value' => $u->data->ID, 'title' => $u->data->display_name ),
        get_users()
    );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( $options );
}

function ajax_login_handler() {
    $user = wp_signon( array( 'user_login' => $_POST['username'], 'user_password' => $_POST['password'] ) );
    if ( is_wp_error( $user ) ) {
        wp_send_json_error( array( 'message' => 'Invalid credentials' ) );
        return;
    }
    $response = array(
        'id'    => $user->get( 'ID' ),
        'email' => $user->get( 'user_email' ),
    );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( $response );
}

function ajax_forgot_password_handler() {
    $user = get_user_by( 'login', $_POST['username'] );
    $key = get_password_reset_key( $user );
    if ( is_wp_error( $key ) ) {
        // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
        wp_send_json_error( array( 'message' => $key->get_error_message() ) );
    }
}

function localize_ai_key_presence_flag() {
    $has_key = ! empty( get_option( 'plugin_openai_api_key' ) );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( array( 'hasApiKey' => $has_key ) );
}

function render_own_profile_edit_form() {
    global $current_user;
    $user = get_userdata( $current_user->ID );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    echo esc_attr( $user->user_email );
}

function ajax_get_arbitrary_user_via_variable( $target_id ) {
    $user = get_userdata( $target_id );
    // ruleid: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    wp_send_json_success( array( 'email' => $user->user_email ) );
}

function render_author_pill_list( $author_ids ) {
    foreach ( $author_ids as $author_id ) {
        $user = get_userdata( $author_id );
        // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
        echo sprintf( '<span>%s</span>', esc_html( $user->display_name ) );
    }
}

// wp_insert_comment()/wp_update_comment() return a fresh autoincrement comment
// ID, never a reflection of the argument data used to build the lookup —
// passing a get_user_by()-derived value into the comment array must not taint
// the returned ID.
function rest_reply_endpoint_returns_new_comment_id( $reply_text, $author_email ) {
    $customer_user = get_user_by( 'email', $author_email );
    $commentdata = array(
        'comment_content' => sanitize_text_field( $reply_text ),
        'user_id'         => $customer_user ? $customer_user->ID : 0,
    );
    $reply_id = wp_insert_comment( $commentdata );
    // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
    return new WP_REST_Response( array( 'replyId' => strval( $reply_id ) ), 201 );
}

// OK: capability gated via a static view-tier capability-gate wrapper method
// (naming convention: *view_capability*) rather than an inline current_user_can().
class Dashboard_Widget_Handler {
    public static function check_ajax_view_capability() {
        return current_user_can( 'read' );
    }

    public static function render_recent_visitors() {
        if ( ! self::check_ajax_view_capability() ) {
            return;
        }
        $license = get_option( 'plugin_api_key' );
        $row_output = esc_html( $license );
        // ok: claude.php.wordpress.info-disclosure.ajax-sensitive-data-no-capability
        echo $row_output;
    }
}
