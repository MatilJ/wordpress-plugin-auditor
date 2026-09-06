<?php

function get_all_users_callback( $request ) {
    $users = get_users( array( 'role' => 'subscriber' ) );
    // ruleid: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    wp_send_json_success( $users );
}

function get_user_data_callback( $request ) {
    $user = get_userdata( $request['id'] );
    // ruleid: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    return new WP_REST_Response( $user, 200 );
}

function get_db_records_callback( $request ) {
    global $wpdb;
    $results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders" );
    // ruleid: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    wp_send_json( $results );
}

function get_user_meta_callback( $request ) {
    $meta = get_user_meta( $request['id'], 'billing_email', true );
    // ruleid: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    return rest_ensure_response( array( 'email' => $meta ) );
}

function get_users_protected_callback( $request ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        return new WP_REST_Response( 'Forbidden', 403 );
    }
    $users = get_users( array( 'role' => 'subscriber' ) );
    // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    wp_send_json_success( $users );
}

function get_db_protected_callback( $request ) {
    if ( ! current_user_can( 'edit_posts' ) ) {
        return new WP_Error( 'rest_forbidden', 'Forbidden', array( 'status' => 403 ) );
    }
    global $wpdb;
    $results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}posts WHERE post_status = 'publish'" );
    // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    wp_send_json_success( $results );
}

function get_author_picker_list_callback( $request ) {
    $authors = get_users( array( 'fields' => array( 'ID', 'display_name', 'user_nicename' ) ) );
    // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    wp_send_json( $authors );
}

function get_author_dropdown_options_callback( $request ) {
    $options = array_map(
        fn( $u ) => array( 'value' => $u->data->ID, 'title' => $u->data->display_name ),
        get_users()
    );
    // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    wp_send_json( $options );
}

function login_callback( $request ) {
    $user = wp_signon( array( 'user_login' => $request['username'], 'user_password' => $request['password'] ) );
    if ( is_wp_error( $user ) ) {
        return new WP_REST_Response( array( 'message' => 'Invalid credentials' ), 401 );
    }
    $response = array(
        'id'    => $user->get( 'ID' ),
        'email' => $user->get( 'user_email' ),
    );
    // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    return new WP_REST_Response( $response, 200 );
}

class Wcar_Detailed_Report_Api {
    // OK: capability check lives in the sibling permission_callback method
    // (WP_REST_Controller convention), not in this route callback itself.
    // Confirmed FP: woo-cart-abandonment-recovery 2.1.3
    // admin/api/detailed-report.php + admin/api/follow-up.php.
    public function get_report( $request ) {
        global $wpdb;
        $results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}wcar_cart_abandonment" );
        // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
        return rest_ensure_response( $results );
    }

    public function get_permissions_check( $request ) {
        return current_user_can( 'manage_woocommerce' );
    }
}

class Wcar_Insecure_Multi_Route_Api {
    // TP: sibling method calls current_user_can(), but it isn't named per the
    // WP_REST_Controller permission_callback convention — must not suppress
    // this route, since the sibling could be gating an unrelated route.
    public function get_report( $request ) {
        global $wpdb;
        $results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}wcar_cart_abandonment" );
        // ruleid: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
        return rest_ensure_response( $results );
    }

    public function some_unrelated_helper( $request ) {
        return current_user_can( 'manage_options' );
    }
}

function reply_to_review_callback( $request ) {
    $customer_user = get_user_by( 'email', $request['email'] );
    $customer_user_id = $customer_user ? $customer_user->ID : 0;
    $commentdata = array(
        'comment_author'       => $request['name'],
        'comment_content'      => $request['text'],
        'user_id'              => $customer_user_id,
        'comment_post_ID'      => $request['product_id'],
        'comment_parent'       => $request['review_id'],
    );
    $reply_id = wp_insert_comment( $commentdata );
    if ( $reply_id ) {
        // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
        return new WP_REST_Response( array( 'replyId' => strval( $reply_id ) ), 201 );
    }
    return new WP_REST_Response( 'Generic error', 500 );
}

function update_reply_callback( $request ) {
    $customer_user = get_user_by( 'email', $request['email'] );
    $commentdata = array(
        'comment_ID'      => $request['reply_id'],
        'comment_content' => $request['text'],
        'comment_author'  => $customer_user ? $customer_user->display_name : '',
    );
    $result = wp_update_comment( $commentdata );
    // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
    return new WP_REST_Response( array( 'updated' => (bool) $result ), 200 );
}

function forgot_password_callback( $request ) {
    $user = get_user_by( 'login', $request['username'] );
    $key = get_password_reset_key( $user );
    if ( is_wp_error( $key ) ) {
        $response = array( 'message' => $key->get_error_message() );
        // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
        return new WP_REST_Response( $response, 500 );
    }
    return new WP_REST_Response( array( 'message' => 'Sent' ), 200 );
}

// OK: capability gated via a static view-tier capability-gate wrapper method
// (naming convention: *view_capability*) rather than an inline current_user_can().
class Stats_Ajax_Handler {
    public static function check_ajax_view_capability() {
        return current_user_can( 'read' );
    }

    public static function get_adminbar_stats( $request ) {
        global $wpdb;
        if ( ! self::check_ajax_view_capability() ) {
            return;
        }
        $results = $wpdb->get_results( "SELECT COUNT(*) as cnt FROM {$wpdb->prefix}stats" );
        // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
        wp_send_json_success( $results );
    }
}

// OK: capability gated via an instance can_view() wrapper (naming convention:
// *can_view*), guarded by an early-return if-condition.
class Report_Renderer {
    public function can_view() {
        return current_user_can( 'read' );
    }

    public function render( $request ) {
        global $wpdb;
        if ( ! $this->can_view() ) {
            return;
        }
        $results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}stats" );
        // ok: claude.php.wordpress.info-disclosure.rest-return-true-sensitive-data-response
        wp_send_json( $results );
    }
}
