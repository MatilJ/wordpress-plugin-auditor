<?php

function rsssl_is_logged_in_rest() {
    if (!isset($_SERVER['REQUEST_URI'])) return false;
    $request_uri = $_SERVER['REQUEST_URI'];
    if (strpos($request_uri, 'rest_route=') !== false) return is_user_logged_in();
    return false;
}

// ruleid: claude.php.wordpress.info-disclosure.rest-prepare-filter-weak-gate-field-restore
function rsssl_add_user_role_to_api_response( $response, $user, $request ) {
    if ( rsssl_is_logged_in_rest() ) {
        $data          = $response->get_data();
        $data['roles'] = $user->roles;
        $response->set_data( $data );
    }
    return $response;
}
add_filter( 'rest_prepare_user', 'rsssl_add_user_role_to_api_response', 10, 3 );

// ruleid: claude.php.wordpress.info-disclosure.rest-prepare-filter-weak-gate-field-restore
function myplugin_add_email_to_response( $response, $post, $request ) {
    $data = $response->get_data();
    $data['author_email'] = get_the_author_meta( 'user_email', $post->post_author );
    $response->set_data( $data );
    return $response;
}
add_filter( 'rest_prepare_post', 'myplugin_add_email_to_response', 10, 3 );

// ok: claude.php.wordpress.info-disclosure.rest-prepare-filter-weak-gate-field-restore
function myplugin_add_internal_notes_to_response( $response, $post, $request ) {
    if ( ! current_user_can( 'edit_post', $post->ID ) ) {
        return $response;
    }
    $data = $response->get_data();
    $data['internal_notes'] = get_post_meta( $post->ID, '_internal_notes', true );
    $response->set_data( $data );
    return $response;
}
add_filter( 'rest_prepare_post', 'myplugin_add_internal_notes_to_response', 10, 3 );

// ok: claude.php.wordpress.info-disclosure.rest-prepare-filter-weak-gate-field-restore
function myplugin_add_role_gated( $response, $user, $request ) {
    $data = $response->get_data();
    if ( current_user_can( 'list_users' ) ) {
        $data['internal_role_notes'] = get_user_meta( $user->ID, '_role_notes', true );
    }
    $response->set_data( $data );
    return $response;
}
add_filter( 'rest_prepare_user', 'myplugin_add_role_gated', 10, 3 );

// ok: claude.php.wordpress.info-disclosure.rest-prepare-filter-weak-gate-field-restore
function myplugin_add_notes_wrapper_gated( $response, $post, $request ) {
    if ( ! myplugin_user_can_manage() ) {
        return $response;
    }
    $data = $response->get_data();
    $data['internal_notes'] = get_post_meta( $post->ID, '_internal_notes', true );
    $response->set_data( $data );
    return $response;
}
add_filter( 'rest_prepare_post', 'myplugin_add_notes_wrapper_gated', 10, 3 );
