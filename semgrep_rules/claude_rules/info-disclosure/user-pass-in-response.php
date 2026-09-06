<?php

// --- TRUE POSITIVES ---

function ajax_get_user_data_inline_cast() {
    $data = (array) get_userdata(intval($_POST['user_id']));
    // ruleid: claude.php.wordpress.info-disclosure.user-pass-in-response
    wp_send_json_success($data);
}

function rest_user_by_email_inline_cast() {
    $arr = (array) get_user_by('email', $email);
    // ruleid: claude.php.wordpress.info-disclosure.user-pass-in-response
    return new WP_REST_Response($arr);
}

function ajax_get_pass_hash() {
    $user = get_userdata(1);
    $hash = $user->data->user_pass;
    // ruleid: claude.php.wordpress.info-disclosure.user-pass-in-response
    wp_send_json(array('hash' => $hash));
}

function rest_user_pass_direct() {
    $user = get_user_by('id', $id);
    $pass = $user->user_pass;
    // ruleid: claude.php.wordpress.info-disclosure.user-pass-in-response
    wp_send_json_error(array('debug' => $pass));
}

function rest_new_user_inline_cast() {
    $data = (array) new WP_User($id);
    // ruleid: claude.php.wordpress.info-disclosure.user-pass-in-response
    return rest_ensure_response($data);
}

// --- TRUE NEGATIVES ---

function ajax_safe_user_response() {
    $user = get_userdata(1);
    $safe = array(
        'name' => $user->display_name,
        'email' => $user->user_email,
    );
    // ok: claude.php.wordpress.info-disclosure.user-pass-in-response
    wp_send_json_success($safe);
}

function rest_safe_id_only() {
    $user_id = get_current_user_id();
    // ok: claude.php.wordpress.info-disclosure.user-pass-in-response
    wp_send_json_success(array('id' => $user_id));
}
