<?php
// Test fixture for claude.php.wordpress.access-control.request-step-gates-auth-bypass

function bl_finish_step_sets_password() {
    $uid = intval( $_REQUEST['uid'] );
    // ruleid: claude.php.wordpress.access-control.request-step-gates-auth-bypass
    if ( $_REQUEST['step'] === 'finish' ) {
        wp_set_password( $_REQUEST['pass'], $uid );
    }
}

function bl_stage_logs_user_in() {
    $uid = intval( $_POST['uid'] );
    // ruleid: claude.php.wordpress.access-control.request-step-gates-auth-bypass
    if ( $_POST['stage'] == 3 ) {
        wp_set_auth_cookie( $uid );
    }
}

function ok_step_only_renders_template() {
    // ok: claude.php.wordpress.access-control.request-step-gates-auth-bypass
    if ( $_REQUEST['step'] === 'finish' ) {
        echo render_step_template( 'finish' );
    }
}

function ok_privileged_sink_not_under_step() {
    $uid = get_current_user_id();
    // ok: claude.php.wordpress.access-control.request-step-gates-auth-bypass
    if ( current_user_can( 'edit_user', $uid ) ) {
        wp_update_user( array( 'ID' => $uid, 'first_name' => 'x' ) );
    }
}
