<?php
// Tests for claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
// TP cases: get_post() + post_content access with no per-resource auth check
// FP cases: same pattern with read_post, edit_post, or manage_options gate

// ruleid: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function generate_ai_content( $request ) {
    $post_id = $request->get_param( 'post_id' );
    $post    = get_post( $post_id );
    $content = $post->post_content;
    wp_remote_post( 'https://api.example.com/ai', [ 'body' => [ 'text' => $content ] ] );
}

// ruleid: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function handle_content_export( $request ) {
    $id   = absint( $request->get_param( 'id' ) );
    $post = get_post( $id );
    $text = $post->post_content;
    return rest_ensure_response( [ 'content' => $text ] );
}

// ok: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function generate_ai_content_gated( $request ) {
    $post_id = absint( $request->get_param( 'post_id' ) );
    if ( ! current_user_can( 'read_post', $post_id ) ) {
        return new WP_Error( 'rest_forbidden', __( 'Access denied.' ), [ 'status' => 403 ] );
    }
    $post    = get_post( $post_id );
    $content = $post->post_content;
    wp_remote_post( 'https://api.example.com/ai', [ 'body' => [ 'text' => $content ] ] );
}

// ok: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function handle_content_export_edit_gated( $request ) {
    $post_id = absint( $request->get_param( 'id' ) );
    if ( ! current_user_can( 'edit_post', $post_id ) ) {
        return new WP_Error( 'rest_forbidden', __( 'Access denied.' ), [ 'status' => 403 ] );
    }
    $post    = get_post( $post_id );
    $content = $post->post_content;
    return rest_ensure_response( [ 'content' => $content ] );
}

// ok: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function admin_export_post_content( $request ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        return new WP_Error( 'rest_forbidden', __( 'Access denied.' ), [ 'status' => 403 ] );
    }
    $post_id = absint( $request->get_param( 'id' ) );
    $post    = get_post( $post_id );
    $content = $post->post_content;
    return rest_ensure_response( [ 'content' => $content ] );
}

// ruleid: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function ajax_template_selected(){
    check_ajax_referer( 'my-plugin-security', 'security' );
    $email_template = get_post( intval( $_POST['template_selected'] ) );
    echo json_encode( array(
        'title' => $email_template->post_title,
        'content' => wpautop( $email_template->post_content ),
    ) );
    wp_die();
}

// ok: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function ajax_template_selected_capability_gated(){
    check_ajax_referer( 'my-plugin-security', 'security' );

    if ( ! current_user_can( apply_filters( 'my_plugin_capability', 'edit_others_posts' ) ) )
        wp_die( -1 );

    $email_template = get_post( intval( $_POST['template_selected'] ) );

    if ( ! $email_template || $email_template->post_type !== 'my_plugin_email_template' )
        wp_die( -1 );

    echo json_encode( array(
        'title' => $email_template->post_title,
        'content' => wpautop( $email_template->post_content ),
    ) );
    wp_die();
}

// ok: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
// Compound if-condition: the capability check is one clause of a larger
// "&&"-joined condition alongside status/type checks, not its own statement.
function resolve_reusable_block_compound_gated( $block_id ) {
    $post = get_post( (int) $block_id );
    if ( $post && $post->post_type === 'wp_block' && $post->post_status === 'publish' && current_user_can( 'read_post', $post->ID ) ) {
        return $post->post_content;
    }
    return '';
}

// ok: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
// Status + password gate: no capability check, but the function only ever
// serves published, non-password-protected posts — closes the disclosure
// vector for any post status/visibility the attacker could otherwise probe.
function ajax_load_reusable_block(){
    check_ajax_referer( 'reusable-block-security', 'security' );
    $post_id = intval( $_POST['post_id'] );
    $content_post = get_post( $post_id );
    if ( ! is_object( $content_post ) || $content_post->post_type !== 'wp_block' ) {
        wp_send_json_error( 'Invalid post' );
    }
    if ( $content_post->post_status !== 'publish' ) {
        wp_send_json_error( 'Block not published' );
    }
    if ( ! empty( $content_post->post_password ) ) {
        wp_send_json_error( 'Block is password protected' );
    }
    $content = $content_post->post_content;
    wp_send_json_success( $content );
}

// ok: claude.php.wordpress.access.rest-get-post-content-no-per-resource-auth
function ajax_template_selected_type_gated_only(){
    check_ajax_referer( 'my-plugin-security', 'security' );

    $email_template = get_post( intval( $_POST['template_selected'] ) );

    if ( ! $email_template || $email_template->post_type !== 'my_plugin_email_template' )
        wp_die( -1 );

    echo json_encode( array(
        'title' => $email_template->post_title,
        'content' => wpautop( $email_template->post_content ),
    ) );
    wp_die();
}
