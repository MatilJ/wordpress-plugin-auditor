<?php
// Tests for claude.php.wordpress.access-control.post-content-echo-no-password-check

// ruleid: claude.php.wordpress.access-control.post-content-echo-no-password-check
function render_share_meta_description() {
    echo '<meta name="description" content="' . get_the_excerpt() . '" />';
}

// ruleid: claude.php.wordpress.access-control.post-content-echo-no-password-check
function render_social_meta_tags( $self ) {
    $tag  = '';
    $tag .= '<meta property="og:title" content="' . get_the_title() . '" />';
    if ( $self->get_meta_description() ) {
        $tag .= '<meta property="og:description" content="' . $self->get_meta_description() . '" />';
    }
    if ( $self->get_meta_description() ) {
        $tag .= '<meta name="twitter:description" content="' . $self->get_excerpt_by_id( get_the_id() ) . '" />';
    }
    echo apply_filters( 'my_plugin_meta_tag', $tag );
}

// ok: claude.php.wordpress.access-control.post-content-echo-no-password-check
function render_social_meta_tags_fixed( $self ) {
    if ( post_password_required( get_the_ID() ) ) {
        return;
    }
    $tag  = '';
    $tag .= '<meta property="og:title" content="' . get_the_title() . '" />';
    if ( $self->get_meta_description() ) {
        $tag .= '<meta property="og:description" content="' . $self->get_meta_description() . '" />';
    }
    if ( $self->get_meta_description() ) {
        $tag .= '<meta name="twitter:description" content="' . $self->get_excerpt_by_id( get_the_id() ) . '" />';
    }
    echo apply_filters( 'my_plugin_meta_tag', $tag );
}

// ok: claude.php.wordpress.access-control.post-content-echo-no-password-check
function render_share_meta_description_guarded() {
    if ( post_password_required() ) {
        return;
    }
    echo '<meta name="description" content="' . get_the_excerpt() . '" />';
}

// ok: claude.php.wordpress.access-control.post-content-echo-no-password-check
function get_field_description_only( $self ) {
    // No echo of the built string in this function — never publicly rendered here.
    $tag = '';
    if ( $self->get_field_description() ) {
        $tag .= '<span>' . $self->get_field_description() . '</span>';
    }
    return $tag;
}

// ok: claude.php.wordpress.access-control.post-content-echo-no-password-check
function export_excerpts_for_admin_report() {
    global $wpdb;
    $rows = $wpdb->get_results( "SELECT post_excerpt FROM {$wpdb->posts} WHERE post_status = 'publish'" );
    return $rows;
}
