<?php
// Test file for wp-insert-post-data-filter-status-elevation rule

// --- TRUE POSITIVES ---

// TP1: Filter modifies post_status without cap check
// ruleid: claude.php.wordpress.access-control.wp-insert-post-data-filter-status-elevation
function force_publish_status( $data, $postarr ) {
    if ( $data['post_type'] === 'custom_type' ) {
        $data['post_status'] = 'publish';
    }
    return $data;
}

// TP2: Filter modifies post_author without cap check
// ruleid: claude.php.wordpress.access-control.wp-insert-post-data-filter-status-elevation
function override_author( $data, $postarr ) {
    $data['post_author'] = 1;
    return $data;
}

// --- TRUE NEGATIVES ---

// TN1: Has current_user_can check
function safe_publish_status( $data, $postarr ) {
    if ( current_user_can( 'publish_posts' ) ) {
        // ok: claude.php.wordpress.access-control.wp-insert-post-data-filter-status-elevation
        $data['post_status'] = 'publish';
    }
    return $data;
}

// TN2: Modifies non-security field (post_name)
function modify_slug_only( $data, $postarr ) {
    // ok: claude.php.wordpress.access-control.wp-insert-post-data-filter-status-elevation
    $data['post_name'] = sanitize_title( $data['post_title'] );
    return $data;
}

// TN3: De-escalates status to a plugin-defined hidden/non-published custom
// status — not a privilege-escalation vector regardless of cap check.
function downgrade_to_custom_copy_status( $data, $postarr ) {
    if ( $data['post_status'] === 'publish' ) {
        // ok: claude.php.wordpress.access-control.wp-insert-post-data-filter-status-elevation
        $data['post_status'] = 'my-plugin-copy-status';
    }
    return $data;
}
