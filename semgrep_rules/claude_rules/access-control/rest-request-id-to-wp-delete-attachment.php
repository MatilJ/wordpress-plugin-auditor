<?php
/**
 * Test cases for claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
 *
 * TRUE POSITIVES: wp_delete_attachment() called with a REST request param
 *   with no prior current_user_can($cap, $id) ownership check.
 * FALSE POSITIVES: per-resource capability check present, or manage_options gate.
 */

// ── MATCH: direct get_param → wp_delete_attachment, no ownership check ────────
// Confirmed TP: sg-ai-studio 1.1.7 core/Rest/Gutenberg.php:367-417 —
// Contributor deletes any admin-owned attachment via delete-image endpoint.

function test_delete_attachment_no_ownership_check( $request ) {
    $image_id = $request->get_param( 'image_id' );
    $attachment = get_post( $image_id );
    if ( ! $attachment || 'attachment' !== $attachment->post_type ) {
        return new WP_Error( 'not_found', '', [ 'status' => 404 ] );
    }
    // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
    wp_delete_attachment( $image_id, true );
}

// ── MATCH: multi-step param extraction, no ownership check ────────────────────

function test_delete_attachment_two_step_no_check( $request ) {
    $params  = $request->get_json_params();
    $media_id = $params['id'];
    // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
    wp_delete_attachment( $media_id, true );
}

// ── MATCH: get_body_params(), no ownership check ──────────────────────────────

function test_delete_attachment_body_params_no_check( $request ) {
    $body_params = $request->get_body_params();
    $file_id     = $body_params['file_id'];
    // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
    wp_delete_attachment( $file_id, false );
}

// ── NO MATCH: per-resource current_user_can() check present ───────────────────

function test_delete_attachment_with_capability_check( $request ) {
    $image_id = $request->get_param( 'image_id' );
    if ( ! current_user_can( 'delete_post', $image_id ) ) {
        return new WP_Error( 'rest_forbidden', '', [ 'status' => 403 ] );
    }
    // ok: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
    wp_delete_attachment( $image_id, true );
}

// ── NO MATCH: delete_attachment capability check present ─────────────────────

function test_delete_attachment_with_delete_attachment_cap( $request ) {
    $id = $request->get_param( 'id' );
    if ( ! current_user_can( 'delete_attachment', $id ) ) {
        return new WP_Error( 'rest_forbidden', '', [ 'status' => 403 ] );
    }
    // ok: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
    wp_delete_attachment( $id, true );
}

// ── MATCH: global-namespace form \wp_delete_attachment() (common in namespaced plugins) ──
// Confirmed TP: sg-ai-studio 1.1.7 core/Rest/Gutenberg.php:395 uses \wp_delete_attachment().

class DeleteHandler {
    public function delete_image( $request ) {
        $image_id = $request->get_param( 'image_id' );
        // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
        $deleted = \wp_delete_attachment( $image_id, true );
        return $deleted;
    }
}

// ── MATCH: single-arg current_user_can('edit_posts') is NOT an ownership check ─
// Global role check does not verify that the caller owns the target attachment.

function test_delete_attachment_global_role_check_still_fires( $request ) {
    $image_id = $request->get_param( 'image_id' );
    if ( ! current_user_can( 'edit_posts' ) ) {
        return new WP_Error( 'rest_forbidden', '', [ 'status' => 403 ] );
    }
    // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
    wp_delete_attachment( $image_id, true );
}

// ── MATCH: bulk delete over a loop, no ownership check (non-REST shape) ───────
// Confirmed TP: kirki 6.1.1 includes/Ajax/Form.php:848-852 delete_attachments() —
// $file_ids relayed from a custom table (kirki_forms_data) one call removed from
// the originating AJAX dispatcher, never validated as belonging to the caller.

class FormAttachmentCleanup {
    private static function delete_attachments( $file_ids ) {
        foreach ( $file_ids as $file_id ) {
            // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
            wp_delete_attachment( $file_id, true );
        }
    }
}

// ── MATCH: bulk delete over a loop, global-namespace call form ────────────────

function delete_selected_media( $ids ) {
    foreach ( $ids as $id ) {
        // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
        \wp_delete_attachment( $id, true );
    }
}

// ── NO MATCH: bulk delete over a loop WITH a per-item ownership check ─────────

function delete_selected_media_with_check( $ids ) {
    foreach ( $ids as $id ) {
        if ( ! current_user_can( 'delete_post', $id ) ) {
            continue;
        }
        // ok: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
        wp_delete_attachment( $id, true );
    }
}

// ── MATCH: hook-callback deletion sourced from persisted comment meta ─────────
// The ID reaches wp_delete_attachment() via get_comment_meta(), read back from
// an earlier, separate request, then hard-deleted the next time this comment
// is moderated (delete_comment action) — a second-order shape distinct from
// the REST-param and simple-loop variants above. Nested two levels below the
// function's own top-level statement sequence (outer foreach over meta keys,
// inner foreach over values, guarded by unrelated if-checks) — the exact
// real-world shape a plain (non-deep) "..." sequence match would miss.

class ReviewMediaCleanup {
    public function delete_review_media_attachments( $comment_id, $comment ) {
        $meta_keys = array( 'review_image_id', 'review_video_id' );
        foreach ( $meta_keys as $meta_key ) {
            $meta_values = get_comment_meta( $comment_id, $meta_key, false );
            if ( empty( $meta_values ) ) {
                continue;
            }
            foreach ( $meta_values as $attachment_id ) {
                $attachment_id = absint( $attachment_id );
                if ( ! $attachment_id ) {
                    continue;
                }
                if ( 'attachment' === get_post_type( $attachment_id ) ) {
                    // ruleid: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
                    wp_delete_attachment( $attachment_id, true );
                }
            }
        }
    }
}

// ── NO MATCH: same meta-sourced shape, WITH a per-item ownership check ────────

class ReviewMediaCleanupChecked {
    public function delete_review_media_attachments( $comment_id, $comment ) {
        $attachment_id = get_comment_meta( $comment_id, 'review_image_id', true );
        if ( ! current_user_can( 'delete_post', $attachment_id ) ) {
            return;
        }
        // ok: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
        wp_delete_attachment( $attachment_id, true );
    }
}

// ── NO MATCH: get_post_meta() used as a possession/ownership gate, not as an
// unchecked ID source — the caller must present a random per-attachment token
// back (stored as meta at upload time) before the deletion is allowed to
// proceed. Real-world idiom: a bearer 'cr-upload-temp-key' postmeta value.

function delete_uploaded_media_with_key_check() {
    $decoded = json_decode( stripslashes( $_POST['image'] ), true );
    $attachment_id = intval( $decoded['id'] );
    if ( 'attachment' === get_post_type( $attachment_id ) ) {
        if ( $decoded['key'] === get_post_meta( $attachment_id, 'upload-temp-key', true ) ) {
            // ok: claude.php.wordpress.access-control.rest-request-id-to-wp-delete-attachment
            wp_delete_attachment( $attachment_id, true );
        }
    }
}
