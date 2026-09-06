<?php

// ---- TRUE POSITIVES ----

class Frontend_Permission_Gate_TP1 {
    private function extract_post_id_from_context( $context ): ?int {
        // ruleid: claude.php.wordpress.access-control.rest-permission-callback-type-discriminator-fallthrough
        return match ( $context['type'] ) {
            'post'    => isset( $context['id'] ) ? absint( $context['id'] ) : null,
            'comment' => isset( $context['post_id'] ) ? absint( $context['post_id'] ) : null,
            default   => null,
        };
    }

    public function get_item_permissions_check( $request ) {
        $context = json_decode( $request->get_param( 'context' ), true );
        $post_id = $this->extract_post_id_from_context( $context );

        if ( $post_id && ! $this->can_user_read_post( $post_id ) ) {
            return new WP_Error( 'rest_forbidden', 'Denied', array( 'status' => 403 ) );
        }

        return true;
    }
}

class Frontend_Permission_Gate_TP2 {
    private function resolve_resource_id( $data ): ?int {
        // ruleid: claude.php.wordpress.access-control.rest-permission-callback-type-discriminator-fallthrough
        switch ( $data['type'] ) {
            case 'page':
                return absint( $data['page_id'] );
            case 'attachment':
                return absint( $data['attachment_id'] );
            default:
                return null;
        }
    }

    public function permission_callback( $request ) {
        $id = $this->resolve_resource_id( $request->get_json_params() );
        if ( $id && ! current_user_can( 'read_post', $id ) ) {
            return false;
        }
        return true;
    }
}

// ---- FALSE POSITIVES ----

class Frontend_Permission_Gate_OK1 {
    // ok: claude.php.wordpress.access-control.rest-permission-callback-type-discriminator-fallthrough
    private function extract_post_id_from_context( $context ): ?int {
        return match ( $context['type'] ) {
            'post'    => isset( $context['id'] ) ? absint( $context['id'] ) : null,
            'comment' => isset( $context['post_id'] ) ? absint( $context['post_id'] ) : null,
            default   => throw new InvalidArgumentException( 'Unknown context type' ),
        };
    }
}

class Frontend_Permission_Gate_OK2 {
    // ok: claude.php.wordpress.access-control.rest-permission-callback-type-discriminator-fallthrough
    private function resolve_resource_id( $data ): ?int {
        switch ( $data['type'] ) {
            case 'page':
                return absint( $data['page_id'] );
            default:
                return -1;
        }
    }
}

class Frontend_Permission_Gate_OK3 {
    // No nullable-int return type — not the vulnerable ID-extraction-helper shape.
    // ok: claude.php.wordpress.access-control.rest-permission-callback-type-discriminator-fallthrough
    private function resolve_label( $data ) {
        return match ( $data['type'] ) {
            'post'  => 'Post',
            default => 'Unknown',
        };
    }
}
