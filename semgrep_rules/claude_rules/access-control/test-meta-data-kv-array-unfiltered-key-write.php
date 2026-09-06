<?php

// ---- TRUE POSITIVES ----

// Real pre-fix shape: caller-supplied 'meta_data' array of {key, value}
// objects, each item's key handed straight to update_meta_data() with no
// block-list check anywhere in the loop.
class Vulnerable_Users_Controller {
    protected function prepare_object_for_database( $request, $creating = false ) {
        $user = new Entity();

        if ( isset( $request['meta_data'] ) && is_array( $request['meta_data'] ) ) {
            foreach ( $request['meta_data'] as $meta ) {
                // ruleid: claude.php.wordpress.access-control.meta-data-kv-array-unfiltered-key-write
                $user->update_meta_data( $meta['key'], $meta['value'], isset( $meta['id'] ) ? $meta['id'] : '' );
            }
        }

        return $user;
    }
}

// Same sink shape via add_meta_data() and a decoded JSON request body.
class Vulnerable_Instructor_Controller {
    public function create_item( $request ) {
        $instructor = new Entity();
        $payload    = json_decode( $request->get_body(), true );

        foreach ( $payload['meta_data'] as $meta ) {
            // ruleid: claude.php.wordpress.access-control.meta-data-kv-array-unfiltered-key-write
            $instructor->add_meta_data( $meta['key'], $meta['value'] );
        }

        return $instructor;
    }
}

// ---- FALSE POSITIVES ----

// Fixed sibling of Vulnerable_Users_Controller — the item's own key field is
// checked against a distinct, non-request-derived block-list before the
// write, and only bypassed for callers with manage_options.
class Fixed_Users_Controller {
    protected function get_privileged_meta_keys() {
        return array( 'roles', 'role', 'capabilities', 'wp_capabilities', 'user_level', 'wp_user_level', 'session_tokens' );
    }

    protected function prepare_object_for_database( $request, $creating = false ) {
        $user = new Entity();

        if ( isset( $request['meta_data'] ) && is_array( $request['meta_data'] ) ) {
            $privileged_meta_keys = $this->get_privileged_meta_keys();
            foreach ( $request['meta_data'] as $meta ) {
                if ( ! isset( $meta['key'] ) ) {
                    continue;
                }
                if ( in_array( sanitize_key( $meta['key'] ), $privileged_meta_keys, true ) && ! current_user_can( 'manage_options' ) ) {
                    continue;
                }
                // ok: claude.php.wordpress.access-control.meta-data-kv-array-unfiltered-key-write
                $user->update_meta_data( $meta['key'], $meta['value'], isset( $meta['id'] ) ? $meta['id'] : '' );
            }
        }

        return $user;
    }
}

// Loop source is a local, hardcoded array — not request-derived, so the
// $ARR metavariable-regex on request/post/input tokens never matches.
function ok_local_defaults_array( $user ) {
    $defaults = array(
        array( 'key' => 'bio', 'value' => '' ),
        array( 'key' => 'location', 'value' => '' ),
    );
    foreach ( $defaults as $meta ) {
        // ok: claude.php.wordpress.access-control.meta-data-kv-array-unfiltered-key-write
        $user->update_meta_data( $meta['key'], $meta['value'] );
    }
}

// Allow-list variant of the fix — isset() against a fixed allow-list keyed
// by the same item field, rather than a block-list.
class Fixed_Allowlist_Controller {
    protected function update( $request ) {
        $product   = new Entity();
        $allowed   = array( 'color' => true, 'size' => true );
        foreach ( $request['meta_data'] as $meta ) {
            if ( isset( $allowed[ $meta['key'] ] ) ) {
                // ok: claude.php.wordpress.access-control.meta-data-kv-array-unfiltered-key-write
                $product->update_meta_data( $meta['key'], $meta['value'] );
            }
        }
        return $product;
    }
}
