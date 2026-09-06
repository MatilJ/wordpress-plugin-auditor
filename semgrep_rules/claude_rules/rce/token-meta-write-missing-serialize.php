<?php

// ---- TRUE POSITIVES ----

function tp_token_save_getter_no_serialize( $contact, $entry ) {
    // ruleid: claude.php.wordpress.rce.token-meta-write-missing-serialize
    Automator()->db->token->save( 'CONTACT_EMAIL', $contact->get_email(), $entry );
}

function tp_token_save_array_access_no_serialize( $data, $trigger_log_entry ) {
    // ruleid: claude.php.wordpress.rce.token-meta-write-missing-serialize
    Automator()->db->token->save( 'MAILPOETFORMS_EMAIL', $data['email'], $trigger_log_entry );
}

function tp_meta_value_array_literal_no_serialize( $address_parts, $id, $log_id, $run ) {
    global $wpdb;
    foreach ( $address_parts as $part_key => $part_value ) {
        $wpdb->trigger->add_meta(
            $id,
            $log_id,
            $run,
            // ruleid: claude.php.wordpress.rce.token-meta-write-missing-serialize
            array(
                'meta_key'   => $part_key,
                'meta_value' => $part_value,
            )
        );
    }
}

// ---- SAFE VARIANTS ----

function ok_token_save_wrapped( $contact, $entry ) {
    // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
    Automator()->db->token->save( 'CONTACT_EMAIL', maybe_serialize( $contact->get_email() ), $entry );
}

function ok_meta_value_wrapped( $part_key, $part_value, $id, $log_id, $run ) {
    global $wpdb;
    $wpdb->trigger->add_meta(
        $id,
        $log_id,
        $run,
        // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
        array(
            'meta_key'   => $part_key,
            'meta_value' => maybe_serialize( $part_value ),
        )
    );
}

function ok_token_save_scalar_id( $recipe_id, $trigger_meta ) {
    // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
    Automator()->db->token->save( 'recipe_id', $recipe_id, $trigger_meta );
}

function ok_unrelated_method_name( $logger, $contact, $entry ) {
    // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
    $logger->write( 'CONTACT_EMAIL', $contact->get_email(), $entry );
}

// "set*"-prefixed method is an in-memory property mutator (read-path
// hydration from a DB row), not a persistence call — the real DB write
// lives in a differently-named sibling (saveMeta()) that re-derives its
// own value rather than reusing this one. Confirmed FP:
// shortpixel-image-optimiser 6.5.5 CustomImageModel::setMeta().
class Image_Model_Hydration {
    public $image_meta;

    public function hydrate( $imagerow ) {
        $data = json_decode( $imagerow->extra_info, true );
        if ( isset( $data['webpStatus'] ) ) {
            // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
            $this->setMeta( 'webp', $data['webpStatus'] );
        }
    }

    public function setMeta( $key, $value ) {
        $this->image_meta->$key = $value;
    }
}

function ok_wp_query_default_args_boilerplate( $offset, $post_types ) {
    // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
    $args = array(
        'posts_per_page' => 20,
        'offset'         => $offset,
        'category'       => '',
        'meta_key'       => '',
        'meta_value'     => '',
        'post_type'      => $post_types,
    );
    return get_posts( $args );
}

// get_posts()/WP_Query accept the legacy top-level 'meta_key'/'meta_value'
// args as a READ-side query filter, not a persistence call — even when
// meta_value is a non-literal variable (not caught by the bare-string-
// literal exclusion above).
function ok_get_posts_meta_value_variable_query_arg( $post_id ) {
    // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
    return get_posts( array(
        'numberposts' => -1,
        'post_status' => 'publish',
        'post_type'   => 'wpz-insta_feed',
        'meta_key'    => '_wpz-insta_user-id',
        'meta_value'  => $post_id,
    ) );
}

// $value was reassigned to its wrapped form via a separate maybe_serialize()
// statement earlier in the same function, before landing unwrapped in the
// meta_value array-literal slot — the wrapping already happened.
function add_meta_to_order_table( $order_id, $meta_key, $value ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'wc_orders_meta';
    $value = maybe_serialize( $value );
    // ok: claude.php.wordpress.rce.token-meta-write-missing-serialize
    $insert_data = array(
        'order_id'   => $order_id,
        'meta_key'   => $meta_key,
        'meta_value' => $value,
    );
    $wpdb->insert( $table_name, $insert_data );
}
