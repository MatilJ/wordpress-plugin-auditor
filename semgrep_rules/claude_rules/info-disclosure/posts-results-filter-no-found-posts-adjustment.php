<?php

// ruleid: claude.php.wordpress.info-disclosure.posts-results-filter-no-found-posts-adjustment
function myplugin_filter_restricted_posts( $posts, $query ) {
    if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST || ! is_array( $posts ) ) {
        return $posts;
    }
    foreach ( $posts as $key => $post ) {
        if ( ! myplugin_current_user_can_view( $post->ID ) ) {
            unset( $posts[ $key ] );
        }
    }
    return array_values( $posts );
}
add_filter( 'posts_results', 'myplugin_filter_restricted_posts', 10, 2 );

// ruleid: claude.php.wordpress.info-disclosure.posts-results-filter-no-found-posts-adjustment
function myplugin_hide_private_from_feed( $posts, $query ) {
    $posts = array_filter( $posts, function( $post ) {
        return myplugin_user_can_read( $post );
    } );
    return $posts;
}
add_filter( 'the_posts', 'myplugin_hide_private_from_feed', 10, 2 );

// ok: claude.php.wordpress.info-disclosure.posts-results-filter-no-found-posts-adjustment
function myplugin_filter_restricted_posts_fixed( $posts, $query ) {
    if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST || ! is_array( $posts ) ) {
        return $posts;
    }
    $removed = 0;
    foreach ( $posts as $key => $post ) {
        if ( ! myplugin_current_user_can_view( $post->ID ) ) {
            unset( $posts[ $key ] );
            $removed++;
        }
    }
    if ( $removed > 0 && $query instanceof WP_Query ) {
        $query->found_posts = max( 0, (int) $query->found_posts - $removed );
        $per_page = (int) $query->get( 'posts_per_page' );
        if ( $per_page > 0 ) {
            $query->max_num_pages = (int) ceil( $query->found_posts / $per_page );
        }
    }
    return array_values( $posts );
}
add_filter( 'posts_results', 'myplugin_filter_restricted_posts_fixed', 10, 2 );

// ok: claude.php.wordpress.info-disclosure.posts-results-filter-no-found-posts-adjustment
function myplugin_prime_post_cache( $posts, $query ) {
    global $wpdb;
    $ids = wp_list_pluck( $posts, 'ID' );
    $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
    $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->postmeta} WHERE post_id IN ({$placeholders})", $ids ) );
    return $posts;
}
add_filter( 'posts_results', 'myplugin_prime_post_cache', 10, 2 );
