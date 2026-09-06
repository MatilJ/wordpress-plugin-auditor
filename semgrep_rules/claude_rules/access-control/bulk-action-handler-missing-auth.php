<?php

// ruleid: claude.php.wordpress.access.bulk-action-handler-missing-auth
function handle_export_no_auth($redirect_to, $doaction, $comment_ids) {
    if ($doaction === 'export_comments_to_csv') {
        export_comments($comment_ids);
    }
    return $redirect_to;
}
add_filter('handle_bulk_actions-edit-comments', 'handle_export_no_auth', 10, 3);

// ruleid: claude.php.wordpress.access.bulk-action-handler-missing-auth
function handle_user_export_no_auth($redirect_to, $doaction, $user_ids) {
    if ($doaction === 'export_users_to_csv') {
        export_users($user_ids);
    }
    return $redirect_to;
}
add_filter('handle_bulk_actions-users', 'handle_user_export_no_auth', 10, 3);

// ok: claude.php.wordpress.access.bulk-action-handler-missing-auth
function handle_export_with_auth($redirect_to, $doaction, $post_ids) {
    if ($doaction === 'bulk_download' && current_user_can('manage_options')) {
        check_admin_referer('bulk-posts');
        $data = [];
        foreach ($post_ids as $post_id) {
            $data[] = get_post($post_id);
        }
        export_posts($data);
    }
    return $redirect_to;
}
add_filter('handle_bulk_actions-edit-post', 'handle_export_with_auth', 10, 3);

// ok: claude.php.wordpress.access.bulk-action-handler-missing-auth
function handle_term_export_with_auth($redirect_to, $doaction, $term_ids) {
    if ($doaction === 'export_terms' && current_user_can('manage_categories')) {
        export_terms($term_ids);
    }
    return $redirect_to;
}
add_filter('handle_bulk_actions-edit-category', 'handle_term_export_with_auth', 10, 3);

// Negation-style dispatch — should fire (no auth check)

// ruleid: claude.php.wordpress.access.bulk-action-handler-missing-auth
function handle_hide_action_no_auth($redirect_to, $doaction, $post_ids) {
    if ('se_show' !== $doaction && 'se_hide' !== $doaction) {
        return $redirect_to;
    }
    save_post_ids($post_ids, $doaction === 'se_hide');
    return $redirect_to;
}
add_filter('handle_bulk_actions-edit-post', 'handle_hide_action_no_auth', 10, 3);

// ok: claude.php.wordpress.access.bulk-action-handler-missing-auth
function handle_hide_action_with_auth($redirect_to, $doaction, $post_ids) {
    if ('se_show' !== $doaction && 'se_hide' !== $doaction) {
        return $redirect_to;
    }
    if (!current_user_can('edit_others_posts')) {
        return $redirect_to;
    }
    save_post_ids($post_ids, $doaction === 'se_hide');
    return $redirect_to;
}
add_filter('handle_bulk_actions-edit-post', 'handle_hide_action_with_auth', 10, 3);

// ── MATCH: class-method handler registered via add_filter(array($this, 'method'))
// inside a sibling registration method — the OOP registration shape this guard adds.

class VulnerableBulkHandler {
    public function register() {
        add_filter('handle_bulk_actions-edit-shop_order', array($this, 'handle_export'), 10, 3);
    }
    // ruleid: claude.php.wordpress.access.bulk-action-handler-missing-auth
    public function handle_export($redirect_to, $doaction, $order_ids) {
        if ($doaction === 'export_orders') {
            export_orders($order_ids);
        }
        return $redirect_to;
    }
}

// ── NO MATCH: same 3-param/action-dispatch/return-redirect shape, but registered
// on an unrelated filter hook (e.g. a WooCommerce Checkout Block default-value
// filter) rather than handle_bulk_actions-* — coincidental signature collision.
// Confirmed FP: woocommerce-pdf-invoices-packing-slips 5.15.2 edi/Peppol.php
// peppol_prefill_checkout_block_field_from_user_meta().

class UnrelatedFilterCallback {
    public function register() {
        add_filter('woocommerce_get_default_value_for_field', array($this, 'handle_export'), 10, 3);
    }
    // ok: claude.php.wordpress.access.bulk-action-handler-missing-auth
    public function handle_export($redirect_to, $doaction, $order_ids) {
        if ($doaction === 'export_orders') {
            export_orders($order_ids);
        }
        return $redirect_to;
    }
}

// Coincidental signature collision — WordPress `plugins_api` filter / EDD Software
// Licensing updater callback, not a bulk-action handler. Same (mixed, string, object)
// triad shape and early-return-first-param convention, unrelated hook.

// ok: claude.php.wordpress.access.bulk-action-handler-missing-auth
function plugins_api_filter($_data, $_action = '', $_args = null) {
    if ('plugin_information' !== $_action) {
        return $_data;
    }
    if (!isset($_args->slug) || ($_args->slug !== 'my-plugin')) {
        return $_data;
    }
    return $_data;
}
