<?php

// ── TRUE POSITIVES ──────────────────────────────────────────────────────────

function tp_wp_doing_ajax_update_option() {
    if (wp_doing_ajax()) {
        $key = sanitize_text_field($_POST['key']);
        $val = sanitize_text_field($_POST['value']);
        // ruleid: claude.php.wordpress.access-control.wp-doing-ajax-as-authorization
        update_option($key, $val);
    }
}

function tp_wp_doing_ajax_wpdb_insert() {
    if (wp_doing_ajax()) {
        global $wpdb;
        // ruleid: claude.php.wordpress.access-control.wp-doing-ajax-as-authorization
        $wpdb->insert($wpdb->prefix . 'custom_table', array('data' => $_POST['data']));
    }
}

function tp_wp_doing_ajax_insert_post() {
    if (wp_doing_ajax()) {
        // ruleid: claude.php.wordpress.access-control.wp-doing-ajax-as-authorization
        wp_insert_post(array(
            'post_title' => sanitize_text_field($_POST['title']),
            'post_status' => 'publish',
        ));
    }
}

function tp_wp_doing_ajax_schedule_event() {
    if (wp_doing_ajax()) {
        // ruleid: claude.php.wordpress.access-control.wp-doing-ajax-as-authorization
        wp_schedule_event(time(), 'hourly', sanitize_text_field($_POST['hook']));
    }
}

function tp_doing_ajax_constant_update_option() {
    if (defined('DOING_AJAX') && DOING_AJAX) {
        // ruleid: claude.php.wordpress.access-control.doing-ajax-constant-as-authorization
        update_option('my_setting', sanitize_text_field($_POST['value']));
    }
}

function tp_doing_ajax_constant_delete_post() {
    if (defined('DOING_AJAX') && DOING_AJAX) {
        // ruleid: claude.php.wordpress.access-control.doing-ajax-constant-as-authorization
        wp_delete_post(intval($_POST['post_id']));
    }
}

function tp_doing_ajax_constant_insert_user() {
    if (defined('DOING_AJAX') && DOING_AJAX) {
        // ruleid: claude.php.wordpress.access-control.doing-ajax-constant-as-authorization
        wp_insert_user(array('user_login' => $_POST['login'], 'user_pass' => $_POST['pass']));
    }
}

// ── TRUE NEGATIVES (OK) ─────────────────────────────────────────────────────

function tn_wp_doing_ajax_with_cap_check() {
    if (wp_doing_ajax()) {
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        // ok: claude.php.wordpress.access-control.wp-doing-ajax-as-authorization
        update_option('my_setting', sanitize_text_field($_POST['value']));
    }
}

function tn_doing_ajax_constant_with_cap_check() {
    if (defined('DOING_AJAX') && DOING_AJAX) {
        current_user_can('manage_options');
        // ok: claude.php.wordpress.access-control.doing-ajax-constant-as-authorization
        update_option('my_setting', sanitize_text_field($_POST['value']));
    }
}

function tn_wp_doing_ajax_no_write() {
    if (wp_doing_ajax()) {
        $value = get_option('my_setting');
        wp_send_json_success($value);
    }
}
