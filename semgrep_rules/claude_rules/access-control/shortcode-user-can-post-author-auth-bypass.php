<?php
// Tests for claude.php.wordpress.access-control.shortcode-user-can-post-author-auth-bypass

// TP: shortcode handler using post_author as auth gate — viewer's identity never checked
function vulnerable_entries_shortcode($atts) {
    $post = get_post();
    if (!$post) {
        return '';
    }
    // ruleid: claude.php.wordpress.access-control.shortcode-user-can-post-author-auth-bypass
    if (!user_can($post->post_author, 'plugin_read_entries')) {
        return '';
    }
    return render_entries_table();
}

// TP: method variant — post_author check in OOP shortcode callback
class MyPlugin {
    public function widget_shortcode($atts) {
        global $post;
        // ruleid: claude.php.wordpress.access-control.shortcode-user-can-post-author-auth-bypass
        if (user_can($post->post_author, 'view_private_data')) {
            return $this->get_private_data();
        }
        return '';
    }
}

// OK: correct check — current_user_can evaluates the viewing user's own capabilities
// ok: claude.php.wordpress.access-control.shortcode-user-can-post-author-auth-bypass
function correct_shortcode($atts) {
    if (!current_user_can('plugin_read_entries')) {
        return '';
    }
    return render_entries_table();
}

// OK: user_can with an explicit integer user ID — not a post_author property access
// ok: claude.php.wordpress.access-control.shortcode-user-can-post-author-auth-bypass
function check_specific_user_id($user_id, $cap) {
    return user_can($user_id, $cap);
}
