<?php

// Test cases for claude.php.wordpress.xss.admin-notice-unescaped-option-output

// --- TRUE POSITIVES ---

function my_plugin_admin_notice_tp1() {
    $message = get_option('my_plugin_notice_message');
    // ruleid: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    printf('<div class="notice notice-success"><p>%s</p></div>', $message);
}

function settings_saved_notice_tp2() {
    if (isset($_GET['message'])) {
        $msg = $_GET['message'];
        // ruleid: claude.php.wordpress.xss.admin-notice-unescaped-option-output
        echo '<div class="updated"><p>' . $msg . '</p></div>';
    }
}

function render_settings_notice_tp3() {
    $min_count = get_option('min_comment_count');
    // ruleid: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    echo '<input type="text" value="' . $min_count . '">';
}

function admin_transient_notice_tp4() {
    $notice = get_transient('plugin_activation_notice');
    if ($notice) {
        // ruleid: claude.php.wordpress.xss.admin-notice-unescaped-option-output
        echo '<div class="notice"><p>' . $notice . '</p></div>';
    }
}

// Wrapper/service-class option accessor (Context/Container/Settings object)
// standing in for the bare get_option() call — same intrinsic source.
class DiagnosticsPanel_TP5 {
    private $context;
    public function renderLastError() {
        // ruleid: claude.php.wordpress.xss.admin-notice-unescaped-option-output
        echo 'Last communication error: ' . $this->context->getOption('last_comm_error', '');
    }
}

// --- FALSE POSITIVES (properly escaped) ---

function my_plugin_admin_notice_escaped_fp1() {
    $message = get_option('my_plugin_notice_message');
    // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    printf('<div class="notice"><p>%s</p></div>', esc_html($message));
}

function settings_saved_notice_escaped_fp2() {
    if (isset($_GET['message'])) {
        $msg = esc_html($_GET['message']);
        // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
        echo '<div class="updated"><p>' . $msg . '</p></div>';
    }
}

function render_settings_notice_escaped_fp3() {
    $min_count = get_option('min_comment_count');
    // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    echo '<input type="text" value="' . esc_attr($min_count) . '">';
}

function admin_notice_intval_fp4() {
    $count = get_option('item_count');
    // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    printf('<div class="notice"><p>%s items</p></div>', intval($count));
}

function admin_notice_sanitized_fp5() {
    $message = sanitize_text_field(get_option('my_message'));
    // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    echo '<div class="notice"><p>' . $message . '</p></div>';
}

// OK: fully-qualified (leading-backslash) sanitizer call — the common style in
// namespaced plugins. Semgrep does not match a bare pattern against a FQN call
// without an explicit backslash-prefixed alternative.
function admin_notice_fqn_escaped_fp6() {
    $message = get_option('my_plugin_notice_message');
    // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    echo '<div class="notice"><p>' . \esc_html($message) . '</p></div>';
}

// OK: wp_text_diff() routes every diff line through htmlspecialchars()
// internally before returning markup.
function admin_notice_wp_text_diff_fp7() {
    $stored = get_option('previous_settings_json');
    // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
    echo wp_text_diff( $stored, $_POST['new_settings_json'] );
}

// OK: wrapper/service-class option accessor whose result is escaped before
// output — mirrors the fix for the wrapper-accessor true positive above.
class DiagnosticsPanel_FP8 {
    private $context;
    public function renderLastError() {
        // ok: claude.php.wordpress.xss.admin-notice-unescaped-option-output
        echo 'Last communication error: ' . esc_html($this->context->getOption('last_comm_error', ''));
    }
}
