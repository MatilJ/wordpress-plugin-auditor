<?php

// Test cases for claude.php.wordpress.xss.sprintf-html-context-unescaped

$value = get_post_meta($post_id, 'custom_class', true);
// ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
echo sprintf('<div class="%s">content</div>', $value);

$title = get_option('widget_title');
// ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
echo sprintf('<h2 class="widget-title">%s</h2>', $title);

$name = get_user_meta($user_id, 'display_name', true);
// ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
printf('<span data-name="%s">%s</span>', $name, $name);

$url = $_GET['redirect'];
// ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
echo sprintf('<a href="%s">Click</a>', $url);

$value = get_post_meta($post_id, 'custom_class', true);
// ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
echo sprintf('<div class="%s">content</div>', esc_attr($value));

$title = get_option('widget_title');
// ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
echo sprintf('<h2>%s</h2>', esc_html($title));

$url = $_GET['redirect'];
// ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
echo sprintf('<a href="%s">Click</a>', esc_url($url));

$count = get_post_meta($post_id, 'view_count', true);
// ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
echo sprintf('<span class="count">%d</span>', intval($count));

// Module/widget/field settings-array source, builder-variable sink
// (assignment/concat, not an immediate echo) — the Forminator
// CVE-2026-57814 shape: $field[...] flows into $html .= sprintf(...).
function render_field($field) {
    $id = $field['element_id'];
    $html = '';
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    $html .= sprintf('<div id="%s" class="field-col">', $id);
    return $html;
}

function widget($args, $instance) {
    $title = $instance['title'];
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    $out = sprintf('<h2 class="widget-title">%s</h2>', $title);
    echo $out;
}

function render_field_safe($field) {
    $id = $field['element_id'];
    $html = '';
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    $html .= sprintf('<div id="%s" class="field-col">', esc_attr($id));
    return $html;
}

function send_status_header($status) {
    $protocol = $_SERVER['SERVER_PROTOCOL'];
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    header(sprintf('%s %d Service Unavailable', $protocol, $status));
}

function notify_admin_by_mail($siteUrl) {
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    mail('admin@example.com', sprintf('Site alert on %s', $siteUrl), 'body');
}

function throw_on_write_failure($error) {
    $message = $error['message'];
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    throw new Exception(sprintf('Unable to write file: %s', $message));
}

function format_permission_octal($filePath) {
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    return sprintf('%o', fileperms($filePath));
}

function format_time_ago($meta) {
    $added = $meta['added'];
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf(esc_html__('%s ago', 'text-domain'), human_time_diff($added, time()));
}

// Positional/numbered specifiers (%1$s, %2$s) — the WP i18n-recommended
// form once a translatable string has 2+ placeholders, since translators
// may need to reorder them. A bare ".*%s.*" check misses this shape.
function render_notice_link($data) {
    $item_id = ( ! empty( $_GET['item_id'] ) ) ? $_GET['item_id'] : false;
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf(__('You can now <a href="%1$s">view the item</a>, which has the ID "%2$s".', 'text-domain'), esc_url($data['url']), $item_id);
}

function render_notice_link_safe($data) {
    $item_id = ( ! empty( $_GET['item_id'] ) ) ? $_GET['item_id'] : false;
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf(__('You can now <a href="%1$s">view the item</a>, which has the ID "%2$s".', 'text-domain'), esc_url($data['url']), esc_html($item_id));
}

// WP-CLI output is command-line stdout, never rendered in a browser context —
// escaping is not applicable regardless of what the interpolated value contains.
function cli_report_job_status($job) {
    $name = get_option('job_display_name_' . $job['id']);
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    WP_CLI::log(sprintf('<job "%s"> completed', $name));
}

function cli_report_job_error($job) {
    $reason = $job['error_message'];
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    WP_CLI::error(sprintf('Job "%s" failed: %s', $job['name'], $reason));
}

// Tracking-pixel noscript-fallback shape: value urlencode()-wrapped before
// reaching the sprintf() src attribute (confirmed safe sibling of a GA4/GTM-
// style vulnerable implementation that omits urlencode() on the same value).
function output_noscript_pixel_safe() {
    $search_term = $_GET['s'];
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    $src = 'https://example.com/collect?ep.search_term=' . urlencode($search_term);
    echo sprintf('<noscript><img src="%s"></noscript>', $src);
}

// TP shape: same value, same sink, but no urlencode()/escaping applied.
function output_noscript_pixel_vulnerable() {
    $search_term = $_GET['s'];
    $src = 'https://example.com/collect?ep.search_term=' . $search_term;
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf('<noscript><img src="%s"></noscript>', $src);
}

// get_search_query(false) explicitly disables WP core's own escaping
// (default $escaped = true applies esc_attr()) and returns the raw query.
function search_page_title() {
    $search_query = get_search_query(false);
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    $title = sprintf(__('Search Results for: %s', 'text-domain'), $search_query ? $search_query : __('No query', 'text-domain'));
    return $title;
}

function search_page_heading() {
    $search_query = get_search_query(0);
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf('<h1>Results for: %s</h1>', $search_query);
}

// Safe sibling: default argument (omitted, i.e. true) keeps WP core's
// built-in esc_attr() escaping intact before the value reaches sprintf().
function search_page_title_safe() {
    $search_query = get_search_query();
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    $title = sprintf(__('Search Results for: %s', 'text-domain'), $search_query ? $search_query : __('No query', 'text-domain'));
    return $title;
}

// A plugin's own logging-wrapper call: the sprintf() result is written to a
// log file / PHP error log, not rendered as HTML. Confirmed FP source:
// templately 3.7.0 AIContent.php chatbot_import_prepare() warm-start log line.
function log_import_progress($chat, $ready, $expected) {
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    Helper::log(sprintf('import[%s] warm start: ready=%d/%d', $chat, count($ready), count($expected)), 'ai-import', 'info');
}

function log_import_progress_instance($logger, $chat) {
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    $logger->log(sprintf('import[%s] saved', $chat), 'ai-import', 'info');
}

// JSON_HEX_TAG hex-encodes < and > in addition to json_encode()'s default
// quote/backslash escaping, so the value cannot break out of a JS string
// literal or inject an HTML tag even outside a <script> block.
function render_command_palette_script($labels) {
    $shortcut = $labels['appleOS'];
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf(
        '( %s )( %s );',
        'function(label){}',
        wp_json_encode($shortcut, JSON_HEX_TAG | JSON_UNESCAPED_SLASHES)
    );
}

function render_command_palette_script_vulnerable($labels) {
    $shortcut = $labels['appleOS'];
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf('( %s )( %s );', 'function(label){}', $shortcut);
}

// Hydrated record/model getter (WC_Data-style get_prop() accessor) whose
// backing property was set verbatim from REST request input at write time.
function render_reply_heading($review) {
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    printf(__('<strong>Reply to %s</strong>', 'text-domain'), $review->get_author_name());
}

function render_comment_heading($comment) {
    // ruleid: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf('<h4 class="comment-author">%s</h4>', $comment->get_user_name());
}

function render_reply_heading_safe($review) {
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    printf(__('<strong>Reply to %s</strong>', 'text-domain'), esc_html($review->get_author_name()));
}

function render_comment_heading_safe($comment) {
    // ok: claude.php.wordpress.xss.sprintf-html-context-unescaped
    echo sprintf('<h4 class="comment-author" data-name="%s">%s</h4>', esc_attr($comment->get_user_name()), esc_html($comment->get_user_name()));
}
