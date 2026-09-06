<?php
// Test cases for claude.php.wordpress.xss.inline-js-template-literal-raw-echo
?>

// ruleid: claude.php.wordpress.xss.inline-js-template-literal-raw-echo
<button class="share-btn" onclick="const text = `<?php
    echo $options['thank-you']['twitter_message']; ?>`; window.Give.share.fn.twitter(url, text); return false;">Share</button>

// ruleid: claude.php.wordpress.xss.inline-js-template-literal-raw-echo
<script>const widgetLabel = `<?php
    echo $settings['widget_label']; ?>`;
    document.querySelector('.widget-title').textContent = widgetLabel;
</script>

// ok: claude.php.wordpress.xss.inline-js-template-literal-raw-echo
<button class="share-btn" onclick="const text = `<?php
    echo esc_js($options['thank-you']['twitter_message']); ?>`; window.Give.share.fn.twitter(url, text);">Share</button>

<?php
// ok: claude.php.wordpress.xss.inline-js-template-literal-raw-echo
global $wpdb;
$row = $wpdb->get_row(
    $wpdb->prepare("SELECT twitter_message FROM {$wpdb->prefix}give_form_meta WHERE form_id = %d", $form_id)
);
$twitter_message = $row->twitter_message;
?>

// Wrong-escaper variant: wp_kses() sanitizes HTML but has no concept of JS
// template-literal substitution syntax ($, {, }) — confirmed real-world
// instance in a popup subscription-form renderer.
// ruleid: claude.php.wordpress.xss.inline-js-template-literal-raw-echo
<script>es_pre_data.messages[0].form_html = `<?php echo wp_kses( html_entity_decode( $form ), $allowedtags ); ?>`;</script>

// Wrong-escaper variant: sanitize_text_field() strips tags but not $/{/}.
// ruleid: claude.php.wordpress.xss.inline-js-template-literal-raw-echo
<script>const label = `<?php echo sanitize_text_field( $_POST['label'] ); ?>`;</script>

// SAFE: the sanitizer's output is additionally wrapped in esc_js() before
// being echoed — esc_js() escapes the JS-template-literal-breaking
// characters that wp_kses() alone does not.
// ok: claude.php.wordpress.xss.inline-js-template-literal-raw-echo
<script>es_pre_data.messages[0].form_html = `<?php echo esc_js( wp_kses( html_entity_decode( $form ), $allowedtags ) ); ?>`;</script>
