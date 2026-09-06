<?php

// ruleid: claude.php.wordpress.rce.shortcode-toggle-default-enabled
$defaults = array(
    'hide_form' => false,
    'scroll'    => false,
    'shortcode' => true,
    'message'   => __('Form updated', 'textdomain'),
    'wrapper'   => '<div id="message" class="updated">%s</div>',
);

// ruleid: claude.php.wordpress.rce.shortcode-toggle-default-enabled
$action_defaults = array(
    'subject'           => '',
    'content'           => '',
    'html'              => false,
    'enable_shortcodes' => true,
);

// ok: claude.php.wordpress.rce.shortcode-toggle-default-enabled
$patched_defaults = array(
    'hide_form' => false,
    'scroll'    => false,
    'shortcode' => false,
    'message'   => __('Form updated', 'textdomain'),
    'wrapper'   => '<div id="message" class="updated">%s</div>',
);

// ok: claude.php.wordpress.rce.shortcode-toggle-default-enabled
$unrelated_defaults = array(
    'post_type' => 'post',
    'per_page'  => true,
    'orderby'   => 'date',
);
