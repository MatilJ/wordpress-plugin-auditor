<?php
// Isolated in its own file (not appended to the main test file) because a
// top-level PHP file is a single flat scope for Semgrep's sequence
// matching: an allow-list guard anywhere in the same file can otherwise be
// mistaken for guarding an earlier, unrelated sink in the same file.
//
// Fix shape: value outside a fixed allow-list is replaced with a hardcoded
// default before the template-loading wrapper call, so only known-safe
// strings ever reach it.
extract(shortcode_atts(array(
    'layout_style' => 'grid',
), $atts));
if (!in_array($layout_style, array('grid', 'list', 'carousel'))) {
    $layout_style = 'grid';
}
// ok: claude.php.wordpress.lfi.template-selector-param-to-include-no-sanitizer
my_get_template('widget/layout/' . $layout_style . '.php', array('layout_style' => $layout_style));
