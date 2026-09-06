<?php
// Test cases for claude.php.wordpress.xss.block-attribute-tag-name-esc-attr

function render_accordion_item_block( $attributes ) {
    $title   = $attributes['title'] ?? 'Accordion Title';
    $content = $attributes['content'] ?? '';

    // Tainted via intermediate variable — esc_attr() is wrong sanitizer at tag-name position
    $tag_var = $attributes['accordionTitleTag'] ?? 'h3';
    // ruleid: claude.php.wordpress.xss.block-attribute-tag-name-esc-attr
    echo esc_attr( $tag_var );

    // Direct access — key 'headingTag' contains 'tag'
    // ruleid: claude.php.wordpress.xss.block-attribute-tag-name-esc-attr
    echo esc_attr( $attributes['headingTag'] );

    // ok: claude.php.wordpress.xss.block-attribute-tag-name-esc-attr
    // Correct function: tag_escape() validates against WordPress allowlist
    echo tag_escape( $attributes['accordionTitleTag'] );

    // ok: claude.php.wordpress.xss.block-attribute-tag-name-esc-attr
    // Key 'className' does not contain tag/element/heading/wrapper — not a tag-name sink
    echo esc_attr( $attributes['className'] );

    // ok: claude.php.wordpress.xss.block-attribute-tag-name-esc-attr
    // Ternary allowlist gate: value is used only if in the fixed allowlist, else
    // a hardcoded fallback — functionally an allowlist-validating sanitizer.
    $allowed_heading_tags = [ 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div' ];
    $heading_tag          = isset( $attributes['headingTag'] ) && in_array( $attributes['headingTag'], $allowed_heading_tags, true )
        ? $attributes['headingTag']
        : 'h2';
    echo esc_attr( $heading_tag );
}
