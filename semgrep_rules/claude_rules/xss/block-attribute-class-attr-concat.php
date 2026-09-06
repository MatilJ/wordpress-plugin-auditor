<?php
// Test cases for claude.php.wordpress.xss.block-attribute-class-attr-concat

function render_block_vuln_class( $attributes ) {
    $customClass = isset( $attributes['className'] ) ? $attributes['className'] : '';
    // ruleid: claude.php.wordpress.xss.block-attribute-class-attr-concat
    $html = '<div class="wp-block-example ' . $customClass . '">';
    $html .= '</div>';
    return $html;
}

function render_block_vuln_id( $attributes ) {
    // ruleid: claude.php.wordpress.xss.block-attribute-class-attr-concat
    echo '<section id="section-' . $attributes['blockId'] . '">';
    echo '</section>';
}

function render_block_safe_esc_attr( $attributes ) {
    $customClass = esc_attr( $attributes['className'] );
    // ok: claude.php.wordpress.xss.block-attribute-class-attr-concat
    $html = '<div class="wp-block-example ' . $customClass . '">';
    return $html;
}

function render_block_safe_sanitize( $attributes ) {
    $customClass = sanitize_html_class( $attributes['className'] );
    // ok: claude.php.wordpress.xss.block-attribute-class-attr-concat
    $html = '<div class="wp-block-example ' . $customClass . '">';
    return $html;
}

// False positive — the attribute pattern only appears EARLIER in a longer
// concat chain whose tag has already closed ('">') before $atts reaches the
// sink; $atts['target'] is itself esc_attr()'d, and the actual unescaped
// concatenation ($content) lands in text-node position, not an attribute.
function render_link_safe_text_node_position( $atts, $content ) {
    $url = esc_url( $atts['url'] );
    // ok: claude.php.wordpress.xss.block-attribute-class-attr-concat
    return '<a href="' . $url . '" target="' . esc_attr( $atts['target'] ) . '">' . $content . '</a>';
}

// False positive — every concatenated attribute value is esc_url()/esc_attr()
// wrapped in place; a long (5+ operand) concat chain like this can trigger a
// Semgrep taint-engine gap where an already-sanitized operand is still
// reported as the sink despite the declared pattern-sanitizers entry.
function render_link_safe_long_chain( $atts, $content ) {
    $url = $atts['url'];
    // ok: claude.php.wordpress.xss.block-attribute-class-attr-concat
    return '<a href="' . esc_url( $url ) . '" target="' . esc_attr( $atts['target'] ) . '">' . $content . '</a>';
}
