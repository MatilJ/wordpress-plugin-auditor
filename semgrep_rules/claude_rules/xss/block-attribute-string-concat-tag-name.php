<?php
// Test cases for claude.php.wordpress.xss.block-attribute-string-concat-tag-name

function render_toc_block_vuln( $attributes ) {
    $listStyle = $attributes['listStyle'];

    // ruleid: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
    $html = '<' . $listStyle . '>';
    $html .= '<li>Item</li>';
    // ruleid: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
    $html .= '</' . $listStyle . '>';

    return $html;
}

function render_heading_block_vuln( $atts ) {
    $tag = $atts['headingTag'];
    // ruleid: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
    echo '<' . $tag . ' class="heading">';
    echo esc_html( $atts['title'] );
    // ruleid: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
    echo '</' . $tag . '>';
}

function render_toc_block_safe( $attributes ) {
    // ok: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
    $listStyle = tag_escape( $attributes['listStyle'] );
    $html = '<' . $listStyle . '>';
    $html .= '</' . $listStyle . '>';
    return $html;
}

function render_heading_block_safe_sanitize_key( $attributes ) {
    // ok: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
    $tag = sanitize_key( $attributes['headingTag'] );
    echo '<' . $tag . '>';
    echo '</' . $tag . '>';
}

function render_form_nonce_block( $attributes ) {
    $output = '<div class="protection" aria-hidden="true">';
    if ( isset( $attributes['formId'] ) ) {
        // ok: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
        $output .= wp_nonce_field( 'form-verification', $attributes['formId'] . '_nonce_field', true, false );
    }
    $output .= '</div>';
    return $output;
}

function _mapOutAttributes( &$root, $path ) {
    $attributes = &getSubArray( $root, $path );
    if ( is_array( $attributes ) ) {
        for ( $i = 0; $i < count( $attributes ); $i++ ) {
            $id = $attributes[$i]['type'];
            // ok: claude.php.wordpress.xss.block-attribute-string-concat-tag-name
            user_error( $id . ' is not a currently supported attribute' );
        }
    }
}
