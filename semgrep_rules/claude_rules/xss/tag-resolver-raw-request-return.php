<?php

// Test cases for claude.php.wordpress.xss.tag-resolver-raw-request-return

// TP: tag registration array with a resolver closure returning a raw
// $_REQUEST value via a helper method — no escaping.
$this->add_tag(array(
    'name'      => 'request',
    'condition' => function($args){ return !empty($args); },
    // ruleid: claude.php.wordpress.xss.tag-resolver-raw-request-return
    'resolver'  => function($args){
        return $this->array_get($_REQUEST, $args);
    }
));

// TP: resolver closure returning a direct $_GET index — no escaping.
$tags['ip'] = array(
    // ruleid: claude.php.wordpress.xss.tag-resolver-raw-request-return
    'resolver' => function($args) {
        return $_GET[$args];
    }
);

// ok: claude.php.wordpress.xss.tag-resolver-raw-request-return
function register_safe_request_tag() {
    return array(
        'resolver' => function($args){
            return esc_html($this->array_get($_REQUEST, $args));
        }
    );
}

// ok: claude.php.wordpress.xss.tag-resolver-raw-request-return
function register_safe_get_tag() {
    return array(
        'resolver' => function($args) {
            return esc_attr($_GET[$args]);
        }
    );
}

// ok: claude.php.wordpress.xss.tag-resolver-raw-request-return
function register_safe_static_tag() {
    return array(
        'resolver' => function($args) {
            return get_bloginfo($args);
        }
    );
}

// TP: str_replace-based dynamic-placeholder substitution — sanitize_text_field()
// strips tags but not quotes, insufficient if the caller's sink is <script>/attr.
function dynamic_placeholders( $value ) {
    if ( strpos( $value, '{{GET:' ) !== false ) {
        preg_match_all( '/\{GET:(.*?)\}/', $value, $matches );
        foreach ( $matches[1] as $val ) {
            if ( isset( $_GET[$val] ) ) {
                // ruleid: claude.php.wordpress.xss.tag-resolver-raw-request-return
                $value = str_replace( '{{GET:' . $val . '}}', sanitize_text_field( wp_unslash( $_GET[$val] ) ), $value );
            }
        }
    }
    return $value;
}

// TP: same defect, two-step form — the sanitized value is assigned to an
// intermediate variable before the str_replace() call.
function dynamic_placeholders_cookie( $value ) {
    if ( strpos( $value, '{{COOKIE:' ) !== false ) {
        preg_match_all( '/\{COOKIE:(.*?)\}/', $value, $matches );
        foreach ( $matches[1] as $val ) {
            if ( ! empty( $_COOKIE[$val] ) ) {
                // ruleid: claude.php.wordpress.xss.tag-resolver-raw-request-return
                $cookie_value = sanitize_text_field( wp_unslash( $_COOKIE[$val] ) );
                $value = str_replace( '{{COOKIE:' . $val . '}}', $cookie_value, $value );
            }
        }
    }
    return $value;
}

// ok: claude.php.wordpress.xss.tag-resolver-raw-request-return
function dynamic_placeholders_esc_js( $value ) {
    if ( strpos( $value, '{{GET:' ) !== false ) {
        preg_match_all( '/\{GET:(.*?)\}/', $value, $matches );
        foreach ( $matches[1] as $val ) {
            if ( isset( $_GET[$val] ) ) {
                $value = str_replace( '{{GET:' . $val . '}}', esc_js( sanitize_text_field( wp_unslash( $_GET[$val] ) ) ), $value );
            }
        }
    }
    return $value;
}

// TP: wp_kses()-based assignment variant — an intermediate merge-tag-engine
// variable is assigned a superglobal value wrapped only in wp_kses(), which
// does not encode quotes/backslashes (later traced forward to an
// unescaped attribute sink in the confirmed real-world instance).
function mla_expand_field_level_parameters( $value ) {
    if ( isset( $_REQUEST[ $value['value'] ] ) ) {
        // ruleid: claude.php.wordpress.xss.tag-resolver-raw-request-return
        $record = wp_kses( wp_unslash( $_REQUEST[ $value['value'] ] ), 'post' );
    }
    return $record;
}

// TP: same wp_kses() assignment variant, no wp_unslash() wrapper.
function mla_expand_field_level_parameters_raw( $value ) {
    if ( isset( $_GET[ $value['value'] ] ) ) {
        // ruleid: claude.php.wordpress.xss.tag-resolver-raw-request-return
        $record = wp_kses( $_GET[ $value['value'] ], 'post' );
    }
    return $record;
}

// ok: claude.php.wordpress.xss.tag-resolver-raw-request-return
function mla_expand_field_level_parameters_safe( $value ) {
    if ( isset( $_REQUEST[ $value['value'] ] ) ) {
        $record = esc_attr( wp_kses( wp_unslash( $_REQUEST[ $value['value'] ] ), 'post' ) );
    }
    return $record;
}
