<?php
/**
 * Test cases for claude.php.wordpress.rce.shortcode-construction-injection
 *
 * Detects user-controlled input concatenated into shortcode strings
 * that reach do_shortcode()/apply_shortcodes(). Attacker can inject ']'
 * to close the tag and inject arbitrary shortcode expressions.
 * CVE-2024-10075 (Jetpack).
 */

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// TP: POST value concatenated into shortcode string → do_shortcode.
function tp_post_concat_shortcode() {
    $tag = $_POST['shortcode_tag'];
    $sc = '[' . $tag . ']';
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $sc );
}

// TP: GET value used as parameter in sprintf-built shortcode.
function tp_get_sprintf_shortcode() {
    $id = $_GET['id'];
    $sc = sprintf('[gallery id="%s"]', $id);
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    return do_shortcode( $sc );
}

// TP: shortcode attribute value from $atts concatenated.
function tp_atts_concat_shortcode($atts) {
    $atts = shortcode_atts(array('inner' => ''), $atts);
    $sc = '[inner_shortcode param="' . $atts['inner'] . '"]';
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    return do_shortcode( $sc );
}

// TP: apply_shortcodes alias with POST input.
function tp_apply_shortcodes_concat() {
    $name = $_POST['name'];
    $built = '[' . $name . ' key="value"]';
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    return apply_shortcodes( $built );
}

// TP: sanitize_text_field does NOT prevent shortcode injection.
function tp_sanitize_text_field_bypass() {
    $tag = sanitize_text_field( $_POST['tag'] );
    $sc = '[' . $tag . ']';
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $sc );
}

// TP: attribute-value quote-breakout — a model/DB-backed property (written by
// an earlier, separate low-privilege request) concatenated unescaped as an
// attribute value inside an already-open shortcode tag. CVE-2025-1119.
function tp_stored_property_attr_concat( $appointment ) {
    $shortcode = '[ssa_booking]';
    $customer_locale = $appointment->customer_locale;
    $shortcode .= ' ssa_locale="'. $customer_locale . '"';
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $shortcode );
}

// TP: same attribute-value breakout shape fed by a getter method result.
function tp_getter_attr_concat( $order ) {
    $sc = '[order_summary]';
    $note = $order->get_customer_note();
    $sc .= ' note="' . $note . '"';
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    return do_shortcode( $sc );
}

// TP: string-interpolation sibling of the concatenation shape — curly-brace
// interpolated variable directly inside literal shortcode-bracket syntax.
// A single-argument "query_var"-named getter call with no sanitize-type
// argument. CVE-2024-11740 (Download Manager <= 3.3.03).
function tp_query_var_curly_interpolation() {
    $pid = wpdm_query_var( '__wpdmxp' );
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( "[wpdm_package id='{$pid}']" );
}

// TP: same shape with a bare (non-curly) interpolated variable.
function tp_query_var_bare_interpolation() {
    $id = get_query_var( 'post_id' );
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( "[gallery id=$id]" );
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// OK: a second (sanitize-type) argument on the getter call — the actual
// CVE-2024-11740 fix shape — excludes the match by call arity.
function ok_query_var_with_sanitize_type_arg() {
    $pid = wpdm_query_var( '__wpdmxp', 'int' );
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( "[wpdm_package id='{$pid}']" );
}

// OK: interpolated variable from an unrelated single-argument getter whose
// name does not resemble a request/query-var accessor.
function ok_unrelated_getter_interpolation() {
    $title = get_the_title( 42 );
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( "[my_widget title='{$title}']" );
}

// OK: intval applied — result is integer, cannot inject shortcode syntax.
function ok_intval_parameter() {
    $id = intval( $_POST['id'] );
    $sc = '[gallery id="' . $id . '"]';
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $sc );
}

// OK: absint applied — unsigned integer.
function ok_absint_parameter() {
    $id = absint( $_GET['id'] );
    $sc = sprintf('[my_shortcode id="%d"]', $id);
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $sc );
}

// OK: sanitize_key strips brackets and special chars.
function ok_sanitize_key_parameter() {
    $tag = sanitize_key( $_POST['tag'] );
    $sc = '[' . $tag . ']';
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $sc );
}

// OK: hardcoded shortcode, no user input.
function ok_hardcoded_shortcode() {
    $sc = '[contact-form-7 id="1"]';
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $sc );
}

// OK: attribute value wrapped in esc_attr() at the concatenation site — the
// fix shape from CVE-2025-1119 (Simply Schedule Appointments 1.6.8.7).
function ok_esc_attr_locale_concat( $appointment ) {
    $shortcode = '[ssa_booking]';
    $customer_locale = $appointment->customer_locale;
    $shortcode .= ' ssa_locale="'. esc_attr( $customer_locale ) . '"';
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    echo do_shortcode( $shortcode );
}

// OK: attribute value passed through sanitize_key() before concatenation.
function ok_sanitize_key_attr_concat( $order ) {
    $sc = '[order_summary]';
    $note = $order->get_customer_note();
    $sc .= ' note="' . sanitize_key( $note ) . '"';
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    return do_shortcode( $sc );
}

// OK: (int) cast operator — same numeric-only effect as intval(), but a
// distinct AST shape the function-call-form pattern-not entries don't cover.
function ok_int_cast_attr_concat( $props ) {
    $sc = '[bookly-form';
    $sc .= ' category_id="' . (int) $props['category_id'] . '"';
    $sc .= ']';
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    return do_shortcode( $sc );
}

// OK: (float) cast operator variant.
function ok_float_cast_attr_concat( $price ) {
    $sc = '[product_price';
    $sc .= ' amount="' . (float) $price . '"';
    $sc .= ']';
    // ok: claude.php.wordpress.rce.shortcode-construction-injection
    return do_shortcode( $sc );
}

// NOT an ok: case — documented, not auto-excluded (tune-semgrep).
// implode() over an array built exclusively from repeated `$arr[] = 'literal';`
// pushes gated by boolean conditionals (a "flags"/"hide"-attribute idiom) is a
// real FP shape confirmed in a live audit, but verifying every push site
// across the enclosing function uses only string literals (never a variable)
// requires inter-procedural/whole-function provenance tracing beyond a local
// pattern-not clause — leaving this unexcluded is intentional, not an oversight.
function residual_hide_attribute_implode_not_excluded( $props ) {
    $sc = '[bookly-form';
    $hide = array();
    if ( isset( $props['hide_categories'] ) && $props['hide_categories'] === 'on' ) {
        $hide[] = 'categories';
    }
    if ( $hide ) {
        $sc .= ' hide="' . implode( ',', $hide ) . '"';
    }
    $sc .= ']';
    // ruleid: claude.php.wordpress.rce.shortcode-construction-injection
    return do_shortcode( $sc );
}
