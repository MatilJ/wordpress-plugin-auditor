<?php
/**
 * Test cases for claude.php.wordpress.rce.user-input-to-do-shortcode
 *
 * Rule tracks: superglobal sources → do_shortcode() sink
 * sanitize_text_field() is intentionally NOT a sanitizer — it preserves
 * shortcode bracket syntax and does not prevent arbitrary shortcode execution.
 */

// ─── Vulnerable patterns ─────────────────────────────────────────────────────

// TP: direct POST value passed to do_shortcode (full shortcode expression user-controlled).
// Mirrors contact-form-7-dynamic-text-extension 5.0.5: wpcf7dtx_js_handler()
// passes rawurldecode($_POST['shortcodes'][N]['value']) through sanitize_text_field()
// then calls do_shortcode('[' . $raw_value . ']').
// sanitize_text_field() does NOT strip shortcode bracket syntax.
function tp_post_to_do_shortcode_direct() {
    $shortcode = sanitize_text_field( $_POST['shortcode'] );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[' . $shortcode . ']' );
}

// TP: GET parameter used as full shortcode string without sanitization.
function tp_get_raw_to_do_shortcode() {
    $tag = $_GET['tag'];
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    $output = do_shortcode( $tag );
    echo $output;
}

// TP: user-supplied value passed through rawurldecode then into do_shortcode
// (shortcode bracket syntax is URL-encoded in the POST body, decoded here).
function tp_rawurldecode_to_do_shortcode() {
    $raw = rawurldecode( $_POST['sc'] );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $raw );
}

// TP: COOKIE value embedded in a shortcode string (attacker controls tag parameters).
function tp_cookie_param_to_do_shortcode() {
    $key = $_COOKIE['key'];
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    $result = do_shortcode( '[my_shortcode key="' . $key . '"]' );
    echo $result;
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// OK: user-supplied value sanitized to integer — cannot form a shortcode expression.
// Numeric parameter embedded in a developer-hardcoded shortcode tag name.
function ok_intval_parameter() {
    $post_id = intval( $_POST['post_id'] );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[my_shortcode post_id="' . $post_id . '"]' );
}

// OK: absint applied — result is an unsigned integer, no shortcode syntax possible.
function ok_absint_parameter() {
    $id = absint( $_GET['id'] );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[gallery id="' . $id . '"]' );
}

// OK: hardcoded shortcode string with no user input — no taint source.
function ok_hardcoded_shortcode() {
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[contact-form-7 id="1"]' );
}

// OK: (int) cast on user input used as parameter — result is integer.
function ok_int_cast_parameter() {
    $page = (int) $_REQUEST['page'];
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[my_plugin_list page="' . $page . '"]' );
}

// ─── apply_shortcodes() alias patterns ───────────────────────────────────────

// TP: apply_shortcodes() is a WP Core alias for do_shortcode() (shortcodes.php:223).
// User input reaching it has identical impact.
function tp_apply_shortcodes_post() {
    $content = $_POST['content'];
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo apply_shortcodes( $content );
}

// TP: GET parameter through sanitize_text_field then apply_shortcodes.
function tp_apply_shortcodes_sanitize_text_field() {
    $sc = sanitize_text_field( $_GET['sc'] );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_shortcodes( '[' . $sc . ']' );
}

// OK: intval applied before apply_shortcodes — safe.
function ok_apply_shortcodes_intval() {
    $id = intval( $_POST['id'] );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo apply_shortcodes( '[gallery id="' . $id . '"]' );
}

// ─── Sanitizer-adjacent-to-sink patterns (cross-function hop) ────────────────
// wp_kses_post()/sanitize_text_field() are modeled as standalone sources so the
// rule still fires when the sanitized value reaches the sink from inside a
// different function than the one that read the superglobal — a call-boundary
// hop plain intraprocedural taint tracking otherwise misses entirely.

// TP: do_shortcode() wraps directly around wp_kses_post() — the classic
// "sanitized, but shortcode brackets survive" anti-pattern.
function tp_kses_post_wrapped_directly( $content_reached ) {
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( wp_kses_post( $content_reached ) );
}

// TP: the superglobal read happens in one function; the sanitize+sink pair
// happens in a completely different function several calls downstream. The
// value crosses a function-call boundary that intraprocedural taint tracking
// cannot trace, so the source is (re)detected at the sanitizer adjacent to
// the sink rather than at the original superglobal read.
function inner_render_reached_message( $content_reached ) {
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( wp_kses_post( $content_reached ) );
}
function outer_ajax_handler_builds_atts() {
    $atts = array();
    $atts['content_reached'] = $_POST['content_rech_data'];
    return inner_render_reached_message( $atts['content_reached'] );
}

// OK: wp_kses_post() used for plain output, never reaches a shortcode sink.
function ok_kses_post_without_shortcode_sink( $x ) {
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo wp_kses_post( $x );
}

// OK: patched shape — strip_shortcodes() replaces do_shortcode() entirely, so
// the sink pattern no longer matches regardless of how the value was sanitized.
function ok_patched_strip_shortcodes( $content_reached ) {
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return strip_shortcodes( wp_kses_post( $content_reached ) );
}

// ─── Implicit sink: apply_filters() on a Core do_shortcode-bound hook ────────
// WP Core itself binds do_shortcode() to 'the_content' / 'widget_text_content' /
// 'widget_block_content' at priority 11 (wp-includes/default-filters.php), so
// running user-controlled text through apply_filters() on one of these hooks
// executes shortcodes with no do_shortcode()/apply_shortcodes() call anywhere
// in the plugin's own source.

// TP: GET parameter substituted into a template string, then rendered through
// 'the_content' — the Core the_content -> do_shortcode binding executes it.
function tp_the_content_filter_template_substitution() {
    $holder = $_GET['account_holder'];
    $text   = str_replace( '[account_holder]', $holder, 'Account holder: [account_holder]' );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    $content = apply_filters( 'the_content', $text );
    echo $content;
}

// TP: POST value passed straight into the 'widget_text_content' hook.
function tp_widget_text_content_filter() {
    $text = $_POST['widget_text'];
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo apply_filters( 'widget_text_content', $text );
}

// OK: strip_shortcodes() applied to the tainted value before it is substituted
// into the template — matches the real-world fix for this sink shape.
function ok_the_content_filter_with_strip_shortcodes() {
    $holder = $_GET['account_holder'];
    $text   = str_replace( '[account_holder]', strip_shortcodes( $holder ), 'Account holder: [account_holder]' );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    $content = apply_filters( 'the_content', $text );
    echo $content;
}

// OK: patched shape — 'the_content' swapped for wptexturize()/wpautop(), which
// are not do_shortcode()-bound Core hooks, so no shortcode execution occurs.
function ok_patched_wptexturize_instead_of_the_content() {
    $holder = $_GET['account_holder'];
    $text   = str_replace( '[account_holder]', strip_shortcodes( $holder ), 'Account holder: [account_holder]' );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    $content = wpautop( wptexturize( $text ) );
    echo $content;
}

// ─── Placeholder-substitution template builders (cross-function-hop shape) ──
// str_replace() building a bracket-wrapped token ('[' . $key . ']') is the
// merge-tag substitution used by mail/mandate/invoice template builders. The
// value being substituted typically arrives as a function/method PARAMETER
// (read from the request several calls upstream), which plain intraprocedural
// taint tracking cannot trace back to the originating superglobal — so the
// bracket-templating str_replace() call itself is modeled as a standalone
// source, matching the real-world CVE-2026-2582 fix shape.

// TP: foreach-driven template substitution loop over a function parameter,
// rendered through 'the_content' — the do_shortcode-bound Core hook fires
// regardless of which caller supplied $args.
function tp_template_placeholder_loop_to_the_content( $args ) {
    $text = 'Account holder: [account_holder]';
    foreach ( $args as $key => $val ) {
        $text = str_replace( '[' . $key . ']', $val, $text );
    }
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_filters( 'the_content', $text );
}

// TP: single (non-loop) bracket-token substitution reaching the same sink.
function tp_template_placeholder_single_to_the_content( $args ) {
    $text = str_replace( '[' . $args['key'] . ']', $args['val'], 'Text: [key]' );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_filters( 'the_content', $text );
}

// OK: real-world fix — strip_shortcodes() wraps the substituted value inline
// in the same loop, so the bracket-templating call no longer qualifies as a
// source (CVE-2026-2582 patch shape: woocommerce-germanized 3.20.6).
function ok_template_placeholder_loop_with_strip_shortcodes( $args ) {
    $text = 'Account holder: [account_holder]';
    foreach ( $args as $key => $val ) {
        $text = str_replace( '[' . $key . ']', strip_shortcodes( $val ), $text );
    }
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_filters( 'the_content', $text );
}

// OK: plain string replacement with a hardcoded (non-bracket) search term —
// not a placeholder-token construction, so this source shape does not apply.
function ok_str_replace_not_bracket_token( $args ) {
    $text = str_replace( 'PLACEHOLDER', $args['val'], 'Hello PLACEHOLDER' );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_filters( 'the_content', $text );
}

// ─── preg_replace_callback() merge-tag token substitution (cross-function-hop
// shape) ──────────────────────────────────────────────────────────────────
// A brace/percent-delimited capture-group regex passed to preg_replace_callback()
// is the "{field}"-style merge-tag/placeholder-token idiom used by mail/template/
// completion-message renderers: the resolver callback commonly reads a
// separately-submitted value (often via the plugin's own generic field-value
// getter) in a different method than the one performing the substitution, a
// call-boundary hop plain intraprocedural taint tracking cannot trace back to
// a superglobal — so the substitution call itself is modeled as a standalone
// source, mirroring the str_replace() bracket-token idiom just above.

// TP: token-substituted result wrapped in shortcode-bracket syntax before an
// unconditional do_shortcode() call.
function tp_merge_tag_token_substitution_to_shortcode_sink( $template, $callback ) {
    $content = preg_replace_callback( '/{(.+?)}/', $callback, $template );
    $shortcode = sprintf( '[my_wrapper]%s[/my_wrapper]', $content );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode );
}

// TP: percent-delimited token variant, result passed directly to do_shortcode()
// with no wrapping.
function tp_percent_token_substitution_direct_to_do_shortcode( $template, $resolver ) {
    $resolved = preg_replace_callback( '/%(\w+)%/', $resolver, $template );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( $resolved );
}

// OK: preg_replace_callback() with an ordinary PCRE quantifier regex (digits/
// comma only, no capture group adjacent to the delimiter) is NOT the merge-tag
// token idiom — must not be mistaken for this source.
function ok_preg_replace_callback_ordinary_quantifier_not_token_source( $template, $callback ) {
    $content = preg_replace_callback( '/\d{2,4}/', $callback, $template );
    $shortcode = sprintf( '[my_wrapper]%s[/my_wrapper]', $content );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode );
}

// OK: real-world fix — strip_shortcodes() applied to the token-substituted
// result before it is wrapped and reaches the sink.
function ok_merge_tag_token_result_stripped_before_sink( $template, $callback ) {
    $content = preg_replace_callback( '/{(.+?)}/', $callback, $template );
    $content = strip_shortcodes( $content );
    $shortcode = sprintf( '[my_wrapper]%s[/my_wrapper]', $content );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode );
}

// ─── preg_replace_callback() shortcode-bracket-delimited merge-tag variant ──
// Same idiom as the brace/percent-delimited source above, but the plugin
// reuses actual shortcode syntax ('[', ']') as its own merge-tag delimiter
// instead of '{}'/'%%' — e.g. a form-builder's own `[field id="..."]` token
// resolved via preg_replace_callback() before the containing setting string
// is separately handed to do_shortcode().

// TP: bracket-delimited token resolver result flows directly into do_shortcode()
// within the same function.
function tp_bracket_delimited_merge_tag_direct_to_do_shortcode( $setting, $resolver ) {
    $resolved = preg_replace_callback( '/(\[field[^]]*id="(\w+)"[^]]*\])/', $resolver, $setting );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $resolved );
}

// OK: ordinary PCRE quantifier regex (digits/comma only, no capture group
// adjacent to an escaped bracket delimiter) is NOT the bracket-delimited
// merge-tag idiom — must not be mistaken for this source.
function ok_bracket_regex_ordinary_quantifier_not_token_source( $setting, $resolver ) {
    $resolved = preg_replace_callback( '/\d{2,4}/', $resolver, $setting );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $resolved );
}

// OK: real-world fix — strip_shortcodes() applied to the bracket-token-
// resolved result before it reaches the sink.
function ok_bracket_delimited_merge_tag_result_stripped_before_sink( $setting, $resolver ) {
    $resolved = preg_replace_callback( '/(\[field[^]]*id="(\w+)"[^]]*\])/', $resolver, $setting );
    $resolved = strip_shortcodes( $resolved );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $resolved );
}

// OK: apply_filters() on an unrelated, non-do_shortcode-bound hook — the
// $HOOK metavariable-regex must not match arbitrary custom filter names.
function ok_apply_filters_unrelated_hook() {
    $text = $_GET['note'];
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo apply_filters( 'my_plugin_custom_note', $text );
}

// ─── REST request-object source (WP_REST_Request::get_param()) ──────────────
// CVE-2025-49398 (easy-appointments <= 3.12.14): a POST REST route registered
// with permission_callback => '__return_true' read the full shortcode string
// via $request->get_param('shortcode') and passed it straight to
// do_shortcode() with no allow-list check — unauthenticated arbitrary
// shortcode execution.

// TP: pre-fix shape — REST param read directly into do_shortcode() with no
// tag-name allow-list check anywhere in the function.
function tp_rest_get_param_direct_to_do_shortcode( WP_REST_Request $request ) {
    $shortcode = $request->get_param( 'shortcode' );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode );
}

// TP: REST param concatenated into a shortcode-parameter string.
function tp_rest_get_param_concatenated_to_apply_shortcodes( WP_REST_Request $request ) {
    $key = $request->get_param( 'key' );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_shortcodes( '[my_shortcode key="' . $key . '"]' );
}

// OK: real-world fix — the shortcode tag name is extracted and checked
// against a fixed allow-list inside an early-return guard before the sink
// (CVE-2025-49398 patch shape, easy-appointments 3.12.14.1).
function ok_rest_get_param_with_allowlist_guard( WP_REST_Request $request ) {
    $shortcode = $request->get_param( 'shortcode' );
    $allowed_shortcodes = array( 'location', 'service', 'worker' );
    preg_match( '/^\[(\w+)/', $shortcode, $matches );
    $shortcode_tag = isset( $matches[1] ) ? $matches[1] : '';
    if ( ! in_array( $shortcode_tag, $allowed_shortcodes, true ) ) {
        return new WP_REST_Response( array( 'success' => false ), 403 );
    }
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return new WP_REST_Response( array( 'html' => do_shortcode( $shortcode ) ) );
}

// ─── REST request-object source (ArrayAccess: $request['key']) ──────────────
// WP_REST_Request implements ArrayAccess, so a route parameter read via
// array-subscript syntax is the same taint source as ->get_param() above,
// just a different accessor. Common in REST-controller-style plugins where
// the route registration (with its permission_callback) lives in a separate
// router file/class from the controller method that reads the parameter and
// builds the shortcode.

// TP: pre-fix shape — controller method reads the route parameter via array
// access, unslashes/decodes it, then passes it straight to do_shortcode()
// with no tag-name allow-list check anywhere in the function.
function tp_rest_array_access_direct_to_do_shortcode( $request ) {
    $shortcode = stripslashes( urldecode( $request['shortcode'] ) );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode );
}

// TP: array-access route parameter concatenated into a shortcode-parameter
// string, reached via the apply_shortcodes() alias.
function tp_rest_array_access_concatenated_to_apply_shortcodes( $req ) {
    $key = $req['key'];
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_shortcodes( '[my_shortcode key="' . $key . '"]' );
}

// ─── Cross-file "dynamic value evaluator" utility (bracket-wraps its own
// parameter, definition-site source) ─────────────────────────────────────
// CVE-2025-13146 (contact-form-7-dynamic-text-extension <= 5.0.6):
// wpcf7dtx_get_dynamic($value, ...) in includes/utilities.php concatenates
// its own $value parameter as '[' . $value . ']' and calls do_shortcode() on
// it. The caller, wpcf7dtx_js_handler() in the main plugin file (registered
// on wp_ajax_nopriv_wpcf7dtx), only runs the $_POST value through
// sanitize_text_field()/rawurldecode() before passing it in — a cross-file
// hop plain intraprocedural taint tracking cannot trace, so the bracket
// concatenation shape on the bare parameter is the modeled source.

// TP: pre-fix shape mirrored directly — bare parameter forms the whole
// bracket-wrapped tag immediately before do_shortcode().
function tp_dynamic_value_evaluator_bracket_wrap( $value ) {
    $shortcode_tag = '[' . $value . ']';
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode_tag );
}

// TP: double-quoted variant of the same shape, apply_shortcodes() alias,
// different parameter name — proves the pattern isn't overfit to $value.
function tp_dynamic_value_evaluator_double_quoted( $raw_input ) {
    $tag = "[" . $raw_input . "]";
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    return apply_shortcodes( $tag );
}

// OK: hardcoded string literal concatenated instead of a variable — the
// metavariable-regex guard excludes a quote-leading capture, since a plain
// literal cannot carry attacker-controlled shortcode syntax.
function ok_dynamic_value_evaluator_hardcoded_literal() {
    $shortcode_tag = '[' . 'contact-form-7 id="1"' . ']';
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode_tag );
}

// OK: sanitize_key() (an existing rule-level sanitizer) applied to the
// parameter before the bracket concatenation strips spaces/brackets/quotes,
// so the full shortcode expression cannot survive to the sink.
function ok_dynamic_value_evaluator_sanitize_key( $value ) {
    $value = sanitize_key( $value );
    $shortcode_tag = '[' . $value . ']';
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode_tag );
}

// OK: the existing allow-list reject-guard shape (negated in_array() with a
// halting return) precedes the sink in the same function — the sink's own
// pattern-not-inside exclusion applies regardless of which pattern-sources
// entry supplied the taint.
function ok_dynamic_value_evaluator_allowlist_guard( $value ) {
    $shortcode_tag = '[' . $value . ']';
    preg_match( '/^\[(\w+)/', $shortcode_tag, $matches );
    $tag_name = isset( $matches[1] ) ? $matches[1] : '';
    if ( ! in_array( $tag_name, array( 'my_shortcode', 'gallery' ), true ) ) {
        return '';
    }
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    return do_shortcode( $shortcode_tag );
}

// OK: array access on a non-request-named variable (a generic args/atts
// array, not a REST request object) must NOT become a source — this is the
// FP guard the $REQ metavariable-regex constraint provides.
function ok_array_access_non_request_variable( $atts ) {
    $tag = $atts['shortcode'];
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( $tag );
}

// OK: request-named variable's array-access value is intval()'d before use —
// result is an integer, cannot form a shortcode expression.
function ok_rest_array_access_intval_parameter( $request ) {
    $id = intval( $request['id'] );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[gallery id="' . $id . '"]' );
}

// ─── preg_replace() negated-character-class allow-list (bracket-stripping fix) ─
// A GET/POST value only run through sanitize_text_field()/esc_attr() still
// carries live shortcode bracket syntax; a preg_replace() call using a
// negated-character-class allow-list regex (`/[^permitted-chars]/`, replacing
// with '') strips '[' and ']' along with any quote characters, and is a
// genuine sanitizer for this sink.

// TP: pre-fix shape — value passes through sanitize_text_field()/wp_unslash()
// then esc_attr() only; neither strips '[' or ']', so the attacker can still
// close the hardcoded tag early and open an arbitrary one via the
// unescaped-for-shortcode-purposes attribute value.
function tp_esc_attr_concatenated_no_bracket_strip() {
    $mode = isset( $_GET['mode'] ) ? sanitize_text_field( wp_unslash( $_GET['mode'] ) ) : 'one';
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[my_list mode="' . esc_attr( $mode ) . '"]' );
}

// OK: real-world fix — a preg_replace() allow-list regex (negated character
// class) strips every character outside an explicit permitted set before the
// value is concatenated, removing '[' and ']' along with it.
function ok_preg_replace_allowlist_strips_brackets() {
    $mode = isset( $_GET['mode'] ) ? preg_replace( '/[^A-Za-z0-9 !@#$%^&*().]/u', '', strip_tags( sanitize_text_field( wp_unslash( $_GET['mode'] ) ) ) ) : 'one';
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[my_list mode="' . esc_attr( $mode ) . '"]' );
}

// OK: preg_replace() call unrelated to a bracket allow-list (no negated
// character class in the pattern argument) must NOT be mistaken for the
// bracket-stripping idiom above — the metavariable-regex constraint on $RE.
function ok_preg_replace_unrelated_not_mistaken_for_allowlist() {
    $mode = isset( $_GET['mode'] ) ? preg_replace( '/\s+/', ' ', sanitize_text_field( wp_unslash( $_GET['mode'] ) ) ) : 'one';
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[my_list mode="' . esc_attr( $mode ) . '"]' );
}

// ─── Post-object property source (post_content flowing to the_content) ──────
// CVE-2025-57928 (AWP Classifieds <= 4.4.3): an unauthenticated AJAX handler
// (wp_ajax_nopriv_...) fetched an attacker-chosen post/listing by ID with no
// ownership/capability check and rendered
// apply_filters('the_content', $listing->post_content). The front-end
// submission form sanitized user text with wp_kses_post()/wp_strip_all_tags()
// but never called strip_shortcodes(), so shortcode syntax planted by the
// submitter survived into post_content and executed for any visitor who
// supplied a valid listing ID.

// TP: pre-fix shape — no authorization/nonce guard anywhere in the function
// before the fetched object's post_content property reaches the sink.
function tp_post_content_property_to_the_content_no_guard( $request, $listings ) {
    $listing_id = $request->post( 'ad_id' );
    $listing    = $listings->get( $listing_id );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    $content = apply_filters( 'the_content', $listing->post_content );
    return $content;
}

// TP: same shape via a differently-named fetched object — the source is the
// `post_content` property itself, not the "listing" naming.
function tp_post_content_property_to_widget_text_content_no_guard( $item_repository, $item_id ) {
    $item = $item_repository->get( $item_id );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo apply_filters( 'widget_text_content', $item->post_content );
}

// OK: real-world fix — a resource-scoped wp_verify_nonce() guard (tied to the
// fetched object's own ID) precedes the sink in the same function, matching
// the patched try_to_generate_listing_preview() shape (AWP Classifieds 4.4.4).
// The plugin-specific ownership/auto-draft check that follows is not itself
// part of the generalized negative clause — the preceding nonce guard is.
function ok_post_content_property_with_nonce_guard( $request, $listings ) {
    $listing_id = $request->post( 'ad_id' );
    $listing    = $listings->get( $listing_id );
    $nonce      = $request->post( 'nonce' );

    if ( ! wp_verify_nonce( $nonce, "preview-listing-{$listing->ID}" ) ) {
        return new WP_Error( 'unauthorized' );
    }

    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    $content = apply_filters( 'the_content', $listing->post_content );
    return $content;
}

// OK: an unrelated object property (not post_content) must not be mistaken
// for this source — the pattern is scoped to the post_content property name.
function ok_unrelated_property_not_post_content( $listing ) {
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo apply_filters( 'the_content', $listing->post_title );
}

// ─── Attribute-key allow-list is NOT a shortcode-tag guard (narrowed sink
// pattern-not-inside) ─────────────────────────────────────────────────────
// CVE-2024-13472 (wc-product-table-lite <= 3.9.4): an unauthenticated AJAX
// handler (wp_ajax_nopriv_wcpt_ajax) builds an attribute string from
// request-supplied key=value pairs, filtering which KEYS get appended via a
// POSITIVE, non-halting in_array() check — it never validates or rejects
// the overall shortcode expression, and has no early return/die/wp_die. The
// broader pre-fix form of this rule's sink pattern-not-inside (any in_array()
// anywhere in an if-guard in the enclosing function) incorrectly treated
// this as an already-guarded function and stayed silent.

// TP: pre-fix shape — the in_array() only filters attribute KEYS; the
// shortcode tag itself and the unfiltered VALUES reach the sink unchecked.
function tp_attribute_key_allowlist_is_not_a_tag_guard() {
    $sc_attrs = '';
    if ( ! empty( $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] )
        && $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] = json_decode( stripslashes( $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] ) )
    ) {
        foreach ( $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] as $key => $val ) {
            if ( in_array( $key, $GLOBALS['wcpt_permitted_shortcode_attributes'] ) ) {
                $sc_attrs .= ' ' . $key . '="' . $val . '" ';
            }
        }
    }
    $id = (int) $_REQUEST['id'];
    // the pre-fix regex below is a broken alternation, not a bracket
    // character class — it does not qualify as a sanitizer (see the
    // dedicated preg_replace test cases further below).
    $sc_attrs = preg_replace( '/\[\]\s|<\s/', '', $sc_attrs );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[product_table id="' . $id . '" ' . $sc_attrs . ' ]' );
}

// ─── preg_replace() positive bracket-denylist character class (fix shape) ───
// CVE-2024-13472 (wc-product-table-lite 3.9.4->3.9.5): the patch replaced the
// broken alternation regex above with a real character class
// ('/[\[\]<>]/') that strips every '[', ']', '<', '>' byte individually —
// distinct from the negated-allowlist ('/[^permitted]/') idiom covered
// earlier: this one lists the dangerous characters directly as members.

// OK: real-world fix — the bracket/angle-bracket denylist character class
// strips '[' and ']' (and '<'/'>') before the value is concatenated.
function ok_preg_replace_bracket_denylist_class() {
    $sc_attrs = '';
    if ( ! empty( $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] )
        && $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] = json_decode( stripslashes( $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] ) )
    ) {
        foreach ( $_REQUEST[ $_REQUEST['id'] . '_sc_attrs' ] as $key => $val ) {
            if ( in_array( $key, $GLOBALS['wcpt_permitted_shortcode_attributes'] ) ) {
                $sc_attrs .= ' ' . $key . '="' . $val . '" ';
            }
        }
    }
    $id = (int) $_REQUEST['id'];
    $sc_attrs = preg_replace( '/[\[\]<>]/', '', $sc_attrs );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[product_table id="' . $id . '" ' . $sc_attrs . ' ]' );
}

// TP: a preg_replace() character class that only strips angle brackets (no
// '\[' or '\]' member) does not qualify as a shortcode-bracket sanitizer —
// scoped narrowly so an unrelated XSS-only fix isn't mistaken for this
// rule's CWE-94 mitigation. The tag name is hardcoded, but the unstripped
// '['/']' bytes in $mode still let the value break out of the attribute and
// construct an arbitrary sibling shortcode (SHORTCODE_CONSTRUCTION_INJECTION
// shape) — still a true positive despite the fixed-looking tag prefix.
function tp_preg_replace_angle_bracket_only_not_bracket_sanitizer() {
    $mode = preg_replace( '/[<>]/', '', $_GET['mode'] );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo do_shortcode( '[contact-form-7 id="1" mode="' . $mode . '"]' );
}

// ─── Custom "*_do_shortcode()" wrapper-utility sink (cross-file hop) ────────
// CVE-2024-13495 (GamiPress <= 7.2.1): an unauthenticated AJAX handler
// sanitizes each $_REQUEST value with sanitize_text_field() only (does not
// strip '[' / ']'), merges it via shortcode_atts(), then hands the array to
// a same-named "*_do_shortcode()" wrapper utility (defined in a different
// file) that itself builds '[tag attr="value" ...]' and calls do_shortcode()
// — a cross-function/cross-file hop plain intraprocedural taint tracking
// cannot see across, so the wrapper call site itself is the modeled sink.

// TP: pre-fix shape — request data sanitized with sanitize_text_field()
// only, then handed to a custom "*_do_shortcode()"-named wrapper utility.
function tp_wrapper_do_shortcode_sanitize_text_field_only() {
    $atts = $_REQUEST;
    foreach ( $atts as $attr => $value ) {
        $atts[$attr] = sanitize_text_field( $value );
    }
    $atts = shortcode_atts( array( 'id' => 0 ), $atts, 'my_logs' );
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    wp_send_json_success( my_plugin_do_shortcode( 'my_logs', $atts ) );
}

// TP: same wrapper-sink shape reached through the apply_shortcodes() naming
// convention on the wrapper itself (still contains "shortcode").
function tp_wrapper_render_shortcode_sanitize_text_field_only() {
    $atts = $_POST;
    foreach ( $atts as $attr => $value ) {
        $atts[$attr] = sanitize_text_field( $value );
    }
    // ruleid: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo my_plugin_render_shortcode( 'my_earnings', $atts );
}

// OK: real-world fix — a str_replace() call stripping '[' / ']' (array
// order as shipped) appears in the enclosing function's sanitization loop
// before the wrapper call, matching the CVE-2024-13495 patch shape (GamiPress
// 7.2.1->7.2.2). Structural pattern-not-inside exclusion (loop form).
function ok_wrapper_do_shortcode_with_bracket_strip_loop() {
    $atts = $_REQUEST;
    foreach ( $atts as $attr => $value ) {
        $atts[$attr] = sanitize_text_field( $value );
        $atts[$attr] = str_replace( array( '[', ']' ), '', $value );
    }
    $atts = shortcode_atts( array( 'id' => 0 ), $atts, 'my_logs' );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    wp_send_json_success( my_plugin_do_shortcode( 'my_logs', $atts ) );
}

// OK: same fix applied as a straightforward whole-variable reassignment
// (not a per-element array loop) — covered by the pattern-sanitizers entry.
function ok_wrapper_do_shortcode_with_bracket_strip_whole_var( $x ) {
    $x = str_replace( array( '[', ']' ), '', $x );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo my_plugin_do_shortcode( 'my_tag', $x );
}

// OK: WP Core's own shortcode_atts()/has_shortcode()/add_shortcode() must
// not be mistaken for the custom wrapper-utility sink above — the
// metavariable-regex exclusion list guard.
function ok_core_shortcode_atts_not_a_wrapper_sink() {
    $atts = shortcode_atts( array( 'id' => 0 ), $_REQUEST, 'my_tag' );
    // ok: claude.php.wordpress.rce.user-input-to-do-shortcode
    echo has_shortcode( $atts['id'], 'my_tag' );
}
