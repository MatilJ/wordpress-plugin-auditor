<?php
/**
 * Test cases for is-callable-dynamic-call.yaml
 * Rule id: claude.php.wordpress.rce.is-callable-dynamic-call
 *
 * Detects: is_callable($VAR) guarding call_user_func[_array]($VAR, ...) where $VAR
 * is not a static developer-defined callable (string literal or static array).
 *
 * Confirmed TP source: acf-extended 0.9.1.1 module-form-front-render.php:148-151.
 */

// ─── Vulnerable patterns ──────────────────────────────────────────────────────

// TP: exact pattern from acf-extended 0.9.1.1 — $form['render'] could be attacker-
// controlled via the render_form_ajax nopriv AJAX endpoint (ACF nonce is public).
function acfe_prepare_form( $form ) {
    if ( is_array( $form['render'] ) ) {
        $html = implode( '', array_map( function( $row ) { return "{render:$row}"; }, $form['render'] ) );
        $form['render'] = $html;
    } elseif ( is_callable( $form['render'] ) ) {
        ob_start();
        // ruleid: claude.php.wordpress.rce.is-callable-dynamic-call
            call_user_func_array( $form['render'], array( $form ) );
        $html = ob_get_clean();
        $form['render'] = $html;
    }
    return $form;
}

// TP: simple variable callable guarded by is_callable()
function handle_dynamic_callback( $callback, $args ) {
    if ( is_callable( $callback ) ) {
        // ruleid: claude.php.wordpress.rce.is-callable-dynamic-call
        call_user_func( $callback, $args );
    }
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// OK: static array callable — developer controls both object and method name.
// is_callable() here is a defensive check, not a dynamic dispatch gate.
function safe_static_array_callable( $obj ) {
    if ( is_callable( array( $obj, 'render' ) ) ) {
        // ok: claude.php.wordpress.rce.is-callable-dynamic-call
        call_user_func_array( array( $obj, 'render' ), array() );
    }
}

// OK: literal string callable — developer-hardcoded function name.
function safe_literal_callable() {
    if ( is_callable( 'my_plugin_render_function' ) ) {
        // ok: claude.php.wordpress.rce.is-callable-dynamic-call
        call_user_func( 'my_plugin_render_function', array() );
    }
}

// OK: registry-dispatch pattern — user controls the lookup key, not the callable value.
// The ['callback'] subscript ensures the value came from a developer-registered registry.
function safe_registry_dispatch( $action ) {
    if ( is_callable( $this->registry[ $action ]['callback'] ) ) {
        // ok: claude.php.wordpress.rce.is-callable-dynamic-call
        call_user_func_array( $this->registry[ $action ]['callback'], array() );
    }
}

// OK: same registry-dispatch shape, but reached through an intermediate
// local variable (a plugin-owned $this->model field-definition array
// indexed by a fixed field name) rather than an inline expression — still a
// developer-defined value, not request-influenced. Confirmed FP:
// shortpixel-image-optimiser 6.5.5 SettingsModel::__get().
class Settings_Model_Default_Dispatch {
    public $model = array();

    public function __get( $name ) {
        if ( isset( $this->model[ $name ]['default'] ) ) {
            $default = $this->model[ $name ]['default'];
            if ( is_array( $default ) ) {
                if ( is_callable( $default ) ) {
                    // ok: claude.php.wordpress.rce.is-callable-dynamic-call
                    return call_user_func( $default );
                }
            }
            return $default;
        }
    }
}

// NOTE — bundled third-party library code in libs/ and vendor/ is excluded via
// paths.exclude in the rule YAML. The WP HTTP API Requests library (bundled as
// razorpay-sdk/libs/Requests-*/Utility/FilteredIterator.php) uses the same pattern
// internally as a legitimate iterator callback — the callable is set by developer
// code, not user input. Any plugin shipping a copy of Requests under a libs/ or
// vendor/ path would produce the same FP without the path exclusion.
