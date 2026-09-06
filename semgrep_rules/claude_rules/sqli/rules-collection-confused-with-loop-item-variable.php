<?php
/**
 * Test file for
 * claude.php.wordpress.sqli.rules-collection-confused-with-loop-item-variable
 *
 * Plural/singular variable confusion inside a "sanitize query args by rules"
 * style helper: a per-item guard checks the OUTER rules collection instead
 * of the CURRENT loop-item variable, permanently disabling the guarded
 * sanitizer/allow-list dispatch.
 */

global $wpdb;

// --- TRUE POSITIVES ---

// TP-1: generalized shape of the real vulnerable helper — a query-args
// sanitizer keyed by field name, whose allow-list guard checks the outer
// $rules collection (field-name keyed) instead of the per-item $rule.
function tp_sanitize_query_args( $query_args, $rules ) {
    $sanitized = array();

    foreach ( $rules as $field => $rule ) {

        if ( ! isset( $query_args[ $field ] ) ) {
            continue;
        }

        switch ( $rule['type'] ) {
            case 'string':
                $query_args[ $field ] = sanitize_text_field( $query_args[ $field ] );
                break;
        }

        // ruleid: claude.php.wordpress.sqli.rules-collection-confused-with-loop-item-variable
        if ( isset( $rules['allowed_values'] ) ) {
            if ( ! in_array( $query_args[ $field ], $rules['allowed_values'] ) ) {
                $query_args[ $field ] = $rules['allowed_values'][0];
            }
        }

        $sanitized[ $field ] = $query_args[ $field ];
    }

    return $sanitized;
}

// TP-2: different variable/function names and array_key_exists() form,
// showing the pattern recurs independent of naming and the exact guard
// function used.
function tp_validate_args_schema( $input_args, $schema ) {
    $clean = array();

    foreach ( $schema as $arg_name => $arg_rule ) {

        if ( ! isset( $input_args[ $arg_name ] ) ) {
            continue;
        }

        // ruleid: claude.php.wordpress.sqli.rules-collection-confused-with-loop-item-variable
        if ( array_key_exists( 'sanitize_callback', $schema ) ) {
            $input_args[ $arg_name ] = call_user_func( $schema['sanitize_callback'], $input_args[ $arg_name ] );
        }

        $clean[ $arg_name ] = $input_args[ $arg_name ];
    }

    return $clean;
}

// --- FALSE POSITIVES (OK) ---

// OK-1: the real fix — the per-item loop variable is checked, not the
// outer collection.
function ok_patched_sanitize_query_args( $query_args, $rules ) {
    $sanitized = array();

    foreach ( $rules as $field => $rule ) {

        if ( ! isset( $query_args[ $field ] ) ) {
            continue;
        }

        // ok: claude.php.wordpress.sqli.rules-collection-confused-with-loop-item-variable
        if ( isset( $rule['allowed_values'] ) ) {
            if ( ! in_array( $query_args[ $field ], $rule['allowed_values'] ) ) {
                $query_args[ $field ] = $rule['allowed_values'][0];
            }
        }

        $sanitized[ $field ] = $query_args[ $field ];
    }

    return $sanitized;
}

// OK-2: defensive variant checking both the outer collection and the
// loop-item variable — not the single-variable bug.
function ok_defensive_both_checked( $query_args, $rules ) {
    $sanitized = array();

    foreach ( $rules as $field => $rule ) {

        if ( ! isset( $query_args[ $field ] ) ) {
            continue;
        }

        // ok: claude.php.wordpress.sqli.rules-collection-confused-with-loop-item-variable
        if ( isset( $rules['allowed_values'] ) || isset( $rule['allowed_values'] ) ) {
            $query_args[ $field ] = $rule['allowed_values'][0];
        }

        $sanitized[ $field ] = $query_args[ $field ];
    }

    return $sanitized;
}

// OK-3: a variable (non-literal) key checked against the outer collection —
// a plain per-field existence check, not the attribute-name typo this rule
// targets.
function ok_variable_key_lookup( $query_args, $rules ) {
    $sanitized = array();

    foreach ( $rules as $field => $rule ) {
        // ok: claude.php.wordpress.sqli.rules-collection-confused-with-loop-item-variable
        if ( isset( $rules[ $field ] ) ) {
            $sanitized[ $field ] = sanitize_text_field( $query_args[ $field ] );
        }
    }

    return $sanitized;
}
