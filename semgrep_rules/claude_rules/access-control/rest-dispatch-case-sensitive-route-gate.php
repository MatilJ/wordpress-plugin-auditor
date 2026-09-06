<?php
// Test cases for claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate

// === TRUE POSITIVES — case-sensitive route gate skips a parameter strip ===

// Exact pre-fix shape (generalized): a rest_pre_dispatch handler that only
// strips internal-only params when the route case-sensitively starts with
// the plugin's namespace. WP_REST_Server::dispatch() matches routes
// case-insensitively, so /Acme/v1/things still reaches the same controller
// while this check fails and 'raw_filter_sql' survives into $request.
class Acme_REST_Middleware {
    const FORBIDDEN_PARAMS = array( 'raw_filter_sql' );

    public function handle( $result, $server, $request ) {
        if ( ! ( $request instanceof WP_REST_Request ) ) {
            return $result;
        }

        // ruleid: claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate
        if ( strpos( $request->get_route(), '/acme/' ) !== 0 ) {
            return $result;
        }

        foreach ( self::FORBIDDEN_PARAMS as $forbidden ) {
            unset( $request[ $forbidden ] );
        }

        return $result;
    }
}

// Reversed comparison operand order (0 !== strpos(...)) and a substr()
// variant — confirms the pattern isn't tied to one exact comparison form.
function widget_strip_internal_params( $result, $server, $request ) {
    // ruleid: claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate
    if ( 0 !== strpos( $request->get_route(), '/widget/' ) ) {
        return $result;
    }

    unset( $request['append_where_sql'] );

    return $result;
}

function gizmo_strip_internal_params( $result, $server, $request ) {
    // ruleid: claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate
    if ( substr( $request->get_route(), 0, 6 ) !== '/gizmo' ) {
        return $result;
    }

    unset( $request['debug_query_override'] );

    return $result;
}

// === FALSE POSITIVES ===

// Real fix shape: the case-sensitive route gate is removed entirely, so the
// strip runs unconditionally for every REST request regardless of route.
class Acme_REST_Middleware_Fixed {
    const FORBIDDEN_PARAMS = array( 'raw_filter_sql' );

    public function handle( $result, $server, $request ) {
        // ok: claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate
        if ( ! ( $request instanceof WP_REST_Request ) ) {
            return $result;
        }

        foreach ( self::FORBIDDEN_PARAMS as $forbidden ) {
            unset( $request[ $forbidden ] );
        }

        return $result;
    }
}

// Alternative valid fix: the gate stays, but the comparison is normalized
// to case-insensitive (stripos) so it can't be defeated by an alternate-
// case route that WordPress still dispatches to the same controller.
function widget_strip_internal_params_fixed( $result, $server, $request ) {
    // ok: claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate
    if ( stripos( $request->get_route(), '/widget/' ) !== 0 ) {
        return $result;
    }

    unset( $request['append_where_sql'] );

    return $result;
}

// Case-sensitive route check present, but it gates an unrelated side
// effect (a debug log line), not any parameter strip/hardening call — the
// function performs no unset() on the request at all.
function log_namespace_requests( $result, $server, $request ) {
    // ok: claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate
    if ( strpos( $request->get_route(), '/acme/' ) !== 0 ) {
        return $result;
    }

    error_log( 'acme route hit: ' . $request->get_route() );

    return $result;
}

// Case-sensitive prefix check against a string that isn't the REST route
// at all (a plain option value) — different domain entirely.
function is_legacy_prefix( $value ) {
    // ok: claude.php.wordpress.access-control.rest-dispatch-case-sensitive-route-gate
    if ( strpos( $value, 'legacy_' ) !== 0 ) {
        return false;
    }
    return true;
}
