<?php
/**
 * Test cases for rest-user-id-param-override-in-permission-check.yaml
 * Rule id: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
 *
 * NOTE: Semgrep reports the match at the first statement of the multi-statement
 * pattern ($user_id = bp_loggedin_user_id() / get_current_user_id()), so
 * ruleid annotations are placed immediately before that first statement.
 */

// TP: mirrors the BuddyPress 14.4.0 vulnerability exactly.
// bp_loggedin_user_id() is overridden by get_param('user_id') inside a
// permission callback; messages_check_thread_access() checks the victim, not
// the attacker.
function get_item_permissions_check( $request ) {
    // ruleid: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
    $user_id = bp_loggedin_user_id();
    if ( ! empty( $request->get_param( 'user_id' ) ) ) {
        $user_id = $request->get_param( 'user_id' );
    }
    $retval = false;
    if ( messages_check_thread_access( 1, $user_id ) ) {
        $retval = true;
    }
    return $retval;
}

// TP: same pattern using get_current_user_id() and delete permission callback.
function delete_item_permissions_check( $request ) {
    // ruleid: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
    $user_id = get_current_user_id();
    if ( ! empty( $request->get_param( 'user_id' ) ) ) {
        $user_id = $request->get_param( 'user_id' );
    }
    return check_user_thread_access( $user_id );
}

// TP: update_item_permissions_check — slightly different form (intermediate variable).
function update_item_permissions_check( $request ) {
    // ruleid: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
    $uid = get_current_user_id();
    if ( $request->get_param( 'user_id' ) ) {
        $uid = $request->get_param( 'user_id' );
    }
    return can_user_do_thing( $uid );
}

// OK: override is not inside a *permission*check* function.
// A generic REST action callback that acts on behalf of a user (admin context).
function handle_rest_request( $request ) {
    $user_id = get_current_user_id();
    if ( $request->get_param( 'user_id' ) ) {
        $user_id = $request->get_param( 'user_id' );
    }
    // ok: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
    return do_something_with_user( $user_id );
}

// OK: override is not inside a *permission*check* function — named differently.
function rest_act_as_user_callback( $request ) {
    $acting_user = get_current_user_id();
    if ( current_user_can( 'manage_options' ) && $request->get_param( 'user_id' ) ) {
        $acting_user = $request->get_param( 'user_id' );
    }
    // ok: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
    return perform_action_for_user( $acting_user );
}

// ── Variant B: capability check evaluated on a request-controlled target,
// not on the authenticated caller ─────────────────────────────────────────

// TP: plain function-call lookup. A request-supplied userId resolves a
// target user object; the target's OWN can_create_course() gates access
// (combined with an inequality against the caller), so any caller is let
// through whenever the *target* happens to have the capability.
class Lazy_Load_Controller {
    public function user_progress( WP_REST_Request $request ): LP_REST_Response {
        $params   = $request->get_params();
        // ruleid: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
        $user_id  = intval( $params['userId'] ?? 0 );
        $response = new LP_REST_Response();

        try {
            $user = learn_press_get_user( $user_id );
            if ( ! $user || $user->is_guest() ) {
                throw new Exception( 'Guest' );
            }

            if ( ! $user->can_create_course() && get_current_user_id() !== $user_id ) {
                throw new Exception( 'No permission' );
            }
        } catch ( Throwable $e ) {
            $response->message = $e->getMessage();
        }

        return $response;
    }
}

// TP: static-call lookup variant (Model::find()-style factory), != comparator.
class Courses_Controller {
    public function continue_course( WP_REST_Request $request ) {
        // ruleid: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
        $user_id = absint( $request->get_param( 'userId' ) );
        $target  = UserModel::find( $user_id, true );
        if ( ! $target->is_admin() && get_current_user_id() != $user_id ) {
            return new WP_Error( 'no' );
        }
    }
}

// OK: the id is bound to the current session, never to a request parameter —
// there is no attacker-controlled key for the authorization decision to key off.
class Self_Check_Controller {
    public function self_check( WP_REST_Request $request ) {
        // ok: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
        $user_id = get_current_user_id();
        $user    = learn_press_get_user( $user_id );
        if ( ! $user->can_create_course() && get_current_user_id() !== $user_id ) {
            throw new Exception( 'No permission' );
        }
    }
}

// OK: the correct fix idiom — the acting user is always resolved from the
// session, so the request parameter never reaches the authorization decision.
class Items_Progress_Controller {
    public function items_progress( $request ) {
        $course_id = $request->get_param( 'courseId' );
        // ok: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
        $user_id   = get_current_user_id();
        $user      = learn_press_get_user( $user_id );
        $check     = $user->can_show_finish_course_btn( $course_id );
        if ( ! $check ) {
            throw new Exception( 'No' );
        }
    }
}

// OK: the vulnerable body is left in place below an unconditional early
// return in a soft-deprecated function (a common WP idiom) — it is
// unreachable dead code, so this must not be flagged.
class Deprecated_Controller {
    public function user_progress( WP_REST_Request $request ): LP_REST_Response {
        _deprecated_function( __METHOD__, '4.4.0' );
        $response = new LP_REST_Response();
        return $response;
        $params  = $request->get_params();
        // ok: claude.php.wordpress.access.rest-user-id-param-override-in-permission-check
        $user_id = intval( $params['userId'] ?? 0 );
        $user    = learn_press_get_user( $user_id );
        if ( ! $user->can_create_course() && get_current_user_id() !== $user_id ) {
            throw new Exception( 'No permission' );
        }
    }
}
