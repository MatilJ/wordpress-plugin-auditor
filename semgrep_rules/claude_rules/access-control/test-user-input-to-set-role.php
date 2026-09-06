<?php

// ---- TRUE POSITIVES ----

function tp_direct_post_role($user) {
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    $user->set_role($_POST['role']);
}

function tp_variable_post_role() {
    $role = $_POST['new_role'];
    $user = get_user_by('id', $_POST['user_id']);
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    $user->set_role($role);
}

function tp_add_role_from_request($user) {
    $role = $_REQUEST['role'];
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    $user->add_role($role);
}

function tp_rest_param_role($request) {
    $role = $request->get_param('role');
    $user = get_user_by('id', $request->get_param('user_id'));
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    $user->set_role($role);
}

function tp_get_param_role() {
    $role = $_GET['role'];
    $user = wp_get_current_user();
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    $user->set_role($role);
}

function tp_wp_insert_user_role_from_post() {
    $role = $_POST['role'];
    $user_id = wp_insert_user( array(
        'user_login' => $_POST['email'],
        'user_email' => $_POST['email'],
        'user_pass'  => wp_generate_password(),
        // ruleid: claude.php.wordpress.access.user-input-to-set-role
        'role'       => $role,
    ) );
}

function tp_foreach_post_role_to_meta_array( $meta ) {
    // Mirrors the real pre-fix shape: a hidden-field role value is copied
    // straight from $_POST into a role-named meta/array key with no
    // allowlist and no signature check.
    foreach ( $_POST as $key => $value ) {
        if ( $key == 'pt-paytium-user-data' ) {
            // ruleid: claude.php.wordpress.access.user-input-to-set-role
            $meta['pt-user-role'] = $value;
        }
    }
    return $meta;
}

function tp_register_role_array_builder_no_signature() {
    // Mirrors the real pre-fix shape: role is read from a POST field and
    // validated only against a static allow-list (no signature bound to
    // which role was actually offered) before the array variable holding
    // it is passed whole to wp_insert_user().
    $role = isset( $_POST['lsd_role'] ) ? sanitize_text_field( wp_unslash( $_POST['lsd_role'] ) ) : '';
    if ( ! in_array( $role, array( 'subscriber', 'contributor', 'shop_manager' ), true ) ) $role = '';

    $user_data = array(
        'user_login' => sanitize_text_field( wp_unslash( $_POST['username'] ) ),
        'user_pass'  => wp_unslash( $_POST['password'] ),
        'user_email' => sanitize_email( wp_unslash( $_POST['email'] ) ),
    );

    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    if ( $role ) $user_data['role'] = $role;
    $user_id = wp_insert_user( $user_data );
}

function tp_update_role_array_builder_no_signature( $target_id ) {
    $role = isset( $_REQUEST['account_role'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['account_role'] ) ) : '';
    if ( ! in_array( $role, array( 'customer', 'vendor' ), true ) ) $role = '';

    $user_data = array( 'ID' => $target_id );
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    if ( $role ) $user_data['role'] = $role;
    wp_update_user( $user_data );
}

function tp_json_register_role_array_builder_no_clobber() {
    // Mirrors the real pre-fix shape (CVE-2023-3076): a REST registration
    // handler reads the role straight out of the decoded JSON request body
    // with no hardcoded override, then the array variable holding it is
    // passed whole to wp_insert_user().
    $json = file_get_contents( 'php://input' );
    $params = json_decode( $json, true );
    $user = array();
    $user['user_login'] = sanitize_user( $params['username'] );
    $user['user_email'] = sanitize_email( $params['email'] );
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    $user['role'] = isset( $params['role'] ) ? sanitize_text_field( $params['role'] ) : get_option( 'default_role' );
    $user_id = wp_insert_user( $user );
}

function tp_update_user_register_direct_call( $user_id ) {
    // Mirrors the real pre-fix shape (CVE-2024-32511): an unauthenticated
    // self-registration handler hooked on user_register copies the posted
    // role straight into an inline wp_update_user() array literal with no
    // validation at all.
    // ruleid: claude.php.wordpress.access.user-input-to-set-role
    $user_id = wp_update_user( array( 'ID' => $user_id, 'role' => $_POST['role'] ) );
}

function tp_array_literal_role_key_wp_insert_user() {
    // Mirrors the real pre-fix shape (CVE-2026-7284): the role key is set
    // inline as part of the array LITERAL itself (not appended afterward
    // via bracket-assignment), validated only by an existence check against
    // the full registered role list (not a safe-role allowlist), and the
    // array variable is passed by name to wp_insert_user() on a later line.
    $user_data = array(
        'user_login' => sanitize_user( wp_unslash( $_POST['user_login'] ), true ),
        'user_email' => sanitize_email( wp_unslash( $_POST['user_email'] ) ),
        'user_pass'  => wp_unslash( $_POST['user_pass'] ),
        // ruleid: claude.php.wordpress.access.user-input-to-set-role
        'role'       => !empty( $_POST['role'] ) && array_key_exists( sanitize_text_field( wp_unslash( $_POST['role'] ) ), wp_roles()->get_names() ) ? sanitize_text_field( wp_unslash( $_POST['role'] ) ) : 'subscriber',
    );
    $user_id = wp_insert_user( $user_data );
}

function tp_array_literal_role_key_wp_update_user( $user_id ) {
    // Second true-positive variant of the same array-literal shape, targeting
    // wp_update_user() instead of wp_insert_user().
    $user_data = array(
        'ID'   => $user_id,
        // ruleid: claude.php.wordpress.access.user-input-to-set-role
        'role' => sanitize_text_field( wp_unslash( $_REQUEST['role'] ) ),
    );
    wp_update_user( $user_data );
}

// ---- FALSE POSITIVES ----

function ok_hardcoded_role($user) {
    // ok: claude.php.wordpress.access.user-input-to-set-role
    $user->set_role('subscriber');
}

function ok_hardcoded_admin_role($user) {
    // ok: claude.php.wordpress.access.user-input-to-set-role
    $user->set_role('administrator');
}

function ok_add_role_hardcoded($user) {
    // ok: claude.php.wordpress.access.user-input-to-set-role
    $user->add_role('editor');
}

function ok_foreach_post_role_signature_verified( $meta ) {
    // The fix: resubmitted role is verified against a server-computed
    // hash_equals() signature before being trusted.
    foreach ( $_POST as $key => $value ) {
        if ( $key == 'pt-paytium-user-data' ) {
            $submitted_role = sanitize_text_field( wp_unslash( $value ) );
            $submitted_sig  = isset( $_POST['pt-paytium-user-data-sig'] )
                ? sanitize_text_field( wp_unslash( $_POST['pt-paytium-user-data-sig'] ) )
                : '';
            $expected_sig = wp_hash( 'pt_user_role|' . $submitted_role );

            if ( $submitted_sig !== '' && hash_equals( $expected_sig, $submitted_sig ) ) {
                // ok: claude.php.wordpress.access.user-input-to-set-role
                $meta['pt-user-role'] = $submitted_role;
            }
        }
    }
    return $meta;
}

function ok_register_role_array_builder_signature_verified( $auth_helper ) {
    // The fix: the resubmitted role must pass a verification helper that
    // is itself keyed on both the role AND a separate signature/token
    // argument resubmitted alongside it, not just an allow-list membership
    // test on the role value in isolation.
    $role = isset( $_POST['lsd_role'] ) ? sanitize_text_field( wp_unslash( $_POST['lsd_role'] ) ) : '';
    $role_signature = isset( $_POST['lsd_role_signature'] ) ? sanitize_text_field( wp_unslash( $_POST['lsd_role_signature'] ) ) : '';
    $role = $auth_helper->verify_role_signature( 'register', $role, $role_signature ) ? $auth_helper->sanitize_supported_role( $role ) : '';

    $user_data = array(
        'user_login' => sanitize_text_field( wp_unslash( $_POST['username'] ) ),
        'user_pass'  => wp_unslash( $_POST['password'] ),
        'user_email' => sanitize_email( wp_unslash( $_POST['email'] ) ),
    );

    // ok: claude.php.wordpress.access.user-input-to-set-role
    if ( $role ) $user_data['role'] = $role;
    $user_id = wp_insert_user( $user_data );
}

function ok_update_user_register_allowlist_gated( $user_id, $wp_roles ) {
    // The real fix (CVE-2024-32511): the direct call is only reached inside
    // an if() that checks the posted role against an admin-curated
    // in_array() allow-list AND explicitly excludes 'administrator';
    // otherwise the role is hardcoded to 'subscriber'.
    $roleKey = array();
    foreach ( $wp_roles->roles as $key => $value ) {
        $roleKey[] = trim( $key );
    }
    if ( isset( $_POST['role'] ) && in_array( trim( $_POST['role'] ), $roleKey ) && strtolower( $_POST['role'] ) != 'administrator' ) {
        // ok: claude.php.wordpress.access.user-input-to-set-role
        $user_id = wp_update_user( array( 'ID' => $user_id, 'role' => $_POST['role'] ) );
    } else {
        $user_id = wp_update_user( array( 'ID' => $user_id, 'role' => 'subscriber' ) );
    }
}

function ok_json_register_role_clobbered_to_subscriber() {
    // The real fix (CVE-2023-3076): the decoded JSON request body's role
    // key is forcibly overwritten with a hardcoded literal before it is
    // ever read into the array that reaches wp_insert_user() — the
    // resubmitted value can no longer influence the assigned role.
    $json = file_get_contents( 'php://input' );
    $params = json_decode( $json, true );
    $params['role'] = 'subscriber';
    $user = array();
    $user['user_login'] = sanitize_user( $params['username'] );
    $user['user_email'] = sanitize_email( $params['email'] );
    // ok: claude.php.wordpress.access.user-input-to-set-role
    $user['role'] = isset( $params['role'] ) ? sanitize_text_field( $params['role'] ) : get_option( 'default_role' );
    $user_id = wp_insert_user( $user );
}

function ok_wp_insert_user_role_from_config() {
    // Role comes from the site's own saved configuration, not the request.
    $role = get_option( 'registration_default_role', 'subscriber' );
    $user_id = wp_insert_user( array(
        'user_login' => 'someuser',
        'user_email' => 'someuser@example.com',
        'user_pass'  => wp_generate_password(),
        // ok: claude.php.wordpress.access.user-input-to-set-role
        'role'       => $role,
    ) );
}

function ok_array_literal_role_safe_helper_no_request_input() {
    // The real fix (CVE-2026-7284): role is never read from $_POST at all.
    // A safe-role helper resolves it from get_option('default_role') plus a
    // capability blocklist, so no request-tainted value ever reaches the
    // array literal's 'role' key.
    $safe_role = get_safe_registration_role();
    $user_data = array(
        'user_login' => sanitize_user( wp_unslash( $_POST['user_login'] ), true ),
        'user_email' => sanitize_email( wp_unslash( $_POST['user_email'] ) ),
        'user_pass'  => wp_unslash( $_POST['user_pass'] ),
        // ok: claude.php.wordpress.access.user-input-to-set-role
        'role'       => $safe_role,
    );
    $user_id = wp_insert_user( $user_data );
}

function ok_array_literal_role_hardcoded_in_variable() {
    // Role is hardcoded to a literal string, never derived from request
    // input, even though it is set inside an array literal assigned to a
    // variable that is later passed by name to wp_insert_user().
    $user_data = array(
        'user_login' => sanitize_user( wp_unslash( $_POST['user_login'] ), true ),
        // ok: claude.php.wordpress.access.user-input-to-set-role
        'role'       => 'subscriber',
    );
    $user_id = wp_insert_user( $user_data );
}

// ---- Mapped-field-property variant (CVE-2026-54196) ----

class TP_Role_Property_No_Capability_Check {
    public $value;

    public function do_after( $modifier ) {
        $id = $modifier->get( 'ID' );

        if ( empty( $this->value ) ) {
            return;
        }

        if ( ! is_array( $this->value ) ) {
            $this->value = array( $this->value );
        }

        $main_role = array_shift( $this->value );

        // Mirrors the real pre-fix shape: the ONLY gate is a lone
        // 'administrator' string exclusion, no current_user_can() anywhere
        // in this function.
        if ( 'administrator' !== $main_role ) {
            // ruleid: claude.php.wordpress.access.user-input-to-set-role
            $id->user->set_role( $main_role );
        }

        foreach ( $this->value as $role ) {
            if ( 'administrator' !== $role ) {
                // ruleid: claude.php.wordpress.access.user-input-to-set-role
                $id->user->add_role( $role );
            }
        }
    }
}

class OK_Role_Property_Capability_Gated {
    public $value;

    public function do_after( $modifier ) {
        $id = $modifier->get( 'ID' );

        if ( empty( $this->value ) ) {
            return;
        }

        if ( ! is_array( $this->value ) ) {
            $this->value = array( $this->value );
        }

        // The real fix: a current_user_can('promote_users') check (here in
        // ternary-assignment form) filters the allowed roles before the
        // value ever reaches set_role()/add_role().
        $available_roles = current_user_can( 'promote_users' )
            ? get_editable_roles()
            : get_registered_roles_safe();

        $this->value = array_values(
            array_filter(
                $this->value,
                function ( $role ) use ( $available_roles ) {
                    return 'administrator' !== $role && isset( $available_roles[ $role ] );
                }
            )
        );

        $main_role = array_shift( $this->value );

        if ( 'administrator' !== $main_role ) {
            // ok: claude.php.wordpress.access.user-input-to-set-role
            $id->user->set_role( $main_role );
        }

        foreach ( $this->value as $role ) {
            if ( 'administrator' !== $role ) {
                // ok: claude.php.wordpress.access.user-input-to-set-role
                $id->user->add_role( $role );
            }
        }
    }
}

// ---- role-key-passthrough-no-trusted-override (CVE-2026-1492 class) ----

// Real pre-fix shape (CVE-2026-1492, user-registration <= 5.1.2): the
// function's own request-decoded payload parameter's 'role' key is trusted
// as the fallback with only a generic string sanitizer, and is never
// unconditionally re-derived from a trusted lookup anywhere in the function.
class VulnerableMembersService {
    public function prepare_members_data( $data ) {
        // ruleid: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $response['role'] = isset( $data['role'] ) ? sanitize_text_field( $data['role'] ) : 'subscriber';

        if ( isset( $data['membership'] ) ) {
            $membership_details = $this->membership_repository->get_single_membership_by_ID( absint( $data['membership'] ) );
            $membership_meta    = json_decode( $membership_details['meta_value'], true );
            // Conditional/optional override of a DIFFERENT local var — does
            // not reassign $data['role'] itself, so the guard above still
            // fires: the plan lookup is skippable by omitting 'membership'.
            $response['role'] = isset( $membership_meta['role'] ) ? sanitize_text_field( $membership_meta['role'] ) : $response['role'];
        }

        return $response;
    }
}

// Second true-positive variant: null-coalescing shorthand instead of an
// isset() ternary, same unconditional passthrough of the caller's own key.
class VulnerablePlanRegistrationHandler {
    public function build_new_member_payload( $request_payload ) {
        // ruleid: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $user_data['role'] = $request_payload['role'] ?? 'subscriber';

        return $user_data;
    }
}

// Fixed shape (5.1.3): the SAME parameter's 'role' key is unconditionally
// re-derived from a trusted, server-controlled plan/membership lookup
// before the passthrough assignment is ever reached.
class FixedMembersService {
    public function prepare_members_data( $data, $context = 'admin' ) {
        if ( 'frontend' === $context ) {
            $membership_detail = $this->membership_repository->get_single_membership_by_ID( absint( $data['membership'] ) );
            // ok: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
            $data['role'] = isset( $membership_detail['role'] ) ? sanitize_text_field( $membership_detail['role'] ) : 'subscriber';
        }

        // ok: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $response['role'] = isset( $data['role'] ) ? sanitize_text_field( $data['role'] ) : 'subscriber';

        return $response;
    }
}

// Unrelated safe WP DB-read pattern: no role-denoting key anywhere, must
// not be flagged.
class UnrelatedReportService {
    public function build_summary_row( $row_data ) {
        global $wpdb;
        // ok: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $summary['total_orders'] = isset( $row_data['total_orders'] ) ? absint( $row_data['total_orders'] ) : 0;

        $users = $wpdb->get_results(
            $wpdb->prepare( "SELECT ID, user_login FROM {$wpdb->users} WHERE user_status = %d", 0 )
        );

        return $summary;
    }
}

// ---- role-key-passthrough-no-trusted-override: object-property variant (CVE-2025-11457 class) ----

// Real pre-fix shape (CVE-2025-11457, easycommerce <= 1.8.2): an abstract
// User model's create() method sets its own $role property straight from
// the caller-supplied $args['role'] with no allowlist or capability check;
// save() later passes $this->role into wp_insert_user()/add_role().
abstract class VulnerableUserModel {
    protected $role = '';

    public function create( $args ) {
        // ruleid: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $this->role = isset( $args['role'] ) ? $args['role'] : $this->role;
        return $this->save();
    }
}

// Second true-positive variant: a differently-named concrete model class,
// same unconditional property passthrough shape.
class VulnerableManagerAccount {
    protected $access_role = 'manager';

    public function register( $payload ) {
        // ruleid: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $this->access_role = isset( $payload['role'] ) ? $payload['role'] : $this->access_role;
        return $this->save();
    }
}

// Fixed shape (1.8.3): the property is hardcoded to itself -- the ternary
// reading from the caller-supplied array is removed entirely, so the
// vulnerable shape no longer exists at this line.
class FixedUserModel {
    protected $role = '';

    public function create( $args ) {
        // Prevent user-supplied role for security reasons (CVE-2025-11457)
        // ok: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $this->role = $this->role;
        return $this->save();
    }
}

// Capability-gated variant: a current_user_can() check anywhere in the
// enclosing function neutralizes the property passthrough (mirrors the
// mapped-field-property guard used elsewhere in this file).
class CapabilityGatedUserModel {
    protected $role = '';

    public function create( $args ) {
        if ( ! current_user_can( 'promote_users' ) ) {
            unset( $args['role'] );
        }
        // ok: claude.php.wordpress.access.role-key-passthrough-no-trusted-override
        $this->role = isset( $args['role'] ) ? $args['role'] : $this->role;
        return $this->save();
    }
}

// ---- role-mutation-wrapper-missing-allowlist (CVE-2024-30542 class) ----

// Real pre-fix shape (wholesalex <= 1.3.2): a shared role-change wrapper
// takes the new role as its own parameter (populated, several call frames
// away in a different file, from an unauthenticated request payload) and
// calls add_role() with no allow-list validation at all.
class Vulnerable_Role_Wrapper {
    // ruleid: claude.php.wordpress.access.role-mutation-wrapper-missing-allowlist
    public function change_role( $user_id, $new_role_id, $prev_role_id = '' ) {
        if ( ! ( isset( $new_role_id ) && ! empty( $new_role_id ) ) ) {
            return;
        }
        $user = new WP_User( $user_id );
        if ( '' !== $prev_role_id ) {
            $user->remove_role( $prev_role_id );
        }
        $user->add_role( $new_role_id );
    }
}

// Second true-positive variant: role parameter first, set_role() instead of
// add_role().
class Vulnerable_Role_First_Wrapper {
    // ruleid: claude.php.wordpress.access.role-mutation-wrapper-missing-allowlist
    public function apply_role( $role, $user_id ) {
        $user = new WP_User( $user_id );
        $user->set_role( $role );
    }
}

// Fixed shape (1.3.3): the wrapper validates the role parameter against the
// plugin's own defined-roles list with in_array() before applying it.
class Fixed_Role_Wrapper_Allowlist {
    // ok: claude.php.wordpress.access.role-mutation-wrapper-missing-allowlist
    public function change_role( $user_id, $new_role_id, $prev_role_id = '' ) {
        if ( ! ( isset( $new_role_id ) && ! empty( $new_role_id ) ) ) {
            return;
        }
        $valid_roles = wholesalex()->get_roles( 'ids' );
        if ( ! in_array( $new_role_id, $valid_roles ) ) {
            return;
        }
        $user = new WP_User( $user_id );
        if ( '' !== $prev_role_id ) {
            $user->remove_role( $prev_role_id );
        }
        $user->add_role( $new_role_id );
    }
}

// Alternate fix shape: the wrapper requires an explicit capability check
// instead of (or in addition to) an allow-list.
class Fixed_Role_Wrapper_Capability {
    // ok: claude.php.wordpress.access.role-mutation-wrapper-missing-allowlist
    public function admin_change_role( $user_id, $new_role_id ) {
        if ( ! current_user_can( 'promote_users' ) ) {
            return;
        }
        $user = new WP_User( $user_id );
        $user->add_role( $new_role_id );
    }
}

// Unrelated safe pattern: a read-only helper that never mutates a role,
// must not be flagged.
class Benign_Role_Reader {
    public function get_current_role( $user_id ) {
        $user = new WP_User( $user_id );
        $roles = $user->roles;
        return $roles ? $roles[0] : '';
    }
}
