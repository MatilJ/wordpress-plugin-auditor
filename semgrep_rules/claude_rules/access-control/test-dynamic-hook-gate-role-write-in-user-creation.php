<?php

// ---- TRUE POSITIVES ----

// Mirrors the real pre-fix shape (CVE-2026-0920, lastudio-element-kit
// <= 1.5.6.3): a gating request key is checked only for non-emptiness, and
// that alone conditionally attaches a dynamically-named hook before the
// account is created.
class Vulnerable_Registration_Handler {

    private function setup_sys_meta_key() {
        return apply_filters( 'lastudio-kit/integration/sys_meta_key', 'insert_lakit_meta' );
    }

    public function ajax_register_handle( $request ) {
        $sys_meta_key = $this->setup_sys_meta_key();

        if ( ! empty( $request['lakit_bkrole'] ) && ! empty( $sys_meta_key ) ) {
            // ruleid: claude.php.wordpress.access-control.dynamic-hook-gate-role-write-in-user-creation
            add_filter( $sys_meta_key, [ $this, 'ajax_register_handle_backup' ], 20 );
        }

        $posted_user_data = array(
            'user_login' => sanitize_user( $request['username'] ),
            'user_email' => sanitize_email( $request['email'] ),
            'user_pass'  => wp_generate_password(),
        );

        $new_user_id = wp_insert_user( $posted_user_data );

        if ( ! empty( $request['lakit_bkrole'] ) && ! empty( $sys_meta_key ) ) {
            remove_filter( $sys_meta_key, [ $this, 'ajax_register_handle_backup' ], 20 );
        }

        return $new_user_id;
    }

    public function ajax_register_handle_backup( $meta ) {
        global $table_prefix;
        $label = $table_prefix . 'capabilities';
        return apply_filters( 'lastudio-kit/integration/user-meta', $meta, $label );
    }
}

// Second true-positive variant: different variable/function names, an
// add_action() call instead of add_filter(), and wp_create_user() instead of
// wp_insert_user() — proves the rule generalizes beyond the seeding plugin's
// exact tokens rather than pattern-matching literal identifiers.
class Vulnerable_Signup_Controller {

    public function handle_signup( $payload ) {
        $target_hook = get_option( 'signup_meta_hook', 'insert_lakit_meta' );

        if ( ! empty( $payload['debug_flag'] ) ) {
            // ruleid: claude.php.wordpress.access-control.dynamic-hook-gate-role-write-in-user-creation
            add_action( $target_hook, array( $this, 'grant_role_backdoor' ) );
        }

        $new_id = wp_create_user( $payload['login'], $payload['pass'], $payload['email'] );

        return $new_id;
    }

    public function grant_role_backdoor( $meta ) {
        $meta['wp_capabilities'] = array( 'administrator' => true );
        return $meta;
    }
}

// ---- FALSE POSITIVES ----

// The common, auditable case: a plain string literal hook name. Even though
// it is gated the same way and creates a user, the hook name itself is
// visible and reviewable, so this rule (which only targets the opaque
// dynamic-hook-name shape) must not flag it.
class OK_Literal_Hook_Registration {

    public function register_new_member( $request ) {
        if ( ! empty( $request['send_welcome_email'] ) ) {
            // ok: claude.php.wordpress.access-control.dynamic-hook-gate-role-write-in-user-creation
            add_filter( 'insert_user_meta', array( $this, 'attach_welcome_flag' ) );
        }

        $user_id = wp_insert_user( array(
            'user_login' => sanitize_user( $request['username'] ),
            'user_email' => sanitize_email( $request['email'] ),
            'user_pass'  => wp_generate_password(),
        ) );

        return $user_id;
    }

    public function attach_welcome_flag( $meta ) {
        $meta['welcome_email_sent'] = 0;
        return $meta;
    }
}

// The fix: a current_user_can() check gates the enclosing function, so even
// a dynamic hook name here is reachable only by an already-privileged user.
class OK_Capability_Gated_Registration {

    public function admin_provision_account( $request ) {
        if ( ! current_user_can( 'create_users' ) ) {
            return new WP_Error( 'forbidden', 'Not allowed' );
        }

        $hook_name = apply_filters( 'acme/provisioning_hook', 'insert_user_meta' );

        if ( ! empty( $request['apply_extra_meta'] ) ) {
            // ok: claude.php.wordpress.access-control.dynamic-hook-gate-role-write-in-user-creation
            add_filter( $hook_name, array( $this, 'apply_extra_meta' ) );
        }

        return wp_insert_user( array(
            'user_login' => sanitize_user( $request['username'] ),
            'user_email' => sanitize_email( $request['email'] ),
            'user_pass'  => wp_generate_password(),
        ) );
    }

    public function apply_extra_meta( $meta ) {
        return $meta;
    }
}

// Unrelated safe WP DB-read pattern: dynamic hook name registration exists,
// but the enclosing function never creates a user account at all — must not
// be flagged.
class UnrelatedReportBuilder {

    public function build_order_summary( $request ) {
        global $wpdb;

        $hook_name = get_option( 'report_filter_hook', 'orders_summary_meta' );

        if ( ! empty( $request['include_extra_columns'] ) ) {
            // ok: claude.php.wordpress.access-control.dynamic-hook-gate-role-write-in-user-creation
            add_filter( $hook_name, array( $this, 'add_extra_columns' ) );
        }

        return $wpdb->get_results(
            $wpdb->prepare( "SELECT ID, post_title FROM {$wpdb->posts} WHERE post_status = %s", 'publish' )
        );
    }

    public function add_extra_columns( $columns ) {
        return $columns;
    }
}
