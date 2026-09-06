<?php

class Role_Switch_Handler {

    public function reset_role_for_username() {
        // ruleid: claude.php.wordpress.access-control.role-restore-membership-gate-no-ownership-check
        $reset_for_username = sanitize_text_field( $_REQUEST['reset-for'] );

        $options = get_option( 'my_plugin_options', array() );
        $usernames = $options['role_switch_pending'];

        if ( in_array( $reset_for_username, $usernames ) ) {

            $target_user = get_user_by( 'login', $reset_for_username );
            $original_roles = get_user_meta( $target_user->ID, '_my_plugin_original_roles', true );

            foreach ( $target_user->roles as $current_role ) {
                $target_user->remove_role( $current_role );
            }

            foreach ( $original_roles as $original_role ) {
                $target_user->add_role( $original_role );
            }
        }
    }
}

function bare_reset_role_for_username() {
    // ruleid: claude.php.wordpress.access-control.role-restore-membership-gate-no-ownership-check
    $requested_login = sanitize_text_field( $_GET['restore_login'] );

    $pending = get_option( 'pending_restores', array() );

    if ( in_array( $requested_login, $pending ) ) {
        $account = get_user_by( 'login', $requested_login );
        $stashed_role = get_user_meta( $account->ID, '_stashed_role', true );
        $account->set_role( $stashed_role );
    }
}

class Role_Switch_Handler_With_Invalidation {

    public function reset_role_for_username() {
        // ok: claude.php.wordpress.access-control.role-restore-membership-gate-no-ownership-check
        $reset_for_username = sanitize_text_field( $_REQUEST['reset-for'] );

        $options = get_option( 'my_plugin_options', array() );
        $usernames = $options['role_switch_pending'];

        if ( in_array( $reset_for_username, $usernames ) ) {

            $target_user = get_user_by( 'login', $reset_for_username );
            $original_roles = get_user_meta( $target_user->ID, '_my_plugin_original_roles', true );

            foreach ( $original_roles as $original_role ) {
                $target_user->add_role( $original_role );
            }
        }
    }

    // Sibling invalidator: purges the stashed role snapshot whenever WP core
    // fires a profile update, closing the stale-state window exploited above.
    public function on_profile_update( $user_id ) {
        delete_user_meta( $user_id, '_my_plugin_original_roles' );
    }
}

class Role_Switch_Handler_With_Identity_Check {

    public function reset_role_for_username() {
        // ok: claude.php.wordpress.access-control.role-restore-membership-gate-no-ownership-check
        $reset_for_username = sanitize_text_field( $_REQUEST['reset-for'] );

        $options = get_option( 'my_plugin_options', array() );
        $usernames = $options['role_switch_pending'];

        if ( in_array( $reset_for_username, $usernames ) ) {

            $target_user = get_user_by( 'login', $reset_for_username );

            if ( get_current_user_id() === $target_user->ID ) {
                $original_roles = get_user_meta( $target_user->ID, '_my_plugin_original_roles', true );

                foreach ( $original_roles as $original_role ) {
                    $target_user->add_role( $original_role );
                }
            }
        }
    }
}
