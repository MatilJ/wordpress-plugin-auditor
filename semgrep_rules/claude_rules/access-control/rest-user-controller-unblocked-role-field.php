<?php

// ---- TRUE POSITIVES ----

// Real pre-fix shape (CVE-2026-49780 class): a vendor/customer REST
// controller extends a WooCommerce customer controller and forwards the
// request to parent:: with no role/roles check anywhere in the method. The
// object-level gate elsewhere in the class only confirms the caller is a
// vendor, not that the fields being written are safe for that caller to set.
class Vulnerable_Customers_Controller extends WC_REST_Customers_Controller {
    public function check_vendor_permission(): bool {
        return dokan_is_user_seller( get_current_user_id() );
    }

    protected function prepare_object_for_database( $request, $creating = false ) {
        // ruleid: claude.php.wordpress.access-control.rest-user-controller-unblocked-role-field
        $customer = parent::prepare_object_for_database( $request, $creating );

        if ( is_wp_error( $customer ) ) {
            return $customer;
        }

        return $customer;
    }
}

// Generalized variant: a membership plugin's REST controller extends the
// core Users controller directly and overrides prepare_item_for_database,
// with only a generic logged-in check gating the endpoint elsewhere.
class Vulnerable_Members_Controller extends WP_REST_Users_Controller {
    protected function prepare_item_for_database( $request ) {
        // ruleid: claude.php.wordpress.access-control.rest-user-controller-unblocked-role-field
        $prepared = parent::prepare_item_for_database( $request );

        return $prepared;
    }
}

// ---- FALSE POSITIVES ----

// Fixed sibling of Vulnerable_Customers_Controller — the official patch
// shape: reject the request outright when a role/roles parameter is present,
// before ever calling parent::.
class Fixed_Customers_Controller extends WC_REST_Customers_Controller {
    protected function prepare_object_for_database( $request, $creating = false ) {
        if ( null !== $request->get_param( 'role' ) || null !== $request->get_param( 'roles' ) ) {
            return new WP_Error( 'dokan_rest_forbidden_field', 'You cannot modify the role of a user.', [ 'status' => 403 ] );
        }

        // ok: claude.php.wordpress.access-control.rest-user-controller-unblocked-role-field
        $customer = parent::prepare_object_for_database( $request, $creating );

        return $customer;
    }
}

// Array-access equivalent of the fix — checking $request['roles'] directly
// rather than via get_param() still neutralizes the finding.
class Fixed_Members_Controller extends WP_REST_Users_Controller {
    protected function prepare_item_for_database( $request ) {
        if ( isset( $request['roles'] ) ) {
            return new WP_Error( 'forbidden_field', 'Role changes are not allowed here.' );
        }

        // ok: claude.php.wordpress.access-control.rest-user-controller-unblocked-role-field
        return parent::prepare_item_for_database( $request );
    }
}

// Unrelated parent controller — a products/orders REST controller has no
// user-role concept at all, so the same delegating shape is not this class
// of bug regardless of a missing role guard.
class Products_Controller extends WC_REST_Products_Controller {
    protected function prepare_object_for_database( $request, $creating = false ) {
        // ok: claude.php.wordpress.access-control.rest-user-controller-unblocked-role-field
        return parent::prepare_object_for_database( $request, $creating );
    }
}
