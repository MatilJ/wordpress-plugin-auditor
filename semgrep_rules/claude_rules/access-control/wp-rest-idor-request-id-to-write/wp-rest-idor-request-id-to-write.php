<?php
// =============================================================================
// TEST FILE: wp-rest-idor-request-id-to-write
// Patterns covered:
//   A) json_decode(file_get_contents('php://input')) → ID → delete/update
//   B) file_get_contents('php://input') → json_decode → ID → delete/update
//   C) WP_REST_Request::get_param() → ID → delete/update
//   D) WP_REST_Request::get_json_params() → ID array → delete/update
// =============================================================================

// ---- VULNERABLE A: php://input inline decoded → ORM delete -----------------

class VulnA1 {
    public function DeleteBooking() {
        $request    = json_decode( file_get_contents( 'php://input' ), true );
        $booking_id = $request['id'];
        $booking    = new Booking();
        // ruleid: wp-rest-idor-request-id-to-write
        $booking->delete( $booking_id );
    }
}

// ---- VULNERABLE A: php://input inline decoded → ORM update -----------------

class VulnA2 {
    public function changeStatus() {
        $request    = json_decode( file_get_contents( 'php://input' ), true );
        $booking_id = $request['booking_id'];
        $status     = $request['status'];
        $booking    = new Booking();
        // ruleid: wp-rest-idor-request-id-to-write
        $booking->update( array( 'id' => $booking_id, 'status' => $status ) );
    }
}

// ---- VULNERABLE A: php://input inline decoded → wpdb delete ----------------

class VulnA3 {
    public function deleteRaw() {
        global $wpdb;
        $request    = json_decode( file_get_contents( 'php://input' ), true );
        $booking_id = $request['id'];
        // ruleid: wp-rest-idor-request-id-to-write
        $wpdb->delete(
            $wpdb->prefix . 'tfhb_bookings',
            array( 'id' => $booking_id ),
            array( '%d' )
        );
    }
}

// ---- VULNERABLE B: two-step file_get_contents → json_decode → delete -------

class VulnB1 {
    public function DeleteMeeting() {
        $raw        = file_get_contents( 'php://input' );
        $body       = json_decode( $raw, true );
        $meeting_id = $body['id'];
        $meeting    = new Meeting();
        // ruleid: wp-rest-idor-request-id-to-write
        $meeting->delete( $meeting_id );
    }
}

// ---- VULNERABLE C: WP_REST_Request::get_param() → ORM delete ---------------

class VulnC1 {
    public function DeleteMeeting( $request ) {
        $meeting_id = $request->get_param( 'id' );
        $meeting    = new Meeting();
        // ruleid: wp-rest-idor-request-id-to-write
        $meeting->delete( $meeting_id );
    }
}

// ---- VULNERABLE C: WP_REST_Request::get_param() → ORM update ---------------

class VulnC2 {
    public function cancelAttendee( $request ) {
        $attendee_id = $request->get_param( 'id' );
        $attendee    = new Attendees();
        // ruleid: wp-rest-idor-request-id-to-write
        $attendee->update( array( 'id' => $attendee_id, 'status' => 'cancelled' ) );
    }
}

// ---- VULNERABLE D: get_json_params() array → ORM delete --------------------

class VulnD1 {
    public function bulkDelete( $request ) {
        $params  = $request->get_json_params();
        $items   = $params['items'];
        $booking = new Booking();
        foreach ( $items as $item ) {
            // ruleid: wp-rest-idor-request-id-to-write
            $booking->delete( $item );
        }
    }
}

// ---- VULNERABLE A: bulk items from php://input → loop delete ---------------

class VulnA4 {
    public function bulkDeleteRaw() {
        $request = json_decode( file_get_contents( 'php://input' ), true );
        $items   = $request['items'];
        $booking = new Booking();
        foreach ( $items as $item ) {
            // ruleid: wp-rest-idor-request-id-to-write
            $booking->delete( $item );
        }
    }
}

// =============================================================================
// SAFE: tainted ID does not reach a write sink
// =============================================================================

// SAFE: request param flows only to a read operation, not delete/update
class SafeReadOnly {
    public function getBooking( $request ) {
        $booking_id = $request->get_param( 'id' );
        $booking    = new Booking();
        // ok: wp-rest-idor-request-id-to-write
        return $booking->get( $booking_id );
    }
}

// SAFE: write uses only a hardcoded/constant condition — no tainted input
class SafeHardcodedCondition {
    public function cleanupExpired() {
        global $wpdb;
        // ok: wp-rest-idor-request-id-to-write
        $wpdb->delete(
            $wpdb->prefix . 'tfhb_bookings',
            array( 'status' => 'expired' ),
            array( '%s' )
        );
    }
}

// SAFE: write uses ID from DB query (untainted), not from request body
class SafeDbSourcedId {
    public function deleteExpiredSessions() {
        global $wpdb;
        $old_ids = $wpdb->get_col(
            "SELECT id FROM {$wpdb->prefix}sessions WHERE expires < NOW()"
        );
        $booking = new Booking();
        foreach ( $old_ids as $id ) {
            // ok: wp-rest-idor-request-id-to-write
            $booking->delete( $id );
        }
    }
}

// SAFE: wpdb update WHERE uses get_current_user_id() (untainted)
class SafeCurrentUser {
    public function markOwnBookingsRead() {
        global $wpdb;
        $user_id = get_current_user_id();
        // ok: wp-rest-idor-request-id-to-write
        $wpdb->update(
            $wpdb->prefix . 'tfhb_bookings',
            array( 'read' => 1 ),
            array( 'host_id' => $user_id ),
            array( '%d' ),
            array( '%d' )
        );
    }
}

// SAFE: get()-before-update on same object with same ID — post-type gate
// The get() call uses a post_type constraint; returns null if $id doesn't belong
// to the expected CPT. The null-check early return prevents reaching update().
class SafeGetBeforeUpdate {
    public function updateRecord( $request ) {
        $id   = $request->get_param( 'id' );
        $post = $this->cpt->get( $id );
        if ( ! $post ) {
            return new WP_Error( 'not_found', 'Not found', array( 'status' => 404 ) );
        }
        // ok: wp-rest-idor-request-id-to-write
        $this->cpt->update( $id, array( 'name' => 'updated' ) );
    }
}

// STILL VULNERABLE: get() on different object — type check not on the write target
class VulnDifferentObject {
    public function updateRecord( $request ) {
        $id      = $request->get_param( 'id' );
        $account = $this->accounts->get( $id ); // different $OBJ
        if ( ! $account ) {
            return new WP_Error( 'not_found', 'Not found', array( 'status' => 404 ) );
        }
        // ruleid: wp-rest-idor-request-id-to-write
        $this->feeds->update( $id, array( 'name' => 'updated' ) ); // different $OBJ
    }
}
