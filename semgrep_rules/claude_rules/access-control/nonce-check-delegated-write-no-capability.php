<?php
// Tests for claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
// NOTE: join mode requires `semgrep login` — --test and standalone --config scans of
// this file will fail locally without it. Verify via sub-rule isolation or with login.
//
// Method names are kept UNIQUE across every class in this file: the join key is
// (file path, method name), not (class, method name), so two unrelated classes
// reusing the same method name would cross-pollinate matches between cases.

// ── TRUE POSITIVES ─────────────────────────────────────────────────────────────

// Case 1: nested-if nonce guard on a hook callback ($_SERVER isset wraps the nonce
// check), delegates to an instance method that performs the write two calls deep.
// Models an AI plugin's "Advisor" module: init() verifies a nonce and calls
// $this->run_advisor(); run_advisor() is the one that actually calls update_option()
// — neither function alone matches the same-function nonce-without-capability-check
// rule, and the nonce check/delegate call sit inside a double-nested if.
class AdvisorModuleTest {
    public function init() {
        if ( isset( $_SERVER['REQUEST_METHOD'] ) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset( $_POST['refresh_nonce'] ) ) {
            if ( wp_verify_nonce( $_POST['refresh_nonce'], 'refresh_action' ) ) {
                $this->run_advisor();
                wp_safe_redirect( remove_query_arg( 'refresh' ) );
                exit;
            }
        }
    }

    public function run_advisor() {
        $recommendations = [ 'title' => 'example' ];
        // ruleid: claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
        update_option( 'plugin_advisor_data', [ 'date' => time(), 'data' => $recommendations ], false );
    }
}

// Case 2: check_ajax_referer variant, flat (non-nested) function body, delegate
// performs a $wpdb delete.
class DelegatedDeleteTest {
    public function handle_ajax_delete() {
        check_ajax_referer( 'delete_item', 'nonce' );
        $this->purge_item_unsafe( intval( $_POST['id'] ) );
        wp_send_json_success();
    }

    public function purge_item_unsafe( $id ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
        $wpdb->delete( $wpdb->prefix . 'items', [ 'id' => $id ] );
    }
}

// ── FALSE POSITIVES (ok) ────────────────────────────────────────────────────────

// Case 3: delegated method itself performs the capability check — safe. Unique
// method names (init_gated / run_advisor_gated) so this case cannot join with
// Case 1's identically-shaped-but-vulnerable pair.
class GatedDelegateTest {
    public function init_gated() {
        if ( wp_verify_nonce( $_POST['refresh_nonce'] ?? '', 'refresh_action' ) ) {
            $this->run_advisor_gated();
        }
    }

    public function run_advisor_gated() {
        // ok: claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        update_option( 'plugin_advisor_data', [ 'date' => time() ], false );
    }
}

// Case 4: outer function already checks capability before delegating — safe.
// Unique method names (handle_ajax_delete_gated / purge_item_gated).
class GatedOuterTest {
    public function handle_ajax_delete_gated() {
        check_ajax_referer( 'delete_item', 'nonce' );
        if ( ! current_user_can( 'delete_posts' ) ) {
            wp_send_json_error( 'Unauthorized' );
        }
        $this->purge_item_gated( intval( $_POST['id'] ) );
    }

    public function purge_item_gated( $id ) {
        global $wpdb;
        // ok: claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
        $wpdb->delete( $wpdb->prefix . 'items', [ 'id' => $id ] );
    }
}

// Case 5: delegate target performs no state-changing write — no join match.
class ReadOnlyDelegateTest {
    public function init_readonly() {
        if ( wp_verify_nonce( $_POST['nonce'] ?? '', 'view_action' ) ) {
            $this->render_preview();
        }
    }

    public function render_preview() {
        global $wpdb;
        // ok: claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
        $rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}items" );
        wp_send_json_success( $rows );
    }
}

// Case 6: self-scoped "dismiss this notice for me" toggle — the delegated write
// targets get_current_user_id() (no cross-user victim) with a literal boolean
// value (no capability-bearing payload). Confirmed FP shape from a bundled
// QuadLayers admin-notice library.
class NoticeDismissTest {
    public function ajax_notice_dismiss() {
        if ( isset( $_REQUEST['notice_index'] ) && check_admin_referer( 'notice_dismiss_action', 'nonce' ) ) {
            $this->set_current_user_notice_meta_hidden( sanitize_key( $_REQUEST['notice_index'] ) );
            wp_send_json_success();
        }
        wp_die();
    }

    private function set_current_user_notice_meta_hidden( $notice_index ) {
        // ok: claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
        return update_user_meta( get_current_user_id(), 'notice_hidden_' . $notice_index, true );
    }
}

// Case 7: boundary — same self-scoped target ID, but the stored VALUE is
// request-derived rather than a boolean literal. The exclusion is scoped to
// literal true/false only, so this must still fire: an attacker-controlled
// value written to the acting user's own meta can still be a genuine issue
// (e.g. a capability-bearing or otherwise security-relevant field).
class NoticeDismissAttackerValueTest {
    public function ajax_set_preference() {
        check_ajax_referer( 'set_pref_action', 'nonce' );
        $this->set_current_user_preference( $_POST['pref_value'] );
        wp_send_json_success();
    }

    private function set_current_user_preference( $value ) {
        // ruleid: claude.php.wordpress.access-control.nonce-check-delegated-write-no-capability
        return update_user_meta( get_current_user_id(), 'plugin_preference', $value );
    }
}
