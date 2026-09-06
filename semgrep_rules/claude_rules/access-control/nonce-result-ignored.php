<?php
function handler_bad() {
    // ruleid: claude.php.wordpress.access.nonce-result-ignored
    wp_verify_nonce($_POST['_wpnonce'], 'do_thing');
    update_option('foo', $_POST['foo']);
}

function handler_good() {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    if (! wp_verify_nonce($_POST['_wpnonce'], 'do_thing')) {
        wp_die('Invalid nonce.');
    }
    update_option('foo', $_POST['foo']);
}

function handler_good_die() {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    check_admin_referer('do_thing');
    update_option('foo', $_POST['foo']);
}

function handler_good_assigned() {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    $ok = wp_verify_nonce($_POST['_wpnonce'], 'do_thing');
    if (! $ok) {
        wp_die('Invalid nonce.');
    }
}

// Formidable FP (FrmEntry.php:1102) — nonce is consumed into a boolean
// expression that is assigned. Not a missing-check bug.
function after_entry_created_actions($values) {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    $is_child = isset($values['parent_nonce']) && ! empty($values['parent_form_id']) && wp_verify_nonce($values['parent_nonce'], 'parent');
    do_action('frm_after_create_entry', 0, compact('is_child'));
}

// Return-value-used variants should not flag.
function handler_good_returned($values) {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    return isset($values['nonce']) && wp_verify_nonce($values['nonce'], 'action');
}

function handler_good_if_expr($values) {
    // ok: claude.php.wordpress.access.nonce-result-ignored
    if (isset($values['nonce']) && wp_verify_nonce($values['nonce'], 'action')) {
        do_thing();
    }
}

// ─── claude.php.wordpress.access.custom-nonce-wrapper-result-ignored ───────

// TP: real confirmed shape (shortpixel-image-optimiser 6.5.5) — a shared
// base-controller's checkPost() computes and returns a nonce-failure signal,
// but the subclass action handler discards it and proceeds unconditionally.
class ViewController {
    protected $form_action = 'my_settings_save';

    protected function checkPost($processPostData = true) {
        if (! wp_verify_nonce($_POST['sp-nonce'], $this->form_action)) {
            if (isset($_POST['ajaxSave']) && isset($_POST['action'])) {
                wp_die('Nonce Failed');
            }
            return false;
        }
        return true;
    }
}

class SettingsViewController extends ViewController {
    public function action_debug_resetQueue() {
        // ruleid: claude.php.wordpress.access.custom-nonce-wrapper-result-ignored
        $this->checkPost(false);
        update_option('my_plugin_queue', array());
    }

    public function load() {
        if (! $this->checkPost()) {
            // ok: claude.php.wordpress.access.custom-nonce-wrapper-result-ignored
            return;
        }
        $this->processSave();
    }

    private function processSave() {}
}

// TP: assignment-free bare call to a differently-named conventional wrapper.
class Ajax_Handler {
    public function remove_all() {
        // ruleid: claude.php.wordpress.access.custom-nonce-wrapper-result-ignored
        $this->checkNonce('remove-all');
        $this->deleteEverything();
    }

    protected function checkNonce($action) {
        return isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], $action);
    }

    private function deleteEverything() {}
}

// Safe: return value checked via if-guard before the state-changing write.
class Safe_Ajax_Handler {
    public function remove_all() {
        // ok: claude.php.wordpress.access.custom-nonce-wrapper-result-ignored
        if (! $this->checkNonce('remove-all')) {
            wp_die('Invalid nonce.');
        }
        $this->deleteEverything();
    }

    protected function checkNonce($action) {
        return isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], $action);
    }

    private function deleteEverything() {}
}

// Safe: return value captured into a variable and checked afterward.
class Safe_Ajax_Handler_Assigned {
    public function remove_all() {
        // ok: claude.php.wordpress.access.custom-nonce-wrapper-result-ignored
        $valid = $this->checkNonce('remove-all');
        if (! $valid) {
            wp_die('Invalid nonce.');
        }
        $this->deleteEverything();
    }

    protected function checkNonce($action) {
        return isset($_POST['_wpnonce']) && wp_verify_nonce($_POST['_wpnonce'], $action);
    }

    private function deleteEverything() {}
}

// Safe: method name does not match the nonce/security-wrapper naming
// convention — an unrelated bare call must not be flagged.
class Unrelated_Bare_Call {
    public function render() {
        // ok: claude.php.wordpress.access.custom-nonce-wrapper-result-ignored
        $this->loadTemplate('main');
    }

    private function loadTemplate($name) {}
}

// Safe: self-halting wrapper defined in the SAME class as its bare caller —
// checkNonce() unconditionally exit()s inside the nonce-failure branch, so
// it never returns control on failure; the caller does not need to consult
// a return value. Confirmed FP: shortpixel-image-optimiser 6.5.5
// AjaxController::checkNonce() (distinct from the cross-class checkPost()
// shape above, which genuinely returns false and IS vulnerable).
class Self_Halting_Ajax_Controller {
    public function ajax_processQueue() {
        // ok: claude.php.wordpress.access.custom-nonce-wrapper-result-ignored
        $this->checkNonce('processing');
        $this->doProcess();
    }

    protected function checkNonce($action) {
        if (! wp_verify_nonce($_POST['nonce'], $action)) {
            $json = new \stdClass;
            $json->status = false;
            $this->send($json);
            exit();
        }
    }

    private function doProcess() {}
    private function send($json) {}
}
