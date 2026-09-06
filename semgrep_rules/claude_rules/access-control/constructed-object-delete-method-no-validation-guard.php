<?php
// Test file: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard

// ── Vulnerable patterns ────────────────────────────────────────────────────────

// VULNERABLE: real pre-fix shape (CVE-2026-59542, kali-forms <= 2.4.18) — the
// AJAX handler pulls formId/submissionId straight out of $_POST, builds a
// helper object from them with no validation, and calls its destructive
// method. The actual wp_delete_post() call lives inside Action_Helper's own
// delete_submission() method, in a different class entirely — invisible to
// this rule, which only needs the construction + destructive call here.
function vuln_delete_submission() {
    $args = stripslashes_deep($_POST['args']);
    $actionHelper = new Action_Helper($args['formId'], $args['submissionId']);
    $actionHelper->add_hash($args['hash']);
    // ruleid: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    wp_die(wp_json_encode($actionHelper->delete_submission()));
}

// VULNERABLE: generic manager/helper idiom, $_GET id, no validation
function vuln_delete_resource() {
    $id = $_GET['resource_id'];
    $manager = new Resource_Manager($id);
    // ruleid: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    $manager->deleteResource();
}

// VULNERABLE: REST route, json params, destroy() method
function vuln_rest_destroy($request) {
    $params = $request->get_json_params();
    $entry = new Entry_Handler($params['formId'], $params['entryId']);
    // ruleid: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    $entry->destroyEntry();
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// SAFE: real post-fix shape (kali-forms 2.4.19) — a static validator call is
// made first, its result checked via is_wp_error(), before construction.
function safe_delete_submission_validated() {
    $args = stripslashes_deep($_POST['args']);
    $validated = Action_Helper::validate_pair($args['formId'], $args['submissionId']);
    if (is_wp_error($validated)) {
        wp_die('Something went wrong');
    }
    $actionHelper = new Action_Helper($args['formId'], $args['submissionId']);
    $actionHelper->add_hash($args['hash']);
    // ok: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    wp_die(wp_json_encode($actionHelper->delete_submission()));
}

// SAFE: bare (unassigned) validator call, same idiom, different phrasing
function safe_delete_resource_checked() {
    $id = $_GET['resource_id'];
    if (!Resource_Manager::verify_ownership($id)) {
        wp_die('Denied');
    }
    $manager = new Resource_Manager($id);
    // ok: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    $manager->deleteResource();
}

// SAFE: id sourced from a DB query — taint broken before construction
function safe_db_sourced_delete() {
    global $wpdb;
    $id = $wpdb->get_var("SELECT ID FROM {$wpdb->posts} WHERE post_status = 'auto-draft' LIMIT 1");
    $manager = new Resource_Manager($id);
    // ok: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    $manager->deleteResource();
}

// SAFE: admin-only gate before construction/deletion
function safe_admin_only_delete() {
    if (!current_user_can('manage_options')) {
        wp_die('Denied');
    }
    $id = $_POST['resource_id'];
    $manager = new Resource_Manager($id);
    // ok: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    $manager->deleteResource();
}

// SAFE: hardcoded id, no request data involved
function safe_hardcoded_delete() {
    $manager = new Resource_Manager(42);
    // ok: claude.php.wordpress.access-control.constructed-object-delete-method-no-validation-guard
    $manager->deleteResource();
}
