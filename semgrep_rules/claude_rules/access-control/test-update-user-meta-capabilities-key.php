<?php

// ---- TRUE POSITIVES ----

function tp_direct_wp_capabilities($uid) {
    // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, 'wp_capabilities', array('administrator' => true));
}

function tp_double_quoted($uid) {
    // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, "wp_capabilities", array('editor' => true));
}

// Dynamic variables — Semgrep cannot evaluate runtime string values.
// These are real-world patterns but require manual audit. Documented here
// for awareness but not annotated as ruleid since the rule is pattern-based.
function fn_multisite_prefix($uid, $prefix) {
    $key = $prefix . 'capabilities';
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, $key, array('administrator' => true));
}

function fn_wpdb_prefix_capabilities($uid) {
    global $wpdb;
    $cap_key = $wpdb->prefix . 'capabilities';
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, $cap_key, $caps);
}

// Unauthenticated role/permission assignment via a REST-style handler that
// takes both the target user ID and the role list from the request body,
// with zero authorization call anywhere in the function (CWE-266).
class Unauth_Role_Update_Controller {
    public function userRoleUpdate($request) {
        $id = $request->get_param('id');
        $roles = json_decode($request->get_body_params()['roles'], true);
        // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($id, 'custom_capabilities', $roles);
        $this->addUserRole($id, $roles);
    }

    private function addUserRole($userId, $roles) {}
}

// Foreach-loop-key idiom: the array KEY of a request/JSON-body-derived
// foreach becomes the meta_key argument directly, gated only by a check
// on a companion VALUE field (the label) rather than the key itself.
function tp_foreach_key_from_json_body($user, $data) {
    $default_fields = array();
    foreach ($data['profile_default_fields_for_register'] as $index => $field) {
        if (isset($field['value']) && in_array($field['label'], array_column($default_fields, 'label'), true)) {
            // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
            update_user_meta($user, $index, $field['value']);
        }
    }
}

function tp_foreach_key_from_post($user_id) {
    foreach ($_POST['fields'] as $key => $value) {
        // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($user_id, $key, $value);
    }
}

// ---- FALSE POSITIVES ----

function ok_normal_meta($uid) {
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, 'first_name', 'John');
}

function ok_profile_setting($uid) {
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, 'profile_photo', 'avatar.jpg');
}

function ok_description($uid) {
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, 'description', 'Bio text');
}

// Fixed sibling of Unauth_Role_Update_Controller::userRoleUpdate() above —
// a permission_check() call gates the same role/id inputs before the write.
class Fixed_Role_Update_Controller {
    public function userRoleUpdate($request) {
        $permissionCheck = $this->permission_check($request, array('manage-roles-permissions'));
        if (is_wp_error($permissionCheck)) {
            return $permissionCheck;
        }
        $id = $request->get_param('id');
        $roles = json_decode($request->get_body_params()['roles'], true);
        // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($id, 'custom_capabilities', $roles);
    }

    public function permission_check($request, $perms = array()) {
        return true;
    }
}

function ok_current_user_can_guard($uid, $roles) {
    if (!current_user_can('promote_users')) {
        return;
    }
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, 'lazytasks_capabilities', $roles);
}

function ok_user_can_guard($uid, $roles) {
    if (!user_can(get_current_user_id(), 'promote_users')) {
        return;
    }
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($uid, 'wp_role_permissions', $roles);
}

// Fixed sibling of tp_foreach_key_from_json_body() above — the KEY itself
// (not a companion value field) is checked against a server-side allow-list.
function ok_foreach_key_allowlisted($user, $data) {
    $default_fields = array('username' => true, 'phone' => true);
    foreach ($data['profile_default_fields_for_register'] as $key => $field) {
        if (isset($field['value']) && !empty($default_fields[$key])) {
            // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
            update_user_meta($user, $key, $field['value']);
        }
    }
}

// Loop source is a local, non-request-derived array — not a privilege risk.
function ok_foreach_key_local_array($user_id) {
    $profile_defaults = array('bio' => '', 'location' => '');
    foreach ($profile_defaults as $key => $value) {
        // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($user_id, $key, $value);
    }
}

// ---- Derived-key idiom (CVE-2025-15027 class: JAY Login & Register <=
// 2.6.03 jay_login_register_ajax_create_final_user()) ----
// The meta key is NOT the raw loop key; it is a separate variable built via
// substr()/str_replace() prefix-stripping then sanitize_key(), with no
// allow-list check on the derived variable before the write.

function tp_derived_key_prefix_strip($user_id) {
    foreach ($_POST as $post_key => $post_value) {
        if (strpos($post_key, 'meta_') === 0) {
            $real_meta_key = substr($post_key, 5);
            $real_meta_key = str_replace(' ', '_', $real_meta_key);
            $real_meta_key = sanitize_key($real_meta_key);
            // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
            update_user_meta($user_id, $real_meta_key, sanitize_text_field($post_value));
        }
    }
}

function tp_derived_key_no_prefix_strip($user_id, $submitted_fields) {
    foreach ($submitted_fields as $field_name => $field_value) {
        $meta_key = sanitize_key($field_name);
        // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($user_id, $meta_key, sanitize_text_field($field_value));
    }
}

// Fixed sibling — three-layer guard (blacklist, wp_-prefix block, then a
// positive allow-list membership check) on the SAME derived variable before
// the write, mirroring the real 2.6.04 patch.
function ok_derived_key_allowlisted($user_id, $allowed_custom_fields) {
    $disallowed_meta_keys = array('wp_capabilities', 'wp_user_level');
    foreach ($_POST as $post_key => $post_value) {
        if (strpos($post_key, 'meta_') !== 0) continue;
        $real_meta_key = substr($post_key, 5);
        $real_meta_key = sanitize_key($real_meta_key);

        if (in_array($real_meta_key, $disallowed_meta_keys, true)) {
            continue;
        }
        if (strpos($real_meta_key, 'wp_') === 0) {
            continue;
        }
        if (!in_array($real_meta_key, $allowed_custom_fields, true)) {
            continue;
        }
        // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($user_id, $real_meta_key, sanitize_text_field($post_value));
    }
}

// Loop source is a local, non-request-derived array — not a privilege risk,
// even though the derived-key idiom (sanitize_key inside the loop) matches.
function ok_derived_key_local_array($user_id) {
    $profile_defaults = array('bio' => '', 'location' => '');
    foreach ($profile_defaults as $field_name => $field_value) {
        $meta_key = sanitize_key($field_name);
        // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($user_id, $meta_key, $field_value);
    }
}

// Blocklist-only-unset idiom (CVE-2024-9636 class: Post Grid and Gutenberg
// Blocks <= 2.3.3 tutorRegisterInstructor branch of
// form_wrap_process_registerForm()). A single privileged key is unset()
// from a request-derived *_meta array, then every remaining key/value pair
// is written straight to user meta with no positive allow-list check.
function tp_foreach_key_from_user_meta_request($request) {
    $new_user_id = 5;
    $user_meta = $request->get_param('user_meta');
    global $wpdb;
    unset($user_meta[$wpdb->prefix . 'capabilities']);
    if (!empty($user_meta)) {
        foreach ($user_meta as $metaKey => $metavalue) {
            // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
            update_user_meta($new_user_id, $metaKey, $metavalue);
        }
    }
}

// Fixed sibling — a positive allow-list check on the same loop key (the
// registerUser branch that shipped alongside the vulnerable
// tutorRegisterInstructor branch in the same file).
function ok_foreach_key_from_user_meta_allowlisted($request, $allowedUserMetaKeys) {
    $new_user_id = 5;
    $user_meta = $request->get_param('user_meta');
    if (!empty($user_meta)) {
        foreach ($user_meta as $metaKey => $metavalue) {
            if (in_array($metaKey, $allowedUserMetaKeys)) {
                // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
                update_user_meta($new_user_id, $metaKey, $metavalue);
            }
        }
    }
}

// Wrapper-indirection idiom (CVE-2025-4334 class: Simple User Registration
// <= 6.2 WPR_Register::set_meta(), called from an unrestricted foreach over
// $_POST-derived registration fields elsewhere in the class). The sink call
// is one method-call hop away from the request-driven loop, inside a thin
// two-arg setter that forwards both parameters straight to
// update_user_meta() with no key gate of its own.
class WPR_Register_Like {
    function setting_user_meta() {
        foreach ($this->singup_data as $type => $fields) {
            if ($type == 'wp_field') continue;
            foreach ($fields as $key => $value) {
                $this->set_meta($key, $value);
            }
        }
    }

    function set_meta($key, $value) {
        // ruleid: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($this->userid, $key, $value);
    }
}

// Fixed sibling of WPR_Register_Like::set_meta() above — mirrors the real
// 6.3 patch: a deny-list bail-out added INSIDE the low-level setter itself
// (the chokepoint the official fix used), not at each call site.
class WPR_Register_Like_Fixed {
    function setting_user_meta() {
        foreach ($this->singup_data as $type => $fields) {
            if ($type == 'wp_field') continue;
            foreach ($fields as $key => $value) {
                $this->set_meta($key, $value);
            }
        }
    }

    function set_meta($key, $value) {
        $dangerous_keys = array('wp_capabilities', 'wp_user_level');
        if (in_array($key, $dangerous_keys)) {
            return false;
        }
        // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
        update_user_meta($this->userid, $key, $value);
    }
}

function ok_wrapper_setter_allowlist_guard($id, $key, $value, $allowed) {
    if (!in_array($key, $allowed)) {
        return;
    }
    // ok: claude.php.wordpress.access.update-user-meta-capabilities-key
    update_user_meta($id, $key, $value);
}
