<?php
// Test cases for claude.php.wordpress.access-control.form-validator-gated-privileged-write-no-capability
//
// Seeded from CVE-2025-15403 (RegistrationMagic <= 6.0.7.1, Unauthenticated
// Privilege Escalation via admin_order): RM_Options_Controller::admin_menu()
// gated a role/menu-accessibility settings write ONLY by
// $this->mv_handler->validateForm('options_admin_menu') — a form-builder
// field-shape validator, not a capability check — before saving an
// attacker-controlled per-role menu-accessibility array. The 6.0.7.2 patch
// added `&& current_user_can('manage_options')` to the same condition.

class RM_Options_Controller_Vulnerable
{
    public function admin_menu($model, $service, $request, $params)
    {
        if ($this->mv_handler->validateForm("options_admin_menu")) {
            if ($request->req['restore'] == 'false') {
                $options = array();
                $menu_order = array();
                $menus = explode(",", (string) $request->req['order']);
                $roles = wp_roles()->roles;
                foreach ($menus as $slug) {
                    $accessible = array('administrator');
                    foreach ($roles as $role_slug => $role) {
                        if ($role_slug != 'administrator') {
                            if (isset($request->req[$slug . "_" . $role['name']])) {
                                array_push($accessible, $role_slug);
                            }
                        }
                    }
                    array_push($menu_order, array($slug, $accessible));
                }
                $options['admin_order'] = $menu_order;
                $service->set_model($model);
                // ruleid: claude.php.wordpress.access-control.form-validator-gated-privileged-write-no-capability
                $service->save_options($options);
            } else {
                $service->set_model($model);
                $service->reset_option('admin_order');
            }
        }
    }
}

// A different plugin's naming convention for the exact same shape: a
// "processForm" validator gating a settings-service write, no capability
// check anywhere in the function. Proves the rule generalizes beyond the
// seeding plugin's literal method name ("validateForm").
class Acme_Permissions_Controller
{
    public function save_role_permissions($request)
    {
        if ($this->form->processForm("acme_role_permissions")) {
            $perms = array();
            foreach (wp_roles()->roles as $role_slug => $role) {
                if (isset($request['perm_' . $role_slug])) {
                    $perms[$role_slug] = sanitize_text_field($request['perm_' . $role_slug]);
                }
            }
            // ruleid: claude.php.wordpress.access-control.form-validator-gated-privileged-write-no-capability
            $this->settings_service->update_settings($perms);
        }
    }
}

class RM_Options_Controller_Patched
{
    public function admin_menu($model, $service, $request, $params)
    {
        // 6.0.7.2 fix: current_user_can() added directly into the same
        // condition as the form validator.
        if ($this->mv_handler->validateForm("options_admin_menu") && current_user_can('manage_options')) {
            if ($request->req['restore'] == 'false') {
                $options = array();
                $options['admin_order'] = array();
                $service->set_model($model);
                // ok: claude.php.wordpress.access-control.form-validator-gated-privileged-write-no-capability
                $service->save_options($options);
            } else {
                $service->set_model($model);
                $service->reset_option('admin_order');
            }
        }
    }
}

class RM_Options_Controller_CapInFunctionBody
{
    public function admin_menu($model, $service, $request, $params)
    {
        if ($this->mv_handler->validateForm("options_admin_menu")) {
            if (!current_user_can('manage_options')) {
                wp_die('Forbidden');
            }
            $options = array('admin_order' => $request->req['order']);
            $service->set_model($model);
            // ok: claude.php.wordpress.access-control.form-validator-gated-privileged-write-no-capability
            $service->save_options($options);
        }
    }
}

class RM_Options_Controller_ReadOnly
{
    // A read-only settings view gated the same way is not this rule's sink
    // shape at all: get_options()/get_var() do not match the
    // save/update/set/persist/write verb-prefix naming regex, so this is
    // simply not matched — no write, nothing to authorize.
    public function admin_menu_view($model, $service, $request, $params)
    {
        global $wpdb;
        if ($this->mv_handler->validateForm("options_admin_menu")) {
            $data = $service->get_options();
            // ok: claude.php.wordpress.access-control.form-validator-gated-privileged-write-no-capability
            $count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->options}");
            return $data;
        }
    }
}
