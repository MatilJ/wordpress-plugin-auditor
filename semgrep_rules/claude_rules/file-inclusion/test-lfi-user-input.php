<?php
// Test file for lfi include-user-input rule — sanitizer additions

function bad_include() {
    $file = $_GET['page'];
    // ruleid: claude.php.wordpress.lfi.include-user-input
    include $file;
}

function good_include_sanitize_key() {
    $file = sanitize_key($_GET['page']);
    // ok: claude.php.wordpress.lfi.include-user-input
    include '/templates/' . $file . '.php';
}

function good_include_realpath() {
    $file = realpath($_GET['page']);
    // ok: claude.php.wordpress.lfi.include-user-input
    include $file;
}

function good_include_intval() {
    $id = intval($_GET['id']);
    // ok: claude.php.wordpress.lfi.include-user-input
    include '/templates/template_' . $id . '.php';
}

function good_include_basename() {
    $file = basename($_GET['page']);
    // ok: claude.php.wordpress.lfi.include-user-input
    include '/templates/' . $file;
}

class Bad_Wizard_Step_Loader {
    private $steps = array('welcome', 'widgets', 'congrats');
    private $current_step = 'welcome';

    public function wizard_page() {
        $this->current_step = isset($_GET['step']) ? sanitize_text_field($_GET['step']) : 'welcome';
        // ruleid: claude.php.wordpress.lfi.include-user-input
        $this->load_step_template($this->current_step);
    }

    private function load_step_template($step) {
        $template_file = TOPPPA_INC_PATH . 'setup-wizard/templates/wizard-' . $step . '.php';
        if (file_exists($template_file)) {
            include $template_file;
        }
    }
}

class Good_Wizard_Step_Loader {
    private $steps = array('welcome', 'widgets', 'congrats');
    private $current_step = 'welcome';

    public function wizard_page() {
        $requested_step = isset($_GET['step']) ? sanitize_text_field($_GET['step']) : 'welcome';
        $this->current_step = in_array($requested_step, $this->steps, true) ? $requested_step : 'welcome';
        // ok: claude.php.wordpress.lfi.include-user-input
        $this->load_step_template($this->current_step);
    }

    private function load_step_template($step) {
        $template_file = TOPPPA_INC_PATH . 'setup-wizard/templates/wizard-' . $step . '.php';
        if (file_exists($template_file)) {
            include $template_file;
        }
    }
}

class Good_Db_Read_Report_Loader {
    public function get_report_template($report_id) {
        $report_id = absint($report_id);
        global $wpdb;
        // ok: claude.php.wordpress.lfi.include-user-input
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}reports WHERE id = %d", $report_id));
    }
}

// Free-function template wrapper shape (CVE-2025-7634 class): the
// request-derived selector is read from an AJAX request-params array
// (not a raw superglobal), cleaned only with a text sanitizer, and handed
// straight to a plugin-prefixed free function matching the loader naming
// convention.
class Bad_Ajax_Mode_Loader {
    protected function process_request() {
        $post = $this->request->get_params();
        $view_mode = sanitize_text_field(wp_unslash($post['mode']));
        // ruleid: claude.php.wordpress.lfi.include-user-input
        acme_get_template('content-' . $view_mode . '.php', array());
    }
}

// Same free-function shape but via a direct $_REQUEST read, exercising
// the sink with a "render_" prefix/"view" noun combination.
function bad_render_view_dispatch() {
    $view = sanitize_text_field($_REQUEST['view']);
    // ruleid: claude.php.wordpress.lfi.include-user-input
    acme_theme_render_view('content-' . $view . '.php', array());
}

class Good_Ajax_Mode_Loader {
    private $allowed_modes = array('grid', 'list');

    protected function process_request() {
        $post = $this->request->get_params();
        $view_mode = sanitize_text_field(wp_unslash($post['mode']));
        $view_mode = in_array($view_mode, $this->allowed_modes, true) ? $view_mode : 'list';
        // ok: claude.php.wordpress.lfi.include-user-input
        acme_get_template('content-' . $view_mode . '.php', array());
    }
}

function good_render_view_dispatch() {
    $view = sanitize_file_name($_REQUEST['view']);
    // ok: claude.php.wordpress.lfi.include-user-input
    acme_theme_render_view('content-' . $view . '.php', array());
}
