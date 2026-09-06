<?php
/**
 * Test cases for request-param-sets-debug-flag.yaml
 * Rule id: claude.php.wordpress.info-disclosure.request-param-sets-debug-flag
 */

global $wpdb;

// TP: REQUEST param enables debug mode — no capability check (YARPP pattern)
class Plugin_Core {
    public $debug = false;
    public function __construct() {
        if ( isset( $_REQUEST['yarpp_debug'] ) ) {
            // ruleid: claude.php.wordpress.info-disclosure.request-param-sets-debug-flag
            $this->debug = true;
        }
    }
}

// TP: GET param enables verbose mode — no capability check
class My_Plugin_Logger {
    public $verbose = false;
    public function init() {
        if ( isset( $_GET['mp_verbose'] ) ) {
            // ruleid: claude.php.wordpress.info-disclosure.request-param-sets-debug-flag
            $this->verbose = true;
        }
    }
}

// TP: direct assignment form — REQUEST enables debug
class Another_Plugin {
    public $debug;
    public function setup() {
        // ruleid: claude.php.wordpress.info-disclosure.request-param-sets-debug-flag
        $this->debug = isset( $_REQUEST['plugin_debug'] );
    }
}

// TP: !empty() form
class Yet_Another {
    public $trace = false;
    public function boot() {
        // ruleid: claude.php.wordpress.info-disclosure.request-param-sets-debug-flag
        $this->trace = ! empty( $_REQUEST['trace'] );
    }
}

// OK: capability check guards the flag via combined && condition
// The if condition is not a bare isset(), so pattern-inside does not match.
class Safe_Plugin_A {
    public $debug = false;
    public function __construct() {
        if ( current_user_can('manage_options') && isset( $_REQUEST['sp_debug'] ) ) {
            // ok: claude.php.wordpress.info-disclosure.request-param-sets-debug-flag
            $this->debug = true;
        }
    }
}

// OK: property name does not match the debug-flag regex
class Safe_Plugin_B {
    public $enabled = false;
    public function init() {
        if ( isset( $_REQUEST['sp_enabled'] ) ) {
            // ok: claude.php.wordpress.info-disclosure.request-param-sets-debug-flag
            $this->enabled = true;
        }
    }
}
