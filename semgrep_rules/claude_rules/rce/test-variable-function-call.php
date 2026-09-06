<?php

// =====================================================
// VULNERABLE PATTERNS (should trigger rule)
// =====================================================

$func = $_POST['function_name'];
// ruleid: claude.php.wordpress.rce.variable-function-call-user-input
$func('argument');

$callback = $_GET['callback'];
// ruleid: claude.php.wordpress.rce.variable-function-call-user-input
$result = $callback($data, $args);

$action = $_REQUEST['action'];
// ruleid: claude.php.wordpress.rce.variable-function-call-user-input
$action();

$handler = wp_unslash($_POST['handler']);
// ruleid: claude.php.wordpress.rce.variable-function-call-user-input
$handler($input);

$processor = stripslashes_deep($_POST['processor']);
// ruleid: claude.php.wordpress.rce.variable-function-call-user-input
$processor($data);

// Taint through wp_parse_args
$settings = wp_parse_args($_POST['settings'], $defaults);
$fn = $settings['callback'];
// ruleid: claude.php.wordpress.rce.variable-function-call-user-input
$fn($value);

// Array subscript with user-controlled key selecting the callable
$key = $_POST['key'];
$fn = $callbacks[$key];
// ruleid: claude.php.wordpress.rce.variable-function-call-user-input
$fn($data);

// =====================================================
// SAFE PATTERNS (should NOT trigger rule)
// =====================================================

// Hardcoded function name — developer-controlled
$func = 'sanitize_text_field';
// ok: claude.php.wordpress.rce.variable-function-call-user-input
$func($input);

// Sanitized with intval — cannot be a valid callable
$func = intval($_POST['function_name']);
// ok: claude.php.wordpress.rce.variable-function-call-user-input
$func('argument');

// Sanitized with sanitize_key
$callback = sanitize_key($_GET['callback']);
// ok: claude.php.wordpress.rce.variable-function-call-user-input
$callback($data);

// Sanitized with absint
$handler = absint($_POST['handler']);
// ok: claude.php.wordpress.rce.variable-function-call-user-input
$handler($input);

// ok: claude.php.wordpress.rce.variable-function-call-user-input
// Method call on object — not a variable function
$this->process_data($input);

// ok: claude.php.wordpress.rce.variable-function-call-user-input
// Static method call — not a variable function
MyClass::process($input);

// Bounded WP_List_Table-style row/bulk-action dispatch idiom: method_exists()
// gates the identical dynamic callee in an enclosing if-condition, restricting
// invocation to methods the class already defines on $this — not an arbitrary
// PHP function/system() call.
class RowActionListTable {
    public function process_row_actions() {
        $action = sanitize_text_field( wp_unslash( $_REQUEST['row_action'] ) );
        $row_id = sanitize_text_field( wp_unslash( $_REQUEST['row_id'] ) );
        $nonce  = sanitize_text_field( wp_unslash( $_REQUEST['nonce'] ) );
        $method = 'row_action_' . $action;
        if ( wp_verify_nonce( $nonce, $action . '::' . $row_id ) && method_exists( $this, $method ) ) {
            // ok: claude.php.wordpress.rce.variable-function-call-user-input
            $this->$method( sanitize_text_field( wp_unslash( $row_id ) ) );
        }
    }

    protected function row_action_delete( $row_id ) {
        // ...
    }
}

// Static method call on an array-indexed class expression: the callee is
// selected from a fixed, developer-registered array by key, and the method
// name itself (getTitle) stays hardcoded — a dynamic-class-selection shape
// (CWE-470), not a variable directly holding an invocable function name.
$slug = $_POST['slug'];
$plugins = apply_filters('registered_plugins', array());
// ok: claude.php.wordpress.rce.variable-function-call-user-input
$title = $plugins[$slug]::getTitle();
