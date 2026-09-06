<?php
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func($_GET['fn']);

$fn = $_POST['fn'];
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func($fn, 'arg');

$action = $_REQUEST['action'];
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func_array($action, [1, 2, 3]);

// ok: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func('strtolower', $text);

// User input only in args — callable is hard-coded, not a dynamic-callable issue.
// ok: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func('my_handler', $_GET['input']);

// Registry-dispatch pattern: user controls the lookup key, not the callable value.
// $this->ajax_actions[$key]['callback'] retrieves a developer-registered callback;
// the ['callback'] subscript ensures the retrieved value came from plugin internals.
// ok: claude.php.wordpress.rce.dynamic-callable-user-input
$action = $_POST['action'];
call_user_func( $this->ajax_actions[ $action ]['callback'], $data, $this );

// ok: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func_array( $this->handlers[ $_GET['fn'] ]['callback'], [$arg1, $arg2] );

// Without ['callback'] subscript the user directly controls the callable — still a TP.
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func( $this->ajax_actions[ $_POST['action'] ], $data );

// TP: taint flows through wp_parse_args() — the propagator lets Semgrep track $_POST
// through the merge operation and into the callable argument.
// Confirmed miss pattern: acf-extended 0.9.1.1 render_form_ajax() in module-form-front.php.
$options = wp_parse_args( $_POST, array( 'callable' => false ) );
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func( $options['callable'], 'arg1' );

// TP: acf_parse_args() propagator — ACF's arg-merge helper.
$args = acf_parse_args( $_POST, array( 'callback' => '' ) );
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func_array( $args['callback'], array( $args ) );

// TP: stripslashes_deep() propagator — common WP preprocessing step that does NOT
// sanitize callable characters. Confirmed miss: kali-forms 2.4.9 form_process().
$data = stripslashes_deep( $_POST['data'] );
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func( $data['fn'], 'arg' );

// TP: wp_unslash() propagator — WP's single-value unslash wrapper.
$action = wp_unslash( $_POST['action'] );
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func( $action );

// Registry dispatch with named sub-key 'sanitize' (not 'callback') — user controls
// the lookup key but the callable is a developer-registered sanitizer function.
// Confirmed FP source: kali-forms 2.4.9 class-meta-save.php:172.
// ok: claude.php.wordpress.rce.dynamic-callable-user-input
$key = $_POST['field'];
call_user_func( $this->fields[ $key ]['sanitize'], $value );

// Registry dispatch with 'handler' sub-key — same two-level structure, different name.
// ok: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func( $this->hooks[ $_POST['type'] ]['handler'], $data );

// Single-level property access — user directly selects the callable slot, not a registry
// entry sub-key. Still a TP: no named developer-written sub-key insulates the callable.
// ruleid: claude.php.wordpress.rce.dynamic-callable-user-input
call_user_func( $this->callbacks[ $_POST['action'] ], $data );
