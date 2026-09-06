<?php

// =====================================================
// VULNERABLE PATTERNS (should trigger rule)
// =====================================================

$callback = $_POST['callback'];
$data = array('test');
// ruleid: claude.php.wordpress.rce.callback-function-user-input
array_map($callback, $data);

$func = $_GET['sort_function'];
$items = array(3, 1, 2);
// ruleid: claude.php.wordpress.rce.callback-function-user-input
usort($items, $func);

$handler = $_REQUEST['handler'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
array_walk($items, $handler);

$filter_func = $_POST['filter'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
array_filter($items, $filter_func);

$walker = $_GET['walker'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
array_walk_recursive($nested_array, $walker);

$sorter = $_POST['sort'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
uasort($assoc_array, $sorter);

$key_sorter = $_REQUEST['key_sort'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
uksort($assoc_array, $key_sorter);

$regex_callback = $_POST['regex_handler'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
preg_replace_callback('/pattern/', $regex_callback, $subject);

$output_handler = $_GET['output_handler'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
ob_start($output_handler);

$shutdown_func = $_POST['shutdown'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
register_shutdown_function($shutdown_func);

$autoloader = $_REQUEST['autoloader'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
spl_autoload_register($autoloader);

$error_handler = $_POST['error_handler'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
set_error_handler($error_handler);

$exception_handler = $_GET['exc_handler'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
set_exception_handler($exception_handler);

$reducer = $_POST['reducer'];
// ruleid: claude.php.wordpress.rce.callback-function-user-input
array_reduce($items, $reducer, 0);

// Taint through wp_unslash propagator
$raw = wp_unslash($_POST['callback']);
// ruleid: claude.php.wordpress.rce.callback-function-user-input
array_map($raw, $data);

// Taint through stripslashes_deep propagator
$cleaned = stripslashes_deep($_POST['func']);
// ruleid: claude.php.wordpress.rce.callback-function-user-input
usort($items, $cleaned);

// Taint through wp_parse_args propagator
$args = wp_parse_args($_POST['args'], $defaults);
// ruleid: claude.php.wordpress.rce.callback-function-user-input
array_map($args['callback'], $data);

// =====================================================
// SAFE PATTERNS (should NOT trigger rule)
// =====================================================

// ok: claude.php.wordpress.rce.callback-function-user-input
array_map('intval', $_POST['values']);

// ok: claude.php.wordpress.rce.callback-function-user-input
array_filter($items, 'is_numeric');

// ok: claude.php.wordpress.rce.callback-function-user-input
usort($items, array($this, 'compare_items'));

// ok: claude.php.wordpress.rce.callback-function-user-input
array_map(array('MyClass', 'sanitize'), $data);

// ok: claude.php.wordpress.rce.callback-function-user-input
array_walk($items, function($item) { echo $item; });

$callback = intval($_POST['callback']);
// ok: claude.php.wordpress.rce.callback-function-user-input
array_map($callback, $data);

$func = sanitize_key($_POST['func']);
// ok: claude.php.wordpress.rce.callback-function-user-input
usort($items, $func);

$handler = absint($_REQUEST['handler']);
// ok: claude.php.wordpress.rce.callback-function-user-input
array_walk($items, $handler);

// ok: claude.php.wordpress.rce.callback-function-user-input
$callback = 'sanitize_text_field';
array_map($callback, $data);
