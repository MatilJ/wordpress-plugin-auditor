<?php
// ruleid: claude.php.wordpress.lfi.include-user-input
include $_GET['page'];

$tpl = $_POST['template'];
// ruleid: claude.php.wordpress.lfi.include-user-input
require "templates/" . $tpl . ".php";

$mod = $_REQUEST['module'];
// ruleid: claude.php.wordpress.lfi.include-user-input
include_once(WP_PLUGIN_DIR . "/modules/" . $mod);

$name = $_COOKIE['theme'];
// ruleid: claude.php.wordpress.lfi.include-user-input
require_once $name;

// ok: claude.php.wordpress.lfi.include-user-input
include dirname(__FILE__) . '/helper.php';

// ok: claude.php.wordpress.lfi.include-user-input
$safe = basename($_GET['page']);
include "templates/" . $safe;

// ok: claude.php.wordpress.lfi.include-user-input
$name = sanitize_file_name($_POST['template']);
require_once WP_PLUGIN_DIR . "/tpl/" . $name . ".php";

// ok: claude.php.wordpress.lfi.include-user-input
// Static factory/constructor method call, not a file-path selector handoff —
// confirmed FP source: ultimate-addons-for-contact-form-7 3.5.47
// inc/class-setup-wizard.php:147 (WPCF7_ContactForm::get_template() returns
// a new form object; it does not include/require a file).
$form_name = $_POST['form_name'];
$contact_form = WPCF7_ContactForm::get_template( array( 'title' => $form_name ) );
