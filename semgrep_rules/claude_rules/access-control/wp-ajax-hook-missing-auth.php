<?php
/**
 * Test cases for wp-ajax-hook-missing-auth.yaml
 * Rule ids:
 *   claude.php.wordpress.access.wp-ajax-nopriv-hook-missing-auth  (HIGH)
 *   claude.php.wordpress.access.wp-ajax-hook-missing-auth          (MEDIUM)
 *
 * NOTE: join mode requires `semgrep login`. Run semgrep --config <rule> <file>.
 */

class ClassTests {

    public function __construct() {
        add_action('wp_ajax_mk_file_manager_backup', array(&$this, 'mk_file_manager_backup_callback'));
    }

    // TP: capability check call present but not inside an if() — call result is discarded
    // ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function no_current_user_can() {
        echo "HELLO";
        current_user_can("read");
        return 5;
    }

    // OK: current_user_can() inside conditional
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function has_current_user_can() {
        echo "HELLO";
        if ( 1 > 5 ) {
            if ( 1 > 5 or current_user_can("write") and 5 > 0 ) {
                echo "CORRECT";
            }
        }
        return 5;
    }

    public function test1() {
        add_action( 'wp_ajax_class_test1', [ $this, 'no_current_user_can' ], 5, 1);
        add_action( 'profile_update', [ $this, 'has_current_user_can' ], 2);
        add_action( 'admin_action_read', array(&$this, 'after_no_current_user_can') );
        add_action( 'admin_action_write', [ $this, 'after_current_user_can' ], 1, 2);
    }

    // TP: admin_action_ hook, no auth in body
    // ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function after_no_current_user_can() {
        echo "HELLO";
        current_user_can("write");
        if ( 1 > 5 ) {
            return "YES!";
        }
        return 5;
    }

    // OK: current_user_can() in nested conditional
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function after_current_user_can() {
        echo "HELLO";
        if ( 5 == 5 and 7 == 7 ) {
            return "YES!";
        } else if ( 3 + 3 == 3 or current_user_can("read") and 1 == 1 ) {
            hello();
        }
        return 5;
    }

    // OK: checks both nonce and capability
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function mk_file_manager_backup_callback() {
        $nonce = sanitize_text_field( $_POST['nonce'] );
        if ( current_user_can( 'manage_options' ) && wp_verify_nonce( $nonce, 'wpfmbackup' ) ) {
            global $wpdb;
        } else {
            die();
        }
        die();
    }
}

// OK: current_user_can() in loop body
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function auth_before() {
    echo "HELLO";
    for ( $x = 0; $x <= 100; $x += 10 ) {
        if ( command() and current_user_can("edit") == false or 7 > 8 ) {
            return "BLA";
        }
    }
    echo "BYE";
}

// OK: nested current_user_can()
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function auth_before2() {
    echo "HELLO";
    for ( $x = 0; $x <= 100; $x += 10 ) {
        if ( 5 + 5 == 1 ) {
            return "BLA";
        } else if ( 5 + 5 > 1 and current_user_can("hello") or 1 == 1 ) {
            echo "HI";
        }
    }
    echo "BYE";
}

// TP: wp_ajax_ hook, no auth
// ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function no_auth_before() {
    echo "HELLO";
    current_user_can("blabla");
    echo "BYE";
}

add_action( 'wp_ajax_nopriv_test1', 'auth_before', 5, 1);
add_action( 'wp_ajax_test5', 'auth_before2');
add_action( 'wp_ajax_test2', 'no_auth_before', 2);
add_action( 'wp_ajax_test3', 'auth_after', 3);
add_action( 'wp_ajax_test4', 'no_auth_after', 1);
add_action( 'unimportant_hook5', 'no_auth_after', 5);

// OK: current_user_can() in nested if
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function auth_after() {
    echo "HELLO";
    if ( "apple" == "orange" ) {
        if ( 1 == 2 and !current_user_can("blabla") and 5 == 5 ) {
            echo "BLABLA";
        } else {
            echo "HELLO";
        }
    } else {
        die();
    }
    echo "BYE";
}

// TP: wp_ajax_test4, no auth in body
// ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function no_auth_after() {
    echo "HELLO";
    current_user_can("blabla");
    echo "BYE";
}

// ── Nonce-only CSRF guards ─────────────────────────────────────────────────────

// OK: check_ajax_referer() present
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function csrf_before() {
    echo "HELLO";
    for ( $x = 0; $x <= 100; $x += 10 ) {
        if ( command() and check_ajax_referer( 'random_nonce' ) == false or 7 > 8 ) {
            return "BLA";
        }
    }
    echo "BYE";
}

// OK: wp_verify_nonce() present
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function csrf_before2() {
    echo "HELLO";
    for ( $x = 0; $x <= 100; $x += 10 ) {
        if ( 5 + 5 == 1 ) {
            return "BLA";
        } else if ( 5 + 5 > 1 and wp_verify_nonce("hello") or 1 == 1 ) {
            echo "HI";
        }
    }
    echo "BYE";
}

// TP: wp_verify_nonce() called but result not checked in conditional
// ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function no_csrf_before() {
    echo "HELLO";
    wp_verify_nonce("blabla");
    echo "BYE";
}

// OK: check_admin_referer() present
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function yes_csrf_before() {
    echo "HELLO";
    check_admin_referer("blabla");
    echo "BYE";
}

add_action( 'wp_ajax_nopriv_test1', 'csrf_before', 5, 1);
add_action( 'admin_init', 'csrf_before2');
add_action( 'wp_ajax_test2', 'no_csrf_before', 2);
add_action( 'wp_ajax_test3', 'csrf_after', 3);
add_action( 'wp_ajax_test4', 'no_csrf_after', 1);
add_action( 'wp_ajax_test12', 'yes_csrf_after');
add_action( 'admin_action_123', 'yes_csrf_after2');
add_action( 'unimportant_hook5', 'no_csrf_after', 5);

// OK: check_admin_referer() inside nested if
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function csrf_after() {
    echo "HELLO";
    if ( "apple" == "orange" ) {
        if ( 1 == 2 and !check_admin_referer("blabla") and 5 == 5 ) {
            echo "BLABLA";
        } else {
            echo "HELLO";
        }
    } else {
        die();
    }
    echo "BYE";
}

// TP: wp_verify_nonce() result discarded
// ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function no_csrf_after() {
    echo "HELLO";
    wp_verify_nonce("blabla");
    echo "BYE";
}

// OK: check_admin_referer() present
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function yes_csrf_after() {
    echo "HELLO";
    check_admin_referer("blabla");
    echo "BYE";
}

// OK: check_ajax_referer() inside if block
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function yes_csrf_after2() {
    echo "HELLO";
    if ( 1 == 1 ) {
        check_ajax_referer("blabla");
    }
    echo "BYE";
}

// ── wp_ajax_nopriv_* — unauthenticated AJAX hooks ─────────────────────────────

// TP: nopriv hook, no auth or nonce check.
// Both rules fire: wp_ajax_nopriv_* also matches the authenticated rule's wp_ajax_.* regex.
// ruleid: claude.php.wordpress.access.wp-ajax-nopriv-hook-missing-auth, claude.php.wordpress.access.wp-ajax-hook-missing-auth
function nopriv_no_auth( $data ) {
    global $wpdb;
    $id = intval( $_POST['id'] );
    $wpdb->delete( $wpdb->prefix . 'records', array( 'id' => $id ) );
    wp_send_json_success();
}

// OK: nopriv hook — nonce check present
// ok: claude.php.wordpress.access.wp-ajax-nopriv-hook-missing-auth
function nopriv_has_nonce() {
    check_ajax_referer( 'my_nonce', 'nonce' );
    wp_send_json_success( array( 'ok' => true ) );
}

add_action( 'wp_ajax_nopriv_delete_record', 'nopriv_no_auth' );
add_action( 'wp_ajax_nopriv_safe_action',   'nopriv_has_nonce' );

// ── OOP checkAjaxReferer() wrappers ───────────────────────────────────────────

class PluginAdmin {
    public function checkAjaxReferer() {
        check_ajax_referer( 'plugin_nonce', 'nonce' );
    }
}

// OK: OOP wrapper around check_ajax_referer() — confirmed FP pattern from luckywp-table-of-contents
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function ajax_with_oop_nonce_wrapper() {
    global $plugin_admin;
    $plugin_admin->checkAjaxReferer();
    echo esc_html( get_option('my_setting') );
    wp_die();
}

// OK: chained OOP wrapper — e.g. Core::$plugin->admin->checkAjaxReferer()
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function ajax_with_chained_nonce_wrapper() {
    global $core_plugin;
    $core_plugin->admin->checkAjaxReferer();
    wp_send_json_success( array( 'data' => 'preview' ) );
}

add_action( 'wp_ajax_oop_nonce_test',    'ajax_with_oop_nonce_wrapper' );
add_action( 'wp_ajax_oop_chained_test',  'ajax_with_chained_nonce_wrapper' );

// ── static verify_access() wrappers ───────────────────────────────────────────
// Confirmed FP: Brevo (mailin) 3.3.4 push-api.php — SIB_Push_API::verify_access()
// encapsulates check_ajax_referer() + current_user_can() internally.

class StaticPluginAPI {
    public static function verify_access() {
        check_ajax_referer( 'plugin_nonce', 'security' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => 'Forbidden' ) );
        }
    }
}

// OK: static self::verify_access() wrapper — semantically equivalent to direct auth checks
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function ajax_with_self_verify_access() {
    self::verify_access();
    echo esc_html( get_option( 'my_setting' ) );
    wp_die();
}

// OK: static::verify_access() (late-static binding variant)
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function ajax_with_static_verify_access() {
    static::verify_access();
    wp_send_json_success( array( 'data' => 'result' ) );
}

add_action( 'wp_ajax_self_verify_test',   'ajax_with_self_verify_access' );
add_action( 'wp_ajax_static_verify_test', 'ajax_with_static_verify_access' );

// ── acf_verify_ajax() / acf_verify_nonce() ────────────────────────────────────
// On wp_ajax_ (authenticated) endpoints: ACF nonce is session-bound → FP for Rule 2.
// On wp_ajax_nopriv_ endpoints: ACF nonce is publicly visible in page HTML → TP for Rule 1.

// OK: acf_verify_ajax() on authenticated wp_ajax_ endpoint (Rule 2 suppressed).
// Confirmed FP pattern: acf-extended 0.9.1.1 — 13+ ACF AJAX handlers use this pattern;
// all are protected because wp_ajax_ requires a valid WordPress login session.
// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function acf_ajax_authenticated() {
    if ( ! acf_verify_ajax() ) {
        die;
    }
    $data = acf_get_field( $_POST['field_key'] );
    wp_send_json_success( $data );
}

// TP: acf_verify_ajax() on wp_ajax_nopriv_ endpoint — ACF nonce is public, so
// this is functionally unauthenticated. Rule 1 (nopriv) MUST still fire.
// ruleid: claude.php.wordpress.access.wp-ajax-nopriv-hook-missing-auth
function acf_ajax_nopriv_still_unauth() {
    if ( ! acf_verify_ajax() ) {
        die;
    }
    // $_POST['form'] reaches call_user_func_array() deeper in the call chain
    acfe_form( $_POST['form'] );
    die;
}

add_action( 'wp_ajax_acf_authed_test',         'acf_ajax_authenticated' );
add_action( 'wp_ajax_nopriv_acf_nopriv_test',  'acf_ajax_nopriv_still_unauth' );

// ── admin_menu and admin_init must NOT fire ────────────────────────────────────
// admin_menu/admin_init run only in authenticated wp-admin/ context (PR:H, OOS).

// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function rtmform_register_menu() {
    add_menu_page('Form Builder', 'Form Builder', 'manage_options', 'rtmform', 'rtmform_render');
}
add_action('admin_menu', 'rtmform_register_menu');

// ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
function admin_init_no_auth_check() {
    $val = get_option('my_setting');
    echo esc_html($val);
}
add_action('admin_init', 'admin_init_no_auth_check');

// ── check_ajax_requirements() wrapper ─────────────────────────────────────────

class PluginAjaxHandler {
    // OK: $this->check_ajax_requirements() bundles nonce + capability check
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function disable() {
        $this->check_ajax_requirements();
        update_option( 'plugin_enabled', false );
        wp_send_json_success();
    }

    // OK: same wrapper, different handler name
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function enable() {
        $this->check_ajax_requirements();
        update_option( 'plugin_enabled', true );
        wp_send_json_success();
    }

    public function check_ajax_requirements() {
        check_ajax_referer( 'plugin_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error();
        }
    }
}

$handler = new PluginAjaxHandler();
add_action( 'wp_ajax_plugin_disable', array( $handler, 'disable' ) );
add_action( 'wp_ajax_plugin_enable',  array( $handler, 'enable' ) );

// ── hasCapability() static wrapper ────────────────────────────────────────────

class PluginWithHasCapability {
    public function init() {
        add_action( 'wp_ajax_plugin_reset', array( $this, 'resetSettings' ) );
        add_action( 'wp_ajax_plugin_download_toolkit', array( $this, 'downloadToolkit' ) );
    }

    // OK: static hasCapability() wrapper calls current_user_can() internally
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function resetSettings() {
        PluginUtil::hasCapability( 'export', 'throw' );
        delete_option( 'plugin_settings' );
        wp_send_json_success();
    }

    // TP: handler delegates to wrapper with nonce but no capability check
    // ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function downloadToolkit() {
        DownloadWrapper::fileDownload(
            array( __CLASS__, 'toolkitCallback' ),
            'plugin_download_toolkit',
            $_POST['nonce']
        );
    }
}

// ── Self-scoped WooCommerce cart read ─────────────────────────────────────────

class CartAjaxHandler {
    public function __construct() {
        add_action( 'wp_ajax_get_cart_items', array( $this, 'getCartItems' ) );
        add_action( 'wp_ajax_nopriv_get_cart_items', array( $this, 'getCartItems' ) );
        add_action( 'wp_ajax_apply_cart_coupon', array( $this, 'applyCoupon' ) );
        add_action( 'wp_ajax_nopriv_apply_cart_coupon', array( $this, 'applyCoupon' ) );
    }

    // OK: reads only the requester's own session cart, no request superglobal at all.
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth, claude.php.wordpress.access.wp-ajax-nopriv-hook-missing-auth
    public function getCartItems() {
        $items = array();
        if ( ! empty( WC()->cart ) ) {
            foreach ( WC()->cart->get_cart() as $cart_item_key => $cart_item ) {
                $items[] = $cart_item;
            }
        }
        wp_send_json_success( $items );
    }

    // TP: also touches WC()->cart, but accepts a request-supplied coupon code with
    // no auth/nonce check — the cart-read guard must NOT suppress this.
    // ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth, claude.php.wordpress.access.wp-ajax-nopriv-hook-missing-auth
    public function applyCoupon() {
        WC()->cart->get_cart();
        WC()->cart->apply_coupon( sanitize_text_field( $_POST['coupon_code'] ) );
        wp_send_json_success();
    }
}

// ── array($this, 'method') registration pattern ──────────────────────────────

class OopAjaxService {
    public function __construct() {
        add_action( 'wp_ajax_oop_no_auth', array( $this, 'noAuthHandler' ) );
        add_action( 'wp_ajax_oop_has_auth', array( $this, 'hasAuthHandler' ) );
    }

    // TP: registered via array($this, 'method'), no auth in body
    // ruleid: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function noAuthHandler() {
        $data = get_option( 'sensitive_data' );
        wp_send_json_success( $data );
    }

    // OK: registered via array($this, 'method'), has current_user_can()
    // ok: claude.php.wordpress.access.wp-ajax-hook-missing-auth
    public function hasAuthHandler() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error();
        }
        update_option( 'plugin_setting', 'new_value' );
        wp_send_json_success();
    }
}
