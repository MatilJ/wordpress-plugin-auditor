<?php

class Dispatcher_Ruleid_Cases {

    private function select_one( $request ) {
        $method = (string) $request['ad_method'] ?? null;
        if ( 'id' === $method ) {
            $method = 'ad';
        }

        $function  = "get_the_$method";
        $id        = (string) $request['ad_id'] ?? null;
        $arguments = $request['ad_args'] ?? [];
        // ruleid: claude.php.wordpress.rce.prefixed-dynamic-function-dispatch
        $content   = $function( (int) $id, '', $arguments );

        return $content;
    }

    public static function output( $id = '' ) {
        $item = explode( '_', $id, 2 );
        $item_id = $item[1] ?? '';

        $func = 'get_the_' . $item[0];

        // ruleid: claude.php.wordpress.rce.prefixed-dynamic-function-dispatch
        return $func( absint( $item_id ) );
    }
}

class Dispatcher_Ok_Cases {

    private function select_one_guarded( $request ) {
        $method = (string) $request['ad_method'] ?? null;
        if ( 'id' === $method ) {
            $method = 'ad';
        }

        if ( ! Conditional::is_entity_allowed( $method ) ) {
            return [
                'status'  => 'error',
                'message' => 'The method is not allowed to render.',
            ];
        }

        $function  = "get_the_$method";
        $id        = (string) $request['ad_id'] ?? null;
        $arguments = $request['ad_args'] ?? [];
        // ok: claude.php.wordpress.rce.prefixed-dynamic-function-dispatch
        $content   = $function( (int) $id, '', $arguments );

        return $content;
    }

    public function get_ad_group_from_option() {
        global $wpdb;

        $option = $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name = 'advads_display'" );
        $data   = maybe_unserialize( $option );

        // ok: claude.php.wordpress.rce.prefixed-dynamic-function-dispatch
        return $data['title'] ?? '';
    }

    // Confirmed FP source: advanced-cf7-db 2.1.3 (bundled Freemius SDK)
    // freemius/includes/managers/class-fs-admin-menu-manager.php:881,979 —
    // both sides of the concatenation are string literals, spelling out
    // add_menu_page()/add_submenu_page() verbatim (done only to dodge the
    // WordPress.org Theme Check static scanner). Zero runtime variability.
    public static function add_page_literal_concat() {
        $fn = 'add_menu' . '_page';
        // ok: claude.php.wordpress.rce.prefixed-dynamic-function-dispatch
        return $fn( 'Page Title', 'Menu Title', 'manage_options', 'my-slug' );
    }
}
