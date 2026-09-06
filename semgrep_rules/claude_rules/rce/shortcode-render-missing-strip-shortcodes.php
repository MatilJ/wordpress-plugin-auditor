<?php
/**
 * Test cases for: claude.php.wordpress.rce.shortcode-render-missing-strip-shortcodes
 */

class Some_Wall_Shortcode {

    public function render_shortcode( $atts ) {
        ob_start();
        foreach ( $this->get_entries( $atts ) as $entry ) {
            echo esc_html( $entry->comment );
        }
        $html = ob_get_clean();

        if ( isset( $atts['only_entry_html'] ) && wp_doing_ajax() ) {
            // ruleid: claude.php.wordpress.rce.shortcode-render-missing-strip-shortcodes
            return $html;
        }

        // ruleid: claude.php.wordpress.rce.shortcode-render-missing-strip-shortcodes
        return $html;
    }
}

function entry_wall_shortcode( $atts ) {
    ob_start();
    render_entries_template( $atts );
    $html = ob_get_clean();
    // ruleid: claude.php.wordpress.rce.shortcode-render-missing-strip-shortcodes
    echo $html;
}

class Some_Wall_Shortcode_Fixed {

    public function render_shortcode( $atts ) {
        ob_start();
        foreach ( $this->get_entries( $atts ) as $entry ) {
            echo esc_html( $entry->comment );
        }
        $html = ob_get_clean();
        $html = strip_shortcodes( $html );

        // ok: claude.php.wordpress.rce.shortcode-render-missing-strip-shortcodes
        return $html;
    }
}

function options_page_shortcode( $atts ) {
    global $wpdb;
    $notice = $wpdb->get_var( "SELECT notice FROM some_table LIMIT 1" );
    // ok: claude.php.wordpress.rce.shortcode-render-missing-strip-shortcodes
    return esc_html( $notice );
}
