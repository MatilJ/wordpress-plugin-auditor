<?php

// VULNERABLE: dashboard widget callback queries and renders restricted data
// with no capability check of its own. Mirrors otter-blocks 3.2.1
// Dashboard::form_submissions_widget()/form_submissions_widget_content().
class Form_Submissions_Dashboard {
    public function init() {
        add_action( 'wp_dashboard_setup', array( $this, 'register_widget' ) );
    }

    public function register_widget() {
        // ruleid: claude.php.wordpress.access-control.dashboard-widget-no-capability-check
        wp_add_dashboard_widget(
            'form_submissions_widget',
            'Form Submissions',
            array( $this, 'widget_content' )
        );
    }

    public function widget_content() {
        $entries = get_posts( array( 'post_type' => 'restricted_record_type', 'posts_per_page' => 5 ) );
        foreach ( $entries as $entry ) {
            echo esc_html( $entry->post_title );
        }
    }
}

// VULNERABLE: a second, unrelated widget in a different class, also with no
// capability check — confirms the rule fires per-callback, not just once.
class Site_Stats_Dashboard {
    public function register() {
        // ruleid: claude.php.wordpress.access-control.dashboard-widget-no-capability-check
        wp_add_dashboard_widget( 'site_stats_widget', 'Site Stats', array( $this, 'render' ) );
    }

    public function render() {
        echo get_option( 'internal_license_key' );
    }
}

// SAFE: the registered callback itself checks current_user_can() before
// rendering any data.
class Admin_Only_Dashboard {
    public function register() {
        // ok: claude.php.wordpress.access-control.dashboard-widget-no-capability-check
        wp_add_dashboard_widget( 'admin_widget', 'Admin Widget', array( $this, 'render' ) );
    }

    public function render() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        echo get_option( 'internal_license_key' );
    }
}

// SAFE: the registering function itself is gated by an early-return
// capability check BEFORE the wp_add_dashboard_widget() call — since
// wp_dashboard_setup fires fresh on every /wp-admin/index.php request, this
// prevents registration (and therefore rendering) for non-admin users.
class Stats_Widget_Registration_Gate {
    public function init() {
        add_action( 'wp_dashboard_setup', array( $this, 'add_widgets' ) );
    }

    public function add_widgets() {
        if ( ! ES()->is_current_user_administrator() ) {
            return;
        }
        // ok: claude.php.wordpress.access-control.dashboard-widget-no-capability-check
        wp_add_dashboard_widget( 'es_dashboard_stats_widget', 'Stats', array( $this, 'render' ) );
    }

    public function render() {
        echo get_option( 'internal_license_key' );
    }
}

// SAFE: widget only ever shows generic, non-sensitive content — still
// capability-checked here to keep this an unambiguous "ok" case.
class Public_Welcome_Dashboard {
    public function register() {
        // ok: claude.php.wordpress.access-control.dashboard-widget-no-capability-check
        wp_add_dashboard_widget( 'welcome_widget', 'Welcome', array( $this, 'render' ) );
    }

    public function render() {
        if ( ! current_user_can( 'read' ) ) {
            return;
        }
        echo 'Welcome to the dashboard!';
    }
}
