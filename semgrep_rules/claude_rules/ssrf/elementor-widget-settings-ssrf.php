<?php

class Vulnerable_Widget extends \Elementor\Widget_Base {

    protected function get_csv_data_vulnerable() {
        $settings = $this->get_settings_for_display();
        $csv_url = $settings['csv_file']['url'];
        // ruleid: claude.php.wordpress.ssrf.elementor-widget-settings-ssrf
        $response = wp_remote_get($csv_url, ['sslverify' => false]);
        return wp_remote_retrieve_body($response);
    }

    protected function fetch_remote_content() {
        $settings = $this->get_settings();
        $url = $settings['remote_url'];
        // ruleid: claude.php.wordpress.ssrf.elementor-widget-settings-ssrf
        $response = wp_remote_post($url, ['body' => ['action' => 'fetch']]);
        return $response;
    }

    protected function fetch_with_curl() {
        $settings = $this->get_settings_for_display();
        $url = $settings['feed_url'];
        // ruleid: claude.php.wordpress.ssrf.elementor-widget-settings-ssrf
        $ch = curl_init($url);
        curl_exec($ch);
        curl_close($ch);
    }

    protected function get_csv_data_safe() {
        $settings = $this->get_settings_for_display();
        $csv_url = $settings['csv_file']['url'];
        // ok: claude.php.wordpress.ssrf.elementor-widget-settings-ssrf
        $response = wp_safe_remote_get($csv_url, ['sslverify' => true]);
        return wp_remote_retrieve_body($response);
    }

    protected function fetch_with_validation() {
        $settings = $this->get_settings_for_display();
        $url = $settings['remote_url'];
        $url = wp_http_validate_url($url);
        if (!$url) {
            return false;
        }
        // ok: claude.php.wordpress.ssrf.elementor-widget-settings-ssrf
        $response = wp_remote_get($url, []);
        return $response;
    }

    protected function fetch_with_intval() {
        $settings = $this->get_settings_for_display();
        $post_id = absint($settings['post_id']);
        // ok: claude.php.wordpress.ssrf.elementor-widget-settings-ssrf
        $response = wp_remote_get($post_id);
        return $response;
    }
}
