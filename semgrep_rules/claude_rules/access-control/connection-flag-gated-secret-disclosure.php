<?php

class Pairing_Status_Handler {

    public function build_status_response() {
        return array(
            // ruleid: claude.php.wordpress.access-control.connection-flag-gated-secret-disclosure
            'auth_key' => $this->mod->isSiteLinked() ? '' : $this->mod->getPluginAuthKey(),
        );
    }
}

function get_response_payload() {
    $payload = array();
    // ruleid: claude.php.wordpress.access-control.connection-flag-gated-secret-disclosure
    $payload['api_key'] = !is_account_connected() ? fetch_stored_secret_token() : '';
    return $payload;
}

class Pairing_Status_Handler_Fixed {

    public function build_status_response() {
        // ok: claude.php.wordpress.access-control.connection-flag-gated-secret-disclosure
        return array(
            'auth_key' => $this->getBootstrapAuthKeyForResponse(),
        );
    }

    public function getBootstrapAuthKeyForResponse() :string {
        return $this->mod->isSiteLinked() || !$this->isUnlinkedBootstrapPermitted()
            ? ''
            : $this->mod->getPluginAuthKey();
    }
}

class Status_Widget {

    public function render() {
        // ok: claude.php.wordpress.access-control.connection-flag-gated-secret-disclosure
        $label = $this->is_connected() ? '' : get_option( 'site_display_name' );
        echo esc_html( $label );
    }
}

class Admin_Only_Handler {

    public function build_response() {
        if ( current_user_can( 'manage_options' ) ) {
            // ok: claude.php.wordpress.access-control.connection-flag-gated-secret-disclosure
            return array(
                'auth_key' => $this->is_linked() ? '' : $this->get_secret_token(),
            );
        }
        return array();
    }
}
