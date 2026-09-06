<?php

class Upload_Handler_1 {
    private function file_validity( $file ) {
        if ( empty( $_POST['allowed_file_types'] ) ) {
            $allowed_file_types = 'jpg,jpeg,png,gif,pdf,doc';
        } else {
            $allowed_file_types = $_POST['allowed_file_types'];
        }

        $f_extension = pathinfo( $file['name'], PATHINFO_EXTENSION );
        $allowed_file_types = explode( ',', $allowed_file_types );
        $allowed_file_types = array_map( 'trim', $allowed_file_types );
        $allowed_file_types = array_map( 'strtolower', $allowed_file_types );

        $f_extension = strtolower( $f_extension );

        // ruleid: claude.php.wordpress.file-upload.request-controlled-extension-allowlist
        return ( in_array( $f_extension, $allowed_file_types ) && !in_array( $f_extension, $this->get_exclusion_list() ) );
    }

    private function get_exclusion_list() {
        return [ 'php', 'phtml', 'phar' ];
    }
}

class Upload_Handler_2 {
    public function validate( $name ) {
        $allowed = $_REQUEST['accept_types'];
        $ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
        // ruleid: claude.php.wordpress.file-upload.request-controlled-extension-allowlist
        if ( in_array( $ext, $allowed ) ) {
            return true;
        }
        return false;
    }
}

class Upload_Handler_Fixed {
    private function file_validity( $file ) {
        $whitelist = [ 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc' ];

        if ( empty( $_POST['allowed_file_types'] ) ) {
            $allowed_file_types = 'jpg,jpeg,png,gif,pdf,doc';
        } else {
            $allowed_file_types = $_POST['allowed_file_types'];
        }

        $f_extension = pathinfo( $file['name'], PATHINFO_EXTENSION );
        $f_extension = strtolower( $f_extension );

        $allowed_file_types = explode( ',', $allowed_file_types );
        $allowed_file_types = array_map( 'trim', $allowed_file_types );
        $allowed_file_types = array_map( 'strtolower', $allowed_file_types );

        // ok: claude.php.wordpress.file-upload.request-controlled-extension-allowlist
        return ( in_array( $f_extension, $allowed_file_types ) && in_array( $f_extension, $whitelist ) && !in_array( $f_extension, $this->get_exclusion_list() ) );
    }

    private function get_exclusion_list() {
        return [ 'php', 'phtml', 'phar' ];
    }
}

function get_recent_activity( $wpdb, $type ) {
    // ok: claude.php.wordpress.file-upload.request-controlled-extension-allowlist
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM wp_activity_log WHERE type = %s", $type ) );
}
