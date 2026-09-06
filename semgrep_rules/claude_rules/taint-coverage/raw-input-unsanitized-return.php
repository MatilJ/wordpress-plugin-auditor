<?php

class ArchiveHelper {

    private function getArchiveFilePath()
    {
        $archive_filepath = filter_input(INPUT_GET, 'archive', FILTER_SANITIZE_SPECIAL_CHARS);
        if (is_dir($archive_filepath)) {
            $archive_filepath = $archive_filepath . '/archive.zip';
        }
        // ruleid: claude.php.wordpress.taint-coverage.raw-input-unsanitized-return
        return $archive_filepath;
    }

    public function getRequestedSection()
    {
        $section = $_POST['section'];
        // ruleid: claude.php.wordpress.taint-coverage.raw-input-unsanitized-return
        return $section;
    }

    public function getSafeArchivePath()
    {
        $archive_filepath = filter_input(INPUT_GET, 'archive', FILTER_SANITIZE_SPECIAL_CHARS);
        // ok: claude.php.wordpress.taint-coverage.raw-input-unsanitized-return
        return sanitize_file_name($archive_filepath);
    }

    public function getStoredArchivePath()
    {
        global $wpdb;
        $row = $wpdb->get_var("SELECT archive_path FROM {$wpdb->prefix}duplicator_packages LIMIT 1");
        // ok: claude.php.wordpress.taint-coverage.raw-input-unsanitized-return
        return $row;
    }
}
