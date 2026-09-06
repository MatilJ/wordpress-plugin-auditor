<?php

class Acme_Cache_Cleaner {

    protected $logger_on = false;

    // ruleid: claude.php.wordpress.file-write-delete.scandir-unlink-param-no-containment
    protected function deleteHtmlFiles($cache_path) {
        $counter = 0;
        $cached_pages = @scandir($cache_path);
        if ($cached_pages) foreach ($cached_pages as $cp) {
            if ($cp == '.' || $cp == '..') continue;
            if (preg_match('/\.html?$/', $cp)) {
                $counter += @unlink(trailingslashit($cache_path) . $cp);
            }
        }
        return $counter;
    }

    // ruleid: claude.php.wordpress.file-write-delete.scandir-unlink-param-no-containment
    public function purgeTempDir($dir) {
        $files = scandir($dir);
        foreach ($files as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            unlink($dir . '/' . $f);
        }
    }

    // ruleid: claude.php.wordpress.file-write-delete.scandir-unlink-param-no-containment
    public function purgeSubdir($dir) {
        $entries = scandir($dir);
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            if (is_dir($dir . DIRECTORY_SEPARATOR . $entry)) {
                rmdir($dir . DIRECTORY_SEPARATOR . $entry);
            }
        }
    }

    // ok: claude.php.wordpress.file-write-delete.scandir-unlink-param-no-containment
    protected function deleteHtmlFilesFixed($cache_path) {
        $safe_path = $this->resolveCacheDirectory($cache_path);
        if ($safe_path === false) {
            return 0;
        }
        $counter = 0;
        $cached_pages = @scandir($safe_path);
        if ($cached_pages) foreach ($cached_pages as $cp) {
            if ($cp == '.' || $cp == '..') continue;
            if (preg_match('/\.html?$/', $cp)) {
                $counter += @unlink(trailingslashit($safe_path) . $cp);
            }
        }
        return $counter;
    }

    protected function resolveCacheDirectory($cache_path) {
        $cache_root = realpath(WP_CONTENT_DIR . '/cache');
        if ($cache_root === false) {
            return false;
        }
        $real = realpath($cache_path);
        if ($real === false || strpos($real, $cache_root) !== 0) {
            return false;
        }
        return $real;
    }

    // ok: claude.php.wordpress.file-write-delete.scandir-unlink-param-no-containment
    public function purgeTempDirGuardedInline($dir) {
        $real_dir = realpath($dir);
        if ($real_dir === false || strpos($real_dir, $this->uploadsBase) !== 0) {
            return;
        }
        $files = scandir($real_dir);
        foreach ($files as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            unlink($real_dir . '/' . $f);
        }
    }

    // ok: claude.php.wordpress.file-write-delete.scandir-unlink-param-no-containment
    public function listOnly($dir) {
        // Not a finding: scandir() result is never unlinked, only counted.
        $files = scandir($dir);
        return count($files);
    }
}
