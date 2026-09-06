<?php

// ---- TRUE POSITIVES ----

function tp_zip_extract_no_validation($file, $dest) {
    $zip = new ZipArchive();
    $zip->open($file);
    // ruleid: claude.php.wordpress.file.zip-extraction-path-traversal
    $zip->extractTo($dest);
    $zip->close();
}

function tp_zip_extract_with_specific_entries($file, $dest) {
    $zip = new ZipArchive();
    $zip->open($file);
    $entries = array('file1.txt', 'file2.txt');
    // ruleid: claude.php.wordpress.file.zip-extraction-path-traversal
    $zip->extractTo($dest, $entries);
    $zip->close();
}

function tp_pclzip_extract($file, $dest) {
    $archive = new PclZip($file);
    // ruleid: claude.php.wordpress.file.zip-extraction-path-traversal-pclzip
    $archive->extract(PCLZIP_OPT_PATH, $dest);
}

function tp_pclzip_extract_with_options($file, $dest) {
    $archive = new PclZip($file);
    // ruleid: claude.php.wordpress.file.zip-extraction-path-traversal-pclzip
    $archive->extract(PCLZIP_OPT_PATH, $dest, PCLZIP_OPT_REMOVE_PATH, 'subdir');
}

// ---- FALSE POSITIVES ----

function ok_zip_with_realpath_validation($file, $dest) {
    $zip = new ZipArchive();
    $zip->open($file);
    $real = realpath($dest);
    // ok: claude.php.wordpress.file.zip-extraction-path-traversal
    $zip->extractTo($real);
    $zip->close();
}
