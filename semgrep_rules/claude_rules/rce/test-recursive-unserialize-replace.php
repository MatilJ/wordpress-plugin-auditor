<?php

// ---- TRUE POSITIVES ----

function tp_recursive_replace_standard() {
    // ruleid: claude.php.wordpress.rce.recursive-unserialize-replace
    $result = recursive_unserialize_replace($from, $to, $data);
}

function tp_recursive_replace_typo_variant() {
    // ruleid: claude.php.wordpress.rce.recursive-unserialize-replace
    $result = recursive_unserialized_replace($from, $to, $data);
}

function tp_recursive_replace_method_call() {
    // ruleid: claude.php.wordpress.rce.recursive-unserialize-replace
    $result = $this->recursive_unserialize_replace($from, $to, $data);
}

function tp_recursive_replace_method_typo() {
    // ruleid: claude.php.wordpress.rce.recursive-unserialize-replace
    $result = $this->recursive_unserialized_replace($from, $to, $data);
}

function tp_recursive_replace_in_import() {
    $imported_data = json_decode(file_get_contents($uploaded_file), true);
    foreach ($imported_data['tables'] as $table => $rows) {
        // ruleid: claude.php.wordpress.rce.recursive-unserialize-replace
        $rows = $db->recursive_unserialize_replace($old_url, $new_url, $rows);
    }
}

function tp_recursive_replace_with_args() {
    // ruleid: claude.php.wordpress.rce.recursive-unserialize-replace
    recursive_unserialize_replace($search, $replace, $serialized_data, false);
}
