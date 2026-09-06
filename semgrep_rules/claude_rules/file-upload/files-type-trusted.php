<?php
// ruleid: claude.php.wordpress.upload.files-type-trusted
if ($_FILES['upload']['type'] === 'image/jpeg') {
    move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/uploads/' . $_FILES['upload']['name']);
}

// ruleid: claude.php.wordpress.upload.files-type-trusted
if (in_array($_FILES['f']['type'], ['image/png', 'image/gif'], true)) {
    move_uploaded_file($_FILES['f']['tmp_name'], '/tmp/' . $_FILES['f']['name']);
}

// ruleid: claude.php.wordpress.upload.files-type-trusted
if (strpos($_FILES['upload']['type'], 'image/') === 0) {
    // allowed
}

// ok: claude.php.wordpress.upload.files-type-trusted
$check = wp_check_filetype_and_ext($_FILES['upload']['tmp_name'], $_FILES['upload']['name']);
if ($check['ext'] === 'jpg') {
    // allowed
}

// ok: claude.php.wordpress.upload.files-type-trusted
// Reading $_FILES['type'] for logging only, not for a security decision.
error_log('upload type reported: ' . $_FILES['upload']['type']);

// ok: claude.php.wordpress.upload.files-type-trusted
$ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
if (in_array(strtolower($ext), ['jpg','png'], true)) {
    // allowed
}
