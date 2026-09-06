<?php

// ---- TRUE POSITIVES ----

function tp_fopen_fwrite_image_url() {
    $data = array('image_url' => $_POST['image_url']);
    // ruleid: claude.php.wordpress.file-upload.exif-imagetype-sole-check-write
    if (!empty($data['image_url']) && exif_imagetype($data['image_url'])) {
        $filename = sanitize_file_name(basename($data['image_url']));
        $uploaddir = wp_upload_dir();
        $uploadfile = $uploaddir['path'] . '/' . $filename;
        $contents = file_get_contents($data['image_url']);
        $savefile = fopen($uploadfile, 'w');
        fwrite($savefile, $contents);
        fclose($savefile);
    }
}

function tp_file_put_contents_remote_avatar() {
    $url = get_option('remote_avatar_url');
    // ruleid: claude.php.wordpress.file-upload.exif-imagetype-sole-check-write
    if (exif_imagetype($url)) {
        $name = basename($url);
        $dest = WP_CONTENT_DIR . '/uploads/avatars/' . $name;
        file_put_contents($dest, file_get_contents($url));
    }
}

// ---- FALSE POSITIVES ----

function ok_getimagesize_with_mime_allowlist() {
    $url = $_POST['image_url'];
    // ok: claude.php.wordpress.file-upload.exif-imagetype-sole-check-write
    $imageData = getimagesize($url);
    if (!isset($imageData['mime']) || !in_array($imageData['mime'], array('image/png', 'image/jpeg', 'image/gif'))) {
        return false;
    }
    $dest = WP_CONTENT_DIR . '/uploads/' . uniqid() . '.' . explode('/', $imageData['mime'])[1];
    file_put_contents($dest, file_get_contents($url));
}

function ok_exif_check_with_extension_allowlist() {
    $url = $_POST['image_url'];
    // ok: claude.php.wordpress.file-upload.exif-imagetype-sole-check-write
    if (exif_imagetype($url)) {
        $name = basename($url);
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        $allowed = array('png', 'jpg', 'jpeg', 'gif');
        if (!in_array($ext, $allowed)) {
            return false;
        }
        $dest = WP_CONTENT_DIR . '/uploads/' . $name;
        file_put_contents($dest, file_get_contents($url));
    }
}
