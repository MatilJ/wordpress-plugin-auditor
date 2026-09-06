<?php

// ── Vulnerable: real pre-fix shape (CVE-2026-6320) — implode/array_filter
// concatenation of upload basedir + subdir + raw submitted "file" field
// value, appended straight into the mail-attachments array ─────────────────
class Booking_Plugin_Vulnerable {
    public function sendMail($view, $data) {
        $settings = new ArrayObject($data);
        $settings['attachments'] = array();
        $additional_fields = Checkout_Fields::additional();
        foreach ($additional_fields as $field) {
            if ($field['type'] === 'file' && isset($data['booking'])) {
                foreach ($data['booking']->getMeta($field['key']) as $f) {
                    if ($f) {
                        // ruleid: claude.php.wordpress.file.mail-attachment-basedir-concat-no-basename
                        $settings['attachments'][] = implode('/', array_filter(array(wp_get_upload_dir()['basedir'], trim($f['subdir'], '/'), $f['file'])));
                    }
                }
            }
        }
        wp_mail($data['to'], 'Booking confirmation', 'body', array(), (array) $settings['attachments']);
    }
}

// ── Vulnerable: plain string-concatenation variant (no implode/array_filter) ─
function build_attachment_path_vulnerable($submission) {
    $upload_dir  = wp_upload_dir();
    $attachments = array();
    foreach ($submission['files'] as $entry) {
        // ruleid: claude.php.wordpress.file.mail-attachment-basedir-concat-no-basename
        $attachments[] = $upload_dir['basedir'] . '/formentries/' . $entry['name'];
    }
    return $attachments;
}

// ── Safe: the real fix — basename() strips the filename component, then
// realpath() + prefix-containment check before the array append ────────────
class Booking_Plugin_Fixed {
    public function sendMail($view, $data) {
        $settings = new ArrayObject($data);
        $settings['attachments'] = array();
        $uploads_basedir = realpath(wp_get_upload_dir()['basedir']);
        $additional_fields = Checkout_Fields::additional();
        foreach ($additional_fields as $field) {
            if ($field['type'] === 'file' && isset($data['booking'])) {
                foreach ($data['booking']->getMeta($field['key']) as $f) {
                    if ($f) {
                        $candidate = implode('/', array_filter(array(wp_get_upload_dir()['basedir'], trim($f['subdir'], '/'), basename((string) $f['file']))));
                        $real = realpath($candidate);
                        // ok: claude.php.wordpress.file.mail-attachment-basedir-concat-no-basename
                        if ($real && $uploads_basedir && strpos($real, $uploads_basedir) === 0) {
                            $settings['attachments'][] = $real;
                        }
                    }
                }
            }
        }
        wp_mail($data['to'], 'Booking confirmation', 'body', array(), (array) $settings['attachments']);
    }
}

// ── Safe: unrelated read of a WP attachment by numeric post ID — no
// user-controlled filename string, no path traversal surface ───────────────
function email_generated_invoice($order_id, $to) {
    $attachment_id = get_post_meta($order_id, '_invoice_attachment_id', true);
    $path = get_attached_file((int) $attachment_id);
    $attachments = array();
    if ($path) {
        // ok: claude.php.wordpress.file.mail-attachment-basedir-concat-no-basename
        $attachments[] = $path;
    }
    wp_mail($to, 'Your invoice', 'body', array(), $attachments);
}

// ── Vulnerable: real pre-fix shape (CVE-2026-5710) — an attacker-controlled
// "mfile"-style field value is URL->path "converted" via str_replace() one
// statement earlier, then the bare result variable is appended straight
// into the attachments array with only a file_exists() guard (not a
// containment check) and no basename()/realpath() anywhere in the function ─
function dnd_cf7_mail_components_vulnerable($components, $form) {
    $uploads_dir = array('upload_url' => 'https://example.com/wp-content/uploads/wpcf7-files', 'upload_dir' => '/var/www/wp-content/uploads/wpcf7-files');
    $submission = true;
    $posted_data = array('mfile-1' => array('https://example.com/wp-content/uploads/wpcf7-files/../../../../etc/passwd'));
    foreach ($posted_data['mfile-1'] as $_file) {
        $new_file_name = str_replace($uploads_dir['upload_url'], $uploads_dir['upload_dir'], $_file);
        if ($submission && file_exists($new_file_name)) {
            // ruleid: claude.php.wordpress.file.mail-attachment-basedir-concat-no-basename
            $components['attachments'][] = $new_file_name;
        }
    }
    return $components;
}

// ── Vulnerable: same str_replace()-conversion shape, plain $attachments
// array variable instead of a nested $components['attachments'] key ────────
function build_link_attachment_vulnerable($uploads_dir, $link) {
    $attachments = array();
    $local_path = str_replace($uploads_dir['upload_url'], $uploads_dir['upload_dir'], $link);
    if (file_exists($local_path)) {
        // ruleid: claude.php.wordpress.file.mail-attachment-basedir-concat-no-basename
        $attachments[] = $local_path;
    }
    return $attachments;
}

// ── Safe: the real fix (1.3.9.7) — realpath()+wp_normalize_path() on the
// converted value, then a strpos() prefix-containment check against the
// realpath()'d base dir before the append ───────────────────────────────────
function dnd_cf7_mail_components_fixed($components, $form) {
    $uploads_dir = array('upload_url' => 'https://example.com/wp-content/uploads/wpcf7-files', 'upload_dir' => '/var/www/wp-content/uploads/wpcf7-files');
    $submission = true;
    $posted_data = array('mfile-1' => array('https://example.com/wp-content/uploads/wpcf7-files/photo.jpg'));
    foreach ($posted_data['mfile-1'] as $_file) {
        $upload_dir = realpath($uploads_dir['upload_dir']);
        $new_file_name = str_replace($uploads_dir['upload_url'], $upload_dir, $_file);
        $file_path = realpath(wp_normalize_path($new_file_name));
        // ok: claude.php.wordpress.file.mail-attachment-basedir-concat-no-basename
        if ($submission && false !== $file_path && 0 === strpos($file_path, $upload_dir)) {
            $components['attachments'][] = $file_path;
        }
    }
    return $components;
}
