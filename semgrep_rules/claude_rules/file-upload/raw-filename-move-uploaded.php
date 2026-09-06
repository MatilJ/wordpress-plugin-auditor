<?php
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/uploads/' . $_FILES['upload']['name']);

$name = $_FILES['f']['name'];
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
move_uploaded_file($_FILES['f']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . $name);

$n = $_FILES['doc']['name'];
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
copy($_FILES['doc']['tmp_name'], "/tmp/" . $n);

// sanitize_file_name() only strips illegal characters — it does not
// restrict/re-check the extension, so a dangerous extension (.php) is
// preserved untouched (CVE-2026-6271 class).
$safe = sanitize_file_name($_FILES['upload']['name']);
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/uploads/' . $safe);

// $wp_filesystem->move()/copy() variant (CVE-2026-6271, career-section
// unauthenticated CV-upload handler): sanitize_file_name() is called on the
// original filename but the extension is never validated before the write.
$orig_name = sanitize_file_name($_FILES['cv']['name']);
$cs_name_file = time() . '_' . $orig_name;
$cs_destination = $cs_dir . '/' . $cs_name_file;
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
$wp_filesystem->move($_FILES['cv']['tmp_name'], $cs_destination, true);

$doc_orig = sanitize_file_name($_FILES['doc']['name']);
$doc_dest = $cs_dir . '/' . $doc_orig;
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
$wp_filesystem->copy($_FILES['doc']['tmp_name'], $doc_dest);

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
$cs_allowed_types = array('pdf' => 'application/pdf', 'doc' => 'application/msword');
$cs_filetype = wp_check_filetype_and_ext($_FILES['cv']['tmp_name'], $_FILES['cv']['name'], $cs_allowed_types);
$cs_safe_name = wp_generate_password(32, false) . '.' . $cs_filetype['ext'];
$cs_safe_dest = $cs_dir . '/' . $cs_safe_name;
$wp_filesystem->move($_FILES['cv']['tmp_name'], $cs_safe_dest, true);

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
$id = md5(uniqid('', true));
move_uploaded_file($_FILES['upload']['tmp_name'], "/var/www/uploads/" . $id . ".jpg");

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
$base = basename($_FILES['upload']['name']);
move_uploaded_file($_FILES['upload']['tmp_name'], '/var/www/uploads/' . $base);

// Chunked/resumable-upload finalize shape: a decoded request-body array
// field (not $_FILES) supplies the raw filename used to build the write
// destination.
$params = json_decode($data, 1);
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
rename($tmp_path, WP_CONTENT_DIR . '/uploads/backups/' . $params['name']);

$item = json_decode($body, true);
$file_path = WP_CONTENT_DIR . '/uploads/backups/' . $item['filename'];
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
$handle = fopen($file_path, 'w');

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
$params2 = json_decode($data, 1);
$safe_name = basename($params2['name']);
$file_path2 = WP_CONTENT_DIR . '/uploads/backups/' . $safe_name;
$handle2 = fopen($file_path2, 'w');

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
$row = $wpdb->get_row("SELECT name FROM {$wpdb->prefix}backups WHERE id = 1", ARRAY_A);
$log_path = WP_CONTENT_DIR . '/uploads/backups/' . $row['name'] . '.log';
$fh = fopen($log_path, 'r');

// Double-extension bypass shape (CVE-2023-0714, metform): a timestamp/uniqid
// prefix is concatenated onto the raw client filename, preserving embedded
// extension tokens (e.g. shell.php.jpg) verbatim in the saved file.
$fname = time() . "-" . $_FILES['entry']['name'];
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
move_uploaded_file($_FILES['entry']['tmp_name'], $upload_dir . "/" . $fname);

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
$ext = pathinfo($_FILES['entry']['name'], PATHINFO_EXTENSION);
$safe_name2 = "entry-file-" . uniqid() . "-" . microtime(true) . "-." . $ext;
move_uploaded_file($_FILES['entry']['tmp_name'], $upload_dir . "/" . $safe_name2);

// Plugin-defined two-argument (src, dest) upload/move wrapper mirroring
// move_uploaded_file()'s own signature instead of calling the builtin
// directly — the destination is still built from the raw client filename,
// so the missing type check is just as exploitable one call hop away.
$w_name = $_FILES['photo']['name'];
$w_dest = '/var/www/uploads/' . $w_name;
// ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
Custom_File::upload($_FILES['photo']['tmp_name'], $w_dest);

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
$w_ext = pathinfo($_FILES['photo']['name'], PATHINFO_EXTENSION);
$w_safe_dest = '/var/www/uploads/' . uniqid() . '.' . $w_ext;
Custom_File::upload($_FILES['photo']['tmp_name'], $w_safe_dest);

// Delegate call-site shape (CVE-2026-14483, WPL Real Estate
// set_property.php): the raw per-file 'name' entry is handed straight to a
// save_image()-named helper method as an argument — the actual write
// happens one call hop away inside that helper, so no extension check ever
// runs anywhere on this path.
foreach ($files['file']['name'] as $dkey => $dfile) {
    $d_name = substr($dfile, 6);
    $d_tmp = $files['file']['tmp_name'][$dkey];
    // ruleid: claude.php.wordpress.upload.raw-filename-move-uploaded
    $this->save_image($d_name, $d_tmp, 0, false);
}

// ok: claude.php.wordpress.upload.raw-filename-move-uploaded
foreach ($files['file']['name'] as $dkey2 => $dfile2) {
    $d_name2 = basename($dfile2);
    $d_tmp2 = $files['file']['tmp_name'][$dkey2];
    $this->save_image($d_name2, $d_tmp2, 0, false);
}

// pathinfo()'s return array reuses the same 'filename'/'name'-shaped keys as
// common upload arrays, but a server-generated tempnam() path has no
// attacker-controlled component anywhere in the chain.
function ok_tempnam_pathinfo_rename() {
    $path = tempnam(sys_get_temp_dir(), 'App_');
    $info = pathinfo($path);
    $new_path = $info['dirname'] . '/' . $info['filename'] . '.ics';
    // ok: claude.php.wordpress.upload.raw-filename-move-uploaded
    rename($path, $new_path);
}

function ok_tempnam_pathinfo_copy() {
    $path = tempnam(sys_get_temp_dir(), 'App_');
    $info = pathinfo($path);
    $dest = $info['dirname'] . '/' . $info['basename'] . '.tmp';
    // ok: claude.php.wordpress.upload.raw-filename-move-uploaded
    copy($path, $dest);
}
