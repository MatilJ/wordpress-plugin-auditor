<?php
// Real pre-fix shape (CVE-2026-1306 class): a validator function reassigns
// its filename parameter through sanitize_file_name() and returns it
// unconditionally — no extension check anywhere in the function. Reached
// indirectly via filter_input(..., FILTER_CALLBACK, array("options"=>...)),
// so the actual write call lives in a different function entirely.
// ruleid: claude.php.wordpress.file-upload.filename-validator-missing-extension-check
function midiSynth_validate_fileName($fileName){
	$fileName = sanitize_file_name($fileName);
	return $fileName;
}

// Same incomplete shape, wired as a sanitize_callback for a registered
// setting/REST argument instead of a FILTER_CALLBACK.
// ruleid: claude.php.wordpress.file-upload.filename-validator-missing-extension-check
function myplugin_sanitize_upload_filename($name){
	$name = basename($name);
	return $name;
}

// One-line variant of the same gap.
// ruleid: claude.php.wordpress.file-upload.filename-validator-missing-extension-check
function acme_clean_upload_filename($filename){
	return sanitize_file_name($filename);
}

// ok: claude.php.wordpress.file-upload.filename-validator-missing-extension-check
function midiSynth_validate_fileName_fixed($fileName){
	$fileName = sanitize_file_name($fileName);
	$extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

	if ($extension === "mid" || $extension === "midi"){
		return $fileName;
	}else{
		wp_die(esc_html("file extension is incorrect: ".$extension));
	}
}

// ok: claude.php.wordpress.file-upload.filename-validator-missing-extension-check
function myplugin_check_upload_filetype($filename){
	$filename = sanitize_file_name($filename);
	wp_check_filetype_and_ext($filename, $filename);
	return $filename;
}

// A same-shaped helper whose name carries no filename/validation semantics
// at all — outside this rule's naming-heuristic scope.
// ok: claude.php.wordpress.file-upload.filename-validator-missing-extension-check
function get_wpdb_row_key($key){
	$key = sanitize_key($key);
	return $key;
}
