<?php

// ── Vulnerable: request-array loop feeding a combiner source list ──────────
function combine_assets_vulnerable() {
    $files = $_GET['f_array'];
    foreach ($files as $name) {
        $uri  = '/' . $name;
        $path = ABSPATH . $uri;
        $real = MyPathHelper::realpath($path);
        // ruleid: claude.php.wordpress.file.tainted-realpath-no-extension-check
        if (false === $real || ! is_file($real)) {
            continue;
        }
        $sources[] = array('filepath' => $real);
    }
    return $sources;
}

// ── Vulnerable: single-value request param checked directly ────────────────
function combine_single_vulnerable() {
    $tpl = $_REQUEST['template'];
    $candidate = WP_CONTENT_DIR . '/cache/combine/' . $tpl;
    // ruleid: claude.php.wordpress.file.tainted-realpath-no-extension-check
    if (file_exists($candidate)) {
        return array('filepath' => $candidate);
    }
    return null;
}

// ── Safe: extension allow-list applied in the same function ────────────────
function combine_assets_safe_extension() {
    $files = $_GET['f_array'];
    foreach ($files as $name) {
        $path = ABSPATH . '/' . $name;
        $real = MyPathHelper::realpath($path);
        $ext = strtolower(pathinfo($real, PATHINFO_EXTENSION));
        if ('css' !== $ext && 'js' !== $ext) {
            continue;
        }
        // ok: claude.php.wordpress.file.tainted-realpath-no-extension-check
        if (is_file($real)) {
            $sources[] = array('filepath' => $real);
        }
    }
    return $sources;
}

// ── Safe: validate_file() guard applied in the same function ───────────────
function combine_single_safe_validate_file() {
    $name = $_POST['file'];
    $path = WP_CONTENT_DIR . '/uploads/' . $name;
    if (0 !== validate_file($path)) {
        return;
    }
    // ok: claude.php.wordpress.file.tainted-realpath-no-extension-check
    if (is_file($path)) {
        echo 'exists';
    }
}

// ── Safe: hardcoded path, no request input in the function ─────────────────
function check_fixed_manifest() {
    $path = WP_CONTENT_DIR . '/cache/fixed-manifest.json';
    // ok: claude.php.wordpress.file.tainted-realpath-no-extension-check
    if (file_exists($path)) {
        echo 'exists';
    }
}

// ── Safe: fully-constant path, request param read elsewhere in the SAME
// function for an unrelated purpose (no relation to the checked $PATH) ─────
function maybe_load_optional_email_class() {
    $preview = isset( $_GET['preview'] ) ? $_GET['preview'] : '';
    // ok: claude.php.wordpress.file.tainted-realpath-no-extension-check
    if ( file_exists( WC_ABSPATH . '/includes/emails/class-wc-email-customer-processing-order.php' ) ) {
        echo $preview;
    }
}
