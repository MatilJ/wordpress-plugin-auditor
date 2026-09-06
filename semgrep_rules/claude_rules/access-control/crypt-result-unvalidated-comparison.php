<?php

function checkAccessCryptedKey($whitelistItem) {
    // ruleid: claude.php.wordpress.access-control.crypt-result-unvalidated-comparison
    $cryptedKey = substr(crypt($whitelistItem['api-key'], '$2y$10$' . $_POST['salt'] . '$'), 28);
    if ($_POST['api-key-crypted'] == $cryptedKey) {
        // Access granted!
        return true;
    }
    return false;
}

function checkAccessTokenLeft() {
    $secret = get_option('my_secret');
    // ruleid: claude.php.wordpress.access-control.crypt-result-unvalidated-comparison
    $crypted = crypt($secret, '$1$' . $_GET['salt'] . '$');
    if ($crypted == $_GET['token']) {
        return true;
    }
    return false;
}

// ok: claude.php.wordpress.access-control.crypt-result-unvalidated-comparison
function checkAccessLengthValidated($whitelistItem) {
    $crypted = substr(crypt($whitelistItem['api-key'], '$2y$10$' . $_POST['salt'] . '$'), 28);
    if (strlen($crypted) !== 31) {
        return false;
    }
    if ($_POST['api-key-crypted'] == $crypted) {
        return true;
    }
    return false;
}

// ok: claude.php.wordpress.access-control.crypt-result-unvalidated-comparison
function checkAccessHashEquals() {
    $secret = get_option('my_secret');
    $crypted = crypt($secret, '$2y$10$' . $_POST['salt'] . '$');
    if (hash_equals($crypted, $_POST['api-key-crypted'])) {
        return true;
    }
    return false;
}
