<?php

function checkAppToken($token, $userToken = "", $userSession = "")
{
    global $wpdb;

    if ($token) {
        // ruleid: claude.php.wordpress.access-control.auth-token-decode-no-signature-verify
        $data = @base64_decode($token);

        if (preg_match('/([\d]+).*/', $data, $m)) {
            $userId = count($m) === 2 && (int)$m[1] ? $m[1] : 0;

            if ($userSession && (int)$userSession === (int)$userId) {
                return true;
            }

            $users = getAppUsersPermissions();

            foreach ($users as $user) {
                if ($user->ID == $userId && $user->get('app_permission')) return true;
            }
        }

        return false;
    }

    return false;
}

function getUserIdFromToken($token)
{
    if (!$token) {
        return null;
    }

    // ruleid: claude.php.wordpress.access-control.auth-token-decode-no-signature-verify
    $decoded = base64_decode($token);

    if (preg_match('/([\d]+).*/', $decoded, $m)) {
        $userId = count($m) === 2 && (int)$m[1] ? $m[1] : 0;
        return $userId ?: null;
    }

    return null;
}

// ok: claude.php.wordpress.access-control.auth-token-decode-no-signature-verify
function checkSignedAppToken($token, $secret)
{
    $data = base64_decode($token);

    if (preg_match('/([\d]+)\.(.+)/', $data, $m)) {
        $userId = (int)$m[1];
        $signature = $m[2];

        $expected = hash_hmac('sha256', (string)$userId, $secret);

        if (hash_equals($expected, $signature)) {
            return $userId;
        }
    }

    return null;
}

// ok: claude.php.wordpress.access-control.auth-token-decode-no-signature-verify
function checkStoredOtpToken($token)
{
    global $wpdb;

    if (!$token || in_array($token, array("web", "usersFind"))) {
        return false;
    }

    $userMeta = $wpdb->get_row($wpdb->prepare(
        "SELECT UM.meta_key, UM.meta_value, UM.user_id FROM {$wpdb->usermeta} AS UM WHERE UM.meta_key IN ('app_otp') AND UM.meta_value = %s",
        $token
    ));

    if ($userMeta && $userMeta->user_id) {
        return true;
    }

    return false;
}
