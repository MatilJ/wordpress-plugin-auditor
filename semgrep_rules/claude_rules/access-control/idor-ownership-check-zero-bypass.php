<?php
// claude.php.wordpress.access-control.idor-ownership-check-zero-bypass test cases

// ── Vulnerable patterns ────────────────────────────────────────────────────────
// ruleid annotation must be immediately before the $OWNER_ID = (int)(...) line
// because that is where the multi-statement pattern match begins.

$currentUserId = get_current_user_id();
// ruleid: claude.php.wordpress.access-control.idor-ownership-check-zero-bypass
$bookingUserId = (int) ($booking['user_id'] ?? 0);
if (!$currentUserId) {
    return new WP_Error('unauthorized', 'Login required.', ['status' => 401]);
}
if ($bookingUserId && $currentUserId !== $bookingUserId && !current_user_can('manage_options')) {
    return new WP_Error('forbidden', 'Access denied.', ['status' => 403]);
}

$cur = get_current_user_id();
// ruleid: claude.php.wordpress.access-control.idor-ownership-check-zero-bypass
$authorId = (int) ($post['author_id'] ?? 0);
if ($authorId && $authorId !== $cur && !current_user_can('edit_others_posts')) {
    wp_send_json_error(['message' => 'Not your resource.'], 403);
}

$currentUser = get_current_user_id();
// ruleid: claude.php.wordpress.access-control.idor-ownership-check-zero-bypass
$ownerId = intval($record['customer_id'] ?? 0);
if ($ownerId && $currentUser !== $ownerId && !current_user_can('manage_options')) {
    return new WP_Error('forbidden', 'Forbidden.', ['status' => 403]);
}

// ── Safe patterns ──────────────────────────────────────────────────────────────

// ok: claude.php.wordpress.access-control.idor-ownership-check-zero-bypass
// Correct: uses explicit !== 0 guard — the short-circuit bypass is eliminated.
// First condition is $bookingUserId !== 0 (a comparison), not a bare variable,
// so the pattern `if ($OWNER_ID && ...)` does not match.
$currentUserId = get_current_user_id();
$bookingUserId = (int) ($booking['user_id'] ?? 0);
if ($bookingUserId !== 0 && $currentUserId !== $bookingUserId && !current_user_can('manage_options')) {
    return new WP_Error('forbidden', 'Access denied.', ['status' => 403]);
}

// ok: claude.php.wordpress.access-control.idor-ownership-check-zero-bypass
// No current_user_can() in the condition — rule requires !current_user_can($CAP),
// so a plain numeric comparison without a capability check does not match.
$count = (int) ($data['count'] ?? 0);
if ($count && $count !== $maxAllowed) {
    return new WP_Error('limit_exceeded', 'Limit exceeded.', ['status' => 400]);
}
