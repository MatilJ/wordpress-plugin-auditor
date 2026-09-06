<?php
// claude.php.wordpress.access-control.request-param-precedence-over-derived-owner-id test cases

// ── Vulnerable patterns ─────────────────────────────────────────────────────

function has_enrolled_content_access($content, $object_id = 0, $user_id = 0) {
    $object_id = get_post_id($object_id);
    // ruleid: claude.php.wordpress.access-control.request-param-precedence-over-derived-owner-id
    $course_id = $_GET['course'];
    if (!$course_id) {
        $course_id = get_course_id_by($content, $object_id);
    }
    if (is_enrolled($course_id, $user_id)) {
        return true;
    }
    return false;
}

function group_content_access($content, $object_id = 0) {
    $user_id = get_current_user_id();
    // ruleid: claude.php.wordpress.access-control.request-param-precedence-over-derived-owner-id
    $group_id = Input::get('group', 0, Input::TYPE_INT);
    if (empty($group_id)) {
        $group_id = derive_group_id_from_post($object_id);
    }
    if ($this->is_member($group_id, $user_id)) {
        return true;
    }
    return false;
}

// ── Safe patterns ────────────────────────────────────────────────────────────

// ok: claude.php.wordpress.access-control.request-param-precedence-over-derived-owner-id
// Correct: the fix removes the request-controlled override entirely — the
// owning course id is always derived from the actual object being accessed.
function has_enrolled_content_access_fixed($content, $object_id = 0, $user_id = 0) {
    $object_id = get_post_id($object_id);
    $course_id = get_course_id_by($content, $object_id);
    if (is_enrolled($course_id, $user_id)) {
        return true;
    }
    return false;
}

// ok: claude.php.wordpress.access-control.request-param-precedence-over-derived-owner-id
// Safe: the request-controlled override is gated behind an explicit
// capability check on the current user before being applied.
function admin_view_as_course($content, $object_id = 0, $user_id = 0) {
    $course_id = $_GET['course'];
    if (current_user_can('manage_options')) {
        if (!$course_id) {
            $course_id = get_course_id_by($content, $object_id);
        }
        if (is_enrolled($course_id, $user_id)) {
            return true;
        }
    }
    return false;
}

// ok: claude.php.wordpress.access-control.request-param-precedence-over-derived-owner-id
// Safe: a normal WP_Query read using a request-derived id — no ownership /
// enrollment / membership authorization function is involved at all.
function get_posts_for_category() {
    $cat_id = $_GET['cat'];
    if (!$cat_id) {
        $cat_id = get_query_var('cat');
    }
    return new WP_Query(['cat' => $cat_id]);
}
