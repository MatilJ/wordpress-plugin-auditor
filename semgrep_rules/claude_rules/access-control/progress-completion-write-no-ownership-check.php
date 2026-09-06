<?php
// claude.php.wordpress.access-control.progress-completion-write-no-ownership-check test cases

// ── Vulnerable patterns ─────────────────────────────────────────────────────

// ruleid: claude.php.wordpress.access-control.progress-completion-write-no-ownership-check
function mark_lesson_complete() {
    tutor_utils()->checking_nonce();
    $user_id = get_current_user_id();
    if (!$user_id) {
        die('Please Sign-In');
    }
    $lesson_id = Input::post('lesson_id', 0, Input::TYPE_INT);
    if (!$lesson_id) {
        return;
    }
    $validated = apply_filters('tutor_validate_lesson_complete', true, $user_id, $lesson_id);
    if (!$validated) {
        return;
    }
    LessonModel::mark_lesson_complete($lesson_id);
}

// ruleid: claude.php.wordpress.access-control.progress-completion-write-no-ownership-check
function ajax_complete_task() {
    check_ajax_referer('tasks_nonce');
    $task_id = $_POST['task_id'];
    mark_task_complete($task_id);
}

// ── Safe patterns ────────────────────────────────────────────────────────────

// ok: claude.php.wordpress.access-control.progress-completion-write-no-ownership-check
// Correct: derives the resource's real owning parent from the submitted id
// and denies unless the current user is enrolled/a member of it, mirroring
// the fix recommended for the vulnerable case above.
function mark_lesson_complete_fixed() {
    tutor_utils()->checking_nonce();
    $user_id = get_current_user_id();
    if (!$user_id) {
        die('Please Sign-In');
    }
    $lesson_id = Input::post('lesson_id', 0, Input::TYPE_INT);
    if (!$lesson_id) {
        return;
    }
    $course_id = tutor_utils()->get_course_id_by('lesson', $lesson_id);
    if (!tutor_utils()->is_enrolled($course_id, $user_id)) {
        die('User is not enrolled in course');
    }
    LessonModel::mark_lesson_complete($lesson_id);
}

// ok: claude.php.wordpress.access-control.progress-completion-write-no-ownership-check
// Safe: same generalized shape (bare-function sink call, not a static method),
// guarded by a bare (non-static) membership check before the write.
function mark_item_complete_positive_style() {
    $user_id = get_current_user_id();
    $item_id = Input::post('item_id', 0, Input::TYPE_INT);
    $course_id = derive_course_id($item_id);
    if (!is_enrolled($course_id, $user_id)) {
        die('nope');
    }
    mark_item_complete($item_id);
}

// ok: claude.php.wordpress.access-control.progress-completion-write-no-ownership-check
// Safe: a normal WP_Query read using a request-derived id — no completion /
// progress-tracking write sink is involved at all.
function get_posts_for_category() {
    $cat_id = $_GET['cat'];
    return new WP_Query(['cat' => $cat_id]);
}
