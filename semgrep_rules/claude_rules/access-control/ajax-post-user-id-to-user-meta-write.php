<?php
/**
 * Test cases for claude.php.wordpress.access-control.ajax-post-user-id-to-user-meta-write
 *
 * Fires when an attacker-controlled user_id from HTTP parameters flows into
 * update_user_meta / delete_user_meta / add_user_meta without an ownership check
 * (current_user_can('edit_user', $user_id)).
 *
 * Confirmed TP pattern (WP Ghost / hide-my-wp 7.0.01 controllers/Twofactor.php):
 *   $user_id = HMWP_Classes_Tools::getValue('user_id');  // reads from $_POST
 *   HMWP_Classes_Tools::saveUserMeta('key', $value, $user_id);  // calls update_user_meta($user_id, ...)
 *   — only 'read' capability checked, no ownership verification.
 */

// ── MATCH: user_id from POST → update_user_meta, no ownership check ───────────

// Direct pattern: $_POST['user_id'] flows to update_user_meta first arg
$user_id = $_POST['user_id'];
// ruleid: claude.php.wordpress.access-control.ajax-post-user-id-to-user-meta-write
update_user_meta( (int) $user_id, 'hmwp_backup_codes', $codes );

// GET variant: IDOR via GET parameter
$uid = $_GET['user_id'];
// ruleid: claude.php.wordpress.access-control.ajax-post-user-id-to-user-meta-write
update_user_meta( (int) $uid, 'plugin_2fa_method', 'email' );

// delete_user_meta — same IDOR class
$target_user = $_POST['user_id'];
// ruleid: claude.php.wordpress.access-control.ajax-post-user-id-to-user-meta-write
delete_user_meta( (int) $target_user, 'plugin_totp_secret' );

// add_user_meta — attacker creates meta for any user
$new_uid = $_REQUEST['uid'];
// ruleid: claude.php.wordpress.access-control.ajax-post-user-id-to-user-meta-write
add_user_meta( (int) $new_uid, 'plugin_enrolled', '1' );

// ── NO MATCH: user_id comes from a non-POST source (no taint) ────────────────
// Note: current_user_can() as a sanitizer does NOT clear taint on $user_id
// because it is a guard, not a data transformer. Hits where POST-sourced
// user_ids reach update_user_meta still require manual triage regardless of
// adjacent capability checks (see triage guidance in rule message).

// user_id from get_current_user_id() — not POST-sourced, no taint
$current_uid = get_current_user_id();
// ok: claude.php.wordpress.access-control.ajax-post-user-id-to-user-meta-write
update_user_meta( $current_uid, 'plugin_setting', 'value' );

// Hardcoded integer user_id — not POST-sourced, no taint
// ok: claude.php.wordpress.access-control.ajax-post-user-id-to-user-meta-write
update_user_meta( 1, 'plugin_setting', 'value' );
