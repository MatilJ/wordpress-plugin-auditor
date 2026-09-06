<?php

// ── Vulnerable: method returns is_user_logged_in() with no capability check ──

// ruleid: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
function logged_in_permissions_check() {
    return is_user_logged_in();
}

// ruleid: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
function check_if_authenticated() {
    if ( ! is_user_logged_in() ) {
        return false;
    }
    return is_user_logged_in();
}

// ── Vulnerable: guard-clause shape `if ( is_user_logged_in() ) { return true; }`
//    on a *_permissions_check method with no capability check ──

// ruleid: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
public function update_item_permissions_check( $request ) {
    if ( is_user_logged_in() ) {
        return true;
    }
}

// ruleid: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
public function delete_item_permissions_check( $request ) {
    if ( is_user_logged_in() ) {
        return true;
    }
}

// ── OK: method also checks current_user_can() ──

// ok: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
function manage_options_permissions_check() {
    return current_user_can( 'manage_options' );
}

// ok: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
function edit_posts_permissions_check() {
    return is_user_logged_in() && current_user_can( 'edit_posts' );
}

// Fix shape: bare capability check, no logged-in short-circuit.
// ok: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
public function patched_update_item_permissions_check( $request ) {
    return current_user_can( 'manage_options' );
}

// Guard-clause present but a capability check also present -> negative clause suppresses.
// ok: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
public function mixed_item_permissions_check( $request ) {
    if ( is_user_logged_in() ) {
        return true;
    }
    return current_user_can( 'manage_options' );
}

// Guard-clause shape but NOT a *_permissions_check name -> new branch is name-scoped.
// ok: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
function widget_visible_for_user() {
    if ( is_user_logged_in() ) {
        return true;
    }
    return false;
}

// Guard-clause present, but a capability check exists in condition form (if(current_user_can()))
// -> strengthened negative clause suppresses (real gate present, e.g. plus an ownership check).
// ok: claude.php.wordpress.access-control.rest-permission-method-logged-in-only
public function owner_item_permissions_check( $request ) {
    if ( current_user_can( 'manage_others_things' ) ) {
        return true;
    }
    if ( is_user_logged_in() ) {
        return true;
    }
    return false;
}
