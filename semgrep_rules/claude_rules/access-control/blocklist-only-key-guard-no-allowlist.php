<?php
// Test cases for claude.php.wordpress.access-control.blocklist-only-key-guard-no-allowlist

// === TRUE POSITIVES — denylist-only key guard, no companion allow-list ===

// Exact pre-fix shape: a "banned meta key" guard whose only logic is a
// foreach over a hardcoded denylist doing substring matching. Any key not
// matching one of the enumerated substrings is accepted by every caller
// that uses this function as the sole gate before a usermeta write.
class Meta_Guard {
    public $banned_keys = array( 'capabilities', 'user_level', 'session_tokens' );

    public function is_metakey_banned( $meta_key ) {
        $is_banned = false;
        // ruleid: claude.php.wordpress.access-control.blocklist-only-key-guard-no-allowlist
        foreach ( $this->banned_keys as $ban ) {
            if ( is_numeric( $meta_key ) || false !== stripos( $meta_key, $ban ) ) {
                $is_banned = true;
                break;
            }
        }
        return $is_banned;
    }

    public function update_profile( $changes ) {
        foreach ( $changes as $key => $value ) {
            if ( $this->is_metakey_banned( $key ) ) {
                continue;
            }
            update_user_meta( get_current_user_id(), $key, $value );
        }
    }
}

// Differently-named guard, reversed stripos argument order, strcasecmp
// variant — confirms the pattern is not tied to UM's naming or argument
// order.
function is_field_blocked( $field_key ) {
    $blocked = array( 'role', 'wp_capabilities', 'user_pass' );
    $blocked_result = false;
    // ruleid: claude.php.wordpress.access-control.blocklist-only-key-guard-no-allowlist
    foreach ( $blocked as $entry ) {
        if ( strcasecmp( $entry, $field_key ) === 0 ) {
            $blocked_result = true;
        }
    }
    return $blocked_result;
}

// === FALSE POSITIVES — a positive allow-list is also present ===

// Post-fix shape: the same denylist loop is retained, but a companion
// allow-list check (in_array(..., true)) also gates acceptance in a
// submission context — this is the real 2.6.7 fix shape and must not fire.
class Meta_Guard_Fixed {
    public $banned_keys = array( 'capabilities', 'user_level', 'session_tokens' );
    public $usermeta_whitelist = array();

    public function is_metakey_banned( $meta_key, $context = '' ) {
        $is_banned = false;
        // ok: claude.php.wordpress.access-control.blocklist-only-key-guard-no-allowlist
        foreach ( $this->banned_keys as $ban ) {
            if ( is_numeric( $meta_key ) || false !== stripos( $meta_key, $ban ) ) {
                $is_banned = true;
                break;
            }
        }

        if ( ! $is_banned && 'submission' === $context && ! in_array( $meta_key, $this->usermeta_whitelist, true ) ) {
            $is_banned = true;
        }

        return $is_banned;
    }
}

// Allow-list expressed as array_key_exists() against a server-computed
// set of accepted keys — a different but equally valid positive-list form.
function is_option_key_disallowed( $option_key ) {
    $disallow = array( 'siteurl', 'home', 'admin_email' );
    $allowed_keys = array( 'display_name' => true, 'bio' => true );
    // ok: claude.php.wordpress.access-control.blocklist-only-key-guard-no-allowlist
    foreach ( $disallow as $entry ) {
        if ( false !== strpos( $option_key, $entry ) ) {
            return true;
        }
    }
    if ( ! array_key_exists( $option_key, $allowed_keys ) ) {
        return true;
    }
    return false;
}

// Ordinary WP data read unrelated to a key guard — a foreach/stripos shape
// that happens to appear in a normal lookup helper, not a banned-key gate.
// Function name does not match the banned/blocked/denylist naming regex.
function find_matching_taxonomy_term( $needle, $terms ) {
    // ok: claude.php.wordpress.access-control.blocklist-only-key-guard-no-allowlist
    foreach ( $terms as $term ) {
        if ( false !== stripos( $needle, $term ) ) {
            return get_term_by( 'name', $term, 'category' );
        }
    }
    return null;
}

// Path/directory-containment loop, not a meta/option/field key guard: the
// function name coincidentally matches the "restrict" token (isRestricted)
// and the AST shape (foreach + strpos + boolean flag) is identical to the
// key-blocklist idiom, but the domain is filesystem containment — the
// candidate variable is a path, not a key. Confirmed FP:
// shortpixel-image-optimiser 6.5.5 FileModel::isRestricted().
class File_Restriction_Guard {
    public $basedirs = array( '/var/www/uploads/', '/var/www/uploads2/' );

    public function isRestricted( $path ) {
        $restricted = true;
        // ok: claude.php.wordpress.access-control.blocklist-only-key-guard-no-allowlist
        foreach ( $this->basedirs as $basepath ) {
            if ( strpos( $path, $basepath ) !== false ) {
                $restricted = false;
                break;
            }
        }
        return $restricted;
    }
}
