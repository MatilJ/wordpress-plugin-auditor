<?php

function load_template_unsafe( $tpl ) {
    $path = PLUGIN_DIR . '/templates/' . $_GET['tpl'] . '.php';
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    if ( file_exists( $path ) ) {
        include $path;
    }
}

function load_module_unsafe( $mod ) {
    $path = PLUGIN_DIR . '/modules/' . $_REQUEST['mod'] . '.php';
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    if ( is_file( $path ) ) {
        require_once $path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_template_with_sanitizer( $tpl ) {
    $name = sanitize_file_name( $_GET['tpl'] );
    $path = PLUGIN_DIR . '/templates/' . $name . '.php';
    if ( file_exists( $path ) ) {
        include $path;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_core_class() {
    $suffix = '/includes/class-core.php';
    if ( file_exists( __DIR__ . $suffix ) ) {
        include __DIR__ . $suffix;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
// $path is built entirely from a plugin-defined constant + string literals
// (no PHP variable) — a fixed, developer-controlled path, same rationale
// as the __DIR__/ABSPATH cases above but generalized to any plugin's own
// PLUGIN_DIR-style define.
function load_bundled_optional_file() {
    if ( file_exists( MY_PLUGIN_DIR . 'includes/custom.php' ) ) {
        include_once MY_PLUGIN_DIR . 'includes/custom.php';
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function upgrade_core() {
    if ( file_exists( ABSPATH.'/wp-admin/includes/update.php' ) ) {
        include_once ABSPATH.'/wp-admin/includes/update.php';
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_legacy_compat_file() {
    $suffix = '/compat/legacy.php';
    if ( file_exists( dirname(__FILE__) . $suffix ) ) {
        require dirname(__FILE__) . $suffix;
    }
}

class DeferredLangLoader {
    private $_lang_path;

    // Negated guard clause + deferred property assignment, consumed by a
    // read sink (file_get_contents) in a different method entirely.
    public function setLang( $lang ) {
        if ( empty( $lang ) ) {
            throw new Exception( 'missing' );
        }
        // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
        if ( !file_exists( PLUGIN_DIR . 'lang/' . $lang ) ) {
            throw new Exception( 'not found' );
        }
        $this->_lang_path = PLUGIN_DIR . 'lang/' . $lang;
    }

    public function getLangData() {
        return json_decode( file_get_contents( $this->_lang_path ) );
    }
}

// Same negated-guard shape, deferred to a plain local variable instead
// of a property.
function load_module_deferred_unsafe( $mod ) {
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    if ( !is_file( PLUGIN_DIR . 'modules/' . $mod . '.php' ) ) {
        return null;
    }
    $resolved = PLUGIN_DIR . 'modules/' . $mod . '.php';
    return $resolved;
}

class DeferredLangLoaderFixed {
    private $_lang_path;

    // ok: claude.php.wordpress.file.file-exists-not-sanitizer
    // Fix shape: basename() + extension allow-list + realpath() prefix
    // containment before the deferred assignment.
    public function setLang( $lang ) {
        if ( empty( $lang ) ) {
            throw new Exception( 'missing' );
        }
        $lang = basename( $lang );
        if ( substr( $lang, -8 ) !== '.inc.php' ) {
            throw new Exception( 'invalid format' );
        }
        $safePath = PLUGIN_DIR . 'lang/' . $lang;
        $realPath = realpath( $safePath );
        $realLangDir = realpath( PLUGIN_DIR . 'lang/' );
        if ( $realPath === false || strpos( $realPath, $realLangDir ) !== 0 ) {
            throw new Exception( 'traversal detected' );
        }
        if ( !file_exists( $safePath ) ) {
            throw new Exception( 'not found' );
        }
        $this->_lang_path = $safePath;
    }

    public function getLangData() {
        return json_decode( file_get_contents( $this->_lang_path ) );
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
function load_module_deferred_sanitized( $mod ) {
    $safe = sanitize_file_name( $mod );
    if ( !is_file( PLUGIN_DIR . 'modules/' . $safe . '.php' ) ) {
        return null;
    }
    $resolved = PLUGIN_DIR . 'modules/' . $safe . '.php';
    return $resolved;
}

// elseif/combined-condition form: file_exists() is one clause of a compound
// elseif condition (paired with a recursion guard), not the sole condition
// of a standalone if. CVE-2025-12851 (My auctions allegro) shape.
class ComponentLoaderElseifTp {
    public static function getInstance( $instance, $rec = false ) {
        $path = COMPONENT_DIR . '/' . str_replace( '_', '/', $instance ) . '.php';
        // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
        if ( class_exists( $instance ) ) {
            return new $instance();
        } elseif ( file_exists( $path ) && !$rec ) {
            require_once( $path );
            return self::getInstance( $instance, true );
        }
        return false;
    }
}

class ComponentLoaderElseifTp2 {
    public static function loadModule( $mod, $rec = false ) {
        $path = MODULE_DIR . '/' . $mod . '.php';
        // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
        if ( class_exists( $mod ) ) {
            return true;
        } elseif ( !$rec && file_exists( $path ) ) {
            include( $path );
            return true;
        }
        return false;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
// Fix shape: inline strpos() traversal-character blocklist with an early
// return, before the path is ever built (CVE-2025-12851 patch).
class ComponentLoaderElseifFixed {
    public static function getInstance( $instance, $rec = false ) {
        if ( strpos( $instance, '-' ) !== false || strpos( $instance, '.' ) !== false || strpos( $instance, '/' ) !== false ) {
            return false;
        }
        $path = COMPONENT_DIR . '/' . str_replace( '_', '/', $instance ) . '.php';
        if ( class_exists( $instance ) ) {
            return new $instance();
        } elseif ( file_exists( $path ) && !$rec ) {
            require_once( $path );
            return self::getInstance( $instance, true );
        }
        return false;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
// Same fix shape expressed with str_contains() instead of strpos().
class ComponentLoaderElseifFixed2 {
    public static function loadModule( $mod, $rec = false ) {
        if ( str_contains( $mod, '..' ) || str_contains( $mod, '/' ) ) {
            return false;
        }
        $path = MODULE_DIR . '/' . $mod . '.php';
        if ( class_exists( $mod ) ) {
            return true;
        } elseif ( !$rec && file_exists( $path ) ) {
            include( $path );
            return true;
        }
        return false;
    }
}

// Negated early-return guard, combined with an unrelated OR'd condition and
// an "@" error-suppressed call, where the SAME variable is re-used directly
// (no reassignment) by an include() after an intervening fopen() step —
// the "read a keyed data file and execute it as PHP" shape used by
// file-backed object/page caches.
class FileBackedCacheReaderUnsafe {
    public function cache_get( $file ) {
        if ( !@is_file( $file ) || empty( @filesize( $file ) ) ) {
            return false;
        }
        if ( !$handle = @fopen( $file, 'rb' ) ) {
            return false;
        }
        // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
        $data = @include $file;
        return $data;
    }
}

function read_module_deferred_unsafe( $mod ) {
    $path = MODULE_DIR . '/' . $mod . '.php';
    if ( !file_exists( $path ) ) {
        return null;
    }
    $fh = fopen( $path, 'rb' );
    // ruleid: claude.php.wordpress.file.file-exists-not-sanitizer
    require_once $path;
    return $fh;
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
// Vendor fix shape: strip './' and '../' segments in-place (preg_replace)
// immediately inside the same function, before the existence check.
class FileBackedCacheReaderFixed {
    public function cache_get( $file ) {
        $file = preg_replace( '@(\.\./|\./)@', '', $file );
        if ( !@is_file( $file ) || empty( @filesize( $file ) ) ) {
            return false;
        }
        if ( !$handle = @fopen( $file, 'rb' ) ) {
            return false;
        }
        $data = @include $file;
        return $data;
    }
}

// ok: claude.php.wordpress.file.file-exists-not-sanitizer
// Same deferred/negated-guard-then-raw-reuse shape, but the assembled path
// itself is reassigned through sanitize_key() before the existence check.
function read_module_deferred_sanitized( $mod ) {
    $path = MODULE_DIR . '/' . $mod . '.php';
    $path = sanitize_key( $path );
    if ( !is_file( $path ) ) {
        return null;
    }
    $fh = fopen( $path, 'rb' );
    include $path;
    return $fh;
}

// $file is built from a glob() listing of the plugin's own bundled
// directory (a __DIR__-rooted glob pattern) — no request-derived input
// reaches $file at any point; populating it with anything else would
// require a separate file-write primitive, a different bug entirely.
function myplugin_load_bundled_widgets() {
    $widgets = glob( __DIR__ . '/widgets/*', GLOB_ONLYDIR | GLOB_NOSORT );
    foreach ( $widgets as $path ) {
        $slug = str_replace( __DIR__ . '/widgets/', '', $path );
        $file = trailingslashit( $path ) . $slug . '.php';
        // ok: claude.php.wordpress.file.file-exists-not-sanitizer
        if ( file_exists( $file ) ) {
            require_once $file;
        }
    }
}
