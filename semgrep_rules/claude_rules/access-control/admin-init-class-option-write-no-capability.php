<?php
// Tests for claude.php.wordpress.access-control.admin-init-class-option-write-no-capability
// NOTE: join mode requires `semgrep login` — --test and standalone --config scans of
// this file will fail locally without it. Verify via sub-rule isolation or with login.
//
// Method names are kept UNIQUE across every class in this file: the join key is
// (file path, class name), not (class, method name) alone across files, so two
// unrelated classes reusing the same method name would not cross-pollinate, but
// classes MUST be unique per test case to avoid joining across cases.

// ── TRUE POSITIVES ─────────────────────────────────────────────────────────────

// Case 1: multi-step setup wizard. The admin_init-registered entry method has no
// capability/nonce check and routes the request-selected step through a callback
// table (call_user_func on a dynamically-looked-up array entry) — several hops
// removed from the sibling method that performs the actual write, which also has
// no capability/nonce check of its own.
class WizardDispatchTest {
    private $steps;

    public function __construct() {
        add_action( 'admin_init', array( $this, 'run_setup' ), 99 );
    }

    public function run_setup() {
        if ( empty( $_GET['page'] ) || 'my_setup' !== $_GET['page'] ) {
            return;
        }
        $step = isset( $_GET['step'] ) ? sanitize_key( $_GET['step'] ) : 'welcome';
        $this->steps = array(
            'customize' => array( 'view' => array( $this, 'render_customize_step' ) ),
        );
        if ( ! empty( $this->steps[ $step ]['view'] ) ) {
            call_user_func( $this->steps[ $step ]['view'] );
        }
    }

    public function render_customize_step() {
        if ( isset( $_POST['submit_customize'] ) ) {
            $this->persist_customize_choices();
        }
    }

    public function persist_customize_choices() {
        if ( isset( $_POST['site_logo'] ) ) {
            // ruleid: claude.php.wordpress.access-control.admin-init-class-option-write-no-capability
            set_theme_mod( 'custom_logo', $_POST['site_logo'] );
        }
        if ( isset( $_POST['site_title'] ) ) {
            // ruleid: claude.php.wordpress.access-control.admin-init-class-option-write-no-capability
            update_option( 'blogname', $_POST['site_title'] );
        }
    }
}

// Case 2: flatter shape — the admin_init-registered method calls a sibling
// directly, one hop, still no auth anywhere in the class.
class DirectDelegateTest {
    public function __construct() {
        add_action( 'admin_init', array( $this, 'maybe_save_settings' ) );
    }

    public function maybe_save_settings() {
        if ( isset( $_POST['save_widget_settings'] ) ) {
            $this->write_widget_option();
        }
    }

    public function write_widget_option() {
        // ruleid: claude.php.wordpress.access-control.admin-init-class-option-write-no-capability
        update_option( 'widget_display_mode', $_POST['display_mode'] );
    }
}

// ── FALSE POSITIVES (ok) ────────────────────────────────────────────────────────

// Case 3: the writing method itself performs the capability check — safe.
class GatedWriteTest {
    public function __construct() {
        add_action( 'admin_init', array( $this, 'run_setup_gated' ), 99 );
    }

    public function run_setup_gated() {
        $step = isset( $_GET['step'] ) ? sanitize_key( $_GET['step'] ) : 'welcome';
        if ( 'customize' === $step ) {
            $this->persist_customize_choices_gated();
        }
    }

    public function persist_customize_choices_gated() {
        // ok: claude.php.wordpress.access-control.admin-init-class-option-write-no-capability
        if ( ! current_user_can( 'manage_options' ) || ! isset( $_REQUEST['_wpnonce'] ) || ! wp_verify_nonce( $_REQUEST['_wpnonce'], 'setup_customize' ) ) {
            wp_die( 'Not authorized' );
        }
        update_option( 'blogname', $_POST['site_title'] );
        set_theme_mod( 'custom_logo', $_POST['site_logo'] );
    }
}

// Case 4: the admin_init-registered method itself performs the capability check
// before ever dispatching — safe, even though the sibling method has no check.
class GatedEntryTest {
    public function __construct() {
        add_action( 'admin_init', array( $this, 'run_setup_entry_gated' ), 99 );
    }

    public function run_setup_entry_gated() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        if ( isset( $_POST['submit_customize'] ) ) {
            $this->persist_choices_entry_gated();
        }
    }

    // ok: claude.php.wordpress.access-control.admin-init-class-option-write-no-capability
    public function persist_choices_entry_gated() {
        update_option( 'blogname', $_POST['site_title'] );
    }
}

// Case 5: option write built only from a hardcoded/internal value — no external
// input reaches the sink, so there is nothing for an unauthenticated caller to
// influence even though no capability check is present.
class HardcodedWriteTest {
    public function __construct() {
        add_action( 'admin_init', array( $this, 'run_self_heal' ) );
    }

    public function run_self_heal() {
        $this->mark_migration_done();
    }

    public function mark_migration_done() {
        // ok: claude.php.wordpress.access-control.admin-init-class-option-write-no-capability
        update_option( 'my_plugin_migration_v2_done', true );
    }
}
