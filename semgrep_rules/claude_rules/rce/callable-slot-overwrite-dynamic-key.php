<?php
/**
 * Test cases for callable-slot-overwrite-dynamic-key.yaml
 * Rule id: claude.php.wordpress.rce.callable-slot-overwrite-dynamic-key
 *
 * Detects: a class property read by a LITERAL key straight into
 * call_user_func()/call_user_func_array(), where the SAME property is also
 * written elsewhere in the class (possibly a different method) using a
 * NON-LITERAL key — a cross-method confused-deputy shape plain taint
 * analysis (intra-procedural) does not see.
 */

// ─── Vulnerable patterns ──────────────────────────────────────────────────

// TP: generalized real-world shape — a per-submission loop (in one method)
// writes into a shared placeholder dictionary using a concatenated key built
// from the loop/field name, while a different method reads a reserved
// literal key from the same dictionary straight into call_user_func().
class Form_Processor_Vulnerable {
    public $placeholders = [];

    public function build_placeholders($fields) {
        foreach ($fields as $name => $value) {
            $this->_apply_field($name, $value);
        }
    }

    private function _apply_field($k, $v) {
        $this->placeholders['{' . $k . '}'] = sanitize_text_field($v);
    }

    public function render() {
        if (isset($this->placeholders['{thisPermalink}'])) {
            // ruleid: claude.php.wordpress.rce.callable-slot-overwrite-dynamic-key
            $this->placeholders['{thisPermalink}'] = call_user_func($this->placeholders['{thisPermalink}']);
        }
    }
}

// TP: bare-variable key (no concatenation) — same confused-deputy shape,
// simpler write expression, call_user_func_array() variant.
class Action_Registry_Vulnerable {
    public $actions = [];

    public function register_from_request($key, $callback_name) {
        $this->actions[$key] = $callback_name;
    }

    public function run_default() {
        // ruleid: claude.php.wordpress.rce.callable-slot-overwrite-dynamic-key
        return call_user_func_array($this->actions['default_action'], []);
    }
}

// ─── Safe patterns ─────────────────────────────────────────────────────────

// OK: fixed shape — the call site no longer trusts the shared property; it
// re-resolves the callable from a fresh, hardcoded source into a local
// variable immediately before invocation (matches the real-world fix: the
// sink argument is a plain variable, not $OBJ->$PROP[$LITERAL] anymore).
class Form_Processor_Fixed {
    public $placeholders = [];
    private $reserved = ['thisPermalink', 'entryCounter'];

    private function _apply_field($k, $v) {
        if (in_array($k, $this->reserved, true)) {
            return;
        }
        $this->placeholders['{' . $k . '}'] = sanitize_text_field($v);
    }

    public function render() {
        $defaults = (new Default_Placeholders())->general_placeholders;
        $callable = $defaults['{thisPermalink}'];
        // ok: claude.php.wordpress.rce.callable-slot-overwrite-dynamic-key
        $this->placeholders['{thisPermalink}'] = call_user_func($callable);
    }
}

// OK: no co-occurring dynamic-key write anywhere in the class — the property
// is only ever seeded from a hardcoded defaults table, never from per-item
// request/field data. Structurally not the vulnerable shape.
class Static_Callback_Registry {
    public $handlers = [];

    public function __construct() {
        $this->handlers['on_save'] = 'MyPlugin\\Hooks::on_save';
    }

    public function run() {
        // ok: claude.php.wordpress.rce.callable-slot-overwrite-dynamic-key
        return call_user_func($this->handlers['on_save']);
    }
}

// OK: registry-dispatch pattern — the write uses a dynamic key, but the read
// is two-level ($OBJ->$PROP[$KEY]['callback']), so the invoked value is
// always a developer-registered sub-field, not the user-influenced slot
// itself. Same established exclusion as the sibling dynamic-callable-user-input rule.
class Two_Level_Registry_Dispatch {
    public $ajax_actions = [];

    public function register($action, $meta) {
        $this->ajax_actions[$action] = $meta;
    }

    public function dispatch($action) {
        // ok: claude.php.wordpress.rce.callable-slot-overwrite-dynamic-key
        return call_user_func($this->ajax_actions[$action]['callback']);
    }
}
