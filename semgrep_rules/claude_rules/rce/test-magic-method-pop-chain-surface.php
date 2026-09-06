<?php

// ---- TRUE POSITIVES: Primary entry points (auto-invoked during deserialization) ----

class DestructGadget {
    private $file;
    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-surface
    function __destruct() {
        if ($this->file) {
            unlink($this->file);
        }
    }
}

class WakeupGadget {
    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-surface
    function __wakeup() {
        $this->init();
    }
}

class UnserializeGadget {
    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-surface
    function __unserialize(array $data) {
        $this->file = $data['file'];
        $this->init();
    }
}

// ---- FALSE POSITIVES: truly empty bodies (defensive no-op stubs) ----

class SingletonHardening {
    // ok: claude.php.wordpress.rce.magic-method-pop-chain-surface
    function __wakeup() { }
}

class EmptyDestruct {
    // ok: claude.php.wordpress.rce.magic-method-pop-chain-surface
    function __destruct() { }
}

// ---- TRUE POSITIVES: Intermediate gadgets (not auto-invoked, triggered from __destruct body) ----

class ToStringGadget {
    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-intermediate
    function __toString() {
        return file_get_contents($this->template);
    }
}

class CallGadget {
    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-intermediate
    function __call($name, $args) {
        return call_user_func_array([$this->delegate, $name], $args);
    }
}
