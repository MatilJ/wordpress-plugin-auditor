<?php
// Test cases for claude.php.wordpress.rce.magic-method-pop-chain-surface
// and claude.php.wordpress.rce.magic-method-pop-chain-intermediate

class Gadget_Entry {
    public $handler;

    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-surface
    public function __destruct() {
        $this->handler->run();
    }
}

class Empty_Destruct_Singleton {
    // ok: claude.php.wordpress.rce.magic-method-pop-chain-surface
    public function __destruct() {
    }
}

class Gadget_Intermediate {
    public $inner;

    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-intermediate
    public function __toString() {
        $this->inner->trigger();
        return 'x';
    }
}

class Gadget_Call_Forward {
    public $target;

    // ruleid: claude.php.wordpress.rce.magic-method-pop-chain-intermediate
    public function __call( $name, $args ) {
        return call_user_func_array( array( $this->target, $name ), $args );
    }
}

// ok: claude.php.wordpress.rce.magic-method-pop-chain-intermediate
// Trivial single-statement cast-and-return body — no method call, property
// write, or other side effect, so it cannot itself act as a POP-chain
// gadget step. Confirmed FP: shortpixel-image-optimiser 6.5.5
// DirectoryModel::__toString() / FileModel::__toString().
class Path_Value_Object {
    private $path;

    public function __toString() {
        return (string) $this->path;
    }
}
