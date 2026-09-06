<?php

class Route_Base {
    private function method_exists_in_current_class( string $method ): bool {
        $class_name = get_class( $this );
        try {
            $reflection = new ReflectionClass( $class_name );
        } catch ( \ReflectionException $e ) {
            return false;
        }
        if ( ! $reflection->hasMethod( $method ) ) {
            return false;
        }
        $method_ref = $reflection->getMethod( $method );

        // ruleid: claude.php.wordpress.access-control.reflection-declaring-class-auth-check
        return ( $method_ref && $class_name === $method_ref->class );
    }
}

class Another_Route_Base {
    // ruleid: claude.php.wordpress.access-control.reflection-declaring-class-auth-check
    private function has_own_permission_override( string $method ) {
        $reflection = new ReflectionObject( $this );
        $method_ref = $reflection->getMethod( $method );
        if ( $method_ref->getDeclaringClass()->getName() === get_class( $this ) ) {
            return true;
        }
        return false;
    }
}

class Docblock_Inspector {
    // ok: claude.php.wordpress.access-control.reflection-declaring-class-auth-check
    private function describe_override( string $method ): string {
        $reflection = new ReflectionClass( get_class( $this ) );
        $method_ref = $reflection->getMethod( $method );
        // Used only to build a debug label, no security decision depends on this.
        return 'declared in ' . $method_ref->class;
    }
}

class Registered_Capability_Route {
    private $allowed_overrides = [];

    // ok: claude.php.wordpress.access-control.reflection-declaring-class-auth-check
    private function register_override( string $method ) {
        // No reflection-based same-class identity check at all — uses an
        // explicit allow-list instead, so this rule does not apply.
        $this->allowed_overrides[] = $method;
        return in_array( $method, $this->allowed_overrides, true );
    }
}
