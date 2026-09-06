<?php

class DB_Statement_Vulnerable {
    private $wpdb;
    private $statement;
    private $bindings = [];

    public function execute(array $params = []) {
        foreach ($params as $key => $value) {
            $this->bindings[$key] = $value;
        }

        $query = $this->statement;

        // ruleid: claude.php.wordpress.sqli.custom-orm-sequential-placeholder-replace
        foreach ($this->bindings as $placeholder => $value) {
            $replacement = 'NULL';
            if ($value !== null) {
                $format = is_int($value) ? '%d' : '%s';
                $replacement = $this->wpdb->prepare($format, $value);
            }
            $query = str_replace($placeholder, $replacement, $query);
        }

        return $this->wpdb->query($query);
    }
}

class DB_Statement_Inline_Vulnerable {
    private $wpdb;

    public function run($template, $bindings) {
        $query = $template;

        // ruleid: claude.php.wordpress.sqli.custom-orm-sequential-placeholder-replace
        foreach ($bindings as $placeholder => $value) {
            $format = is_int($value) ? '%d' : '%s';
            $query = str_replace($placeholder, $this->wpdb->prepare($format, $value), $query);
        }

        return $this->wpdb->query($query);
    }
}

class DB_Statement_Fixed {
    private $wpdb;
    private $statement;
    private $bindings = [];

    public function execute(array $params = []) {
        foreach ($params as $key => $value) {
            $this->bindings[$key] = $value;
        }

        $query = $this->statement;

        if ($this->bindings) {
            $replacements = [];

            // ok: claude.php.wordpress.sqli.custom-orm-sequential-placeholder-replace
            foreach ($this->bindings as $placeholder => $value) {
                if (strpos($this->statement, $placeholder) === false) {
                    continue;
                }
                $replacement = 'NULL';
                if ($value !== null) {
                    $format = is_int($value) ? '%d' : '%s';
                    $replacement = $this->wpdb->prepare($format, $value);
                }
                $replacements[$placeholder] = $replacement;
            }

            if ($replacements) {
                $query = strtr($this->statement, $replacements);
            }
        }

        return $this->wpdb->query($query);
    }
}

class Standard_Repository {
    public function get_by_id($id) {
        global $wpdb;

        // ok: claude.php.wordpress.sqli.custom-orm-sequential-placeholder-replace
        $sql = $wpdb->prepare("SELECT * FROM {$wpdb->prefix}items WHERE id = %d", $id);

        return $wpdb->get_row($sql);
    }
}
