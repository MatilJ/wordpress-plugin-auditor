<?php

class Custom_Query_Builder_Vulnerable {
    protected $comparisons = ['>=', '<=', '<', '>', '!=', 'LIKE'];

    protected function build_or_condition($column, $value) {
        $sub_queries = [];
        $condition_values = $value['OR'];

        // ruleid: claude.php.wordpress.sqli.dynamic-where-array-key-as-operator
        foreach ($condition_values as $condition_key => $condition_value) {
            if (is_string($condition_key) && is_string($column)) {
                $temp_key = $this->with_table_name($column) . $condition_key;
                $sub_conditions = [$temp_key => $condition_value];
            } else {
                $sub_conditions = [$column => $condition_value];
            }
            $sub_queries[] = $this->build_conditions_query($sub_conditions);
        }

        return $sub_queries;
    }

    protected function merge_filter_into_where($column, $filters) {
        $sub_conditions = [];

        // ruleid: claude.php.wordpress.sqli.dynamic-where-array-key-as-operator
        foreach ($filters as $filter_key => $filter_value) {
            $sub_conditions = [$column . $filter_key => $filter_value];
        }

        return $sub_conditions;
    }
}

class Template_Var_Renamer {
    // this loop only renames template placeholders for an HTML replacer —
    // it never builds a WHERE clause and has no query-builder value pairing
    public function snapshot_old_vars($temp_vars) {
        $vars = [];

        // ok: claude.php.wordpress.sqli.dynamic-where-array-key-as-operator
        foreach ($temp_vars as $key => $data) {
            $vars['old_' . $key] = $data;
        }

        return $vars;
    }
}

class Custom_Query_Builder_Fixed {
    protected $comparisons = ['>=', '<=', '<', '>', '!=', 'LIKE'];

    protected function build_or_condition($column, $value) {
        $sub_queries = [];
        $condition_values = $value['OR'];

        // ok: claude.php.wordpress.sqli.dynamic-where-array-key-as-operator
        foreach ($condition_values as $condition_key => $condition_value) {
            if (is_string($condition_key) && is_string($column)) {
                if (!in_array(trim($condition_key), $this->comparisons, true)) {
                    continue;
                }
                $temp_key = $this->with_table_name($column) . $condition_key;
                $sub_conditions = [$temp_key => $condition_value];
            } else {
                $sub_conditions = [$column => $condition_value];
            }
            $sub_queries[] = $this->build_conditions_query($sub_conditions);
        }

        return $sub_queries;
    }
}

class Standard_Repository {
    public function get_by_id($id) {
        global $wpdb;

        // ok: claude.php.wordpress.sqli.dynamic-where-array-key-as-operator
        $sql = $wpdb->prepare("SELECT * FROM {$wpdb->prefix}items WHERE id = %d", $id);

        return $wpdb->get_row($sql);
    }
}
