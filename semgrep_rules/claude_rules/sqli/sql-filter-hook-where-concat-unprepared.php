<?php
// Test cases for claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared

// comments_clauses-style filter callback: a class property (populated from
// request input in a different, earlier-invoked method — not visible here)
// is concatenated raw into the returned WHERE fragment. WordPress core
// executes this string verbatim once the callback returns (CVE-shape:
// wpdiscuz 7.6.62 WpdiscuzCore::commentsClauses()).
class CommentsClausesVulnerable {
    public $commentsArgs;

    public function commentsClauses( $args ) {
        global $wpdb;
        if ( $this->commentsArgs["last_parent_id"] ) {
            // ruleid: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
            $args["where"] = $wpdb->comments . ".`comment_ID` > " . $this->commentsArgs["last_parent_id"] . ( $args["where"] ? " AND " : "" ) . $args["where"];
        }
        return $args;
    }
}

// posts_clauses-style filter callback using the compound .= form instead of
// a full reassignment.
class PostsClausesVulnerable {
    public function filter_posts_join_paged( $piece, $tainted_offset ) {
        global $wpdb;
        // ruleid: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
        $piece["join"] .= " LEFT JOIN " . $wpdb->prefix . "extra_meta em ON em.post_id = " . $tainted_offset;
        return $piece;
    }
}

// get_meta_sql-style filter callback, trailing-variable form (no $AFTER).
class MetaSqlFilterVulnerable {
    public function filter_meta_sql( $sql, $search_term ) {
        // ruleid: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
        $sql["where"] = $sql["where"] . " AND extra_field = '" . $search_term;
        return $sql;
    }
}

// ---- SAFE: cast to int before concatenation ----

class CommentsClausesFixedIntval {
    public $commentsArgs;

    public function commentsClauses( $args ) {
        global $wpdb;
        $lastParentId = intval( $this->commentsArgs["last_parent_id"] );
        // ok: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
        $args["where"] = $wpdb->comments . ".`comment_ID` > " . $lastParentId . $args["where"];
        return $args;
    }
}

// ---- SAFE: esc_sql() applied before concatenation ----

class PostsClausesFixedEscSql {
    public function filter_posts_where( $args, $tainted ) {
        // ok: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
        $args["where"] .= " AND category = '" . esc_sql( $tainted ) . "'";
        return $args;
    }
}

// ---- SAFE: $wpdb->prepare() applied before concatenation ----

class PostsClausesFixedPrepare {
    public function filter_posts_where( $args, $wpdb, $tainted ) {
        // ok: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
        $args["where"] .= $wpdb->prepare( " AND category = %s", $tainted );
        return $args;
    }
}

// ---- SAFE: re-concatenating the incoming clause array's own existing value
// back onto itself — the "preserve prior WHERE" idiom, not new taint ----

class CommentsClausesPreserveOnly {
    public function commentsClauses( $args ) {
        global $wpdb;
        // ok: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
        $args["where"] = $wpdb->comments . ".`comment_approved` = '1' AND " . $args["where"];
        return $args;
    }
}

// ---- SAFE: unrelated array key name, not a SQL clause key — should not fire
// regardless of concatenation shape ----

class UnrelatedFilterCallback {
    public function build_response( $data, $tainted ) {
        // ok: claude.php.wordpress.sqli.sql-filter-hook-where-concat-unprepared
        $data["message"] = "Result: " . $tainted;
        return $data;
    }
}
