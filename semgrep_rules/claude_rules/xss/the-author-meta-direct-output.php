<?php
// Test cases for claude.php.wordpress.xss.the-author-meta-direct-output

// ── MATCH: the_author_meta() in JavaScript string context ─────────────────────
// the_author_meta() always echoes directly (void return). A " in the nickname
// value breaks out of the JS string literal — Stored XSS.

function output_author_nickname_in_js_string( $pid ) {
    $queried_post = get_post( $pid );
    $author_id    = $queried_post->post_author;
    ?>
    <script type="text/javascript">
        var _tracker = _tracker || [];
        // ruleid: claude.php.wordpress.xss.the-author-meta-direct-output
        _tracker.push({"tags": {"author": "<?php the_author_meta( 'nickname', $author_id ); ?>"}});
    </script>
    <?php
}

// esc_html() applied to the WRONG argument — ID, not the echoed value (TP)
function output_author_nickname_misapplied_escape( $pid ) {
    $queried_post = get_post( $pid );
    $author_id    = $queried_post->post_author;
    ?>
    <script type="text/javascript">
        var _tracker = _tracker || [];
        // ruleid: claude.php.wordpress.xss.the-author-meta-direct-output
        _tracker.push({"tags": {"author": "<?php the_author_meta( 'nickname', esc_html( $author_id ) ); ?>"}});
    </script>
    <?php
}

// the_author_meta() in an HTML paragraph — lower risk but still flags as audit lead
function output_author_display_name_html( $pid ) {
    $queried_post = get_post( $pid );
    $author_id    = $queried_post->post_author;
    // ruleid: claude.php.wordpress.xss.the-author-meta-direct-output
    echo '<p>By: '; the_author_meta( 'display_name', $author_id ); echo '</p>';
}

// ── NO MATCH: safe replacement — echo esc_js( get_the_author_meta(...) ) ──────
// the safe pattern replaces the_author_meta() with get_the_author_meta() wrapped
// in esc_js(). This is NOT a call to the_author_meta() so the pattern does not fire.

function output_author_nickname_safe_js( $pid ) {
    $queried_post = get_post( $pid );
    $author_id    = (int) $queried_post->post_author;
    ?>
    <script type="text/javascript">
        var _tracker = _tracker || [];
        // ok: claude.php.wordpress.xss.the-author-meta-direct-output
        _tracker.push({"tags": {"author": "<?php echo esc_js( get_the_author_meta( 'nickname', $author_id ) ); ?>"}});
    </script>
    <?php
}

function output_author_name_safe_html( $pid ) {
    $queried_post = get_post( $pid );
    $author_id    = (int) $queried_post->post_author;
    // ok: claude.php.wordpress.xss.the-author-meta-direct-output
    echo '<p>By: ' . esc_html( get_the_author_meta( 'display_name', $author_id ) ) . '</p>';
}
