<?php

// ── TRUE POSITIVES — should match ────────────────────────────────────────────

// Inline: headers_list() wrapped in json_encode() passed directly as the
// write call's argument, no intermediate variable and no filtering.
class PageCacheWriter {
    protected $cache_headers_file;

    protected function cache_content( $buffer ) {
        file_put_contents( $this->cache_file, $buffer );
        // ruleid: claude.php.wordpress.info-disclosure.unfiltered-response-headers-cached-to-file
        file_put_contents( $this->cache_headers_file, json_encode( headers_list() ) );
        return $buffer;
    }
}

// Assign-then-write: headers_list() captured to a variable first. Match is
// reported at the first statement of the matched region (the assignment),
// not the later write call.
function persist_response_headers( $cache_headers_path ) {
    // ruleid: claude.php.wordpress.info-disclosure.unfiltered-response-headers-cached-to-file
    $headers = headers_list();
    fwrite( fopen( $cache_headers_path, 'w' ), json_encode( $headers ) );
}

// ── FALSE POSITIVES — should NOT match ───────────────────────────────────────

// array_filter() strips Set-Cookie before persisting — the real fix shape.
class PageCacheWriterFixed {
    protected $cache_headers_file;

    protected function cache_content( $buffer ) {
        $headers = array_filter( headers_list(), function ( $h ) {
            return stripos( $h, 'Set-Cookie:' ) !== 0;
        } );
        // ok: claude.php.wordpress.info-disclosure.unfiltered-response-headers-cached-to-file
        file_put_contents( $this->cache_headers_file, json_encode( $headers ) );
        return $buffer;
    }
}

// Explicit Set-Cookie stripos() check present elsewhere in the function.
function persist_response_headers_filtered( $cache_headers_path ) {
    $filtered = [];
    foreach ( headers_list() as $header ) {
        if ( stripos( $header, "Set-Cookie" ) === 0 ) {
            continue;
        }
        $filtered[] = $header;
    }
    // ok: claude.php.wordpress.info-disclosure.unfiltered-response-headers-cached-to-file
    fwrite( fopen( $cache_headers_path, 'w' ), json_encode( $filtered ) );
}
