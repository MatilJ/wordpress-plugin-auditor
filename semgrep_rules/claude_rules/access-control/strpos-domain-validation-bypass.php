<?php
// Tests for claude.php.wordpress.access-control.strpos-domain-validation-bypass

// strpos on ip_domain — substring bypass possible, TP.
// ruleid: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (strpos($ip_domain, '.trustedhost.org') !== false) { authorize(); }

// str_contains on remote_host — substring bypass possible, TP.
// ruleid: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (str_contains($remote_host, 'api.service.com')) { allow_request(); }

// strpos on hostname — substring bypass possible, TP.
// ruleid: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (strpos($hostname, 'trusted.example.com') !== false) { grant_access(); }

// str_contains on origin — substring bypass possible, TP.
// ruleid: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (str_contains($request_origin, 'mysite.com')) { process(); }

// Strict equality comparison — not bypassable, safe.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if ($hostname === 'trustedhost.org') { authorize(); }

// Suffix matching — correct validation, safe.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (substr($domain, -strlen('.trustedhost.org')) === '.trustedhost.org') { authorize(); }

// strpos on non-domain variable — not a domain check, safe.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (strpos($email, '@example.com') !== false) { send_mail(); }

// str_contains on non-domain variable — not a domain check, safe.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (str_contains($username, 'admin')) { log_access(); }

// strpos checking for www. prefix — formatting check, not auth gate.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (strpos($domain, 'www.') !== false) { $domain = str_replace('www.', '', $domain); }

// strpos checking for wildcard — pattern matching, not auth gate.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (strpos($domain, '*') !== false) { continue; }

// str_contains checking for .local — local network detection, not auth gate.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (str_contains($host, '.local')) { $is_local = true; }

// strpos on $originalMessage — 'origin' is a substring of 'original', not a domain/origin
// variable; this is error-message classification, not an auth gate.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (strpos($originalMessage, $code) !== false) { return $code; }

// strpos on $original_error_text — same naming collision in snake_case.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
if (strpos($original_error_text, $causeCode) !== false) { return $causeCode; }

// strpos on hostname against a loop of trusted values from an option — $host is NOT
// derived from this site's own URL, still a genuine substring-bypass TP.
function validate_webhook_origin($request_host) {
    $trusted_hosts = get_option('trusted_webhook_hosts');
    foreach ($trusted_hosts as $trusted) {
        // ruleid: claude.php.wordpress.access-control.strpos-domain-validation-bypass
        if (false !== strpos($request_host, $trusted)) {
            return true;
        }
    }
    return false;
}

// strpos comparing this site's OWN configured URL host against known local/dev TLD
// markers, inside a function that also computes network_site_url() — environment
// detection on admin-controlled config, not validating an attacker-supplied domain.
// ok: claude.php.wordpress.access-control.strpos-domain-validation-bypass
function is_local_environment() {
    $url = network_site_url( '/' );
    $url_parts = parse_url( $url );
    $host = ! empty( $url_parts['host'] ) ? $url_parts['host'] : false;
    $tlds_to_check = array( '.dev', '.local', ':8888' );
    foreach ( $tlds_to_check as $tld ) {
        if ( false !== strpos( $host, $tld ) ) {
            return true;
        }
    }
    return false;
}
