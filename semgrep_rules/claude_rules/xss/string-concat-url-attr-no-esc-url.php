<?php
// Test cases for string-concat-url-attr-no-esc-url

// ---- VULNERABLE: href with stored value, no esc_url ----

$url = $options['url'];
// ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= "<a href='" . $url . "'>";

$link = $item['link'];
// ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . $link . '">';

// ---- VULNERABLE: src attribute ----

$image_url = $meta['image'];
// ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
echo '<img src="' . $image_url . '" />';

// ---- SAFE: esc_url() wrapping ----

$url = $options['url'];
// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . esc_url($url) . '">';

// ---- SAFE: esc_url_raw() wrapping ----

$url = $options['url'];
// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . esc_url_raw($url) . '">';

// ---- SAFE: esc_attr() wrapping ----

$url = $options['url'];
// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . esc_attr($url) . '">';

// ---- SAFE: WP URL generator function ----

// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . admin_url('edit.php') . '">';

// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . home_url('/page/') . '">';

// ---- SAFE: get_comment_link() is a WP core permalink-style URL generator,
// same class as get_permalink() -- always returns a site-internal URL ----

// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$moreLink = "&nbsp;<a href='" . get_comment_link($comment) . "' class='load-more'>[...]</a>";

// ---- SAFE: menu_page_url() unconditionally applies esc_url() internally ----

// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . menu_page_url('my-plugin', false) . '">';

// ---- SAFE: fully-qualified (leading-backslash) sanitizer call — the common
// style in namespaced plugins ----

// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$html .= '<a href="' . \esc_url($url) . '">';

// ---- VULNERABLE: PHP double-quoted string interpolation — CVE-2026-9148 shape
// (wpdiscuz getCommentAuthor(): stored comment_author_url interpolated
// directly into a single-quoted href attribute, no esc_url()/esc_attr()) ----

$href = $comment->comment_author_url;
$rel  = "noreferrer ugc";
// ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$authorNameHtml = "<a rel='$rel' href='$href' target='_blank'>$authorName</a>";

$imageUrl = $meta['image'];
// ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$avatarHtml .= "<img src='$imageUrl' class='avatar'>";

// ---- VULNERABLE: interpolated variable preceded by a static scheme prefix
// inside the same attribute quotes — CVE-2026-5721 shape (wpDataTables cell
// formatter builds a mailto: link from a stored/imported contact-data cell,
// no sanitize_email()/esc_url()/esc_html() anywhere in the method) ----

$emailCellContent = $row['email'];
// ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$formattedValue = "<a href='mailto:{$emailCellContent}'>{$emailCellContent}</a>";

// ---- SAFE: prefixed form fixed the same way — sanitize_email() + esc_url()
// via concatenation (the actual wpDataTables 6.5.0.5 fix) ----

$rawEmail = $row['email'];
$email = sanitize_email($rawEmail);
// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$formattedValue = '<a href="' . esc_url('mailto:' . $email) . '">' . esc_html($email) . '</a>';

// ---- SAFE: interpolation replaced by concatenation + esc_url()/esc_attr()
// (the actual wpdiscuz 7.6.57 fix) ----

$href = $comment->comment_author_url;
$rel  = "noreferrer ugc";
// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$authorNameHtml = "<a rel='" . esc_attr($rel) . "' href='" . esc_url($href) . "' target='_blank'>$authorName</a>";

// ---- SAFE: ordinary interpolated string, no href/src/action attribute ----

$post_title = get_the_title($post_id);
// ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
$label = "Post title: $post_title";

// ---- SAFE: sanitize-then-use idiom — esc_url() self-reassignment earlier in the
// same function, then the variable is used bare at the concatenation site ----

function get_help_link_test($link) {
    $link = esc_url($link);
    if (!$link) {
        return '';
    }
    // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '&nbsp;<a href="' . $link . '" target="_blank">Get help</a>';
}

// ---- VULNERABLE: same shape, but the reassignment sanitizes a DIFFERENT variable
// than the one concatenated — the fix must not suppress this ----

function bad_help_link_test($link, $other) {
    $other = esc_url($other);
    // ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '<a href="' . $link . '">click</a>';
}

// ---- SAFE: assigned variable's esc_url() argument is a DIFFERENT expression than
// the assigned variable itself (e.g. a developer-hardcoded asset path built via
// plugins_url()) — must still suppress, since $VAR (the assigned/concatenated
// variable) matches on both sides even though esc_url()'s argument does not ----

class Settings_Test {
    public static function get_default_confirmation_message() {
        $check_icon = esc_url( plugins_url( 'images/check-icon.svg', __FILE__ ) );
        // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
        return '<p><img src="' . $check_icon . '" alt="" /></p>';
    }
}

// ---- SAFE: object-method-wrapper form — a plugin wraps WP core escaping functions
// behind an injectable facade object for unit-testability (e.g. mailpoet's
// lib/WP/Functions.php: $this->wp->escUrl()) instead of calling the bare global ----

class Wrapper_Form_Test {
    public function render_inline($actionUrl) {
        // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
        return '<form action="' . $this->wp->escUrl($actionUrl) . '">';
    }

    public function render_assigned($captchaUrl) {
        $safeUrl = $this->wp->escUrl($captchaUrl);
        // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
        return '<img src="' . $safeUrl . '" />';
    }
}

// ---- VULNERABLE: unrelated object-method call — must still be flagged (proves the
// wrapper-method exclusion is scoped to escUrl/escAttr/escUrlRaw, not any $OBJ->method()) ----

class Wrapper_Form_Vuln_Test {
    public function render($rawUrl) {
        $resolved = $this->wp->getRawUrl($rawUrl);
        // ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
        return '<a href="' . $resolved . '">click</a>';
    }
}

// ---- SAFE: variable assigned from a bare WP core URL-generator function earlier
// in the function, then concatenated raw — these functions always return a
// site-internal, non-attacker-controlled URL, but the value is a plain variable
// at the concat site (not the generator call itself), so only the "assigned
// earlier" exclusion form (not the direct-call regex) can suppress this ----

function render_ssl_notice_test() {
    $siteSSLurl = get_home_url(null, '', 'https');
    // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '<a href="' . $siteSSLurl . '" target="_blank">' . $siteSSLurl . '</a>';
}

function render_home_link_test() {
    $link = home_url('/pricing/');
    // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '<a href="' . $link . '">Pricing</a>';
}

function render_admin_link_test() {
    $link = get_admin_url(null, 'edit.php');
    // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '<a href="' . $link . '">Posts</a>';
}

function render_permalink_test($post_id) {
    $link = get_permalink($post_id);
    // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '<a href="' . $link . '">View</a>';
}

function render_comment_link_test($comment) {
    $link = get_comment_link($comment);
    // ok: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '<a href="' . $link . '">Read More</a>';
}

// ---- VULNERABLE: variable assigned from an UNRELATED function (not a WP core URL
// generator) earlier in the function — must still be flagged, proving the new
// exclusions are scoped to the specific generator-function name list ----

function render_option_link_test() {
    $link = get_option('external_profile_url');
    // ruleid: claude.php.wordpress.xss.string-concat-url-attr-no-esc-url
    return '<a href="' . $link . '">Profile</a>';
}
