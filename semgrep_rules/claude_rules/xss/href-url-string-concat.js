// href-url-string-concat test cases

// ─── Vulnerable patterns ──────────────────────────────────────────────────────

// Single-quoted href concat — loco-translate 2.8.3 admin.js pattern exactly
// ruleid: claude.js.wordpress.xss.href-url-string-concat
var out = '<a href="' + url + '" target="_blank">' + text + '</a>';

// Double-quoted href concat
// ruleid: claude.js.wordpress.xss.href-url-string-concat
var link = "<a href=\"" + href + "\">" + label + "</a>";

// Returned from a linkification helper function
function linkify(url, text) {
    // ruleid: claude.js.wordpress.xss.href-url-string-concat
    return '<a href="' + url + '" rel="noopener">' + text + '</a>';
}

// ─── Safe patterns ────────────────────────────────────────────────────────────

// encodeURIComponent encodes " as %22 — attribute breakout not possible
// ok: claude.js.wordpress.xss.href-url-string-concat
var safe1 = '<a href="' + encodeURIComponent(url) + '">' + text + '</a>';

// ok: claude.js.wordpress.xss.href-url-string-concat
var safe2 = "<a href=\"" + encodeURIComponent(href) + "\">" + label + "</a>";

// DOM method — browser handles all encoding
// ok: claude.js.wordpress.xss.href-url-string-concat
var a = document.createElement('a');
a.href = url;
a.textContent = text;

// jQuery .attr() — safe attribute encoding
// ok: claude.js.wordpress.xss.href-url-string-concat
$('<a>').attr('href', url).text(text).prop('outerHTML');

// ─── src= on img/iframe (same sink class, different attribute/tag) ───────────

// <img src=...> concat inside a larger accumulated markup string — the
// gallery-thumbnail-builder shape
// ruleid: claude.js.wordpress.xss.href-url-string-concat
var thumb = "<li class='" + cls + "'><a href='#'><img src='" + img_src + "' width='50' alt='' /></a></li>";

// <iframe src=...> concat — custom video-embed builder
// ruleid: claude.js.wordpress.xss.href-url-string-concat
var frame = '<iframe src="' + embedUrl + '" frameborder="0" allowfullscreen></iframe>';

// jQuery attribute-object constructor — the fix pattern: build the bare tag
// literal with no interpolated attribute, then set src via the object map
// ok: claude.js.wordpress.xss.href-url-string-concat
var safeImg = $('<img/>', { src: img_src, alt: '' });

// ok: claude.js.wordpress.xss.href-url-string-concat
var safeFrame = $('<iframe/>', { src: embedUrl, frameborder: 0 });

// .attr() chained onto a bare tag literal — safe attribute encoding
// ok: claude.js.wordpress.xss.href-url-string-concat
$('<iframe/>').attr('src', embedUrl).appendTo(container);
