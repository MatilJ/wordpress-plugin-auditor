// Test cases for claude.js.wordpress.xss.jquery-html-unsafe-variable
//
// NOTE on paths.exclude: The rule excludes:
//   "jquery.*.js"  — jQuery plugin/extension files
//   "*.min.js"     — minified files
//   "**/inc/**"    — bundled third-party libraries (select2, datepicker, timepicker…)
//                    Confirmed FP source: ACF 6.8.0 assets/inc/select2/ (6 hits)
//   "**/vendor/**" — Composer/npm vendor directories
// This file is named "jquery-html-unsafe-variable.js" (hyphen, not period)
// and does NOT match any of those glob patterns, so all annotations below apply.
// Path exclusions cannot be tested in Semgrep --test; they are verified by
// running `semgrep --config <rule.yaml> <target_dir>` and confirming that
// jquery.calendar.js, *.min.js, inc/**/*.js and vendor/**/*.js produce zero findings.

// === PATH-EXCLUDED PATTERNS (informational — cannot be tested with --test) ===
// These patterns WOULD match the rule's syntax but are excluded by paths.exclude
// when scanning files under inc/ or vendor/. The select2 library (bundled under
// assets/inc/select2/ in ACF 6.8.0) generated all 6 FP hits in the ACF audit.
// Example FP from assets/inc/select2/3/select2.js:3361 (excluded by **/inc/**):
//
//   var container = $( document.createElement( 'div' ) ).html(
//       '<span class="select2-container">...</span>' + label
//   );
//
// Example FP from assets/inc/select2/4/select2.full.js:1796 (excluded by **/inc/**):
//
//   $selection.html(
//       '<span class="select2-selection__rendered"></span>' + ...
//   );
//
// These are internal rendering calls inside the library using its own sanitised
// data, not attacker-controlled input.

// === TRUE POSITIVES — should match ===

// Array join into .html() — common pattern from calendar plugin
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
container.html(html.join(""));

// innerHTML assignment
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
document.getElementById("content").innerHTML = userContent;

// === FALSE POSITIVES — should NOT match ===

// Static string is safe
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html("<p>Loading...</p>");

// .text() is safe
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.text(userInput);

// Function call into .html() — too broad to match reliably, excluded
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html(buildStaticMenu());

// === CSS/style-named variables excluded from innerHTML ===
// Variables named 'css', 'style', 'cssText', 'styleContent', etc. are
// admin-configured CSS strings, not attacker-controlled HTML.

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
document.getElementById('booking-package_customizeButtons').innerHTML = css;

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
document.getElementById('my_element').innerHTML = style;

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
document.getElementById('output').innerHTML = cssContent;

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
document.getElementById('preview').innerHTML = styleText;

// Non-CSS-named variables must still fire
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
document.getElementById('output').innerHTML = html;

// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
document.getElementById('widget').innerHTML = userContent;

// === String concatenation inside .html() ===
// Pattern seen in Easy Appointments customers.tpl.php — inline JS in PHP
// template files is not scanned, but identical patterns in .js files are.

// Single concatenation with string literal and variable
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
jQuery('#customer-table-body').html('<td>' + c.name + '</td>');

// Multi-level concatenation (A+B+C is parsed as (A+B)+C — still matches)
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
$('#out').html('<tr><td>' + row.name + '</td><td>' + row.email + '</td></tr>');

// .append() with concatenation is equally dangerous
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
$('#list').append('<li>' + item.title + '</li>');

// === Safe concatenation patterns — should NOT match ===

// .text() is always safe regardless of content
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.text(c.name + ' (' + c.email + ')');

// DOMPurify-sanitized content before .html()
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html(DOMPurify.sanitize(rawHtml));

// === Template-literal HTML construction ===
// A distinct building method from concat/.join(): backtick strings with
// ${} interpolation. Seen in admin "lookup"/"debug" tools that fetch a
// record from a REST/AJAX endpoint and render its fields client-side.

// Row accumulator built from a fetched record, no escaping
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
rows += `<tr data-field="${fieldKey}"><td class="val">${displayValue}</td></tr>`;

// Direct innerHTML assignment of an interpolated template literal
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
resultsContainer.innerHTML = `<div class="summary">${data.message}</div>`;

// .html() with template-literal interpolation
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html(`<span>${record.name}</span>`);

// .map() callback returning an interpolated template literal, joined later
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
tags.map(tag => `<span class="chip">${tag}</span>`).join('');

// === Fixed: interpolation wrapped by a named escaping helper ===

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
rows += `<tr data-field="${esc(fieldKey)}"><td class="val">${esc(displayValue)}</td></tr>`;

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
tags.map(tag => `<span class="chip">${esc(tag)}</span>`).join('');

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html(`<span>${DOMPurify.sanitize(record.name)}</span>`);

// === Bare variable / member-expression passed straight to .html() ===
// No construction operator at all — the raw value itself is the markup.
// Common in link-preview / curation widgets that read a URL query param
// or AJAX-response field and drop it straight into a preview element.

// Bare identifier sourced from a URL query parameter
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
jQuery('.preview-url').html(url);

// Member expression sourced from an AJAX/JSON response
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
jQuery('.preview-title').html(response.og_title);

// === Safe bare-argument forms — should NOT match ===

// Static string literal — no user input possible
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html("<p>No preview available</p>");

// Static template literal with no interpolation
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html(`<p>No preview available</p>`);

// Call expression — escaping/sanitizing/validating wrapper (or a
// deliberately narrow helper); too broad to match reliably, excluded
// consistent with the existing buildStaticMenu() exclusion above.
// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$el.html(escapeHtml(url));

// === Concatenation sink with an inline escaping-helper call ===
// A single dynamic value passed through a local escHtml()-style helper,
// sandwiched between two literal HTML fragments — fully neutralized.

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$panel.find('.funnel-body').html('<p class="empty">' + escHtml(msg) + '</p>');

// ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
$('#list').append('<li>' + escapeHtml(item.title) + '</li>');

// Unescaped concatenation must still fire (regression check)
// ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
$panel.find('.funnel-body').html('<p class="empty">' + msg + '</p>');

// === Escaping performed one assignment BEFORE the sink ===
// The TRIAGE note documents this as a normally-invisible gap; the earlier-
// assignment exclusion below closes it for the three template-literal shapes.

function renderRow(record) {
    const safeName = escHtml(record.name);
    // ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
    rows += `<tr><td>${safeName}</td></tr>`;
}

function showSummary(data) {
    let safeMessage = sanitizeText(data.message);
    // ok: claude.js.wordpress.xss.jquery-html-unsafe-variable
    resultsContainer.innerHTML = `<div class="summary">${safeMessage}</div>`;
}

// Unescaped upstream assignment must still fire (regression check)
function showSummaryUnsafe(data) {
    var rawMessage = data.message;
    // ruleid: claude.js.wordpress.xss.jquery-html-unsafe-variable
    resultsContainer.innerHTML = `<div class="summary">${rawMessage}</div>`;
}
