// Test cases for claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
//
// This rule only fires on code hidden inside eval("...") — the shape webpack's
// `devtool: eval` build mode produces for each bundled module. Every case
// below wraps a minimal snippet in eval(" ... ") with the escapes a real
// webpack-eval bundle would use (\n for newlines, \" for embedded double
// quotes), mirroring the real-world confirmed instance in
// essential-addons-for-elementor-lite 6.6.2 event-calendar.js.

// === TRUE POSITIVES — should match ===

// ruleid: claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
eval("function render(event, thumbnailPosition) {\n  if (thumbnailPosition === 'body-left') {\n    $(\".eaelec-modal-body\").html('<img class=\"eaelec-modal-body-img\" src=\"' + event.extendedProps.imageUrl + '\" alt=\"' + event.title + '\">' + bodyContent);\n  }\n}");

// ruleid: claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
eval("function renderCard(item) {\n  $card.append('<div class=\"card-title\">' + item.name + '</div>');\n}");

// === FALSE POSITIVES — should NOT match ===

// Patched shape: DOM API (.attr()) instead of string concatenation — no
// leading-quote-then-plus shape for metavariable-regex to anchor on.
// ok: claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
eval("function render(event, thumbnailPosition) {\n  if (thumbnailPosition === 'body-left') {\n    var $img = $('<img>').addClass('eaelec-modal-body-img').attr('src', event.extendedProps.imageUrl).attr('alt', event.title);\n    $(\".eaelec-modal-body\").html('').append($img);\n  }\n}");

// Sanitizer applied immediately after the concatenation operator.
// ok: claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
eval("function render(event) {\n  locationSelector.html('<i class=\"eicon-map-pin\"></i> ' + DOMPurify.sanitize(event.extendedProps.location)).show();\n}");

// Same .html()+concat shape, but NOT inside eval() — this is the AST-visible
// case already covered by the jquery-html-unsafe-variable sibling rule, not
// this one, so it must not double-fire here.
// ok: claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
function render(event) {
  $(".modal-body").html('<img alt="' + event.title + '">');
}

// eval() call whose argument is a variable, not a string literal — the
// metavariable-regex has no string source text to scan and self-filters.
// ok: claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
eval(compiledModuleSource);

// Bare local identifier after the `+`, not a property access — matches the
// most common benign shape found in real plugin bundles (formatted date
// strings, CSS classes, icon markup snippets held in local vars). Confirmed
// FP class from essential-addons-for-elementor-lite 6.6.2 simple-menu.js:
// $(this).append('<span class="indicator"> ' + $indicator_icon + '</span>').
// ok: claude.js.wordpress.xss.eval-wrapped-jquery-html-concat
eval("function render(startView) {\n  startSelector.html('<i class=\"eicon-calendar\"></i> ' + startView);\n}");
