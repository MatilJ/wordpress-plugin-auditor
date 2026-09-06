// Test cases for claude.js.wordpress.xss.href-attr-unsanitized-scheme

// --- TRUE POSITIVES ---

// Vue-style render-function attrs object, hydrated from a fetched/stored
// record (the real pre-fix shape: an admin-viewer render function reads a
// nested field straight off a stored record with no scheme validation).
function renderSubmittedLink(h, record) {
  return h("a", {
    // ruleid: claude.js.wordpress.xss.href-attr-unsanitized-scheme
    attrs: { target: "_blank", href: record.pageSubmitted.link },
  }, [record.pageSubmitted.title]);
}

// Flat props object (React/Preact/hyperscript element factory).
function LinkCell({ row }) {
  // ruleid: claude.js.wordpress.xss.href-attr-unsanitized-scheme
  return React.createElement("a", { href: row.sourceUrl }, row.label);
}

// Direct DOM property assignment fed by an AJAX/REST response field.
function applyLink(anchorEl, apiResponse) {
  // ruleid: claude.js.wordpress.xss.href-attr-unsanitized-scheme
  anchorEl.href = apiResponse.entry.link;
}

// setAttribute() fed by a stored value.
function applyLinkAttr(anchorEl, entry) {
  // ruleid: claude.js.wordpress.xss.href-attr-unsanitized-scheme
  anchorEl.setAttribute("href", entry.link);
}

// --- FALSE POSITIVES ---

// Fixed shape: value passed through a scheme-stripping helper before
// binding — the real remediation idiom this rule must stay silent on.
function renderSubmittedLinkFixed(h, record) {
  return h("a", {
    attrs: {
      target: "_blank",
      // ok: claude.js.wordpress.xss.href-attr-unsanitized-scheme
      href: sanitizeLink(record.pageSubmitted.link),
    },
  }, [record.pageSubmitted.title]);
}

// Plain string literal — no attacker-controlled value at all.
function renderStaticLink(h) {
  return h("a", {
    // ok: claude.js.wordpress.xss.href-attr-unsanitized-scheme
    attrs: { target: "_blank", href: "https://example.com" },
  }, ["Example"]);
}

// DOMPurify-wrapped assignment.
function applyLinkSafe(anchorEl, apiResponse) {
  // ok: claude.js.wordpress.xss.href-attr-unsanitized-scheme
  anchorEl.href = DOMPurify.sanitize(apiResponse.entry.link);
}

// setAttribute() with a sanitizer wrap.
function applyLinkAttrSafe(anchorEl, entry) {
  // ok: claude.js.wordpress.xss.href-attr-unsanitized-scheme
  anchorEl.setAttribute("href", sanitizeUrl(entry.link));
}
