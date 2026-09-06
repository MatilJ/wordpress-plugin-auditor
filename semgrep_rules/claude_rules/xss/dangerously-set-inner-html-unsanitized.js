// Test cases for claude.js.wordpress.xss.dangerously-set-inner-html-unsanitized

// --- TRUE POSITIVES ---

// ruleid: claude.js.wordpress.xss.dangerously-set-inner-html-unsanitized
var entryValueEl = React.createElement("span", { className: "entry-value", dangerouslySetInnerHTML: { __html: field.value } });

function RenderEntry({ value }) {
  // ruleid: claude.js.wordpress.xss.dangerously-set-inner-html-unsanitized
  return <span className="entry-value" dangerouslySetInnerHTML={{ __html: value }} />;
}

function RenderNote({ note }) {
  // ruleid: claude.js.wordpress.xss.dangerously-set-inner-html-unsanitized
  return <div dangerouslySetInnerHTML={{ __html: note }}></div>;
}

function renderMessage(entry) {
  return typeof entry.value === "string" && entry.value.match(/<[^>]+>/g)
    // ruleid: claude.js.wordpress.xss.dangerously-set-inner-html-unsanitized
    ? React.createElement("span", { dangerouslySetInnerHTML: { __html: entry.value } })
    : React.createElement("span", null, entry.value);
}

// --- FALSE POSITIVES ---

// ok: claude.js.wordpress.xss.dangerously-set-inner-html-unsanitized
var safeEntryValueEl = React.createElement("span", { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(field.value) } });

function RenderEntrySafe({ value }) {
  // ok: claude.js.wordpress.xss.dangerously-set-inner-html-unsanitized
  return <span dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(value) }} />;
}
