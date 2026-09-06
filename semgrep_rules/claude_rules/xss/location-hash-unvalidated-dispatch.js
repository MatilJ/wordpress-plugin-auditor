// Test cases for claude.js.wordpress.xss.location-hash-unvalidated-dispatch

class UrlActions {
  runHashAction() {
    if (location.hash) {
      // ruleid: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
      this.runAction(location.hash);
    }
  }

  runHashActionWithEvent(event) {
    // ruleid: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
    this.runAction(location.hash, event);
  }
}

function jumpToHashTab() {
  // ruleid: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
  openTab(window.location.hash);
}

function jqueryHashSelectorGadget() {
  if (document.location.hash) {
    // ruleid: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
    $(document.location.hash).addClass('active');
  }
}

function unrelatedHashPropertyIsNotLocation(item) {
  // ok: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
  processChecksum(item.hash);
}

function guardedByExactLiteralComparison() {
  if (location.hash === '#popup') {
    // ok: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
    openPopup(location.hash);
  }
}

function guardedByDomExistenceCheck() {
  if (document.getElementById(location.hash.substring(1))) {
    // ok: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
    scrollToAnchor(location.hash);
  }
}

function guardedByQuerySelectorCheck() {
  if (document.querySelector(location.hash)) {
    // ok: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
    highlightSection(location.hash);
  }
}

function fixedElementorStyleGuard() {
  const elementWithHash = document.querySelector(`[e-action-hash="${location.hash}"]`);

  if (elementWithHash) {
    // ok: claude.js.wordpress.xss.location-hash-unvalidated-dispatch
    runAction(elementWithHash.getAttribute('e-action-hash'));
  }
}
