<?php
// Test cases for personalization-tag-resolver-unescaped-getter
// Rule id: claude.php.wordpress.xss.personalization-tag-resolver-unescaped-getter
//
// NOTE: the rule's `paths: include` restricts matching to files whose path
// contains one of PersonalizationTag*/MergeTag*/SmartTag*/DynamicTag*/
// Shortcodes/Categor* — semgrep --test does not apply `paths:` filtering
// (it always scans the given test file directly), so these cases exercise
// the pattern logic; path-scoping itself is verified in Phase 5 against the
// real plugin source tree instead.

namespace Vendor\PersonalizationTags;

// TP: raw getter passthrough, no escaping — mirrors mailpoet 5.34.0
// Subscriber::getFirstName()/getLastName() (PersonalizationTags/Subscriber.php),
// which resolves the entity via a helper call on a preceding statement before
// the ternary-guarded return (the common real-world shape, not a bare
// single-statement passthrough).
class Subscriber {
    // ruleid: claude.php.wordpress.xss.personalization-tag-resolver-unescaped-getter
    public function getFirstName(array $context, array $args = []): string {
        $subscriber = $this->getSubscriber($context);
        return ($subscriber && $subscriber->getFirstName()) ? $subscriber->getFirstName() : $args['default'] ?? '';
    }

    // ok: claude.php.wordpress.xss.personalization-tag-resolver-unescaped-getter
    // The sibling method in the SAME class correctly escapes — confirms the
    // omission above is a genuine gap, not an intentional "callers escape" contract.
    public function getCustomField(array $context, array $args = []): string {
        $subscriber = $this->getSubscriber($context);
        return htmlspecialchars($subscriber->getCustomFieldValue(), ENT_QUOTES);
    }

    // ok: claude.php.wordpress.xss.personalization-tag-resolver-unescaped-getter
    public function getDisplayName(array $context, array $args = []): string {
        $subscriber = $this->getSubscriber($context);
        return esc_html($subscriber->getDisplayName());
    }
}

// ok: claude.php.wordpress.xss.personalization-tag-resolver-unescaped-getter
// Legacy shortcode-category class in the same naming convention, escapes correctly
// (mirrors mailpoet's own Newsletter\Shortcodes\Categories\Subscriber::process()).
namespace Vendor\Shortcodes\Categories;

class Subscriber {
    // ok: claude.php.wordpress.xss.personalization-tag-resolver-unescaped-getter
    public function process($subscriber, $args = []) {
        return htmlspecialchars($subscriber->getFirstName());
    }
}
