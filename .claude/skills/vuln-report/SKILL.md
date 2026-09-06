# Skill: Vulnerability Disclosure Report (Wordfence)

## Purpose
Produce a submission-ready disclosure report for the Wordfence Intelligence Bug Bounty Program. Invoke after vuln-audit confirms confidence >90%.

Submission: https://www.wordfence.com/threat-intel/vulnerabilities/submit

## Pre-flight Checklist

All must be known before writing (maps to Wordfence form fields):
- [ ] Software type (Plugin/Theme/Core)
- [ ] Software name (exact wordpress.org display name)
- [ ] Software slug
- [ ] Affected versions string (e.g. `<= 2.4.1`)
- [ ] Vuln exists in latest available version
- [ ] Description (1-2 sentences, factual)
- [ ] Vulnerability type (from reference below)
- [ ] Impact statement (one sentence, max 200 chars)
- [ ] CWE type
- [ ] Auth level (Unauthenticated/Subscriber/Customer/Contributor)
- [ ] SVN/Trac URL(s): `https://plugins.trac.wordpress.org/browser/<slug>/tags/<version>/path/file.php#L<line>`
- [ ] PoC type (Python/PHP/JavaScript/HTML/Other/Text)
- [ ] Working PoC — GUI-first walkthrough (install→config→create content→account→trigger→confirm) with exact wp-admin menu paths, plus raw HTTP requests + exact payloads
- [ ] Environment details (PHP, WP, MySQL versions incl. versions verified against, required config)
- [ ] CVSS v3.1 score (https://www.first.org/cvss/calculator/3.1)
- [ ] Recommended mitigation — vendor patch guide: what/why/where + before→after corrected code, referencing vulnerable file:line (no update/defense-in-depth/WAF/site-operator advice)
- [ ] Meets Wordfence scope per global CLAUDE.md

## Vulnerability Type Reference

Exact dropdown values from Wordfence submission form:

**Auth & Authz:** Account Takeover (Admin) | Account Takeover (Limited/User) | Authentication Bypass (Admin) | Authentication Bypass (Non-Admin) | IDOR with Availability/Confidentiality/Integrity Impact | Missing Authorization with Availability/Confidentiality/Integrity Impact | Privilege Escalation (Admin) | Privilege Escalation (Non-Admin)

**Business Logic:** Business Logic Abuse (Non-Payment) | Payment / Checkout Manipulation — _OOS per global CLAUDE.md when the impact is primarily business/revenue/transactional; select these only if the flaw has a direct CIA security impact (otherwise do not submit)._

**Content & Config:** Arbitrary Content Deletion | Arbitrary Content Modification | Plugin / Theme Installation or Activation | Settings / Configuration Changes

**Cross-Site:** CSRF with Availability/Confidentiality/Integrity Impact | Reflected Cross-Site Scripting (XSS) | Stored Cross-Site Scripting (XSS)

**Data Exposure:** Content Disclosure (Private Content) | Credential / Secret Disclosure | General Information Disclosure | Unauthorized Data Access (PII / User Data)

**File System:** Arbitrary File Deletion (Non-PHP) | Arbitrary File Deletion (PHP Included) | Arbitrary File Read / Download (Non-PHP) | Arbitrary File Read / Download (PHP Included) | Arbitrary File Upload (Leading to RCE) | Arbitrary File Write / Overwrite (Non-PHP) | Arbitrary File Write / Overwrite (PHP Included) | Directory Traversal | Limited File Upload (Non-RCE Impact)

**Injection & RCE:** Arbitrary Shortcode Execution | Local File Inclusion (LFI) - Arbitrary | Local File Inclusion (LFI) - PHP Files Only | PHP Object Injection | Remote Code Execution / Code Injection | Remote File Inclusion (RFI) | SQL Injection (Full Access - DB Read/Write) | SQL Injection (Standard DB Read)

**Malicious Dev:** Intentional Backdoors Accessible by Threat Actors

**Server & Network:** Denial of Service (DoS) | Open Redirect / Phishing | Server-Side Request Forgery (SSRF)

## Prerequisite Reference

| Value | When |
|---|---|
| Unauthenticated | No login required |
| Subscriber | WordPress Subscriber role |
| Customer | WooCommerce Customer (≈Subscriber) |
| Contributor | Accepted, lower price |
| Author | Accepted, lower price |

## Report Output

Save to `AUDIT_DIR/reports/[plugin-slug]-[vuln-type]-disclosure.md`.
Pipeline: `AUDIT_DIR` = `./audit/<slug>/<version>/`. Standalone: `./audit/reports/`.

### Report hygiene — body vs. metadata
The whole report is submitted to Wordfence **except** the `## Internal Metadata (not submitted)` section (below the `---`), which is stripped before submission.
- **Main body** (`## Type Of Software` through `## All environment, setting, and configuration details`, everything above the `---`): factual disclosure only. Do NOT include any validation narrative — no "(validated against…)", "confirmed in Docker/localhost", "we ran `wp eval-file`", "live-validated", or any reference to the researcher's own test run. Fold corrections discovered while testing into the normal fields as plain fact, with no mention that a test was run.
- **`All environment, setting, and configuration details`**: state accurate versions, including the versions the finding was verified against (e.g. `Plugin version tested: 5.6.1`). These are factual environment data — keep them correct, written as plain values, with no Docker/localhost narrative around them.
- **`Internal Metadata (not submitted)`**: this is the ONLY place a live-validation stamp may appear — add extra rows there if needed (e.g. `Live Validation`, `Version Confirmed Affected — live-validated`, `Exploit Flow Correction`). Never place these in the body.

```markdown
# Vulnerability Disclosure — [Software Name]

## Type Of Software
[WordPress Plugin / WordPress Theme / WordPress Core]

## Software Name
[Full display name]

## Software Slug
[e.g. contact-form-7]

## Affected Version(s)
[e.g. <= 5.8.7]

## Description of Vulnerability
[1–2 sentence factual description]

## Vulnerability Type
[Exact value from reference above]

## Impact Statement
[One sentence impact statement, max 200 characters]

## Common Weakness (CWE) Type
[e.g. CWE-79]

## Authentication Level Required
[Unauthenticated / Subscriber / Customer / Contributor / Author]

## References to Affected Code
- https://plugins.trac.wordpress.org/browser/[slug]/tags/[version]/[path]#L[line]

## What is your Proof of Concept?
[Python / PHP / JavaScript / HTML / Other / Text instructions]

## Provide a working concept

### Part 1 — Setup
Write every step as a concrete GUI action an analyst can follow verbatim. Replace every `[...]` with real, plugin-specific values — no generic placeholders may remain in the final report.
1. Install and activate **[Plugin Name]** version **[x.x.x]** (`Plugins → Add New → Upload Plugin`, then **Activate**).
2. **Configure** — for each required setting give the exact wp-admin menu path and value, e.g. `[Plugin X] → Settings → [Tab Y] → [Field Z]` = `[value]`. If none: "No configuration required."
3. **Create required content** — any page/post/product/form/shortcode the vulnerability needs, with the GUI path to create it (e.g. `Pages → Add New`, insert shortcode `[...]`, **Publish**). If none: "None."
4. **User account** — create the exact role via `Users → Add New` (e.g. Subscriber / Customer), or "Unauthenticated — no account needed."

### Part 2 — Triggering the Vulnerability

**Option A — Via GUI (primary — full clickthrough, no placeholders left):**
5. Navigate to **[exact wp-admin or front-end URL / menu path]**.
6. In **[exact field / control]**, enter payload: `[exact payload]`.
7. Click **[exact button label]**.
8. Navigate to **[observable URL]** as **[role]**.
9. Observe: **[exact result confirming the vulnerability]**.

**Option B — Via HTTP request (secondary — automatable equivalent):**
5. Send:
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: [session cookie if authenticated]

action=[action]&nonce=[value]&[param]=[payload]
```
   - Nonce: [how to obtain]
   - Cookie: [how to obtain]
6. Verify response: [expected status/body].
7. Navigate to [observable URL].
8. Observe: [confirmation].

### Part 3 — Confirming Impact
- [Exact observable evidence]

## Recommended Mitigation
[A vendor patch guide, written as flowing prose followed by one corrected-code block — NOT as separate what/why/where sub-headings. In prose state: WHAT is vulnerable and WHERE (the vulnerable construct + its `file:line` / handler); and WHY it is exploitable (what the flaw enables). Then give ONE before→after fenced code block: the vulnerable line(s) commented `// vulnerable`, followed by the `// fixed` version applying the root-cause fix — the capability check (`current_user_can('manage_options')`), the output escaper (`esc_html()`/`esc_attr()`/`esc_url()`/`wp_kses()`), the `$wpdb->prepare()` / `%i` placeholder, or the per-resource ownership/nonce check. Optionally add related notes (other affected functions, root-cause-relevant hardening). Do NOT include "update to the patched version", defense-in-depth padding, interim/WAF/virtual-patch workarounds, site-operator/admin advice, or generic boilerplate. See "Recommended Mitigation — format & example" below the template for the exact shape.]

## All environment, setting, and configuration details
- WordPress version: [e.g. 6.7.2]
- PHP version: [e.g. 8.1]
- MySQL version: [e.g. 8.0]
- Plugin version tested: [exact]
- Special settings: [or "None — default configuration"]

---

## Internal Metadata (not submitted)

| Field | Value |
|---|---|
| CVSS Score | [e.g. 7.2] |
| CVSS Vector | [e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N] |
| Active Installations | [e.g. 10,000+] |
| CVSS Calculator | https://www.first.org/cvss/calculator/3.1 |
```

## Recommended Mitigation — format & example

Write `## Recommended Mitigation` as prose (what/why/where) followed by one before→after code block. Example:

The AJAX handler in `booking.php:210` writes `$_POST['status']` straight to the database with no capability check, letting any unauthenticated user set an arbitrary booking status. Gate the write with a capability + nonce check:

```php
// booking.php ~L208 — vulnerable
$wpdb->update( $t, [ 'status' => $_POST['status'] ], ... );

// fixed
if ( ! current_user_can( 'manage_options' ) ) { wp_die( '', 403 ); }
check_ajax_referer( 'lp_save' );
$status = sanitize_key( $_POST['status'] );
$wpdb->update( $t, [ 'status' => $status ], ... );
```

## Quality Checklist

- [ ] All form sections populated, no `[PLACEHOLDER]` values
- [ ] Description 1-2 sentences, factual
- [ ] Auth level matches what PoC actually requires
- [ ] Full GUI walkthrough (install→config→create content→account→trigger→confirm) with exact wp-admin menu paths and no leftover [placeholder] values
- [ ] No live-validation / Docker narrative in the main body (validation stamps only under Internal Metadata; environment versions stated as plain accurate values)
- [ ] Raw HTTP request included verbatim
- [ ] Nonce/cookie acquisition documented
- [ ] Exact payload shown
- [ ] Impact confirmation describes exact observable result
- [ ] No undemonstrated impact claims
- [ ] SVN/Trac URLs correct version
- [ ] CVSS vector internally consistent
- [ ] Recommended Mitigation present — vendor patch guide: what/why/where prose + a before→after corrected-code block anchored to file:line (no update/defense-in-depth/WAF/site-operator advice, no boilerplate)
- [ ] Meets Wordfence scope

**Bonuses:** "Meaningful Researcher" (10%): complete, zero-ambiguity GUI reproduction **plus actionable remediation** (the `## Recommended Mitigation` section — what/why/where + before→after corrected code, anchored to the vulnerable file:line). "Affects Multiple Functions": include dedicated section listing ALL affected functions with file:line and per-function notes.

After saving, trigger poc-generator if standalone PoC not yet written.
