---
name: tune-semgrep
description: "Post-audit Semgrep rule tuner. Run after a Full Audit Pipeline to: (1) reduce false positives in existing rules (only when >90% confidence); (2) create new detection rules for vulnerability patterns discovered during the audit; (3) write PHP test cases with ruleid/ok annotations; (4) validate and test all changes via semgrep CLI; (5) cross-reference each rule's lifetime TP/FP from pattern_accumulator.db to prioritize systemic false positives and avoid loosening rules that catch real bugs in other audits."
---

# Skill: Semgrep Rule Tuner (`/tune-semgrep`)

## Purpose
Refine and extend `semgrep_rules/` using confirmed findings and FP triage data from `findings.md` as ground truth. Every change traceable to audit evidence.

## Trigger
```
/tune-semgrep [plugin-slug]
```
If slug omitted, locate most recently modified `findings.md` under `audit/*/`.

## Key paths
```
PROJECT_ROOT = ${CLAUDE_PROJECT_DIR}
RULES_DIR    = ${CLAUDE_PROJECT_DIR}/semgrep_rules/claude_rules
```
All custom rules under `RULES_DIR/<category>/`. Do NOT modify files outside `RULES_DIR`.

## Phase 0 — Locate Audit Artefacts

**0a** — Resolve slug/version: use arg or find most recent `findings.md`.
Set: `FINDINGS = audit/<slug>/<version>/findings.md`, `SEMGREP_SCAN = plugins/<slug>/<version>/semgrep-scan/`

**0b** — Read findings.md. Extract:
- **FP_LIST**: semgrep hits triaged as FP. Record: rule ID (`check_id`), file:line, why FP.
- **MISSED_LIST**: confirmed vulns NOT flagged by semgrep. Record: vuln type, file:line, pattern description.

**0c** — Read semgrep scan data. If `AUDIT_DIR/semgrep/semgrep-group-*.md` exist (pipeline mode), read those instead of parsing raw JSON — the extraction was already done during the pipeline. Otherwise, read semgrep scan JSON. For each FP_LIST entry, retrieve check_id, matched path/line, code snippet. (The `semgrep-group-<id>` filenames and the rule-id→group classification are defined in `group_registry.py`; this skill globs `semgrep-group-*.md` so it is group-count-agnostic — but if you add a new rule-id keyword that should route to a group, add it to the registry's `semgrep_rule_patterns`, not to `extract_semgrep_coords.py` directly.)

**0d** — Print: `[TUNE] Phase 0 complete. Plugin: <slug> <version>. FP hits: N. Missed: N.`

## Phase 1 — FP Triage & Rule Modification

Process each FP_LIST entry. Ground the triage in the rule's cross-audit history first, then map → read → gate → modify:

**1a** — Cross-audit lifetime lookup (DB-informed, read-only). Before judging this audit's FP in isolation, pull the rule's lifetime record across ALL audits:
```
python pattern_accumulator.py stats --semgrep-rule <rule-id> --format json
```
`<rule-id>` is the canonical id = the last dotted segment of the `check_id` (the same string used as the YAML filename, e.g. `nonce-without-capability-check`). From the JSON, record `tp`, `fp`, `tp_rate`, `audits_seen`, `top_fp_reasons`, then interpret:
- **Systemic dead rule** (`fp` ≥ 10 AND `tp` == 0): the rule has never produced a confirmed finding anywhere — this FP is the rule's norm, not an exception. Prioritize tightening it, and record it in the Phase 6 **dead-rule candidates** list for human-reviewed deletion (do NOT delete it here — see Hard Constraints).
- **Productive rule** (`tp` ≥ 1, especially `tp_rate` ≥ 0.05 or `audits_seen` > 1): the rule catches real bugs in other audits. Any filtering clause must provably preserve those historical TPs — this raises the bar in the 1d gate; when in doubt, split (1f) instead of narrowing the shared rule.
- **`top_fp_reasons`**: the dominant dismissal categories for this rule corpus-wide — the clause you add should neutralize the most common reason, not just this single match.
- Empty/zero record → the corpus DB has no history for this rule yet (fresh setup); proceed on this audit's evidence alone. (`pattern_accumulator.py backfill` populates history — see `docs/accumulator-playbook.md`.)

**1b** — Map `check_id` to YAML file under `RULES_DIR/`. All rules used in scans are local custom rules in `RULES_DIR/` — no external rules exist. The `check_id` in semgrep JSON uses dot-separated path notation (e.g., `semgrep_rules.claude_rules.xss.claude.php.wordpress.xss.rule-slug` maps to `RULES_DIR/xss/rule-slug.yaml`). Extract the category and slug from the check_id: the category is the segment after `claude_rules.` (before the rule's own ID prefix `claude.php.wordpress.`), and the filename is the last segment of the rule ID. If a simple path lookup fails, use Glob to search `RULES_DIR/**/*.yaml` for the rule ID. Never classify a rule as "external" — if a rule file cannot be found after searching, log `[SKIP] <rule-id>: rule file not located in RULES_DIR` and continue.

**1c** — Read rule YAML. Identify: current patterns, existing sanitizers/pattern-not clauses, why FP code matches despite being safe.

**1d** — 90% confidence gate. Modification ONLY allowed when ALL true:
1. >90% confident new clause filters ONLY FPs, not genuine vulns
2. FP from clearly safe pattern (e.g., data from `get_option()`/`get_post_meta()` reaching sink)
3. Can write `// ok:` test proving FP filtered without removing TP coverage
4. If the rule has lifetime `tp` ≥ 1 (step 1a), the new clause provably preserves those historical TP patterns — otherwise split (1f) rather than narrow the shared rule

Do NOT modify if: confidence ≤90%, fix suppresses genuine vulns, pattern is context-dependent, requires inter-procedural logic.
Skip: `[SKIP] <rule-id>: confidence ≤90%. Reason: <one-line>`

**1e** — Apply modification: add filtering clause (`pattern-sanitizers`, `pattern-not-inside`, `metavariable-regex`). Add inline comment explaining WHY safe (1 sentence max, generic pattern description, no plugin names). Log: `[MODIFIED] <rule-id>: added <clause> — <reason>`

**1f** — Rule splitting (last resort): split into tight Rule A + wider Rule B (`confidence: LOW`). Log: `[SPLIT] <original> → <a> + <b>`

## Phase 2 — New Rule Creation

Process each MISSED_LIST entry. (This phase is also the DESTINATION when `tune-vuln-audit` / `codify-variant` relocate a pattern-expressible detection out of group-file prose: treat such a relocation request as a MISSED_LIST entry — author/extend the rule here under the matching category and `semgrep --test` it, after which the caller condenses the prose.)

**2a** — Deduplication + Viability:
1. Search existing rules in RULES_DIR for overlapping detection (same source-sink pair). If covered → extend existing rule with variant pattern instead of creating duplicate. Log: `[EXTEND] <rule-id>: added variant pattern`
2. Viability: pattern must recur across WP plugins, be expressible in Semgrep (taint/pattern mode), and would have fired on the vulnerable code. If not viable: `[SKIP NEW] <vuln-type>: <reason>`

**2b** — Choose approach: **Taint mode** for injection-class (SQLi, XSS, RCE, SSRF, LFI, POI). **Pattern mode** for structural issues (missing auth, dangerous config).

**2c** — Write the rule:

ID format: `claude.php.wordpress.<category>.<descriptive-slug>`
File: `RULES_DIR/<category>/<descriptive-slug>.yaml`

Required metadata: `id`, `mode` (taint/omit), `languages: [php]`, `severity`, `message`, `metadata` (category, cwe, owasp, confidence, likelihood, impact, subcategory, vulnerability_class, technology, references).
- `severity` levels: CRITICAL, HIGH, MEDIUM, or LOW

Metadata format constraints:
- `message`: State the vulnerability pattern generically. No plugin names or plugin-specific class references.
- `references`: CWE/OWASP links only. No plugin-specific audit URLs or changelog links.
- YAML comments (`# ...`): Describe detection logic only. No audit war stories or plugin-specific context. 1 sentence max.

Standard WP taint sources:
```yaml
pattern-sources:
  - pattern-either:
      - pattern: $_GET
      - pattern: $_POST
      - pattern: $_REQUEST
      - pattern: $_COOKIE
      - pattern: $_SERVER
      - pattern: $_FILES
      - pattern: file_get_contents("php://input")
      - pattern: filter_input(...)
```

Standard WP sanitizers (include relevant subset only):
```yaml
pattern-sanitizers:
  - pattern-either:
      - pattern: (int) $X
      - pattern: (float) $X
      - pattern: intval(...)
      - pattern: absint(...)
      - pattern: floatval(...)
      - pattern: sanitize_key(...)
      - pattern: $wpdb->get_results(...)
      - pattern: $wpdb->get_row(...)
      - pattern: $wpdb->get_var(...)
      - pattern: $wpdb->get_col(...)
      - pattern: get_option(...)
      - pattern: get_post_meta(...)
      - pattern: get_user_meta(...)
      - pattern: get_transient(...)
      - pattern: get_comment_meta(...)
      - pattern: get_site_option(...)
```

Only include sanitizers relevant to the sink. `sanitize_text_field` does NOT neutralize SQLi.

**Pattern Syntax Quick Reference:**

| Syntax | Description |
|--------|-------------|
| `...` | Match anything |
| `$VAR` | Capture metavariable |
| `<... ...>` | Deep expression match |
| `pattern-either` | OR |
| `patterns` | AND |
| `pattern-not` / `pattern-not-inside` | Exclude |
| `metavariable-regex` | Regex on captured value |

**2d** — Log: `[NEW RULE] <rule-id> → <file-path>`

## Phase 3 — Test Case Creation

For every modified or new rule, create/update test file at `RULES_DIR/<category>/<slug>.php`.

Requirements per rule:
- ≥2 `// ruleid: <rule-id>` cases (common vulnerable patterns, include actual audit code)
- ≥2 `// ok: <rule-id>` cases (sanitized variant + WP DB-read pattern)

Rules: file starts with `<?php`, use `global $wpdb;` when needed, annotation on line immediately before flagged expression, keep cases self-contained.

Log: `[TEST FILE] <rule-id> → <path> (N ruleid, M ok cases)`

## Phase 4 — Validate & Test via CLI

**4a** — Validate YAML: `semgrep --validate --config "<path-to-rule.yaml>"`
PASS → `[VALIDATE] <rule-id>: PASS`. FAIL → fix and retry (max 2 attempts).

**4b** — Run tests: `semgrep --test --config "<path-to-rule.yaml>" "<path-to-test.php>"`
PASS → `[TEST] <rule-id>: PASS`. FAIL → diagnose (rule too narrow/broad or annotation wrong), fix, re-run.
`semgrep --test` DOES correctly execute `mode: join` rules (confirmed empirically,
recent Semgrep, when logged in via `semgrep login`) — always run it for join-mode
rules too. Do not skip `--test` or treat a join-mode rule as "unverifiable" — that
assumption has previously masked a real bug (see 4c).

**4c** — If a rule (join-mode or plain) reports 0 findings where you expect ≥1,
debug in this order BEFORE suspecting the environment (login/auth/join-mode itself):
1. **Isolate every sub-pattern.** For a join-mode rule, temporarily copy each
   `join.rules[]` entry out as its own standalone top-level `rules:` file and run
   it alone against the test PHP. For a plain rule with multiple `pattern-not`
   clauses, temporarily strip them one at a time. Find exactly which clause
   produces 0 when it should produce >0 — do not debug the whole rule at once.
2. **Check for the two `metavariable-regex` gotchas** documented in
   `references/quick-reference.md`: (a) prefix-anchored matching — a regex like
   `(foo|bar)` without a leading `.*` will silently fail to match `myplugin_foo`;
   (b) a metavariable embedded as a partial prefix inside a quoted string literal
   (`pattern: fn('literal_$X')`) never matches — capture the whole string with a
   bare metavariable and filter with `metavariable-regex` instead.
3. Only after ruling out 1–2 should you suspect `semgrep login` state, join-mode
   memory limits, or a genuine environment issue — verify login separately with
   `cat ~/.semgrep/settings.yml` (look for a populated `api_token`), not by
   inference from a 0-finding result, since a pattern bug and an auth failure can
   look identical in the summary output (both show `Findings: 0`).
Log: `[DEBUG] <rule-id>: 0 findings — isolated to <sub-rule/clause> — root cause: <one-line>`

## Phase 5 — Plugin Source Verification

Run every modified/new rule against audited plugin source:
```bash
semgrep --config "<path-to-rule.yaml>" "<SOURCE_DIR>" --text
```

**5a (modified rules):** Previously-FP locations must no longer appear. If still firing → fix rule.
Log: `[SOURCE SCAN] <rule-id>: N hits remaining (was M). Suppressed: [list]. Remaining: [list]`

**5b (new rules):** Must fire on expected vulnerable file:line. List all hits, classify additional as TP or expected FP with one-sentence reason. If expected location missing → revise pattern.
Log: `[SOURCE SCAN] <rule-id>: N hits. Expected TP: file:line ✓/✗. Additional: [list]`

**5c** — If source scan reveals uncovered FP pattern, document in test file comment (not as `// ok:` unless genuinely safe).

## Phase 6 — Summary Report

```
════════════════════════════════════════════════════
[TUNE] Semgrep rule tuning complete — <slug> <version>
════════════════════════════════════════════════════

Rules modified:   N
  - <rule-id>: <change description>

Rules created:    N
  - <rule-id> @ <path>

Rules skipped (confidence <90% or not located):  N
New rules skipped (not viable):    N
Dead-rule candidates (lifetime FP≥10 & TP=0 from pattern_accumulator.db — flagged for human review, NOT deleted):  N
  - <rule-id>: lifetime FP=<fp>, TP=0

Validation: N pass / N fail
Tests:      N pass / N fail
Source scans: N pass / N fail

All changes in: semgrep_rules/claude_rules/
════════════════════════════════════════════════════
```

## Hard Constraints

- Never modify files outside `RULES_DIR/claude_rules/`
- Never delete existing rules, test cases, or annotations
- Dead-rule candidates surfaced from pattern_accumulator.db (lifetime FP≥10, TP=0) are REPORTED for human review only — never auto-delete a rule based on accumulator stats
- Never lower confidence/likelihood/impact metadata without audit-grounded reason
- Never add `# nosemgrep` to plugin source — fix the rule
- Never create rules firing on all uses of common functions regardless of data flow — use taint mode
- All new IDs: `claude.php.wordpress.<category>.<slug>`
- Test files must be syntactically valid PHP
- Always `--validate` before `--test`
- 90% confidence gate is a hard floor
- Rule `message` fields and YAML comments must not reference specific plugin names or audit slugs
- Inline `# ...` comments: max 1 sentence, describe safe/unsafe pattern generically
- Before creating new rule, verify no existing rule in RULES_DIR covers same source-sink pair
- `metavariable-regex` is prefix-anchored (Python `re.match` semantics), not substring search — a regex without a leading `.*` only matches strings starting with that literal text. Always lead with `.*` unless intentionally anchoring to position 0.
- Never write a metavariable as a partial prefix inside a quoted string literal (e.g. `pattern: fn('literal_$X')`) — it silently matches nothing. Capture the whole argument with a bare metavariable (`pattern: fn($X)`) and constrain it with `metavariable-regex`.
- A rule/clause that inexplicably produces 0 findings is validate-clean and error-free — Semgrep does not warn on unmatchable patterns. Treat unexpected 0-finding results as a pattern bug to isolate (Phase 4c) before concluding the vulnerability class isn't present or the environment is broken.

## References

- [Semgrep Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
- [Rule Schema](https://github.com/semgrep/semgrep-interfaces/blob/main/rule_schema_v1.yaml)
- [Local Quick Reference](references/quick-reference.md)
