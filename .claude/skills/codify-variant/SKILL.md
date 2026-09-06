---
name: codify-variant
description: "Turn ONE confirmed Wordfence variant/CVE (plus its official patch) into a general, reusable Semgrep rule and grep pattern that catch the same vulnerability class in OTHER plugins. Lightweight, single-CVE, run right after a variant-analysis session confirms a disclosed bug in the affected code. The public CVE + patch diff (DIFF.md) is externally-validated ground truth: the pre-fix code is the vulnerable pattern, the fix becomes the rule's FP-suppressing negative clause, and the affected-vs-patched trees on disk are a built-in true-positive/false-positive oracle. Reuses the rule-authoring mechanics of tune-semgrep and tune-vuln-audit rather than duplicating them; never over-fits to the seeding plugin. Use when the user says /codify-variant, or asks to 'turn this CVE/variant into a rule', 'generalize this confirmed bug into a detection', or 'harden the corpus from this disclosure'. NOT for post-full-audit rule tuning from findings.md (that is /tune-semgrep + /tune-vuln-audit)."
---

# Skill: Codify Variant → Detection Rule (`/codify-variant`)

## Purpose
A variant-analysis session (`Variant-analyze CVE-… in <slug>`) confirms a *publicly-disclosed*
vulnerability in the affected code. That CVE + its official patch is higher-quality ground truth than
a self-triaged audit finding: the patch **is** the vulnerable code, and the fix **is** the sanitizer.
This skill folds that one confirmation into the **general** rule corpus so the same class is caught in
other plugins next time — FP-aware, plugin-agnostic, one CVE at a time.

**Why not `/tune-semgrep` / `/tune-vuln-audit`?** Those are heavyweight post-**full-audit** tuners keyed
on a `findings.md` FP/TP/MISSED triage and `pattern_accumulator.db` lifetime stats. A focused variant
session produces no such `findings.md`, and its input (a CVE + patch diff) is a different, cleaner
signal. This skill owns the *patch → general pattern* transform and **defers rule mechanics** to the
proven guidance in those skills (referenced below) so nothing is duplicated or allowed to drift.

## Trigger
```
/codify-variant [slug] [CVE]
```
If `slug`/`CVE` omitted, resolve from the current session's confirmed variant, else the most recently
modified `audit/*/*/DIFF.md`.

## Key paths
```
PROJECT_ROOT = ${CLAUDE_PROJECT_DIR}
RULES_DIR    = ${CLAUDE_PROJECT_DIR}/semgrep_rules/claude_rules   (categories: access-control, email-injection, file-inclusion, file-upload, file-write-delete, info-disclosure, rce, sqli, ssrf, ssti, xss)
GREP_SCRIPT  = ${CLAUDE_PROJECT_DIR}/grep_scan.py
GROUP_REGISTRY = ${CLAUDE_PROJECT_DIR}/group_registry.py
PROVENANCE   = ${CLAUDE_PROJECT_DIR}/semgrep_rules/claude_rules/VARIANT-PROVENANCE.md
REUSE: tune-semgrep/SKILL.md (Phases 2–5) + tune-semgrep/references/quick-reference.md ; tune-vuln-audit/SKILL.md (Phase 4b)
```

## Phase 0 — Resolve the confirmed variant + patch (ground truth)

**0a** — Resolve `SLUG`, `CVE`, `CWE`. Identify the two versions from the variant lead / audit dir:
`AFFECTED_V` (last vulnerable) and `PATCHED_V` (first fixed).
Set `DIFF = audit/<SLUG>/<PATCHED_V>/DIFF.md`, `AFFECTED_SRC = plugins/<SLUG>/<AFFECTED_V>/`,
`PATCHED_SRC = plugins/<SLUG>/<PATCHED_V>/`.

**0b** — Read, in priority order: (1) `DIFF.md` — the patch; (2) the session's confirmed finding
(context, or a `findings.md` if one was written); (3) the CVE/CWE + Wordfence `why:` prose (from the
`targets.md` lead or passed inline). The patch is authoritative when sources disagree.

**0c** — Pin the vulnerable **source→sink** in `AFFECTED_SRC` to an exact `file:line`. This is the
mandatory true-positive oracle for Phase 4. If it cannot be pinned in the actual source tree, STOP —
do not author a rule from an unverified location (global CLAUDE.md: never a code ref you can't verify).

**0d** — Print: `[CODIFY] Phase 0. <SLUG> <AFFECTED_V>→<PATCHED_V> | CVE <CVE> CWE-<n> | sink: <file:line>`

## Phase 1 — Extract & generalize the pattern from the patch (the novel step this skill owns)

**1a — Read the patch as before/after.** The removed (pre-fix) lines are the **vulnerable pattern**;
the added (fix) lines reveal the **neutralizer** (a capability check, a sanitizer, an uploads-dir
containment test, a prepared statement, an allow-list).

**1b — Generalize (90% gate).** Strip everything plugin-specific down to the intrinsic class:
- Replace plugin class/function/hook/option names with the WP-core primitives and the structural shape
  they stand for (e.g. `Image_Backup::remove()` → the generic `get_post_meta(...)` → `wp_delete_file()`/
  `unlink()` flow with no `wp_upload_dir()` containment).
- Keep only tokens that recur across WP plugins. If the pattern is inseparable from this plugin's
  architecture, STOP: `[SKIP] not generalizable — <reason>` (record CVE in Phase 5 log, author nothing).

**1c — Turn the fix into the negative clause.** The sanitizer/guard the patch ADDED becomes the rule's
`pattern-sanitizers` / `pattern-not` / `pattern-not-inside`, so the rule stays silent on already-patched
code. This is FP suppression grounded in the real fix, not guesswork.

**1d** — Print the generalized source→sink + negative clause as 3–5 lines before writing YAML.

## Phase 2 — Semgrep rule: create or extend (mechanics reused from `tune-semgrep`)

**2a — Dedup first.** Search `RULES_DIR/**` for a rule on the **same source-sink pair**.
- Covered but the affected code would NOT have fired → this is a false-negative gap: **extend/widen**
  the existing rule with the variant pattern (add a `pattern-either` branch / loosen an over-tight
  clause). Log `[EXTEND] <rule-id>: variant pattern from <CVE>`.
- Genuinely new class → create a new rule.

**2b — Author.** Follow **tune-semgrep `SKILL.md` Phases 2b–2d verbatim** for: taint-vs-pattern choice,
ID format `claude.php.wordpress.<category>.<slug>`, file `RULES_DIR/<category>/<slug>.yaml`, required
metadata, standard WP sources/sanitizers, and the pattern-syntax quick reference. Place the rule in the
category matching the CWE (e.g. CWE-73/22 → `file-write-delete`/`file-inclusion`, CWE-79 → `xss`,
CWE-89 → `sqli`, CWE-434 → `file-upload`, CWE-862/639 → `access-control`, CWE-502 → `rce`).
Set `metadata.cwe` to this CVE's CWE. **The FP-suppressing negative clause from Phase 1c is mandatory.**

## Phase 3 — Grep pattern: create or extend (mechanics reused from `tune-vuln-audit`)

**3a — Dedup.** Check the existing `SECTIONS` in `GREP_SCRIPT` for a section already surfacing this
sink. If present → add the new regex to its `"patterns"` list. Else → new section.

**3b — Author.** Follow **tune-vuln-audit `SKILL.md` Phase 4b format rules verbatim**: add the section
to the `SECTIONS` dict (`"group"` must be a valid `group_registry.grep_file_map()` bucket) and append the
section name to the correct `GROUP_SECTION_ORDER` list. Regex targets the generalized sink token (Python
`re` syntax), NOT the plugin name. Log `[GREP] <section>: <pattern>`.

**3c — Group-file prose is optional and conditional (cheapest-sink-first).** The detection now lives in
the Semgrep rule + grep section + `PROVENANCE`; do NOT reflexively add a group-file line. Add a
`vuln-audit-group-*.md` reference ONLY if it carries a ≤2-sentence *general principle* a pattern cannot
encode (a sanitizer-semantics or trust-boundary fact), and only if the owning group's "FP Verification
Rules" list is under its 15-rule cap and no existing rule already names this section (check with
`python skill_size_report.py` + a dedup read). Otherwise author nothing in the group file. Log
`[GROUP-REF] <file> — <principle>` or `[GROUP-REF] none (detection in machine sinks only)`.

## Phase 4 — Two-version CVE oracle + standard validation

The affected-vs-patched trees are a free TP+FP oracle straight from the CVE. Every new/extended rule
MUST pass all four:

1. `semgrep --validate --config <rule.yaml>` → PASS.
2. `semgrep --test --config <rule.yaml> <test.php>` → PASS. Author ≥2 `// ruleid:` (vulnerable variants,
   incl. the real pre-fix shape) and ≥2 `// ok:` cases (the fix + a WP DB-read pattern), per
   tune-semgrep Phase 3.
3. `semgrep --config <rule.yaml> <AFFECTED_SRC>` → **fires on the Phase-0c `file:line`** (true positive).
4. `semgrep --config <rule.yaml> <PATCHED_SRC>` → **silent** at that location (the fix is the natural
   `ok` — false-positive guard confirmed by the real patch).
If (3) misses or (4) still fires, fix the rule (isolate per tune-semgrep Phase 4c) — do not ship a rule
that fails its own CVE oracle. Log each: `[VALIDATE]/[TEST]/[TP]/[FP-GUARD] <rule-id>: PASS|FAIL`.

## Phase 5 — Provenance + summary

**5a** — Append one line to `PROVENANCE` (create if absent) mapping rule/section → seeding CVE, so the
CVE trail lives OUTSIDE the rule YAML (rule `references` stay CWE/OWASP-only):
`<rule-id or section>  ⇐  <CVE>  CWE-<n>  (<SLUG> <AFFECTED_V>→<PATCHED_V>, <date>)`.

**5b** — Report:
```
════════════════════════════════════════════════
[CODIFY] variant codified — <CVE> (CWE-<n>)
════════════════════════════════════════════════
Semgrep:  [NEW|EXTEND|SKIP] <rule-id> @ <path>
Grep:     [NEW|EXTEND|SKIP] <section>
Oracle:   TP on <AFFECTED_V> ✓ | silent on <PATCHED_V> ✓
Validate/Test: PASS/PASS
Provenance appended: <PROVENANCE>
════════════════════════════════════════════════
```

## Hard Constraints
- One CVE per run. Author at most 1 Semgrep rule (new or extended) + 1 grep pattern (new or extended).
- Cheapest sink first: the detection belongs in the Semgrep rule + grep section (+ `PROVENANCE`); a
  `vuln-audit-group-*.md` line is added only per Phase 3c (≤2-sentence principle, under the 15-rule cap),
  never a per-CVE recipe.
- Only write under `RULES_DIR/`, `GREP_SCRIPT` (`SECTIONS` + `GROUP_SECTION_ORDER`), the owning
  `vuln-audit-group-*.md`, and `PROVENANCE`. Never edit `group_registry.py`, `extract_semgrep_coords.py`,
  or `pattern_accumulator.py`; add a group only in `group_registry.py` if genuinely needed (rare).
- Do NOT touch `pattern_accumulator.db` — that is full-audit territory.
- No plugin name, plugin-specific class/function/option, or CVE/changelog URL in rule `message`, YAML
  comments, or `references` (CWE/OWASP links only). Provenance goes only in `PROVENANCE`.
- 90% generalizability gate is a hard floor — pattern must recur across WP plugins. When in doubt, SKIP.
- The Phase-1c fix-derived negative clause is mandatory; a rule with no FP guard from a patch that added
  one is incomplete.
- Never ship a rule that fails its Phase-4 CVE oracle (must fire on affected, be silent on patched).
- All Semgrep mechanics/constraints inherit from `tune-semgrep/SKILL.md` (Hard Constraints + the two
  `metavariable-regex` gotchas) and all grep-format rules from `tune-vuln-audit/SKILL.md` Phase 4b —
  read them; do not restate or diverge.
