---
name: tune-vuln-audit
description: "Post-audit vuln-audit skill tuner. Run after a Full Audit Pipeline to: (1) identify vulnerability patterns the skill's methodology didn't surface efficiently and add grep patterns, tier guidance, or chain examples to close the gap; (2) remove demonstrably false assertions from the skill (only when >90% confidence); (3) expand false-positive prevention guidance based on investigated-but-dismissed leads, prioritized by the cross-audit FP-cause backlog from pattern_accumulator.db. Every change requires audit-grounded evidence. Never over-fits to a specific plugin. Enforces conciseness caps and deduplication to prevent unbounded skill growth."
---

# Skill: Vuln-Audit Skill Tuner (`/tune-vuln-audit`)

## Purpose
Refine `vuln-audit` skill using confirmed findings, investigated FPs, and triage notes from `findings.md`. Every change traceable to explicit audit evidence. Stylistic improvements and "could be useful" additions are out of scope.

## Trigger
```
/tune-vuln-audit [plugin-slug]
```
If slug omitted, locate most recently modified `findings.md` under `audit/*/`.

## Key paths
```
PROJECT_ROOT      = ${CLAUDE_PROJECT_DIR}
SKILL_CORE_PATH   = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/SKILL.md
SKILL_GROUP_FOUNDATION = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-foundation.md
SKILL_GROUP_AB    = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-ab.md
SKILL_GROUP_AC    = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-ac.md
SKILL_GROUP_A     = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-a.md
SKILL_GROUP_SQLI  = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-sqli.md
SKILL_GROUP_C     = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-c.md
SKILL_GROUP_D1    = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-group-d1.md
SKILL_CHAIN       = ${CLAUDE_PROJECT_DIR}/.claude/skills/vuln-audit/vuln-audit-chain.md
# Group adv collapsed — there is NO vuln-audit-group-adv.md.
# Route: Tier-12 race + Beyond-the-Checklist adversarial → SKILL_CHAIN; draft-status/parse_args → SKILL_GROUP_AC.
GREP_SCRIPT_PATH  = ${CLAUDE_PROJECT_DIR}/grep_scan.py
GROUP_REGISTRY_PATH = ${CLAUDE_PROJECT_DIR}/group_registry.py
SIZE_REPORT       = ${CLAUDE_PROJECT_DIR}/skill_size_report.py
YIELD_REPORT      = ${CLAUDE_PROJECT_DIR}/grep_section_yield.py
AUDIT_ROOT        = ${CLAUDE_PROJECT_DIR}/audit/
```

## Phase 0 — Locate Audit Artefacts

**0a** — Resolve slug/version from arg or most recent findings.md.
Set: `FINDINGS`, `AUDIT_CTX` (may not exist), `SEMGREP_SCAN` (may not exist).

**0b** — Read findings.md. Build three lists:

**TP_LIST** — confirmed vulns: vuln class/tier, file:line, discovery method (grep/independent/chain/second-order), which Phase led to it.

**FP_LIST** — dismissed leads: trigger source, dismissal reason, whether skill FP prevention would have covered it.

**INACCURACY_LIST** — findings contradicting specific skill assertions: incorrect quote, audit evidence, proposed correction.

**0c** — Read audit-context.md (if present): missed attack surfaces, entry point types not in Phase 1 greps, security mechanisms not in Phase 2B.

**0d** — Print: `[TUNE-AUDIT] Phase 0 complete. Plugin: <slug> <version>. TPs: N. FPs: N. Inaccuracies: N.`

**0e — Read the size/list budget report (read-only gate).**
```
python skill_size_report.py
```
Record which files are `OVER`/`WARN` and which governed lists (per-group FP Verification, chain catalog, core FP/FN) are at/over cap. A file or list already `OVER` is in **reduction-only** mode for this run: any addition to it MUST be offset by a merge/condense/auto-removal in the SAME file so its top-level count does not grow (Phase 4.5/4.6). If the report cannot run, proceed but treat every file as at-budget (append only under an existing rule).

## Phase 1 — True Positive Gap Analysis

For each TP, assess:
1. **Grep coverage** — existing Phase 1/Tier pattern surfaces the file/function? `[COVERED]` or candidate for new pattern.
2. **Tier coverage** — vuln class in relevant Tier? Specific variant documented?
3. **Chain coverage** — multi-step chain in Phase 2C?
4. **Second-order/flow coverage** — stored-value trace guidance in Phase 1B/Tier?

Build **TP_GAPS**: TPs where any question = "no".

**1b — Generalizability gate (90% required):**
Do NOT add if: plugin-specific architecture/naming, function unique to one plugin (unless WP core/widely-used library), gap requires knowing this plugin's structure, confidence ≤90%.
Skip: `[SKIP GAP] <vuln-class>: <reason>`

**1c — Classify approved additions:**

| Type | When |
|---|---|
| New grep pattern | Function/hook/structure signaling attack surface, not yet in Phase 1/Tier greps |
| New anti-pattern example | Variant of known vuln class |
| New chain pattern | Multi-step escalation not in Phase 2C |
| New false-negative blind spot | "Never assume" item preventing future misses |
| New tier sub-section | Whole vuln class missing from tier structure |

**Routing note (apply before finalizing any classification):** run the Phase 4a cheapest-sink-first test on each candidate. If the detection is pattern-expressible (a specific sink/shape), it becomes a Semgrep rule and/or grep section — not a prose example/tier/FP rule — and any accompanying prose is trimmed to the ≤2-sentence principle.

## Phase 1.5 — Deduplication & Coverage Check

Before proposing any addition from Phase 1 or Phase 2, check existing vuln-audit coverage:

**1.5a — Search existing rules.** For each candidate addition:
1. Read every list the candidate could duplicate: the core FP Verification + FN Prevention lists (SKILL_CORE_PATH Phase 4), the "FP Verification Rules" list in the OWNING group file, the chain-pattern catalog (SKILL_CHAIN), and — for grep/Semgrep candidates — the existing `grep_scan.py` `SECTIONS` and the `semgrep_rules/claude_rules/<category>/` rules on the same source-sink pair.
2. Does an existing rule/section already state the same general principle or cover the same source-sink pair? Match on: same sink type, same auth pattern, same sanitization misconception.
3. If YES → `[ALREADY COVERED] <candidate> — covered by <file> FP #N / FN #N / section <name>` → SKIP.
4. If PARTIAL (existing rule covers the category but candidate adds a genuinely new sub-case) → extend it (a sub-bullet under the existing prose rule, an added regex in the existing grep section, or a `pattern`/`pattern-not` clause in the existing Semgrep rule), not a new top-level rule.

**1.5b — Merge candidates.** If two or more candidates from this audit share the same underlying principle, merge into one addition.

## Phase 2 — FP Investigation & Prevention Gap Analysis

**2a — Cross-audit FP-cause backlog (DB-informed, read-only).** Before triaging this audit's FPs, pull the corpus-wide FP-cause histogram so prevention effort targets the dismissal categories that cost the most triage across ALL audits, not just the ones that happened to recur here:
```
python pattern_accumulator.py fp-causes --format json
```
Read `.categories[]` — each entry has `category`, `count`, `pct`, and `top_rules`. The highest-`count` categories (historically `admin_only`, `escaped_output`, `hardcoded_data`, `nonce_present`, `has_cap_check`) are the highest-value FP-prevention targets. If `fp-causes` returns nothing (fresh DB), proceed on this audit's evidence alone (`pattern_accumulator.py backfill` populates it — see `docs/accumulator-playbook.md`).

**2a2 — Grep/Semgrep yield (DB + disk, read-only).** Before ADDING or EVICTING any group-file rule, grep section, or Semgrep rule, pull per-sink yield so the decision is evidence-driven:
```
python grep_section_yield.py
python pattern_accumulator.py stats --semgrep-rule <id>   # for any rule/candidate naming a Semgrep id
```
A section/rule that is `PRODUCTIVE` (≥1 TP) is protected — never prune it. A section/rule that is `NEVER_HIT`/`HIGH_NOISE_NO_TP`, or FP≥10 & TP=0, is an eviction candidate (Phase 4.6). If neither report runs (fresh DB), proceed on this audit's evidence alone.

**2b — Per-FP analysis.** For each dismissed FP:
1. Matching rule in Phase 4 / "never assume" blind spot? `[FP COVERED]` or candidate.
2. Generalizable? (Same 90% test as Phase 1)
3. Corpus weight: does this FP's dismissal reason map to a top `fp-causes` category (2a)? If yes, it is a high-priority prevention candidate — corpus evidence shows the pipeline re-derives this dismissal repeatedly; pair the eventual Phase 4f rule with that category's `top_rules`.

Classify additions: new Phase 4 verification item, new "never assume" blind spot, new capability/nonce context rule.

## Phase 3 — Skill Accuracy Audit

For each INACCURACY_LIST entry:

**3a** — Verify: quote exact text from SKILL_PATH, state contradicting evidence, confirm not plugin-specific edge case.

A statement is an inaccuracy if: demonstrably false in common case, describes security function behavior incorrectly, or grep pattern reliably produces high-noise results.

NOT an inaccuracy just because: wasn't relevant to this plugin, describes uncommon-but-real vuln class, this plugin happened to be safe, phrasing preference.

**3b** — 90% confidence gate for removals. ALL must be true:
1. Confidence >90% factually incorrect
2. Would cause missed vuln OR false report
3. Correction doesn't remove real vuln class coverage
4. Can state specific verified correction

Skip: `[SKIP INACCURACY] "<text>": <reason>`

## Phase 4 — Apply Changes

**4a** — Read current SKILL_CORE_PATH, all SKILL_GROUP_* files, SKILL_CHAIN, and GREP_SCRIPT_PATH in full.

**Routing an addition — cheapest sink first (the growth-control rule).**
Detection knowledge has three sinks with very different context cost. The Semgrep corpus
and `grep_scan.py` are NEVER read into an agent's context window and each already carries
yield governance; group-file/core prose is read WHOLE into every group sub-agent and is the
least-governed, most-expensive copy. Route to the CHEAPEST sink that can hold it — prose is
the last resort, not the default:

**Precedence:**
1. **A detectable sink/shape** (a specific function/call/AST shape that signals the vuln) →
   **a Semgrep rule** (author/extend via tune-semgrep Phase 2b–2d mechanics) AND/OR **a
   `grep_scan.py` section** (Phase 4b). This is the DEFAULT home for any pattern-expressible
   detection.
2. **Reasoning a pattern cannot encode** (sanitizer/escaper semantics, a trust-boundary
   distinction, a WP Core behavior fact) → a **thin prose rule**, a **≤2-sentence general
   principle**. NEVER a per-CVE recipe; NEVER a rule whose body just restates a grep/Semgrep
   id. Litmus test: if the substance is "use grep X + Semgrep Y, then verify Z", X/Y hold the
   detection and only the ≤1-sentence "verify Z" principle may become prose.

**Prose destination (only after the precedence test sends it here):**
- Canonical definition, write-through protocol, or *universal* FP/FN rule → SKILL_CORE_PATH.
  Do NOT put tier-specific reasoning in the core — it is read by all 8 groups.
- Tier-specific reasoning → the owning group file:
  - Foundation facts (auth model, role/capability mapping, nonce availability, custom-sink inventory) → SKILL_GROUP_FOUNDATION
  - Tier 1-2 → SKILL_GROUP_A
  - Tier 3 (SQL injection) → SKILL_GROUP_SQLI
  - Tier 4/4B (broken access control, CSRF) + Tier 11 IDOR, and draft-status/`parse_args` patterns → SKILL_GROUP_AC
  - Tier 5-6 → SKILL_GROUP_C
  - Tier 8-10 (email, info disclosure; SSRF is OOS) → SKILL_GROUP_D1
  - Auth Bypass (CWE-287/288) → SKILL_GROUP_AB
  - Tier 12 race + Beyond-the-Checklist adversarial reasoning → SKILL_CHAIN (Group adv collapsed; no group-adv file exists)
- Chain pattern (combine confirmed findings for higher impact) → SKILL_CHAIN (Phase 2C Step 2)
- *Reconciliation* pattern — a late-discovery class (an orphan/unconsumed sink, or an impact-group
  auth-model addendum) that should re-open an earlier group's benign/dismissed verdict and become
  a net-new finding → SKILL_CHAIN (Phase 2C Step 1)

**Relocation protocol (moving existing fat prose into a machine sink — never lose recall mid-change).**
When an existing prose rule is a per-CVE recipe that belongs in a machine sink:
1. Create or confirm the Semgrep rule (tune-semgrep Phase 2b–2d) and/or the `grep_scan.py` section FIRST.
2. Validate: `semgrep --test` passes the rule's `ruleid`/`ok` annotations (and the grep section fires on a known-vulnerable tree).
3. ONLY THEN condense the prose to its ≤2-sentence principle (Phase 4.5) or remove it (Phase 4.6).
Never condense or remove the prose before its replacement sink exists and is validated.

**4b** — Grep patterns: add a new entry to the `SECTIONS` dict in GREP_SCRIPT_PATH (`grep_scan.py`), add the section name to the correct list in `GROUP_SECTION_ORDER`, and add a reference in the relevant vuln-audit group file. Log: `[ADDED GREP] <pattern> -> section: <name>`

  **grep_scan.py format rules (hard requirements):**
  - Each section is a key in the `SECTIONS` dict with a value dict containing at minimum `"group"` and `"patterns"`.
  - `"group"` must be one of the bucket ids in `GROUP_REGISTRY_PATH` (`group_registry.grep_file_map()` keys): `"surface"`, `"foundation"`, `"group-a"`, `"group-ab"`, `"group-ac"`, `"group-sqli"`, `"group-c"`, `"group-d1"`. The group set is defined ONLY in `group_registry.py` — never add a group by editing `grep_scan.py`/`extract_semgrep_coords.py`/`pattern_accumulator.py` directly; add it to the registry first.
    (Note: the per-section `"group"` field is currently informational — the writer routes sections via `GROUP_SECTION_ORDER` — but keep it accurate.)
  - `"patterns"` is a list of regex strings (Python `re` syntax, NOT ripgrep).
  - Optional keys: `"invert"` (bool), `"limit"` (int), `"exclude_patterns"` (list of regex strings), `"cross_file_filter"` (regex string — only search files whose full text matches), `"case_insensitive"` (bool), `"glob_override"` (comma-separated glob string — search these files instead of `**/*.php`), `"line_filter"` (regex string — matched line must also satisfy), `"exclude_path_patterns"` (list of regex strings — skip files matching).
  - After adding the SECTIONS entry, append the section name to the correct group list in `GROUP_SECTION_ORDER`.
  - No analysis notes or vulnerability context in the Python dict — those belong in vuln-audit group files.

**4c** — Anti-pattern examples: insert in relevant Tier/Phase 4 with code examples. Max 3-line code snippet + 1-sentence description. No plugin names in example comments. Log: `[ADDED EXAMPLE] <class>: <name>`

**4d** — Chain / reconciliation patterns: insert in Phase 2C of SKILL_CHAIN. A combine-confirmed-findings pattern goes under **Step 2 (Chaining)**; a late-discovery pattern that should turn an orphan/unconsumed sink or an impact-group auth-model addendum into a net-new finding goes under **Step 1 (Reconciliation)**. Only add a reconciliation pattern when this audit shows a real finding the forward-only ordering would have dropped (evidence-grounded, per the no-over-fit rule). Log: `[ADDED CHAIN] <name> → Phase 2C Step <1|2>`

**4e** — Blind spots (FN Prevention list):
1. Search existing FN Prevention list for a rule covering the same general principle (same sink, same auth misconception, same sanitization gap).
2. If covered → `[SKIP BLIND SPOT] already covered by FN #N` → SKIP.
3. If partially covered → add 1-sentence sub-bullet under the existing rule. Log: `[EXTENDED FN #N] — <sub-bullet text>`
4. If genuinely novel category → append new numbered rule. Log: `[ADDED BLIND SPOT] #N — <text>`

**4f** — FP prevention (FP Verification list). Prioritize additions that close a top `fp-causes` category (Phase 2a) — these eliminate the most repeated corpus-wide triage cost:
1. Search existing FP Verification list for a rule covering the same general principle.
2. If covered → `[SKIP FP CHECK] already covered by FP #N` → SKIP.
3. If partially covered → add 1-sentence sub-bullet under the existing rule. Log: `[EXTENDED FP #N] — <sub-bullet text>`
4. If genuinely novel verification category → append new numbered rule. Log: `[ADDED FP CHECK] #N — <text>`

**Format constraint for 4e/4f additions:** Max 2 sentences per rule or sub-bullet. No plugin names, plugin-specific class/function names, or `[TP: plugin version]`/`[FP: plugin version]` annotations. State the general principle and verification action only.

**4g** — Inaccuracy corrections: replace/delete incorrect text, no placeholders. Log: `[CORRECTED] "<text>" → <summary>` or `[DELETED] "<text>" — <reason>`

**4.5 — Consolidation pass (after all additions).** Run this over EVERY governed prose list touched or grown this run — the core FP Verification and FN Prevention lists AND each group file's "FP Verification Rules" list AND the chain-pattern catalog — not just the core. For each list:
1. **Duplicate coverage** — two rules stating the same principle with different examples. Merge into the earlier-numbered rule; delete the later one. Log: `[MERGED] <list> #M into #N — <principle>`
2. **Plugin-specific content** — any rule referencing a specific plugin name, plugin-specific class, or plugin-specific function. Rewrite to state the general principle only. Remove `[TP: plugin version]` and `[FP: plugin version]` tags. Log: `[GENERALIZED] <list> #N — removed plugin-specific content`
3. **Excessive length / recipe drift** — any rule exceeding 2 sentences, OR any rule whose body is a per-CVE recipe that just restates a grep/Semgrep id. Condense to principle + verification action; move the detection detail into the named grep section / Semgrep rule (Relocation protocol, Phase 4a). Log: `[CONDENSED] <list> #N` (and `[RELOCATED] <list> #N → <sink>` when detail moved to a machine sink).
4. **Numbering hygiene** — no duplicate numbers, no letter-suffix appends (`28b`, `30b`); renumber each list contiguously from 1.

Hard caps (enforced by `skill_size_report.py`): core FP Verification ≤ 25 top-level rules; core FN Prevention ≤ 35; EACH group file's "FP Verification Rules" list ≤ 15; chain-pattern catalog ≤ 20 `####` entries. At a list's cap, a new addition MUST be offset — a sub-bullet under an existing rule, a merge/condense of two existing rules, or an auto-removal (Phase 4.6) — so the list's top-level count does not grow.

**4.6 — Evidence-based auto-removal (bounded — recall must be preserved).** When a group file's "FP Verification Rules" list (or the chain catalog) is at cap and a genuinely novel rule must go in, or a rule is surfaced as dead by yield evidence (Phase 2a2), a group-file prose rule MAY be deleted — but ONLY when BOTH hold:
- **(a) detection is preserved or was already dead** — the rule names a grep section and/or Semgrep rule that REMAINS PRESENT after this run (recall is carried by the machine sink), OR that named grep section / Semgrep rule is itself classified dead (`grep_section_yield.py` = `HIGH_NOISE_NO_TP`/`NEVER_HIT`, or `pattern_accumulator.py stats --semgrep-rule <id>` shows FP≥10 & TP=0) — i.e. the prose never caught anything; AND
- **(b) zero corpus TP** attributable to the rule (no confirmed finding maps to its grep section / Semgrep rule in the accumulator).

A prose rule carrying PURE reasoning with no machine-sink equivalent, whose yield is nonzero or unknown, is **NOT auto-removable** — condense it (4.5) or list it as a human-review eviction candidate in the Phase 5 report. Never delete the only remaining detector of a real class. Log: `[AUTO-REMOVED] <file> #N — <evidence: sink-preserved | dead-section | dead-rule>`.

**4h** — No cosmetic changes. Every character changed must be attributable to logged audit-grounded reason.

## Phase 5 — Summary Report

```
════════════════════════════════════════════════════════
[TUNE-AUDIT] Vuln-audit skill tuning complete — <slug> <version>
════════════════════════════════════════════════════════

Grep patterns added:      N
Anti-pattern examples:    N
Chain patterns:           N
Blind spots:              N
FP prevention checks:     N
  FP-cause categories targeted (Phase 2a): <list>
Inaccuracies corrected:   N
Content deleted:          N
Relocated to machine sink: N
Auto-removed (Phase 4.6):  N
Human-review eviction candidates: <list, or none>
Skipped (confidence ≤90% or plugin-specific): N

Changes in: SKILL_PATH + GREP_SCRIPT_PATH
════════════════════════════════════════════════════════
```

**5b — Post-change size gate.** Re-run `python skill_size_report.py`. No file may have crossed from within-budget to `OVER` because of this run, and no governed list may exceed its cap. If any did, the run is NOT complete: apply an offsetting merge/condense/auto-removal (Phase 4.5/4.6) until every list you touched is at/under cap, then re-run. Print the before/after `~tokens` for each file you modified.

## Hard Constraints

- Modify only: SKILL_CORE_PATH, SKILL_GROUP_* files, SKILL_CHAIN, GREP_SCRIPT_PATH, and — when relocating a detectable sink out of prose — Semgrep rules under `semgrep_rules/claude_rules/<category>/` following tune-semgrep Phase 2b–2d mechanics (author/extend + `.php` test + `semgrep --test`)
- Cheapest sink first (Phase 4a): a pattern-expressible detection goes to a Semgrep rule and/or grep section, NOT a group-file prose rule; prose is reserved for ≤2-sentence reasoning a pattern cannot encode
- Grep pattern sections in GREP_SCRIPT_PATH use Python dict format (`SECTIONS` dict + `GROUP_SECTION_ORDER` list) — no analysis notes or vulnerability context
- Never delete content solely because not triggered in THIS audit — auto-removal (Phase 4.6) requires corpus-wide dead evidence AND a preserved/dead machine sink
- Never add plugin-specific patterns/function names/architecture details
- Never add `[TP: plugin version]` or `[FP: plugin version]` annotations to vuln-audit rules
- Max 2 sentences per FP/FN rule or sub-bullet — state principle and verification action only
- Caps (enforced by `skill_size_report.py`): core FP ≤ 25, core FN ≤ 35, EACH group file's "FP Verification Rules" ≤ 15, chain catalog ≤ 20; per-file ~token budgets core ≤ 14K, each group ≤ 8K
- Run `skill_size_report.py` at Phase 0 and Phase 5; a file already `OVER` budget is reduction-only for the run (additions must be net-non-positive)
- Always run Phase 1.5 deduplication check (across ALL governed lists + grep/Semgrep) before proposing additions
- Never add "completeness" or "nice to have" content — must close demonstrated gap
- Never lower severity of existing warnings without audit evidence
- Never add guidance contradicting global CLAUDE.md scope rules
- 90% confidence gate is a hard floor
- Verify every quoted line exists in actual source before acting
- After edits, skill must remain syntactically coherent Markdown
