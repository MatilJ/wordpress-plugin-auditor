# Pattern Accumulator — Operator Playbook

`pattern_accumulator.py` records every confirmed finding and dismissed false-positive
across all audits into `databases/pattern_accumulator.db`. This doc is the **weekly ritual**
that turns that data into pruning and methodology decisions. All dashboard/stats/fp-causes
commands are **strictly read-only**.

> **How the DB stays current** — three write paths, all idempotent upserts:
> 1. **Pipeline Stage 2d** ingests every audit at the end of analysis (zero-touch) — including clean audits whose only output is FP-triage data (the fuel for `fp-causes` and the dead-rule list).
> 2. **Pipeline Stage 7** re-ingests after live validation so `LIVE VALIDATED` / `REJECTED` statuses overwrite the pre-validation snapshot.
> 3. **`tune-*` hook** (`hooks/pattern-accumulator-hook.py`) ingests the targeted audit when you invoke `/tune-semgrep` or `/tune-vuln-audit`.
>
> `backfill` remains the catch-all — it (re)loads every audit **plus** `vuln-registry.md` (Submitted/Duplicate status, which per-audit `ingest` does NOT capture) **plus** INVALIDATED PoCs. Run it before a weekly dashboard review to pick up registry-status changes and any audits that predate Stage 2d:
> ```
> python pattern_accumulator.py backfill
> ```

---

## Weekly ritual

```
python pattern_accumulator.py dashboard      # blocks 1-5 below
python pattern_accumulator.py fp-causes       # FP prevention backlog
python skill_size_report.py                   # block 6 — vuln-audit skill size/list budgets
```

Then act on each block in order.

---

## Block 1 — Submission funnel

```
total findings → TP → logged to registry → Submitted → Submitted & not Duplicate
```

The gap between **logged to registry** and **Submitted** is your *slot backlog* — confirmed,
ready-to-submit findings sitting unsubmitted. The Wordfence program caps you at **10 pending**
submissions, so treat the slots as a **portfolio**.

**Action:** Are the 10 findings currently in your Wordfence slots your 10 highest-EV unsubmitted
TPs (Block 2)? If not, you are leaving money on the table. Hold the top EV; let low-EV TPs wait.
Watch the **duplicate rate of submitted** — a high rate means you are racing other researchers on
low-differentiation findings; bias toward higher-EV / more-novel findings to cut wasted slots.

---

## Block 2 — EV ranking of holdable findings

Top 15 registry-logged, **unsubmitted** TPs ranked by expected bounty
(`base ÷ auth_divisor × install_multiplier × impact`, the Stage 5a formula from
`pipeline-stage3-6.md`, using `bounty_calculator_config.json`).

**Action:** These are the findings worth holding in your 10 slots. Submit from the top down.
Anything below the top ~10 can wait without opportunity cost.

> Re-rank as JSON for scripting:
> ```
> python pattern_accumulator.py dashboard --format json   # -> .holdable_top[]
> ```

---

## Block 3 — Dead-rule kill-list (Semgrep)

Rules with **FP ≥ 10 AND TP = 0**, plus any with **TP % < 5 %**. These rules cost a triage on
every tier-agent pass and have (near-)never produced a confirmed finding.

> **Now wired into `tune-semgrep`:** its Phase 1a reads each rule's lifetime `stats --semgrep-rule`
> automatically — prioritizing systemic dead rules for tightening, protecting productive rules from
> over-narrowing, and surfacing the FP≥10/TP=0 set in its Phase 6 report. This dashboard block remains
> the human view for the **deletion** decision (the skill flags but never deletes).

### Deletion procedure (human-reviewed; never automated)

```
# 1. Re-confirm the rule's lifetime ratio before deleting:
python pattern_accumulator.py stats --semgrep-rule <rule-id>

# 2. Locate the rule file (id is the last dotted segment of the check_id):
grep -rl "id:[[:space:]]*<rule-id>" semgrep_rules/claude_rules/

# 3. Delete the rule file and its companion test .php (if present):
#    (do this in a branch; commit with the stats snapshot in the message)
rm semgrep_rules/claude_rules/<category>/<rule-id>.yaml
rm semgrep_rules/claude_rules/<category>/<rule-id>.php   # if it exists
```

### The bigger lever — retire the whole Semgrep stage?

The pipeline's own note says *"Semgrep hits are leads only, most are FPs."* The data agrees: the
corpus is largely a token sink whose FPs every tier agent re-triages.

**Decision threshold:** count rules that clear **TP % ≥ 5 %** with meaningful volume:

```
python pattern_accumulator.py stats --format json | python -c "import sys,json; rs=json.load(sys.stdin); print(sum(1 for r in rs if r['tp_rate']>=0.05 and (r['tp']+r['fp'])>=5))"
```

- **< 5** rules clear → retire the Semgrep stage in the pipeline `SKILL.md` and the `tune-semgrep`
  skill; keep only the handful of survivors (or fold them into grep sections).
- **≥ 5** clear → keep the stage but apply the kill-list above.

> The number this returns is read from your local `pattern_accumulator.db`; compare it against the
> **< 5 / ≥ 5** threshold above to decide whether to retire or keep the Semgrep stage.

---

## Block 4 — Dead-section prune-list (grep)

Grep sections with **hits ≥ 10 AND TP = 0** (attributed via `findings.grep_section`).

**Caveat:** `grep_section` is populated on *findings only* (not on the FP triage leads), so this
signal is conservative — a section only shows here if it appeared on non-TP findings and never on
a TP. Today no section qualifies; use the "top sections by hits" list to see which sections
actually catch real bugs, and treat a section that is **absent from that list across many audits**
as a manual prune candidate.

### Removal procedure

Per the `tune-vuln-audit` skill's format rules, remove the section from **both** structures in
`grep_scan.py`:

```
# 1. Delete the section's entry from the SECTIONS dict:
#      "<SECTION_NAME>": { "group": ..., "patterns": [...] },
# 2. Remove "<SECTION_NAME>" from GROUP_SECTION_ORDER[<group>].
```

> Section names drift across pipeline generations (old audits: `TIER3_SQL`; current
> `grep_scan.py` keys: `STANDALONE_PHP`, etc.). Map the stored name to the current `SECTIONS`
> key before deleting — confirm with `grep -n '"<NAME>"' grep_scan.py`.

---

## Block 5 — Tier-group yield + relay collapse

Lifetime TP grouped by pipeline tier-group, each tagged `EARNS` (≥ 5 TP), `KEEP` (2–4), or
`COLLAPSE CANDIDATE` (< 2 TP).

**Action:** A `COLLAPSE CANDIDATE` group runs a full sequential sub-agent for ~no return. Merge it
into a sibling group's prompt in the pipeline (`SKILL.md` Stage 2c relay) to cut the 8-agent relay.
Re-check after a few more audits before collapsing — a single new finding can flip the verdict.

> Example read: a group at 0 lifetime TP is a collapse candidate — this is exactly why the former
> **Group adv** (race/adversarial) was folded into the Chain pass and Group AC; a group at 2–4 TP is
> borderline — keep and watch. The live numbers come from your local `pattern_accumulator.db`.

---

## Block 6 — vuln-audit skill size/list budgets (grep)

```
python skill_size_report.py
```

Reports each vuln-audit skill file's `~tokens` vs its budget and each governed list's count vs its cap
(the current budgets and caps live in `FILE_BUDGETS` / `LIST_CAPS` in `skill_size_report.py`). Exit is
non-zero when anything is `OVER`. Unlike the grep/Semgrep corpora, this prose is loaded WHOLE into every
tier-group sub-agent — the core file is a tax on every group — so an `OVER` here directly inflates every
audit's context.

**Action:** An `OVER` file/list means the group prose has outgrown its budget. Run `/tune-vuln-audit`,
whose Phase 4.5/4.6 consolidates over-long rules, relocates pattern-expressible per-CVE detail into the
Semgrep/grep sinks (which don't tax context and carry their own yield governance), and — evidence
permitting — auto-removes dead rules. Pair with `grep_section_yield.py` (Block 4) and
`stats --semgrep-rule` (Block 3) so relocation targets and eviction candidates are chosen by yield,
never blindly.

---

## FP-cause mining (`fp-causes`)

Histogram of `triage_entries.reason_category` across all dismissed FP leads, with the top rules per
category. The top categories are **what the pipeline spends the most effort dismissing** — each is a
candidate FP-prevention rule for the `tune-vuln-audit` skill (core `SKILL.md` Phase 4 list).

> **Now wired into `tune-vuln-audit`:** its Phase 2a reads this histogram automatically and prioritizes
> Phase 4f FP-prevention additions toward the highest-count categories. This command remains the
> operator view for auditing that backlog directly.

**Action:** Walk the ranked backlog top-down. For each high-count category (e.g. `admin_only`,
`escaped_output`, `hardcoded_data`), add or sharpen a Phase-4 FP-prevention check so the pipeline
stops re-deriving that dismissal. The `top rules` per category tell you which Semgrep rule most
often triggers that wasted triage — pair the prevention guidance with that rule.

```
python pattern_accumulator.py fp-causes --format json    # -> .categories[] for scripting
```
