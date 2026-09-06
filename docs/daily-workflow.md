# The Daily Workflow — from target selection to submission

This is the **master guide**. It ties the two halves of the system together:

- **Target selection** (the three edges) decides **which plugins you audit**.
- the **Full Audit Pipeline** (a Claude skill) **finds the vulnerabilities**.
- **The accumulator** (`pattern_accumulator.py`) decides **which of your findings you submit**, and
  feeds methodology improvements back in.

Read this first. Two deeper docs sit underneath it:
`docs/edge-workflow.md` (target-selection edges in detail) and
`docs/accumulator-playbook.md` (the accumulator's weekly ritual in detail).

---

## 1. The loop in one picture

```
        ┌──────────────────────────────────────────────────────────────┐
        │                      DAILY (morning)                          │
        │                                                               │
        │   python daily_targets.py --online --prepare 5                │
        │              │                                                │
        │              ▼                                                │
        │          targets.md   ──►  A. diff   B. variant   C. never    │
        │              │             (what to audit, in EV order)       │
        │              ▼                                                │
        │   "Audit <slug> with Full Audit Pipeline"  (fresh session)    │
        │              │                                                │
        │              ▼                                                │
        │        findings.md  ──(pipeline Stage 2d auto-ingest)──┐      │
        └───────────────────────────────────────────────────────┼──────┘
                                                                 ▼
                                                  databases/pattern_accumulator.db
                                                                 │
        ┌────────────────────────────────────────────────────────┼─────┐
        │                      WEEKLY (ritual)                    ▼     │
        │                                                               │
        │   python pattern_accumulator.py backfill                      │
        │   python pattern_accumulator.py dashboard   (5 blocks)        │
        │              │                                                │
        │              ├─ Block 2: EV ranking ─► hold your 10 best in   │
        │              │                          the Wordfence slots   │
        │              ├─ Block 3/4/5: prune dead Semgrep rules / grep  │
        │              │                 sections / collapse tier groups│
        │              ▼                                                │
        │   submit highest-EV findings to Wordfence (cap: 10 pending)   │
        └───────────────────────────────────────────────────────────────┘
```

**In one sentence:** every morning target selection hands you a ranked list of *fresh, uncontested*
targets; you audit them; every audit auto-records into the accumulator; once a week the accumulator
tells you which accumulated findings are worth one of your 10 Wordfence submission slots.

---

## 2. The pieces and what each one decides

| Layer | Script / skill | Question it answers | Output |
|---|---|---|---|
| **Target selection** | `daily_targets.py` | What should I audit today? | `targets.md` |
| ↳ Edge 1 | `audit_targets.py` + `diff_audit.py` | Which plugins shipped a *new release* since I audited them? | section **A** + `DIFF.md` |
| ↳ Edge 2 | `wf_variants.py` | Which *fresh Wordfence disclosures* can I turn into my own leads? | section **B** |
| ↳ Edge 3 | `audit_targets.py` | Which high‑install plugins have I *never* audited? | section **C** |
| **Audit** | Full Audit Pipeline (skill) | Where are the vulnerabilities? | `audit/<slug>/<v>/findings.md` |
| **The accumulator** | `pattern_accumulator.py` | Which findings do I submit, and what should I prune? | `dashboard`, `fp-causes` |

Why this split exists: **breadth‑first auditing runs out fast once most of your tracked plugins are
already audited** (popular plugins are contested by every AI pipeline). Once that happens for you,
the remaining alpha is the
three edges — *fresh code, variant analysis, and depth* — and the discipline to submit only your
highest‑EV findings.

---

## 3. DAILY — generate the briefing, then work it

### 3.1 One command

```bash
python daily_targets.py --online --prepare 5
```

This does everything:

- **ranks Edge 1 + Edge 3** from the tier DBs by `installs × freshness`;
- **`--online`** polls wordpress.org for each plugin's *true current version* (the tier DBs were
  last bulk‑refreshed Apr–May, so they miss recent releases). Budgeted, highest‑install first;
- **pulls Edge 2** variant leads from the cached Wordfence feed (auto‑refreshes if > 24 h old and a
  key is present);
- **`--prepare 5`** makes the top 5 items audit‑ready: diff items get their new version downloaded +
  `DIFF.md` written + a Semgrep pre‑scan; never‑audited items get source downloaded + pre‑scanned;
- writes the single prioritized checklist **`targets.md`**.

Knobs you'll actually use:

```bash
python daily_targets.py --online                       # briefing only, prepare nothing
python daily_targets.py --online --prepare 5           # + prep items 1-5  (DIFF.md + Semgrep)
python daily_targets.py --prepare 5 --prepare-offset 5 # + prep the NEXT batch (items 6-10)
python daily_targets.py --online --prepare 5 --no-scan # faster prep: DIFF.md / source only
python daily_targets.py --min-installs 100000 --top 50 # tighter, deeper
python daily_targets.py --max-installs 500000          # ONLY <=500k installs (less contested)
python daily_targets.py --min-installs 50000 --max-installs 500000   # a band: 50k-500k
python daily_targets.py --skip-mined                   # drop plugins already picked over (>=3 finds)
```

**Dodging the crowd — batch by install band.** The 1M+ plugins are audited by every researcher and AI
pipeline the moment a release drops, so dupes are likely. `--max-installs N` (a ceiling) together with
`--min-installs N` (a floor) defines an **install band** that scopes the **whole briefing — sections
A, B and C alike** — so you can work one tier per day:

```bash
python daily_targets.py --online --min-installs 10000000               # day 1: the heavyweights (>=10M)
python daily_targets.py --online --min-installs 1000000 --max-installs 10000000   # day 2: 1M-10M
python daily_targets.py --online --min-installs 100000  --max-installs 1000000    # day 3: 100k-1M
python daily_targets.py --online --min-installs 500      --max-installs 100000     # day 4: the long tail
```

Each day's `targets.md` states the active band in its section headers (e.g. *"…within installs
1,000,000–10,000,000…"*), so the scope is never silent. `--max-installs 0` (the default) = no ceiling.
Two things to keep in mind:

- **The default floor `--min-installs 50000` now scopes variant leads (B) too** (previously B was
  unfiltered). A variant lead for a sub‑50k plugin won't appear in a default run. For **High‑Threat
  (≥ 25)** or **XSS/SQLi (≥ 500)** variant leads — which clear *lower* thresholds — give the long tail
  its own day with a low band, e.g. `--min-installs 500 --max-installs 50000`.
- Mind the program thresholds when lowering the floor: High‑Threat ≥ 25, XSS/SQLi ≥ 500, everything
  else ≥ 50,000 (Standard tier) — see §7. (An UNKNOWN install count — a slug you audited that isn't in
  a tier DB — is never hidden by a band, so nothing unsizable is silently dropped.)

**Progress while preparing.** `--prepare` prints a per‑item counter, the result, and elapsed time, so
a long batch never looks frozen:

```
[daily_targets] preparing item(s) 1-5 of 47 (scan=on; Semgrep can take a few minutes per plugin)...
  [1/47] code-snippets  (diff-audit)...
        ↳ DIFF.md: 8 PHP file(s), 3 new entry point(s)  + Semgrep ✓  [41s]
  [2/47] updraftplus  (never-audited)...
        ↳ source 1.25.6 ready  + Semgrep ✓  [126s]
  ...
[daily_targets] prepared 5 item(s) in 188s.
```

In an interactive terminal a live spinner ticks elapsed seconds during each download/Semgrep step (the
Semgrep scan is the long pole — minutes per plugin is normal). `+ Semgrep ✓` / `✗` reports whether the
pre‑scan landed (`✗` usually means semgrep isn't on PATH).

**Already prepared? The briefing tells you — no ledger to keep.** Re‑running `daily_targets.py`
re‑reads what's on disk and tags each item, so you never re‑run a `prep:` you already did:

- **`✓ prepared`** — source/`DIFF.md` **and** the Semgrep scan are present; the `prep:` line becomes
  *"skip prep; go to audit:"*. Go straight to the audit step.
- **`◑ partly prepared`** — the artifact exists but the Semgrep pre‑scan doesn't; the `prep:` line
  shows the one command that adds just the scan.
- **no tag** — not prepared yet; run the `prep:` line (or `--prepare`).

### 3.2 Work the list top‑down

`targets.md` is ordered **A → B → C by expected value**. For each item:

1. open a **fresh Claude session** (each pipeline run wants a clean context window);
2. paste the item's `audit:` trigger — `Audit <slug> with Full Audit Pipeline`;
3. respect the **10‑pending Wordfence cap** — auditing is cheap, slots are scarce. Generate findings
   freely; submit selectively (see §6).

### 3.3 What "prep" buys you, and why the Semgrep pre‑scan matters

A plugin is **fully audit‑ready** only when its version directory has **both**:

- the **source** (`plugins/<slug>/<v>/`), and
- a **Semgrep pre‑scan** (`plugins/<slug>/<v>/semgrep-scan/`).

The Full Audit Pipeline's Stage 2 runs `extract_semgrep_coords.py`, which reads that
`semgrep-scan/` directory and hands each tier‑group agent its pre‑filtered Semgrep leads. **If the
pre‑scan is missing, the pipeline still runs the full manual audit — but it starts blind to a whole
lead layer that every other plugin in the corpus has.** That is why `--prepare` now runs Semgrep by
default (with the project's *custom* rule corpus, `./semgrep_rules`, so the results stay consistent
with the accumulator's rule statistics — **not** the generic `p/php` pack).

> **Group taxonomy is centralised in `group_registry.py`.** The tier‑group set, per‑layer casing
> (`group-ab` / `ab` / `AB`), output filenames, CWE map, and Semgrep rule‑id classification are
> defined once there and imported by `grep_scan.py`, `extract_semgrep_coords.py`, and
> `pattern_accumulator.py`. To add/rename/remove a group, edit the registry — never the three
> consumers directly. (`pattern_accumulator.db` stores no group column, so history survives renames.)

The Semgrep scan is the slow part of prep (the corpus under `semgrep_rules/` plus dataflow traces
— hundreds of custom rules once you've grown it). Trade‑off:

- **default (`--prepare N`)** — thorough: DIFF.md + pre‑scan, every prepared target pipeline‑ready.
- **`--no-scan`** — fast: just DIFF.md / source, for a quick triage when you're not auditing yet.

You can always scan later — each `targets.md` `prep:` line already includes the scan, and you can
run it directly:

```bash
python diff_audit.py <slug> --scan                                   # diff item: DIFF.md + pre-scan
python wp-plugin-downlauditor.py --plugin <slug> -m both --config ./semgrep_rules   # never-audited: download + pre-scan
```

---

## 4. Acting on each section of `targets.md`

### A. DIFF‑AUDIT — a new release since your last audit (Edge 1, highest EV)

A plugin you already audited shipped a newer version. Only the **changed** code is new attack
surface; re‑running the whole pipeline wastes effort. `DIFF.md` (in `audit/<slug>/<new_v>/`) isolates
the PHP‑only changeset and lists the **new/changed entry points** (functions, hooks, REST routes,
shortcodes, AJAX) to examine first.

```
Audit <slug> with Full Audit Pipeline — prioritize the files and entry points in DIFF.md
```

- **Stale baseline:** if the gap spans many releases, `DIFF.md` prints a warning (> 120 changed PHP
  files) and recommends a full audit instead — the diff is too big to be a focused delta.
- **Translation noise** (`*.l10n.php`, `lang/`, `languages/`) is excluded from the diff (it churns
  every release, no auditable logic) but counted so nothing is hidden.
- **Batching (the "items 6‑10" question):** two ways to do the next batch —
  - each item carries its own `prep:` line, so just copy the prep commands for the items you want; or
  - `python daily_targets.py --prepare 5 --prepare-offset 5` preps items 6‑10 in one go
    (offset counts through the briefing order: diff items first, then never‑audited).
- **Prepared markers:** an item already showing **`✓ prepared`** (its `DIFF.md` **and** Semgrep scan
  are on disk) needs no prep — go straight to the audit step. **`◑ partly prepared`** means the
  `DIFF.md` exists but the pre‑scan doesn't; run the short `--scan` command the `prep:` line shows.

### B. VARIANT LEADS — fresh Wordfence disclosures you can chase (Edge 2)

**This is the section to internalize — it's the least obvious and often the highest‑value.** When
another researcher's vuln is published for a plugin you track, the same vein is usually still
productive. **You don't grep or diff by hand** — each lead is shaped like a diff target (`prep:` +
`audit:`): run one command, paste one prompt, the session does the rest. Real example:

```
- [ ] advanced-custom-fields  (2,000,000 installs)  CVE-2026-8382  CWE-862 (Missing Authorization)  — patched in 6.8.2   [PR:N unauth]   ★ affected copy on disk   ✓ DIFF.md ready
      disclosure: ACF <= 6.8.1 - Missing Authorization
      why:    The ACF plugin for WordPress is vulnerable to unauthorized access due to a missing capability check on a function in versions up to, and including, 6.8.1. This makes it possible for unauthenticated attackers to…
      prep:   ✓ audit/advanced-custom-fields/6.8.2/DIFF.md ready — skip prep; paste audit: below
      audit:  (fresh session, paste verbatim) "Variant-analyze CVE-2026-8382 (CWE-862, Missing
              Authorization) in advanced-custom-fields. Wordfence's description: '<the why: prose above>'.
              Read audit/advanced-custom-fields/6.8.2/DIFF.md — the fix reveals exactly what was vulnerable.
              Then: (1) confirm the bug and where it lives; (2) judge whether the fix in 6.8.2 is COMPLETE or
              BYPASSABLE; (3) grep advanced-custom-fields for sibling functions/handlers with the same pre-fix
              pattern the patch left untouched. I also have plugins/advanced-custom-fields/6.8.0 on disk
              (affected, no recorded CWE-862 finding) — confirm the bug there. Report any bypass or unpatched
              sibling as a NEW finding — unauth/subscriber scope only."
      also:   WP Engine also ships ... — same author, likely same bug:
              python wp-plugin-downlauditor.py --plugin <sibling> -m both --config ./semgrep_rules  →  Audit <sibling> with Full Audit Pipeline (focus CWE-862)
```

(Before you've run `prep:`, that line shows the `diff_audit.py … --old-version … --new-version …`
command instead of the `✓ … ready` shown above.)

**The two‑step routine for every variant lead:**

1. **Run the `prep:` command.** It downloads the last‑affected and patched versions and writes
   `audit/<slug>/<patched>/DIFF.md` — the diff of *exactly what the fix changed*, i.e. the vulnerable
   code — leaving both versions on disk for the session to read and grep.
2. **Open a fresh session and paste the `audit:` prompt verbatim.** That one prompt delegates **the
   entire investigation** — you do none of it by hand:
   - **confirm** the disclosed bug and where it lives;
   - **bypass check** — is the official fix complete, or can it be circumvented (wrong capability,
     a surviving `_nopriv` path, a sanitizer that misses an encoding)? A confirmed patch bypass is a
     **fresh, separately‑rewardable vulnerability**;
   - **sibling hunt** — grep the plugin for other handlers sharing the pre‑fix pattern the patch
     didn't touch (authors fix the reported call site, miss the copies);
   - when the lead shows **`★ affected copy on disk`**, also **confirm it in the version you already
     have** — the cheapest win, because you audited a version inside the affected range and recorded
     no finding of this class.

**How the session knows the root cause (the `why:` line).** A bare CVE + CWE doesn't say *what* was
fixed. Two things carry that for you, so you never read the advisory yourself:

1. **`DIFF.md`** — the patch (last‑affected → patched) *is* the vulnerable code; the session reads the
   exact lines that changed.
2. **`why:`** — Wordfence's own `description` field for the disclosure, which the tool now pulls from
   the feed. It names the **mechanism and required privilege** in prose — e.g. *"missing capability
   check on a function … unauthenticated attackers"* or *"insufficient sanitization on the `id`
   parameter"*. That same text is embedded inside the `audit:` prompt (`Wordfence's description: '…'`),
   so the session starts from the disclosed mechanism and uses `DIFF.md` to pin it to code. The prose
   is often what tells you *which pattern to grep for* in the sibling hunt.

The `also:` line is the **same‑author** angle — that one *is* a full pipeline run on a sibling plugin
(a genuinely new target), so it uses `-m both` + `Audit … with Full Audit Pipeline`.

> ⚠️ **Don't run `Audit <slug> with Full Audit Pipeline` on the disclosed plugin itself.** After the
> patch‑diff the highest version on disk is the **patched** one, and the pipeline audits the highest
> version — it would analyse fixed code. The disclosed‑plugin work is the *focused* `audit:` prompt;
> the Full Audit Pipeline is only for the `also:` sibling.

**Scope hint.** Each lead's scope tag is derived from the **disclosure title's effective‑attacker
role**, not the CVSS `PR:` field — CVSS `PR:L` is assigned to *any* authenticated role, so it can't
tell in‑scope Subscriber from out‑of‑scope Contributor/Author. Tags read `[unauth — in scope]`,
`[Subscriber+ — in scope]`, or `[… — verify]` when the privilege is unclear (a plugin‑custom role).
**Leads whose title role is OOS — Contributor+/Author+ (bounty‑ineligible) or Editor+/Admin+
(PR:H) — are hidden by default**; a footer counts them and `--include-oos` shows them (each retagged
with its true role). A per‑lead install‑threshold line flags leads below the program floor for their
class (High‑Threat ≥ 25, XSS/SQLi ≥ 500, else ≥ 50k), and leads sort **in‑scope‑first** (unauth before
subscriber). The `★` marker flags the highest‑EV leads, and **`✓ DIFF.md ready`** means you've already
run `prep:` — skip it and paste the `audit:` prompt. Full scope rules: global `CLAUDE.md` + §7 below.

**After you confirm a variant → codify it.** When the `audit:` session confirms the disclosed bug in the
affected code, fold that CVE into the general rule corpus so the same class is caught in other plugins
next time:

```
/codify-variant <slug> <CVE>
```

The CVE + its patch (`DIFF.md`) is externally‑validated ground truth: the pre‑fix code is the vulnerable
pattern, the fix becomes the rule's false‑positive guard, and the affected‑vs‑patched trees on disk are
a built‑in TP/FP oracle. It writes at most one general (plugin‑agnostic) Semgrep rule + one grep pattern,
reusing the `tune-semgrep` / `tune-vuln-audit` mechanics. This is *not* `tune-semgrep` (that tunes from a
full‑audit `findings.md`; a focused variant session has no such file).

> Edge 2 is variant analysis of *public, already‑disclosed* vulnerabilities for coordinated
> disclosure of the **new** variant you find (patch bypass, unpatched sibling, missed class). It is
> read‑only recon against wordpress.org/wordfence.com plus local diffing — no interaction with any
> third‑party live site.

### C. NEVER AUDITED — first pass (Edge 3 shortlist)

High‑install plugins with no audit dir yet. Straight pipeline run; the `prep:` line downloads **and**
Semgrep‑pre‑scans so it's immediately pipeline‑ready.

```
Audit <slug> with Full Audit Pipeline
```

- **Prepared markers:** **`✓ prepared`** here means the **current** version's source + Semgrep scan
  are on disk — skip prep. If only an **older** copy is on disk (the briefing names a newer release),
  the item shows **no** tag and the `prep:` line re‑downloads the current one. That distinction
  matters: the pipeline audits the highest *local* version, so auditing against a stale copy would
  analyse old code — let prep refresh it first.

---

## 5. AFTER the audit — capture is automatic

You don't run the accumulator by hand after each audit. The Full Audit Pipeline ingests itself:

- **Stage 2d** runs `pattern_accumulator.py ingest` at the end of analysis on **every** audit —
  including clean ones (0 findings), because the dismissed‑FP triage data is the fuel for the
  dead‑rule and `fp-causes` analyses.
- **Stage 7** re‑ingests after live validation so `LIVE VALIDATED` / `REJECTED` overwrite the
  pre‑validation snapshot.

Both are idempotent and non‑fatal — a measurement‑tool hiccup never fails an audit. The only status
the per‑audit ingest does **not** capture is registry Submitted/Duplicate, which `backfill` picks up
(see §6).

---

## 6. WEEKLY — the submission ritual

Once a week (and before deciding what to submit), run:

```bash
python pattern_accumulator.py backfill     # reload every audit + vuln-registry status
python pattern_accumulator.py dashboard    # the five blocks
python pattern_accumulator.py fp-causes    # FP-prevention backlog
```

Then act on the dashboard blocks in order:

1. **Submission funnel** — `total → TP → logged → Submitted → not‑Duplicate`. The gap between
   *logged* and *Submitted* is your **slot backlog**. The Wordfence program caps you at **10 pending**
   submissions: treat the slots as a **portfolio**.
2. **EV ranking of holdable findings** — top unsubmitted TPs by expected bounty
   (`base ÷ auth_divisor × install_mult × impact`). **These are the findings worth holding in your 10
   slots. Submit from the top down.** Anything below ~10 can wait without opportunity cost. Watch the
   **duplicate rate** of what you've submitted — a high rate means you're racing others on
   low‑differentiation bugs; bias toward higher‑EV / more‑novel findings.
3. **Semgrep dead‑rule kill‑list** (FP ≥ 10 & TP = 0) — candidates to prune. *Human‑reviewed
   deletion only* (procedure in `accumulator-playbook.md`); `tune-semgrep` already reads these stats
   automatically.
4. **Grep dead‑section list** — conservative; usually empty.
5. **Tier‑group yield / collapse** — a group with < 2 lifetime TP runs a full sub‑agent for ~no
   return; merge it into a sibling's prompt to shorten the relay. Restructuring a group is now a
   `group_registry.py` edit (regenerate + diff outputs), not a four‑file hunt.

> The final relay agent runs **Reconciliation + Chaining**: before chaining confirmed findings it
> re‑opens earlier‑group verdicts using the SINK LEDGER's unconsumed (`Consumed-by (none)`) sinks and
> the impact groups' auth‑model addenda, so a late discovery can become a net‑new finding the
> forward‑only ordering would otherwise drop. Cross‑group leads/sinks flow through the single
> deduplicated `leads-forward.md` ledger.

**Submit** your top‑EV findings to Wordfence (via the program's submission page), newest CVE links
and PoCs attached. Hold the rest.

Full detail: `docs/accumulator-playbook.md`.

---

## 7. Submission & confidentiality (non‑negotiable)

These come from the global `CLAUDE.md`; the workflow exists to serve them:

- **Confidence > 90 %** that a finding is real **and** exploitable before it's a finding. Never
  submit a code reference you haven't verified in the actual source tree. False positives and
  AI‑hallucinated reports carry escalating submission restrictions.
- **In scope:** Unauthenticated, Subscriber, Customer (and lower‑reward Contributor/Author).
  **Out of scope:** anything needing Admin/Editor/Shop‑Manager or `unfiltered_html`, and
  **admin‑granted** access.
- **Two recurring mis‑submissions to self‑check every candidate against:**
  (a) read‑only disclosure of *non‑public post/page/CPT content* (drafts, private, password‑protected
  — including custom post types) is OOS even unauthenticated; (b) access reachable only after an admin
  explicitly grants a capability is OOS. (User/customer **PII** disclosure is *not* (a) — that's
  in‑scope.)
- **Open Redirect, CSV/CSS/HTML injection, self‑XSS, rate‑limiting, clickjacking, business/payment
  logic** → OOS. See the global `CLAUDE.md` OOS classes before queueing.
- **Install thresholds:** High‑Threat (file ops / options update / RCE / auth bypass) ≥ 25;
  Common & Dangerous (stored XSS / SQLi) ≥ 500; everything else ≥ 50,000 (Standard tier — flag if
  the project tier isn't set). The `[INSTALL‑COUNT]` hook injects the authoritative number; never
  guess.
- **Confidentiality:** submit only to Wordfence. **No public disclosure** until Wordfence completes
  coordinated disclosure and the CVE is public. The Wordfence feed cache and your `.env` API key stay
  local (see §8).

---

## 8. Maintenance & housekeeping

- **Wordfence feed cache** — `databases/wf_feed_cache.json` (~142 MB) refreshes itself when > 24 h old
  and a key is present; force with `python wf_variants.py --refresh`. The v2 no‑key feed was retired
  (`410`); the v3 feed is free but **token‑gated** — key via `WORDFENCE_API_KEY`, a bare token in
  `.env`, or `databases/wf_api_key.txt`. (Setup detail in `edge-workflow.md`.)
- **Tier DB staleness** — `version`/`last_updated` were last bulk‑refreshed Apr–May. `--online`
  corrects this per‑run by polling wordpress.org (rate‑limited, highest‑install first). For a full
  refresh, re‑run `wp-plugin-downlauditor.py`.
- **`.gitignore`** — keep `.env` (your API key) and `databases/wf_feed_cache.json` (large, regenerable)
  out of version control.
- **Pruning** (Semgrep rules, grep sections, tier groups) is always **human‑reviewed** — the tools
  flag, you delete. Do it in a branch with the stats snapshot in the commit message.

---

## 9. Command cheat‑sheet

```bash
# ── DAILY (target selection) ───────────────────────────────────────────────────────────
python daily_targets.py --online --prepare 5            # briefing + prep top 5 (DIFF.md + Semgrep)
python daily_targets.py --prepare 5 --prepare-offset 5  # prep the next batch (items 6-10)
python daily_targets.py --max-installs 500000           # only <=500k installs (less contested)
python diff_audit.py <slug> --scan                      # one diff target, pipeline-ready
python diff_audit.py <slug> --old-version A --new-version B   # read a Wordfence patch A->B
python wf_variants.py --since YYYY-MM-DD --top 60        # variant leads, wider window
python wf_variants.py --fetch                            # also list patched-vs-affected changed funcs

# ── per target ───────────────────────────────────────────────────────────────
# (fresh Claude session)
Audit <slug> with Full Audit Pipeline                    # paste the trigger from targets.md
python daily_targets.py --online --include-oos           # section B: also show OOS-by-role leads
/codify-variant <slug> <CVE>                             # after confirming a variant, fold it into the rule corpus

# ── WEEKLY (the accumulator) ──────────────────────────────────────────────────────────
python pattern_accumulator.py backfill                   # reload audits + registry status
python pattern_accumulator.py dashboard                  # 5 blocks: funnel, EV, kill-lists, collapse
python pattern_accumulator.py fp-causes                  # FP-prevention backlog
python pattern_accumulator.py stats --semgrep-rule <id>  # one rule's lifetime TP/FP
```

---

## 10. Go deeper

| Topic | Doc |
|---|---|
| Target-selection edges (diff / variant / never), feed setup, integration notes | `docs/edge-workflow.md` |
| The accumulator's weekly ritual, dashboard blocks, deletion procedures | `docs/accumulator-playbook.md` |
| Scope, eligibility, thresholds, OOS classes, confidentiality | global `CLAUDE.md` (from `templates/global-CLAUDE.md.example`) + `AUTHORIZATION.md` |
