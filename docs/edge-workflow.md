# Edge Workflow — the daily target-selection routine

> **Start here:** for the whole picture — how target selection (this doc), the Full Audit
> Pipeline, and the submission‑ranking accumulator fit into one daily/weekly loop — read
> **`docs/daily-workflow.md`** first. This doc is the target-selection deep dive.

Breadth-first auditing runs out fast: once most of the plugins in your tier databases already have
an audit dir, re-running the pipeline on the same plugins yields the same findings, and popular
plugins are contested by every AI pipeline. The remaining alpha at that point is **three edges**:

1. **Edge 1 — Diff-audit** a plugin that shipped a NEW release since you last
   audited it (fresh, uncontested code).
2. **Edge 2 — Variant analysis** of freshly-disclosed Wordfence vulnerabilities
   (incomplete patches, sibling functions, same-author plugins, a class you
   missed on a version you already have).
3. **Edge 3 — Depth** on a small hand-picked never-audited shortlist.

This workflow prints exactly which plugins to audit each morning.

---

## The daily routine

```bash
# 1. After starting the computer, generate today's briefing:
python daily_targets.py --online --prepare 5

# 2. Open targets.md. It is ordered by expected value: A (diff) -> B (variant) -> C (never).

# 3. In a FRESH Claude session, paste the trigger from targets.md:
Audit contact-form-7 with Full Audit Pipeline
#    Diff targets already have audit/<slug>/<new_v>/DIFF.md pre-generated, so tell the session:
#    "Audit contact-form-7 with Full Audit Pipeline — prioritize the files/entry points in DIFF.md"

# 4. Repeat down the list. Respect the Wordfence 10-pending-submission cap:
#    submit only your highest-EV findings (see the accumulator dashboard EV ranking).
```

That single first command does everything: polls wordpress.org for true current
versions, ranks the diff and never-audited queues, pulls fresh Wordfence
disclosures into variant leads, downloads the top 5 targets, and pre-generates
`DIFF.md` for the diff items.

---

## The four scripts

| Script | Edge | What it does |
|--------|------|--------------|
| `daily_targets.py` | all | **The one command.** Orchestrates the others, writes a single `targets.md`. |
| `audit_targets.py` | 1 + 3 | Ranks the diff queue (new release since audit) and the never-audited queue by `installs × freshness`. |
| `diff_audit.py`    | 1 | Isolates the PHP changeset old→new and writes `audit/<slug>/<new_v>/DIFF.md`. |
| `wf_variants.py`   | 2 | Reads the Wordfence feed and emits variant leads for plugins you track. |

Run any of them standalone (`python <script> --help`). `daily_targets.py` is the
normal entrypoint.

> **Sibling — detection backfill (`wf_class_harvest.py`).** The *reverse* of Edge 2: instead of
> fresh disclosures for plugins you track, it mines **all past disclosures of one CWE across every
> plugin** and clusters them into a worklist for `/codify-variant`, so future audits catch that class
> earlier. It's a rule-building loop, not a daily target loop — see **`docs/detection-backfill.md`**.

### Useful standalone invocations
```bash
python audit_targets.py --online --skip-mined          # ranking only; drop picked-over plugins
python diff_audit.py contact-form-7                     # one diff-audit -> DIFF.md
python diff_audit.py <slug> --scan                      # diff + Semgrep pre-scan (pipeline-ready)
python diff_audit.py <slug> --new-version 1.2.4         # diff against a specific version
python diff_audit.py <slug> --old-version A --new-version B   # diff an arbitrary pair (e.g. a patch)
python wf_variants.py --since YYYY-MM-DD --top 60       # variant leads, wider window
python wf_variants.py --fetch                           # also diff patched/affected to list changed funcs
python wf_variants.py --min-installs 1000000 --max-installs 10000000   # variant leads for one install tier
python daily_targets.py --prepare 5 --prepare-offset 5  # prep the NEXT batch (items 6-10)
python daily_targets.py --prepare 5 --no-scan           # faster prep: DIFF.md / source only
python daily_targets.py --min-installs 100000 --top 50  # tighter, deeper briefing
python daily_targets.py --max-installs 500000           # ceiling: only <=500k installs (less contested)
python daily_targets.py --mark-analyzed CVE-2026-12345  # never list this variant CVE again
python daily_targets.py --include-analyzed --include-oos-authors   # show everything (debugging)
```

---

## Wordfence Intelligence feed (Edge 2) — API key required

**Important change:** the old no-key v2 feed was retired (`410 Gone`). The
current **v3 Production feed is free but token-gated**:

```
GET https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production
Authorization: Bearer <YOUR_API_KEY>
```

Get a free key: wordfence.com account → **Integrations** → create an API key (it
is shown once — copy it). Then provide it in any of:

- env var `WORDFENCE_API_KEY` (preferred), or
- a bare token on one line in `.env` (this repo's format), or
- `databases/wf_api_key.txt`.

Notes:
- The feed is ~142 MB / 36k+ records. It is cached to
  `databases/wf_feed_cache.json` and reused for 24 h; `--refresh` forces a pull.
- The API rate-limits aggressively (`429`). Pull at most daily. If a live pull
  fails, the tools fall back to the cached feed and warn.
- If no key and no cache are present, `wf_variants` exits with setup instructions
  and `daily_targets` still produces sections A and C (B shows "unavailable").

### How to act on a variant lead (you run ONE command, then paste ONE prompt)

**You do not grep or diff anything by hand.** A Wordfence disclosure is a *map* to a bug; your job is
to run the prep command and hand the whole investigation to a fresh Claude session. Each lead in
`targets.md` is now shaped exactly like the diff targets — a `prep:` line and an `audit:` line:

```
- [ ] wpforms-lite  (6,000,000 installs)  CVE-2026-48835  CWE-862 (Missing Authorization)  — patched in 1.10.0.5   [PR:N unauth]   ★ affected copy on disk
      disclosure: WPForms ... <= 1.10.0.4 - Missing Authorization
      why:    The WPForms ... plugin for WordPress is vulnerable to unauthorized access due to a missing capability check on a function in versions up to, and including, 1.10.0.4. This makes it possible for unauthenticated attackers to…
      prep:   python diff_audit.py wpforms-lite --old-version 1.10.0.4 --new-version 1.10.0.5
      audit:  (fresh session, paste verbatim) "Variant-analyze CVE-2026-48835 (CWE-862, Missing
              Authorization) in wpforms-lite. Wordfence's description: '<the why: prose above>'. Read
              audit/wpforms-lite/1.10.0.5/DIFF.md — the fix reveals exactly what was vulnerable. Then:
              (1) confirm the bug and where it lives; (2) judge whether the fix in 1.10.0.5 is COMPLETE or
              BYPASSABLE; (3) grep wpforms-lite for sibling functions/handlers with the same pre-fix pattern
              the patch left untouched. I also have plugins/wpforms-lite/1.10.0.4 on disk (affected, no
              recorded CWE-862 finding) — confirm the bug there. Report any bypass or unpatched sibling as a
              NEW finding — unauth/subscriber scope only."
      also:   Syed Balkhi also ships wp-mail-smtp, all-in-one-seo-pack, ... — same author, likely same bug:
              python wp-plugin-downlauditor.py --plugin wp-mail-smtp -m both --config ./semgrep_rules  →  Audit wp-mail-smtp with Full Audit Pipeline (focus CWE-862)
      ref:    https://www.wordfence.com/threat-intel/vulnerabilities/id/...
```

(Once you've run `prep:`, the header gains `✓ DIFF.md ready` and the `prep:` line becomes
`✓ … ready — skip prep; paste audit: below`, so a re‑generated briefing shows what's already done.)

**So the answer to "do I run `diff_audit.py` then audit?" is yes — exactly this:**

1. **Run the `prep:` command.** It downloads the last‑affected and patched versions and writes a
   `DIFF.md` of *exactly what the fix changed* (= the vulnerable code), with both versions left on
   disk for the session to read and grep.
2. **Open a fresh Claude session and paste the `audit:` prompt verbatim.** That single prompt does
   **all three** jobs for you — you don't do any of them manually:
   - **confirm** the disclosed bug and where it lives;
   - **bypass check** — decide whether the official fix is complete or can be circumvented (a
     confirmed patch bypass is its own, separately‑rewardable vulnerability);
   - **sibling hunt** — grep the plugin for other functions/handlers sharing the pre‑fix pattern that
     the patch didn't touch (authors fix the reported call site and miss the copies);
   - and, when the `★` marker is present, **confirm it in the affected copy you already have on disk**
     — the cheapest win, since you audited a version inside the affected range and recorded no
     finding of this class.
3. **Follow the `also:` line** when you want the same‑author angle: that one *is* a full pipeline run
   on a sibling plugin (a genuinely new target), so it uses `-m both` + `Audit … with Full Audit
   Pipeline`.

**The `why:` line answers "what was actually fixed?"** CVE + CWE alone don't say. The `why:` line is
Wordfence's own `description` for the disclosure (pulled from the feed), naming the **mechanism +
required privilege** — e.g. *"missing capability check on a function … unauthenticated attackers"*,
or *"insufficient sanitization on the `id` parameter"*. The same prose is embedded in the `audit:`
prompt (`Wordfence's description: '…'`), so the session starts from the disclosed mechanism while
`DIFF.md` pins it to the exact code. It's frequently the line that tells you which pattern to grep for
in the sibling hunt.

> ⚠️ **Do not run `Audit <slug> with Full Audit Pipeline` on the disclosed plugin itself.** After the
> patch‑diff, the highest version on disk is the **patched** one, and the pipeline audits the highest
> version — it would analyse already‑fixed code. Variant analysis is a *focused* session (the `audit:`
> prompt), not a full‑plugin sweep. The Full Audit Pipeline is only for the `also:` sibling.

**Scope hint.** `[PR:N]` (unauth) and `[PR:L]` (subscriber+) are in Wordfence bounty scope — chase
first. `[PR:H]` needs a high‑privilege role → usually OOS, deprioritise. The `★ affected copy on
disk` marker flags the highest‑EV leads (sorted first). (Full rules: global `CLAUDE.md`; the two
recurring OOS traps — non‑public post/CPT content and admin‑granted access — are summarized in
`daily-workflow.md` §7.)

> Variant analysis targets *public, already‑disclosed* vulns and reports the **new** variant you
> find (bypass / sibling / missed class) via coordinated disclosure. It's read‑only recon
> (wordpress.org + wordfence.com) plus local diffing — no third‑party live‑site interaction.

---

## Integration notes

- **The Full Audit Pipeline auto-picks the highest downloaded version** (Stage 0).
  So downloading the new version (what `--prepare` does) is all that is needed to
  make the pipeline audit it.
- **Semgrep pre-scan is part of being audit-ready.** The pipeline's Stage 2 reads
  `plugins/<slug>/<v>/semgrep-scan/` (via `extract_semgrep_coords.py`) for each
  tier-group's leads. A freshly-downloaded version has no such scan, so `--prepare`
  (and the `prep:` lines / `diff_audit.py --scan`) now run Semgrep with the project's
  **custom** corpus (`./semgrep_rules`, *not* `p/php`) to match the rest of the DB and
  keep `pattern_accumulator` rule stats coherent. Skip it with `--no-scan` for a fast
  triage; the manual audit still runs fully without it, just minus that lead layer.
- **Batching the prep:** `--prepare N` does items 1‑N; add `--prepare-offset M` for the
  next batch (offset counts through the briefing order — diff items first, then
  never-audited). Or just copy any item's own `prep:` line.
- **Prepared markers (no ledger needed):** the briefing reads on-disk artifacts and tags each item
  `✓ prepared` (artifact + Semgrep scan present → the `prep:` line says "skip prep") or
  `◑ partly prepared` (artifact present, scan missing). Re-running `daily_targets.py` any day reflects
  reality, so you never re-run a prep you already did. For never-audited items, `✓ prepared` requires
  the **current** version on disk — an older copy shows no tag so prep re-downloads the latest.
- **Progress + timer:** `--prepare` prints a `[pos/total]` counter, per-item result and elapsed time,
  plus a total; in a terminal a live spinner ticks during each (slow) download/Semgrep step so the
  command never looks frozen (the Semgrep scan is minutes per plugin).
- **Install band applies to ALL sections (A, B *and* C).** `--min-installs` / `--max-installs` bound
  the whole briefing, so you can batch one tier per day (`>10M`, `1–10M`, `100k–1M`, …) — variant
  leads included. The active band is printed in each section's header. An unknown install count is
  never hidden by a band. Caveat: the default floor (`--min-installs 50000` in `daily_targets.py`) now
  scopes variant leads too — give the long tail its own low‑band day (`--min-installs 500
  --max-installs 50000`) for High‑Threat (≥25) / XSS·SQLi (≥500) leads on smaller plugins.
- **DIFF.md** sits in `audit/<slug>/<new_v>/`. Two ways to use it:
  - **(a) default, no skill change:** tell the session to prioritise the changed
    files / new entry points listed in DIFF.md.
  - **(b) optional future enhancement:** edit the pipeline `SKILL.md` Stage 2 to
    read `DIFF.md` if present and weight changed files first. Not required.
- A `DIFF.md`-only audit dir is **not** treated as "audited" by the ranker
  (`audited_versions()` requires a real artifact — `findings.md` /
  `audit-context.md` / `pipeline-state.md`), so pre-generating a diff never drops
  a plugin out of the diff queue.
- **Stale baseline:** if old→new spans many releases, DIFF.md flags it
  (>120 changed PHP files) and recommends a full audit instead of a diff.
- **Translation noise:** `*.l10n.php` and `lang/` · `languages/` files are
  excluded from the diff (machine-generated; they churn every release) but
  counted so nothing is hidden.
- **Edge 2 leads point at a specific function/file** — feed that directly to a
  focused session rather than a full pipeline run.

---

## Scope filters — out-of-scope authors & already-analyzed CVEs

Two filters keep the briefing focused on eligible, un-repeated work. Both are **on by
default** across every run.

### Out-of-scope-author blacklist (all sections A/B/C)

Plugins whose WordPress.org author is out of scope for the Wordfence program —
**Automattic** (incl. WooCommerce), **WordPress Core** (`wordpressdotorg`), **Yoast**,
**Google**, **Facebook/Meta**, **SiteGround** — are dropped from *every* section, so
akismet, jetpack-*, wordpress-seo, woocommerce, google-site-kit, sg-cachepress,
facebook-for-woocommerce, secure-custom-fields, classic-editor, etc. never appear as targets.

- The match keys on the **profile author-slug** parsed from the `Plugins.author` column
  (`profiles.wordpress.org/<slug>`), **not** the display name or the plugin slug — so a
  third-party plugin that merely mentions a vendor (e.g. `weight-based-shipping-for-woocommerce`
  by an independent author, or a third-party "… for Google Analytics") is **not** over-blocked.
- The built-in list is `BLOCKED_AUTHOR_SLUGS` in `wf_variants.py`. Add more author-slugs
  (one per line) in **`databases/oos_authors.txt`** — no code edit needed.
- `--include-oos-authors` bypasses the filter (debugging). The run summary prints
  `OOS-author plugins hidden: N`.

### Analyzed-CVE dedup (section B only)

`targets.md` is overwritten every run and keeps no history, so a persistent ledger —
**`databases/analyzed_variants.json`** (module `analyzed_ledger.py`) — remembers which
variant CVEs you've already analyzed and hides them from section B. It accumulates across
all runs, so regenerating the briefing several times a day is safe.

A CVE enters the ledger two ways:

- **Auto-harvest (default):** before overwriting `targets.md`, any section-B lead you
  **ticked** (`- [x]`) in the existing file is harvested into the ledger. So your normal
  habit of checking off a finished lead is the signal — no extra step. (`--no-harvest`
  disables this for one run.)
- **Manual:** `python daily_targets.py --mark-analyzed CVE-2026-12345` (repeatable;
  comma-separated ok). `--forget-analyzed CVE-…` removes an entry.

Notes:
- Dedup keys on the **CVE id**; the plugin slug is stored as metadata only. A disclosure
  with no CVE assigned yet can't be deduped until it gets one on a later feed refresh.
- Entries are pruned after **90 days** (`--analyzed-retention-days N`) — comfortably past the
  default 14-day feed window; raise it before a deep historical `--since` run.
- `--include-analyzed` shows hidden leads anyway. The run summary and section-B footer print
  `N already-analyzed hidden`.
- Inspect/edit the ledger directly with `python analyzed_ledger.py --list` (also `--mark` /
  `--forget`).

---

## Maintenance

- The tier DBs' `last_updated` / `version` go stale (last bulk refresh Apr–May).
  `--online` corrects this by polling wordpress.org for the true current version
  (rate-limited, highest-install plugins first, budget `--online-budget`).
- Refresh the Wordfence feed cache about daily: `python wf_variants.py --refresh`
  (or just run `daily_targets.py` — it auto-refreshes a >24 h cache when a key is
  present).
- `--skip-mined` drops plugins that already yielded ≥3 confirmed findings
  (picked over → diminishing returns / higher dupe risk).

---

## Cross-reference: the accumulator

The accumulator's dashboard EV ranking decides **which** of your findings fill the 10
Wordfence submission slots. This workflow decides **which plugins you audit** to
generate them. Run the accumulator dashboard first if you want EV-ranked slot guidance.
