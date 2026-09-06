# Detection Backfill — turning past disclosures into detection rules

> **Related reading:** `docs/edge-workflow.md` covers **Edge 2 — variant analysis** of *fresh*
> Wordfence disclosures for the plugins you track (`wf_variants.py`). This doc is its **historical,
> class-driven sibling**: mine **all past disclosures of one vulnerability class** across **every**
> plugin and codify them into general Semgrep rules + grep patterns, so future audits catch that
> class earlier.

## Why

`wf_variants.py` asks *"what fresh disclosures exist for plugins I track?"* — great for chasing
incomplete patches and same-author siblings day to day. It deliberately filters to tracked plugins,
which is exactly wrong for building **detection coverage**: to harden the corpus against a whole
vulnerability class you want the **opposite** — the widest possible set of *already-disclosed,
already-patched* examples of that class, across plugins you've never touched.

Each such CVE is externally-validated ground truth: the pre-fix code is the vulnerable pattern, the
official patch is the sanitizer, and the affected-vs-patched trees on disk are a free
true-positive/false-positive oracle. `wf_class_harvest.py` selects and clusters those CVEs; the
existing `/codify-variant` skill turns each one into a general rule.

**Detection value ≠ bounty scope.** We harvest across *all* attacker roles (an Admin+ PHP Object
Injection still teaches the same `unserialize()` sink), but every lead is tagged with its disclosed
reachability so the downstream audit prioritises unauth/subscriber-reachable hits. The rules this
seeds are **leads only**, never auto-filed (global CLAUDE.md Semgrep rule).

## The pipeline

```
  wf_class_harvest.py --cwe N            → <N>-harvest.md   (ranked, family-bucketed worklist)
        │  per representative:
        ▼
  diff_audit.py <slug> --old-version A --new-version P --old-fallback   → audit/<slug>/<P>/DIFF.md
        │      (or run it inline with  wf_class_harvest.py --fetch)
        ▼
  /codify-variant <slug> <CVE>           → 1 general Semgrep rule (+ grep pattern) with a
        │                                   fires-on-affected / silent-on-patched oracle
        ▼
  VARIANT-PROVENANCE.md  +  semgrep_rules/…  +  grep_scan.py SECTIONS  +  pattern_accumulator.db
```

`wf_class_harvest.py` only does the parts that scale poorly by hand across hundreds of historical CVEs
— **selection, clustering, patch staging**. Rule authoring stays in `/codify-variant` so the
90%-generalizability gate and the two-version oracle are always applied.

## `wf_class_harvest.py` — usage

```bash
# Print a ranked, family-bucketed worklist for a class (no downloads). 502 = PHP Object Injection.
python wf_class_harvest.py --cwe 502

# Bigger selection, write the worklist to a file (default: <cwe>-harvest.md)
python wf_class_harvest.py --cwe 502 --top 25 --out poi-harvest.md

# Print to stdout only, write no file, no downloads (quick look / Phase-0 gate)
python wf_class_harvest.py --cwe 502 --dry-run

# Also STAGE the patch pairs for the top representatives (downloads affected+patched from WP.org,
# writes each audit/<slug>/<patched>/DIFF.md). --max-diffs caps the downloads.
python wf_class_harvest.py --cwe 502 --fetch --max-diffs 8

# Show CVEs already turned into a rule (hidden by default — parsed from VARIANT-PROVENANCE.md)
python wf_class_harvest.py --cwe 502 --include-codified

# Reuse the framework for another class (family map is per-CWE; see "Other classes")
python wf_class_harvest.py --cwe 89          # SQL injection
python wf_class_harvest.py --cwe 434         # arbitrary file upload
```

| Flag | Meaning |
|---|---|
| `--cwe N` | CWE id to harvest (default `502`). |
| `--top N` | Representatives to select via family round-robin (default `20`). |
| `--since YYYY-MM-DD` | Lower date bound (default: **all history** — this is a backfill). |
| `--refresh` | Force re-download the Wordfence feed (else uses the daily cache). |
| `--fetch` | Also stage `DIFF.md` for the top reps (downloads from WP.org). |
| `--max-diffs N` | Cap on `--fetch` downloads (default `8`). |
| `--include-codified` | Also show CVEs already in `VARIANT-PROVENANCE.md` (hidden by default). |
| `--include-oos-authors` | Don't drop plugins by out-of-scope authors (Automattic/WooCommerce/Yoast/etc.). |
| `--dry-run` | Print to stdout only; write no file, no downloads. |
| `--out PATH` | Output file (default `<cwe>-harvest.md`). |

### What the worklist gives you, per representative

```
- [ ] CVE-2025-9083  **ninja-forms**  (600,000 installs)   [unauth — in scope]
      versions: affected ≤ 3.11.0  →  patched 3.11.1
      disclosure: Ninja Forms <= 3.11.0 - Unauthenticated PHP Object Injection
      why:    … deserialization of untrusted input …
      prep:   python diff_audit.py ninja-forms --old-version 3.11.0 --new-version 3.11.1 --old-fallback
      codify: /codify-variant ninja-forms CVE-2025-9083
      ref:    https://www.wordfence.com/threat-intel/vulnerabilities/id/…
```

Run `prep` (stages `DIFF.md` + both trees), then `codify`. `✓ DIFF.md ready` on a row means the pair
is already staged — skip `prep` and go straight to `codify`.

### How selection works

- **Reuses the feed + helpers** of `wf_variants.py` (feed load/cache, record date, version ranges,
  disclosed role, in-scope/OOS verdict, out-of-scope-author blacklist) and `diff_audit.py`'s
  downloader — no duplicated logic.
- **Dedup by slug** — keeps the single best-scoring disclosure per plugin (a plugin's POI is usually
  the same sink).
- **Ranking (rule-building value, not bounty value):** oracle-readiness (a downloadable
  affected→patched pair) dominates; then in-scope/unauth reachability, install weight, recency.
- **Family round-robin** — the top-N spans sink families instead of N copies of the most common one.
- **Exclusions:** CVEs already codified (in `VARIANT-PROVENANCE.md`) are hidden unless
  `--include-codified`; out-of-scope-author plugins are dropped unless `--include-oos-authors`.
  CVEs already variant-analyzed (in `databases/analyzed_variants.json`) are annotated, not excluded.
- **`_patched_after()` guard** — unlike `wf_variants._first_patched` (which takes the *min* patched
  tag), this requires the patched version to be **newer than the last-affected** one. The feed
  sometimes lists a lower-branch maintenance tag next to the real fix (e.g. SureForms CVE-2025-6742
  lists `0.0.14`); taking the min there produces a backwards diff that `diff_audit` rejects. The guard
  keeps every emitted `prep` command forward-valid (and drops such rows from "oracle-ready").

### Expected non-failures during `--fetch`

Some reps can't be staged from WP.org — this is normal, logged, and skipped (never fatal):

- **Pruned patched tag** — the author keeps only a subset of past releases, so the exact patched tag
  404s. The harvester prints the nearest published version to diff from instead (e.g.
  *"On disk you could diff from: 7.106"*). You can stage it manually with that version.
- **Premium slug** — a `-pro` / premium plugin isn't in the free `.org` repo (e.g.
  `profile-builder-pro`). Not downloadable here; audit the premium build separately if in scope.
- **Transient** — an occasional API hiccup; just re-run `--fetch` (already-staged reps are skipped).

## Worked example: PHP Object Injection (CWE-502)

A plain source→sink rule under-covers POI, so it's a good illustration of how to author for a class.
The backfill authors along **two axes**:

**Axis 1 — sink families** (one generalized Semgrep rule each; extend the two existing
`rce/recursive-unserialize-replace` + `rce/wpdb-meta-table-unserialize` rules where the corpus shows a
false-negative gap):

1. Direct `unserialize()`/`maybe_unserialize()` on request input (`$_GET/$_POST/$_REQUEST/$_COOKIE`,
   incl. `wp_unslash`-wrapped) with no `allowed_classes => false`.
2. `is_serialized()`-gated then unserialized (the false-safety pattern — see the ninja-forms fix).
3. Import/migration/backup: unserialize on uploaded-file contents (updraftplus, All-in-One WP Migration).
4. Second-order: request value → custom table → unserialize on read (extends `wpdb-meta-table-unserialize`).
5. base64/gz wrapper → unserialize (promote the `BASE64_TO_UNSERIALIZE` grep section into Semgrep).
6. **Phar deserialization**: attacker-controlled `phar://` reaching `file_exists`/`is_dir`/`unlink`/
   `getimagesize` (forminator, sureforms).

The fix (`allowed_classes => false`, or a refactor to a guarded wrapper) becomes each rule's mandatory
FP-suppressing negative clause — `/codify-variant` derives it from the patch diff automatically.

**Axis 2 — POP gadget availability** (exploitability, not just the sink): the sink is not RCE without a
reachable magic-method gadget (`__wakeup`/`__destruct`/`__unserialize`/`__toString`/`__call`). The
`POI_MAGIC_METHODS` grep section already inventories these; consider building your own gadget
catalog mapping the POP chains you find in the corpus (vendored libs — Guzzle, Monolog, PHPExcel —
recur) as you go. This directly serves the "newly-documented usable POP chain = highest PHP Object
Injection reward" tier most bounty programs offer.

### CWE-502 grep coverage that already exists

`grep_scan.py` is already mature for this class (extend rather than recreate): `TIER1_DESERIALIZATION`,
`BASE64_TO_UNSERIALIZE`, `RECURSIVE_UNSERIALIZE_REPLACE`, `POI_MAGIC_METHODS`, `SHORTCODE_ATTR_UNSERIALIZE`,
`COOKIE_DESERIALIZATION`, `CUSTOM_META_TABLE_UNSERIALIZE`, `TOKEN_META_WRITE_NO_SERIALIZE`,
`IMPORT_HANDLER_UNSERIALIZE`, `CUSTOM_UNSERIALIZE_WRAPPERS`, and a `phar://` section. The **Semgrep** side
is the gap the backfill closes.

## Other classes

The framework is class-agnostic — only the family bucket map is CWE-specific. It lives in `_FAMILY_MAP`
in `wf_class_harvest.py` (keyed by CWE id; unknown CWEs fall back to a single `generic` bucket). Seed
maps ship for 502 (POI), 89 (SQLi), and 434 (file upload); add a list of `(family_name, keyword_regex)`
tuples to extend to a new class. Everything else — ranking, dedup, staging, provenance/oracle — is shared.

## Cross-references

- `docs/edge-workflow.md` — Edge 2 (fresh variant analysis) via `wf_variants.py`.
- `/codify-variant` skill (`.claude/skills/codify-variant/SKILL.md`) — the per-CVE rule authoring step.
- `semgrep_rules/claude_rules/VARIANT-PROVENANCE.md` — rule ⇐ seeding-CVE trail (kept out of rule YAML).
- `docs/accumulator-playbook.md` — lifetime TP/FP tracking used for the Phase-5 coverage metric.
