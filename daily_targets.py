#!/usr/bin/env python3
"""
daily_targets.py - The morning briefing. ONE command, ONE file.

Run this after starting the computer. It orchestrates the three edges and writes a
single prioritized, copy-paste checklist (targets.md):

  A. DIFF-AUDIT   - plugins that shipped a new release since you audited them (Edge 1)
  B. VARIANT LEADS- fresh Wordfence disclosures you can chase (Edge 2)
  C. NEVER AUDITED- first-pass shortlist (Edge 3)

Sections are in expected-value order. Each item carries the exact prep command and
the exact `Audit <slug> with Full Audit Pipeline` trigger to paste into a fresh
Claude session.

CLI:
  python daily_targets.py                       # offline-ish briefing, top 30, installs >= 50k
  python daily_targets.py --online              # poll wordpress.org for true current versions
  python daily_targets.py --online --prepare 5  # download top 5: DIFF.md + Semgrep pre-scan
  python daily_targets.py --prepare 5 --prepare-offset 5   # prep the NEXT batch (items 6-10)
  python daily_targets.py --prepare 5 --no-scan # faster prep: DIFF.md / source only, no Semgrep
  python daily_targets.py --min-installs 100000 --top 50
  python daily_targets.py --max-installs 500000        # only <=500k installs (less contested)
  python daily_targets.py --since YYYY-MM-DD --fetch   # deeper Edge-2 enrichment

See docs/edge-workflow.md for the full routine.
"""
import argparse
import os
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from audit_targets import (load_db_plugins, load_mined_slugs, rank_targets,  # noqa: E402
                           render_targets_md, prepare_targets, has_semgrep_scan)
import diff_audit  # noqa: E402
import wf_variants  # noqa: E402
import analyzed_ledger  # noqa: E402
import diff_audited_ledger  # noqa: E402


def _scan_mark(scan, slug, version):
    """Suffix reporting whether the Semgrep pre-scan landed for this version."""
    if not scan or not version:
        return ""
    return "  + Semgrep ✓" if has_semgrep_scan(slug, version) else "  + Semgrep ✗ (is semgrep on PATH?)"


def prepare(new_release, never, n, offset=0, scan=True):
    """Make a batch of items immediately audit-ready. Items follow the briefing order
    (diff items first — higher EV — then never-audited). `offset` skips that many
    leading items so you can prepare the NEXT batch:
        --prepare 5                     -> items 1-5
        --prepare 5 --prepare-offset 5  -> items 6-10
    Diff items get DIFF.md; never-audited items get source downloaded. When `scan`
    (default), each prepared version is also Semgrep pre-scanned so the Full Audit
    Pipeline has its lead layer; pass --no-scan for a faster DIFF.md-only prep.

    Progress: prints a per-item [pos/total] counter and elapsed time, plus a live
    spinner during each (slow) download/Semgrep step when run in a terminal."""
    work = [("diff", r) for r in new_release] + [("never", r) for r in never]
    batch = work[offset:offset + n]
    if not batch:
        print(f"\n[daily_targets] nothing to prepare at offset {offset} "
              f"(only {len(work)} preparable item(s)).")
        return
    lo, hi = offset + 1, offset + len(batch)
    print(f"\n[daily_targets] preparing item(s) {lo}-{hi} of {len(work)} "
          f"(scan={'on' if scan else 'off'}; Semgrep can take a few minutes per plugin)...")
    t0 = time.time()
    for pos, (kind, r) in enumerate(batch, start=lo):
        slug = r["slug"]
        label = "diff-audit" if kind == "diff" else "never-audited"
        print(f"  [{pos}/{len(work)}] {slug}  ({label})...")
        ti = time.time()
        if kind == "diff":
            md_path, result = diff_audit.run(slug, scan=scan, verbose=False, progress=True)
            if md_path:
                print(f"        ↳ DIFF.md: {result['n_files']} PHP file(s), "
                      f"{len(result['added_entry_points'])} new entry point(s)"
                      f"{_scan_mark(scan, slug, result['new_v'])}  [{time.time() - ti:.0f}s]")
            else:
                print(f"        ↳ skipped: {result}  [{time.time() - ti:.0f}s]")
        else:
            res = prepare_targets([r], 1, verbose=False, scan=scan, progress=True)
            _, ver = res[0] if res else (slug, None)
            if ver:
                print(f"        ↳ source {ver} ready"
                      f"{_scan_mark(scan, slug, ver)}  [{time.time() - ti:.0f}s]")
            else:
                print(f"        ↳ download FAILED  [{time.time() - ti:.0f}s]")
    print(f"\n[daily_targets] prepared {len(batch)} item(s) in {time.time() - t0:.0f}s.")


def build_variant_section(args, blocked=None):
    """Edge 2 leads, degrading gracefully if the feed/key is unavailable so the
    briefing always produces sections A and C. `blocked` (out-of-scope-author slug set)
    is reused from main() to avoid a second DB pass."""
    since = wf_variants.parse_since(args.since)
    analyzed = analyzed_ledger.analyzed_cves(args.analyzed_retention_days)
    try:
        leads, since, source = wf_variants.get_variant_leads(
            since=since, refresh=args.refresh, fetch=args.fetch,
            min_installs=args.min_installs, max_installs=args.max_installs,
            blocked=blocked, include_blocked=args.include_oos_authors,
            analyzed_cves=analyzed)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        note = ("## B. VARIANT LEADS — fresh Wordfence disclosures you can chase (Edge 2)\n"
                "_unavailable: no Wordfence API key/cached feed. See docs/edge-workflow.md "
                "(set WORDFENCE_API_KEY or .env), then re-run._")
        return note, [], "unavailable", since
    except Exception as e:  # never let Edge 2 sink the briefing
        print(f"[daily_targets] variant leads skipped: {e}", file=sys.stderr)
        note = ("## B. VARIANT LEADS — fresh Wordfence disclosures you can chase (Edge 2)\n"
                f"_unavailable: {e}_")
        return note, [], "error", since
    section = wf_variants.render_variant_section(leads, args.top,
                                                 min_installs=args.min_installs,
                                                 max_installs=args.max_installs,
                                                 include_oos=args.include_oos,
                                                 include_analyzed=args.include_analyzed,
                                                 since=since, source=source)
    return section, leads, source, since


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--online", action="store_true",
                    help="poll wordpress.org for true current versions (catches releases since DB refresh)")
    ap.add_argument("--prepare", type=int, default=0, metavar="N",
                    help="download + pre-generate DIFF.md (+ Semgrep pre-scan) for N items")
    ap.add_argument("--prepare-offset", type=int, default=0, metavar="M",
                    help="skip the first M preparable items so --prepare does the NEXT batch "
                         "(e.g. --prepare 5 --prepare-offset 5 = items 6-10)")
    ap.add_argument("--no-scan", dest="scan", action="store_false", default=True,
                    help="when preparing, skip the Semgrep pre-scan (faster; DIFF.md / source only)")
    ap.add_argument("--min-installs", type=int, default=50000)
    ap.add_argument("--max-installs", type=int, default=0,
                    help="only target plugins with AT MOST this many installs (0 = no cap); "
                         "focus on less-contested smaller plugins, e.g. --max-installs 500000. "
                         "Bounds the ranked queues (A diff-audit + C never-audited).")
    ap.add_argument("--include-oos", action="store_true",
                    help="in section B, also show variant leads whose disclosure-title role is "
                         "OOS (Contributor+/Author+ = bounty-ineligible, Editor+/Admin+ = PR:H); "
                         "hidden by default")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--skip-mined", action="store_true",
                    help="drop plugins that already yielded >=3 findings (picked over)")
    ap.add_argument("--include-oos-authors", action="store_true",
                    help="do NOT exclude plugins by out-of-scope authors (Automattic/WooCommerce, "
                         "WordPress Core, Yoast, Google, Facebook, SiteGround); excluded from ALL "
                         "sections by default")
    # Analyzed-CVE ledger (section B dedup)
    ap.add_argument("--include-analyzed", action="store_true",
                    help="in section B, also show variant CVEs already marked analyzed "
                         "(databases/analyzed_variants.json); hidden by default")
    ap.add_argument("--mark-analyzed", action="append", default=[], metavar="CVE",
                    help="mark CVE id(s) as already analyzed (repeatable; comma-separated ok) so "
                         "they drop out of section B on future runs")
    ap.add_argument("--forget-analyzed", action="append", default=[], metavar="CVE",
                    help="remove CVE id(s) from the analyzed ledger (repeatable)")
    ap.add_argument("--no-harvest", action="store_true",
                    help="skip auto-harvesting ticked ([x]) items from the existing targets.md "
                         "into the ledgers (section-B CVEs -> analyzed ledger; section-A "
                         "slug@version -> diff-audited ledger)")
    # Diff-audited ledger (section A dedup)
    ap.add_argument("--mark-diff-audited", action="append", default=[], metavar="SLUG@VERSION",
                    help="mark slug@version pair(s) as already diff-audited (repeatable; "
                         "comma/space-separated ok) so they drop out of section A on future runs")
    ap.add_argument("--forget-diff-audited", action="append", default=[], metavar="SLUG@VERSION",
                    help="remove slug@version pair(s) from the diff-audited ledger (repeatable)")
    ap.add_argument("--diff-audited-retention-days", type=int,
                    default=diff_audited_ledger.DEFAULT_RETENTION_DAYS, metavar="N",
                    help="prune diff-audited entries older than N days (default 0 = keep all; "
                         "version-keyed entries self-supersede when a newer release ships)")
    ap.add_argument("--analyzed-retention-days", type=int,
                    default=analyzed_ledger.DEFAULT_RETENTION_DAYS, metavar="N",
                    help="prune analyzed CVEs older than N days (default 90)")
    # Edge-2 knobs
    ap.add_argument("--since", default=None, help="variant window start YYYY-MM-DD (default: 14 days ago)")
    ap.add_argument("--refresh", action="store_true", help="force re-download the Wordfence feed")
    ap.add_argument("--fetch", action="store_true",
                    help="download patched/affected pairs to list changed functions in variant leads")
    ap.add_argument("--out", default="targets.md")
    args = ap.parse_args()
    out_path = args.out if os.path.isabs(args.out) else os.path.join(ROOT, args.out)

    # Analyzed-CVE ledger: apply manual marks/forgets, then auto-harvest ticked ([x])
    # section-B CVEs from the EXISTING targets.md BEFORE it is overwritten (and before
    # section B is built), so freshly-marked CVEs are hidden this same run.
    if args.mark_analyzed:
        added = analyzed_ledger.mark_analyzed(args.mark_analyzed, source="manual",
                                              retention_days=args.analyzed_retention_days)
        print(f"[daily_targets] marked analyzed: {', '.join(added) if added else '(none new)'}")
    if args.forget_analyzed:
        removed = analyzed_ledger.forget(args.forget_analyzed,
                                         retention_days=args.analyzed_retention_days)
        print(f"[daily_targets] forgot: {', '.join(removed) if removed else '(none)'}")
    if not args.no_harvest and os.path.exists(out_path):
        harvested = analyzed_ledger.harvest_from_targets(out_path)
        if harvested:
            slug_by_cve = {h["cve"]: h.get("slug") for h in harvested if h.get("slug")}
            got = analyzed_ledger.mark_analyzed(
                [h["cve"] for h in harvested], source="harvest",
                slug_by_cve=slug_by_cve, retention_days=args.analyzed_retention_days)
            if got:
                print(f"[daily_targets] harvested {len(got)} analyzed CVE(s) from "
                      f"{os.path.basename(out_path)}: {', '.join(got)}")

    # Diff-audited ledger (section A dedup): same pattern as the analyzed ledger above —
    # apply manual marks/forgets, then auto-harvest ticked ([x]) section-A slug@version
    # pairs from the EXISTING targets.md BEFORE it is overwritten (and before ranking),
    # so a version ticked today drops out of section A this same run.
    if args.mark_diff_audited:
        added = diff_audited_ledger.mark_diff_audited(
            args.mark_diff_audited, source="manual",
            retention_days=args.diff_audited_retention_days)
        print(f"[daily_targets] marked diff-audited: {', '.join(added) if added else '(none new)'}")
    if args.forget_diff_audited:
        removed = diff_audited_ledger.forget(
            args.forget_diff_audited, retention_days=args.diff_audited_retention_days)
        print(f"[daily_targets] forgot diff-audited: {', '.join(removed) if removed else '(none)'}")
    if not args.no_harvest and os.path.exists(out_path):
        harvested_a = diff_audited_ledger.harvest_from_targets(out_path)
        if harvested_a:
            got_a = diff_audited_ledger.mark_diff_audited(
                harvested_a, source="harvest", retention_days=args.diff_audited_retention_days)
            if got_a:
                print(f"[daily_targets] harvested {len(got_a)} diff-audited pair(s) from "
                      f"{os.path.basename(out_path)}: {', '.join(got_a)}")

    plugins = load_db_plugins()
    mined = load_mined_slugs()
    diff_audited = diff_audited_ledger.audited_pairs(args.diff_audited_retention_days)

    # Out-of-scope authors: drop their plugins from every section (A/B/C). Computed once
    # and reused by build_variant_section (Edge 2) so the DB is walked for authors once.
    blocked = wf_variants.load_blocked_slugs()
    n_blocked_hidden = 0
    if not args.include_oos_authors:
        before = len(plugins)
        plugins = {s: v for s, v in plugins.items() if s not in blocked}
        n_blocked_hidden = before - len(plugins)

    # Edge 1 + Edge 3
    new_release, never, polled = rank_targets(
        plugins, mined, online=args.online, min_installs=args.min_installs,
        max_installs=args.max_installs, skip_mined=args.skip_mined,
        diff_audited=diff_audited)

    # Edge 2
    variant_md, leads, source, since = build_variant_section(args, blocked)

    # Optional: make a batch of items audit-ready
    if args.prepare:
        prepare(new_release, never, args.prepare, offset=args.prepare_offset, scan=args.scan)

    # Single briefing file
    md = render_targets_md(new_release, never, top=args.top, variant_md=variant_md,
                           generator="daily_targets.py")
    if leads:
        md += "\n" + wf_variants.ATTRIBUTION + "\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)

    n_missed = sum(1 for L in leads if L.get("missed_class"))
    n_oos = sum(1 for L in leads if L.get("scope") == "oos")
    n_analyzed = sum(1 for L in leads if L.get("analyzed"))
    n_in = len(leads) - n_oos
    b_note = (f"{n_in} in-scope"
              + (f" (+{n_oos} OOS hidden)" if n_oos and not args.include_oos else "")
              + (f" (+{n_analyzed} analyzed hidden)" if n_analyzed and not args.include_analyzed else "")
              + f", feed={source}, {n_missed} you-already-have")
    print(f"\n[daily_targets] {datetime.now():%Y-%m-%d} | "
          f"A diff-audit: {len(new_release)} | "
          f"B variant leads: {b_note} | "
          f"C never-audited: {len(never)}"
          + (f" | diff-audited suppressed: {len(diff_audited)}" if diff_audited else "")
          + (f" | OOS-author plugins hidden: {n_blocked_hidden}" if n_blocked_hidden else "")
          + (f" | online polls: {polled}" if args.online else ""))
    print(f"[daily_targets] wrote {out_path}  — open it and start at the top.")


if __name__ == "__main__":
    main()
