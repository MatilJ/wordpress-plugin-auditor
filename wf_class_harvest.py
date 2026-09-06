#!/usr/bin/env python3
"""
wf_class_harvest.py - class-driven historical backfill of detection rules.

The reverse of wf_variants.py. Where wf_variants asks "what FRESH disclosures exist for
the plugins I track?", this asks "across the WHOLE feed and ALL history, what past
disclosures of ONE vulnerability class (CWE) can I mine to build general detection
rules?". It selects disclosures by CWE, ranks them for *rule-building* value (not bounty
value), buckets them into sink families, and emits a copy-paste worklist that hands each
representative to `diff_audit.py` (stage the patch) and then `/codify-variant` (turn the
patch into a general Semgrep rule + grep pattern with a two-version oracle).

It is deliberately NOT an auto-authoring tool: rule authoring stays in the human/agent-in-
the-loop `/codify-variant` skill so the 90%-generalizability gate and the affected-vs-
patched oracle are always applied. This script only does the selection + clustering + patch
staging that scale poorly by hand across hundreds of historical CVEs.

CLI:
  python wf_class_harvest.py --cwe 502                 # POI worklist (no downloads)
  python wf_class_harvest.py --cwe 502 --top 25        # more representatives
  python wf_class_harvest.py --cwe 502 --dry-run       # print only, write no file
  python wf_class_harvest.py --cwe 502 --fetch --max-diffs 8   # also stage top-8 DIFF.md
  python wf_class_harvest.py --cwe 89                  # reuse the framework for SQLi
  python wf_class_harvest.py --cwe 502 --include-codified   # show CVEs already in provenance

Detection value != bounty scope: this harvests across ALL attacker roles (an Admin+ POI
still teaches the same sink), but every lead is TAGGED with its disclosed reachability so
the downstream audit prioritises unauth/subscriber-reachable hits. The rules it seeds are
LEADS ONLY, never auto-filed (global CLAUDE.md Semgrep rule).

Reuses (no duplication):
  wf_variants  - load_feed + per-record helpers (date/versions/role/scope/authors)
  diff_audit   - run() to stage DIFF.md + affected/patched trees for any slug
  audit_targets- vkey, load_db_plugins, has_diff_md
  analyzed_ledger / VARIANT-PROVENANCE.md - "already analyzed / already codified" signals
"""
import argparse
import os
import re
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from wf_variants import (  # noqa: E402
    load_feed, _record_date, _last_affected, _cvss_pr,
    _title_role, _scope_verdict, _ROLE_LABEL, _trim,
    load_db_authors, load_blocked_slugs, _author_name,
)
from audit_targets import vkey, load_db_plugins, has_diff_md  # noqa: E402
from diff_audit import run as diff_run  # noqa: E402

PROVENANCE = os.path.join(ROOT, "semgrep_rules", "claude_rules", "VARIANT-PROVENANCE.md")
ATTRIBUTION = ("_Vulnerability data (c) Defiant Inc. (Wordfence Intelligence), used under the "
               "WTI Community Edition license; CVE (c) The MITRE Corporation._")

# --------------------------------------------------------------------------- #
# Sink-family buckets (metadata heuristic — the TRUE family is assigned by
# /codify-variant from the real sink line once DIFF.md exists; this is only for
# a diverse, readable worklist). Ordered by specificity: first match wins.
# Keyed by CWE; unknown CWEs fall back to a single "all" bucket.
# --------------------------------------------------------------------------- #
_FAMILY_MAP = {
    502: [
        ("phar-deserialization",   r"phar://|\bphar\b"),
        ("base64-wrapped",         r"base64|gzinflate|gzuncompress|gzip|gzdecode"),
        ("import-migration-backup", r"import|migrat|backup|restore|\bexport\b|all[\s-]?in[\s-]?one"),
        ("cookie-deserialization", r"\bcookie\b"),
        ("shortcode-widget-block", r"shortcode|widget|elementor|\bblock\b|page[\s-]?builder"),
        ("form-builder",           r"gravity|\bform\b|form[\s-]?builder"),
        ("ajax-endpoint",          r"\bajax\b|admin-ajax"),
        ("rest-endpoint",          r"rest[\s-]?api|/wp-json|rest[\s-]?route|rest[\s-]?endpoint"),
    ],
    89: [
        ("orderby-sort",   r"order[\s-]?by|\bsort\b|\border\b"),
        ("search-filter",  r"\bsearch\b|\bfilter\b|\bquery\b"),
        ("ajax-endpoint",  r"\bajax\b|admin-ajax"),
        ("rest-endpoint",  r"rest[\s-]?api|/wp-json"),
    ],
    434: [
        ("import-restore", r"import|restore|backup|migrat"),
        ("avatar-media",   r"avatar|profile|media|image|photo"),
        ("ajax-endpoint",  r"\bajax\b|admin-ajax"),
    ],
}
_GENERIC_FAMILY = "generic"


def _patched_after(patched_versions, last_aff):
    """First concrete patched version strictly newer than `last_aff` (by vkey).
    Unlike wf_variants._first_patched (min of all patched tags), this guards against
    feed rows that list a lower-branch patched tag alongside the real fix (e.g. a 0.x
    maintenance release next to the 1.x fix — SureForms CVE-2025-6742 lists 0.0.14).
    Taking the min there yields a backwards affected→patched pair that diff_audit
    rejects; requiring `> last_aff` keeps the copy-paste `prep` command always valid."""
    concrete = [v for v in (patched_versions or []) if v and v != "*"]
    if not concrete:
        return None
    if last_aff:
        newer = [v for v in concrete if vkey(v) > vkey(last_aff)]
        return min(newer, key=vkey) if newer else None
    return min(concrete, key=vkey)


def family_of(cwe_id, title, description):
    """First-match family bucket for a disclosure, from title+description keywords."""
    text = f"{title or ''} {description or ''}".lower()
    for name, rx in _FAMILY_MAP.get(cwe_id, []):
        if re.search(rx, text):
            return name
    return _GENERIC_FAMILY


# --------------------------------------------------------------------------- #
# "Already codified" (provenance) + "already analyzed" (ledger)
# --------------------------------------------------------------------------- #
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def codified_cves():
    """Set of CVE ids already turned into a rule (parsed from VARIANT-PROVENANCE.md)."""
    try:
        with open(PROVENANCE, encoding="utf-8") as f:
            return {m.group(0).upper() for m in _CVE_RE.finditer(f.read())}
    except OSError:
        return set()


def analyzed_cve_set():
    """Best-effort set of CVEs already variant-analyzed (annotation only, never excludes)."""
    try:
        from analyzed_ledger import analyzed_cves
        return {c.upper() for c in analyzed_cves()}
    except Exception:
        return set()


# --------------------------------------------------------------------------- #
# Ranking — rule-building value, NOT bounty value
# --------------------------------------------------------------------------- #
_SCOPE_BONUS = {"in_scope": 30, "review": 10, "oos": 0}


def _score(rec_ctx):
    """Higher = better representative for authoring a general rule.
    Oracle-readiness (a downloadable patch) dominates; reachability, install weight and
    recency are secondary tiebreaks so the worklist front-loads the cleanest examples."""
    s = 0.0
    if rec_ctx["oracle_ready"]:
        s += 100                                   # last-affected + patched both known
    s += _SCOPE_BONUS.get(rec_ctx["scope"], 0)     # unauth/subscriber-reachable ranks up
    if rec_ctx["role"] == "unauth":
        s += 15
    s += min(rec_ctx["installs"], 1_000_000) / 100_000.0   # up to +10 for install weight
    yr = rec_ctx["year"]
    if yr:
        s += max(0, yr - 2016) * 0.6               # newer code shapes slightly preferred
    return s


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #
def collect(data, cwe_id, db_plugins, slug_author, blocked, since=None,
            include_codified=False, include_oos_authors=False):
    codified = codified_cves()
    analyzed = analyzed_cve_set()
    best_by_slug = {}   # slug -> ctx (keep the best-scoring disclosure per plugin)

    for uuid, rec in data.items():
        if rec.get("informational"):
            continue
        if (rec.get("cwe") or {}).get("id") != cwe_id:
            continue
        dt = _record_date(rec)
        if since and (dt is None or dt < since):
            continue
        cve = (rec.get("cve") or "").upper() or None
        if cve and cve in codified and not include_codified:
            continue
        role = _title_role(rec.get("title"))
        scope = _scope_verdict(role, _cvss_pr(rec))
        title = rec.get("title", "")
        desc = (rec.get("description") or "").strip()

        for sw in rec.get("software", []):
            if sw.get("type") != "plugin":
                continue
            slug = sw.get("slug")
            if not slug:
                continue
            if not include_oos_authors and slug in blocked:
                continue
            last_aff = _last_affected(sw.get("affected_versions") or {})
            patched = _patched_after(sw.get("patched_versions"), last_aff)
            inst = db_plugins.get(slug, {}).get("installs", 0)
            ctx = {
                "uuid": uuid, "slug": slug, "name": sw.get("name") or slug,
                "cve": cve, "title": title, "description": desc,
                "role": role, "scope": scope,
                "last_affected": last_aff, "patched": patched,
                "oracle_ready": bool(last_aff and patched),
                "installs": inst,
                "published": (rec.get("published") or rec.get("updated") or "")[:10],
                "year": (dt.year if dt else None),
                "family": family_of(cwe_id, title, desc),
                "author": _author_name(slug_author.get(slug, "")) or None,
                "references": rec.get("references") or [],
                "cve_link": rec.get("cve_link"),
                "diff_ready": bool(patched and has_diff_md(slug, patched)),
                "already_analyzed": bool(cve and cve in analyzed),
            }
            ctx["score"] = _score(ctx)
            cur = best_by_slug.get(slug)
            if cur is None or ctx["score"] > cur["score"]:
                best_by_slug[slug] = ctx

    return sorted(best_by_slug.values(), key=lambda c: -c["score"])


def diversify(candidates, top):
    """Family round-robin so the top-N spans sink families instead of N copies of the
    most common one. Within a family, higher score first."""
    from collections import OrderedDict, defaultdict
    buckets = defaultdict(list)
    for c in candidates:
        buckets[c["family"]].append(c)
    # family order = by best score in that family (so richest families lead)
    fam_order = sorted(buckets, key=lambda f: -buckets[f][0]["score"])
    picked, i = [], 0
    while len(picked) < top and any(buckets[f] for f in fam_order):
        f = fam_order[i % len(fam_order)]
        if buckets[f]:
            picked.append(buckets[f].pop(0))
        i += 1
        if i > top * len(fam_order) + 10:
            break
    return picked


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _scope_tag(c):
    label = _ROLE_LABEL.get(c["role"]) or ("unauth" if c["scope"] == "in_scope" else "privilege unclear")
    verdict = {"in_scope": "in scope", "oos": "OOS role", "review": "verify"}.get(c["scope"], "verify")
    return f"[{label} — {verdict}]"


def _render_lead(c, cwe_id):
    head = f"- [ ] {c['cve'] or 'disclosure'}  **{c['slug']}**"
    if c["installs"]:
        head += f"  ({c['installs']:,} installs)"
    head += f"   {_scope_tag(c)}"
    if not c["oracle_ready"]:
        head += "   ⚠ no patch pair in feed"
    if c["diff_ready"]:
        head += "   ✓ DIFF.md ready"
    if c["already_analyzed"]:
        head += "   (already variant-analyzed)"
    out = [head]
    if c["oracle_ready"]:
        out.append(f"      versions: affected ≤ {c['last_affected']}  →  patched {c['patched']}")
    if c["title"]:
        out.append(f"      disclosure: {_trim(c['title'], 150)}   ({c['published']})")
    if c["description"]:
        out.append(f"      why:    {_trim(c['description'], 200)}")

    # prep: stage the patch (last-affected -> patched) so DIFF.md + both trees exist
    if c["oracle_ready"]:
        if c["diff_ready"]:
            out.append(f"      prep:   ✓ audit/{c['slug']}/{c['patched']}/DIFF.md ready — skip; run codify")
        else:
            out.append(f"      prep:   python diff_audit.py {c['slug']} "
                       f"--old-version {c['last_affected']} --new-version {c['patched']} --old-fallback")
        # codify: hand the staged patch to the single-CVE rule authoring skill
        out.append(f"      codify: /codify-variant {c['slug']} {c['cve'] or ''}".rstrip())
    else:
        out.append("      prep:   (no patched version in feed — locate the fix manually before codifying)")

    ref = next((r for r in c["references"] if "wordfence.com" in r), None) or \
        (c["references"][0] if c["references"] else c["cve_link"])
    if ref:
        out.append(f"      ref:    {ref}")
    return "\n".join(out)


def render(candidates, cwe_id, top, total_disclosures, n_oracle, n_codified, source, since):
    from collections import Counter
    picked = diversify(candidates, top)
    fam_counts = Counter(c["family"] for c in candidates)
    L = [f"# CWE-{cwe_id} Detection Backfill — harvest worklist   "
         f"({datetime.now():%Y-%m-%d}, generated by wf_class_harvest.py)",
         "",
         f"_Class-driven historical backfill. {total_disclosures} CWE-{cwe_id} plugin "
         f"disclosure(s) in the feed"
         + (f" since {since:%Y-%m-%d}" if since else " (all history)")
         + f"; {n_oracle} have a downloadable affected→patched pair (oracle-ready); "
         f"{n_codified} CVE(s) already codified into rules (hidden). Feed: {source}._",
         "",
         "**Workflow per row:** run `prep` (stages DIFF.md + both trees) → run `codify` "
         "(`/codify-variant` turns the patch into a general rule with a fires-on-affected / "
         "silent-on-patched oracle). Detection value ≠ bounty scope — rules are leads only.",
         "",
         "## Family distribution (all candidates)",
         ""]
    for fam, n in fam_counts.most_common():
        L.append(f"- `{fam}`: {n}")
    L += ["", f"## Selected representatives (family round-robin, top {len(picked)})", ""]

    from collections import OrderedDict
    groups = OrderedDict()
    for c in picked:
        groups.setdefault(c["family"], []).append(c)
    for fam, rows in groups.items():
        L.append(f"### {fam}  ({len(rows)})")
        for c in rows:
            L.append(_render_lead(c, cwe_id))
        L.append("")
    L += [ATTRIBUTION, ""]
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Fetch (stage DIFF.md pairs for the top-N)
# --------------------------------------------------------------------------- #
def stage_diffs(picked, max_diffs):
    staged, n = [], 0
    for c in picked:
        if n >= max_diffs:
            break
        if not c["oracle_ready"] or c["diff_ready"]:
            continue
        n += 1
        print(f"[harvest] staging {c['slug']} {c['last_affected']} -> {c['patched']} …", file=sys.stderr)
        try:
            md_path, res = diff_run(c["slug"], new_version=c["patched"],
                                    old_version=c["last_affected"], old_fallback=True,
                                    verbose=False)
        except Exception as e:
            md_path, res = None, str(e)
        if md_path:
            c["diff_ready"] = True
            staged.append((c["slug"], c["cve"], md_path))
            print(f"[harvest]   ✓ {md_path}", file=sys.stderr)
        else:
            print(f"[harvest]   ✗ {c['slug']}: {res}", file=sys.stderr)
        time.sleep(0.4)  # rate-limit WP.org downloads
    return staged


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cwe", type=int, default=502, help="CWE id to harvest (default 502 = PHP Object Injection)")
    ap.add_argument("--top", type=int, default=20, help="representatives to select (family round-robin)")
    ap.add_argument("--since", default=None, help="YYYY-MM-DD lower bound (default: all history)")
    ap.add_argument("--refresh", action="store_true", help="force re-download the feed")
    ap.add_argument("--fetch", action="store_true", help="also stage DIFF.md for the top representatives")
    ap.add_argument("--max-diffs", type=int, default=8, help="cap on --fetch downloads")
    ap.add_argument("--include-codified", action="store_true",
                    help="also show CVEs already turned into a rule (in VARIANT-PROVENANCE.md)")
    ap.add_argument("--include-oos-authors", action="store_true",
                    help="do NOT drop plugins by out-of-scope authors (Automattic/WooCommerce/etc.)")
    ap.add_argument("--dry-run", action="store_true", help="print to stdout only; write no file, no downloads")
    ap.add_argument("--out", default=None, help="output file (default: <cwe>-harvest.md)")
    args = ap.parse_args()

    since = datetime.strptime(args.since, "%Y-%m-%d") if args.since else None
    data, source = load_feed(refresh=args.refresh)
    db_plugins = load_db_plugins()
    slug_author, author_slugs = load_db_authors()
    blocked = load_blocked_slugs(author_slugs)

    candidates = collect(data, args.cwe, db_plugins, slug_author, blocked, since=since,
                         include_codified=args.include_codified,
                         include_oos_authors=args.include_oos_authors)
    n_oracle = sum(1 for c in candidates if c["oracle_ready"])
    n_codified = len(codified_cves() & {
        (rec.get("cve") or "").upper()
        for rec in data.values()
        if (rec.get("cwe") or {}).get("id") == args.cwe and rec.get("cve")
    })

    picked = diversify(candidates, args.top)
    if args.fetch and not args.dry_run:
        staged = stage_diffs(picked, args.max_diffs)
        print(f"[harvest] staged {len(staged)} DIFF.md pair(s)", file=sys.stderr)

    md = render(candidates, args.cwe, args.top, len(candidates), n_oracle, n_codified, source, since)
    print(f"[harvest] CWE-{args.cwe}: {len(candidates)} candidate plugin(s) "
          f"({n_oracle} oracle-ready), {len(picked)} selected across "
          f"{len({c['family'] for c in picked})} families | feed={source}", file=sys.stderr)

    if args.dry_run:
        print(md)
        return
    out = args.out or os.path.join(ROOT, f"{args.cwe}-harvest.md")
    out = out if os.path.isabs(out) else os.path.join(ROOT, out)
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[harvest] wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
