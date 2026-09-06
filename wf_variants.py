#!/usr/bin/env python3
"""
wf_variants.py - Edge 2: turn other researchers' freshly-published Wordfence
disclosures into YOUR leads (variant analysis).

When a vuln is disclosed in a plugin, the same vein is often still productive:
the patch may be incomplete, sibling functions may share the bug, the same author
likely repeated the pattern in their other plugins, and you may already have an
affected version on disk that you audited before the bug was known. This script
reads the Wordfence Intelligence vulnerability feed and emits those three lead
types for the plugins you track.

CLI:
  python wf_variants.py                       # leads for disclosures in the last 14 days
  python wf_variants.py --since YYYY-MM-DD     # custom window
  python wf_variants.py --refresh              # force re-download the feed
  python wf_variants.py --fetch                # also download patched/affected pairs and
                                               #   diff them to list the changed functions
  python wf_variants.py --top 60

Feed: Wordfence Intelligence v3 Production feed (https://www.wordfence.com/help/
wordfence-intelligence/). The v2 no-key feed was retired (410 Gone); v3
is free but token-gated. Provide the key via the WORDFENCE_API_KEY env var, a bare
token in .env, or databases/wf_api_key.txt. The 142 MB feed is cached to
databases/wf_feed_cache.json and refreshed at most daily.

Importable helpers (used by daily_targets.py):
  collect_leads(...) -> list[dict]
  render_variant_section(leads, top) -> markdown for the "B. VARIANT LEADS" section
"""
import argparse
import glob
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
AUDIT_DIR = os.path.join(ROOT, "audit")
DB_GLOB = os.path.join(ROOT, "databases", "*.db")
ACC_DB = os.path.join(ROOT, "databases", "pattern_accumulator.db")
CACHE = os.path.join(ROOT, "databases", "wf_feed_cache.json")
FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
UA = "wordpress-plugin-auditor/1.0 (vulnerability research; coordinated disclosure)"
ATTRIBUTION = ("_Vulnerability data (c) Defiant Inc. (Wordfence Intelligence), used under the "
               "WTI Community Edition license; CVE (c) The MITRE Corporation. "
               "Each lead links to its source record._")

# WordPress.org profile author-slugs whose plugins are out of scope for the Wordfence
# bounty program (Automattic — incl. WooCommerce, WordPress Core, Yoast, Google,
# Facebook/Meta, SiteGround). Keyed on the profile slug parsed by _author_key(), NOT the
# display name, so third-party plugins that merely mention a vendor (e.g. a third-party
# "… for Google Analytics") are never over-blocked. Extend without editing code via
# databases/oos_authors.txt (one author-slug per line; '#' comments allowed).
BLOCKED_AUTHOR_SLUGS = frozenset({
    "automattic", "woocommerce",   # Automattic (WooCommerce is an Automattic product)
    "wordpressdotorg",             # WordPress Core / WordPress.org official plugins
    "yoast", "google", "facebook", "siteground",
})
OOS_AUTHORS_FILE = os.path.join(ROOT, "databases", "oos_authors.txt")

sys.path.insert(0, ROOT)
from audit_targets import vkey, audited_versions, load_db_plugins, has_diff_md  # noqa: E402
from diff_audit import diff_php, download_version, nearest_published_below  # noqa: E402


# --------------------------------------------------------------------------- #
# API key + feed
# --------------------------------------------------------------------------- #
def resolve_api_key():
    for var in ("WORDFENCE_API_KEY", "WF_API_KEY", "WORDFENCE_INTEL_KEY"):
        v = os.environ.get(var)
        if v and v.strip():
            return v.strip()
    for p in (os.path.join(ROOT, ".env"), os.path.join(ROOT, "databases", "wf_api_key.txt")):
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, val = line.split("=", 1)
                if any(t in k.upper() for t in ("WORDFENCE", "WF", "API", "TOKEN", "KEY")):
                    return val.strip().strip('"').strip("'")
            elif re.fullmatch(r"[A-Za-z0-9._\-]{20,}", line):
                return line  # bare token (this repo's .env format)
    return None


def fetch_feed(key, timeout=180):
    req = urllib.request.Request(
        FEED_URL, headers={"Authorization": f"Bearer {key}", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


_HTTP_HINT = {
    401: "API key missing/invalid (set WORDFENCE_API_KEY or put the token in .env)",
    403: "API key not authorised for this feed",
    410: "endpoint retired — check the v3 docs URL",
    429: "rate limited (the feed allows infrequent pulls — try later / use the cache)",
}


def load_feed(refresh=False, max_age_hours=24):
    """Return (data, source). Uses the daily cache unless stale/--refresh, falling
    back to a stale cache if a live fetch is impossible."""
    have_cache = os.path.exists(CACHE)
    fresh_cache = have_cache and (time.time() - os.path.getmtime(CACHE) < max_age_hours * 3600)
    if not refresh and fresh_cache:
        with open(CACHE, encoding="utf-8") as f:
            return json.load(f), "cache"

    key = resolve_api_key()
    if not key:
        if have_cache:
            print("[wf_variants] no API key found; using existing cache (may be stale). "
                  "Set WORDFENCE_API_KEY / .env to refresh.", file=sys.stderr)
            with open(CACHE, encoding="utf-8") as f:
                return json.load(f), "stale-cache"
        raise SystemExit(
            "[wf_variants] No Wordfence API key and no cached feed.\n"
            "  The free v2 no-key feed was retired (410). Get a free key:\n"
            "  wordfence.com account -> Integrations -> create API key, then either\n"
            "    set WORDFENCE_API_KEY=<key>  OR  put the bare token in .env\n"
            "  and re-run (optionally with --refresh).")
    try:
        raw = fetch_feed(key)
        with open(CACHE, "wb") as f:
            f.write(raw)
        return json.loads(raw), "fresh"
    except urllib.error.HTTPError as e:
        hint = _HTTP_HINT.get(e.code, f"HTTP {e.code}")
        if have_cache:
            print(f"[wf_variants] feed fetch failed ({hint}); using cached feed.", file=sys.stderr)
            with open(CACHE, encoding="utf-8") as f:
                return json.load(f), "stale-cache"
        raise SystemExit(f"[wf_variants] feed fetch failed ({hint}) and no cache present.")
    except (urllib.error.URLError, TimeoutError) as e:
        if have_cache:
            print(f"[wf_variants] network error ({e}); using cached feed.", file=sys.stderr)
            with open(CACHE, encoding="utf-8") as f:
                return json.load(f), "stale-cache"
        raise SystemExit(f"[wf_variants] network error and no cache present: {e}")


# --------------------------------------------------------------------------- #
# Tracked plugins / authors / prior findings
# --------------------------------------------------------------------------- #
def actionable_slugs(db_plugins):
    audited = {d for d in os.listdir(AUDIT_DIR)
               if os.path.isdir(os.path.join(AUDIT_DIR, d))} if os.path.isdir(AUDIT_DIR) else set()
    return set(db_plugins) | audited


def load_db_authors():
    """Return (slug->author_html, author_key->set(slugs)) across tier DBs."""
    slug_author = {}
    for db in glob.glob(DB_GLOB):
        if os.path.basename(db).startswith("pattern_accumulator"):
            continue
        try:
            rows = sqlite3.connect(db).execute("SELECT slug, author FROM Plugins").fetchall()
        except sqlite3.Error:
            continue
        for slug, author in rows:
            if author and slug not in slug_author:
                slug_author[slug] = author
    author_slugs = {}
    for slug, author in slug_author.items():
        k = _author_key(author)
        if k:
            author_slugs.setdefault(k, set()).add(slug)
    return slug_author, author_slugs


def _author_key(html):
    m = re.search(r"profiles\.wordpress\.org/([^/\"']+)", html or "")
    if m:
        return m.group(1).lower()
    m = re.search(r">([^<]+)<", html or "")
    txt = (m.group(1) if m else re.sub(r"<[^>]+>", "", html or "")).strip().lower()
    return txt or None


def _author_name(html):
    m = re.search(r">([^<]+)<", html or "")
    return (m.group(1).strip() if m else re.sub(r"<[^>]+>", "", html or "").strip()) or "?"


def blocked_author_slugs():
    """Effective set of out-of-scope author-slugs: the built-in BLOCKED_AUTHOR_SLUGS plus
    any extra slugs listed in databases/oos_authors.txt (one per line, '#' comments)."""
    extra = set()
    try:
        with open(OOS_AUTHORS_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    extra.add(line)
    except OSError:
        pass
    return set(BLOCKED_AUTHOR_SLUGS) | extra


def load_blocked_slugs(author_slugs=None):
    """Set of plugin slugs whose author is out of scope. Reuses the author_key->{slugs}
    map from load_db_authors() (pass one in to avoid a second DB pass)."""
    if author_slugs is None:
        _, author_slugs = load_db_authors()
    blocked = set()
    for key in blocked_author_slugs():
        blocked |= author_slugs.get(key, set())
    return blocked


def load_reported_cwes():
    """{slug: set(int cwe)} of confirmed (TP) findings — to spot a missed class."""
    out = {}
    if not os.path.exists(ACC_DB):
        return out
    try:
        rows = sqlite3.connect(ACC_DB).execute(
            "SELECT plugin_slug, cwe FROM findings WHERE status='TP'").fetchall()
    except sqlite3.Error:
        return out
    for slug, cwe in rows:
        m = re.search(r"\d+", cwe or "")
        if m:
            out.setdefault(slug, set()).add(int(m.group()))
    return out


# --------------------------------------------------------------------------- #
# Record helpers (schema verified against the live v3 feed)
# --------------------------------------------------------------------------- #
def _record_date(rec):
    s = rec.get("published") or rec.get("updated")
    if not s:
        return None
    try:
        return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _vcmp(a, b):
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


def _last_affected(affected_versions):
    best = None
    for r in (affected_versions or {}).values():
        tv = r.get("to_version")
        if tv and tv != "*":
            if best is None or _vcmp(tv, best) > 0:
                best = tv
    return best


def _first_patched(patched_versions):
    concrete = [v for v in (patched_versions or []) if v and v != "*"]
    return min(concrete, key=vkey) if concrete else None


def _in_affected(version, affected_versions):
    if not version:
        return False
    for r in (affected_versions or {}).values():
        fv, fi = r.get("from_version"), r.get("from_inclusive", True)
        tv, ti = r.get("to_version"), r.get("to_inclusive", True)
        ok = True
        if fv and fv != "*":
            c = _vcmp(version, fv)
            if c < 0 or (c == 0 and not fi):
                ok = False
        if ok and tv and tv != "*":
            c = _vcmp(version, tv)
            if c > 0 or (c == 0 and not ti):
                ok = False
        if ok:
            return True
    return False


def _cvss_pr(rec):
    vec = ((rec.get("cvss") or {}).get("vector") or "")
    m = re.search(r"PR:([NLH])", vec)
    return m.group(1) if m else None


# Wordfence names the effective-attacker role in the disclosure title, and THAT is
# authoritative for bounty scope. CVSS PR:L is assigned to ANY authenticated role
# (Subscriber through Author), so it cannot tell in-scope (Subscriber/Customer) from
# out-of-scope (Contributor/Author = bounty-ineligible; Editor+ = PR:H).
_ROLE_ALIASES = {
    "subscriber": "subscriber", "customer": "customer",
    "contributor": "contributor", "author": "author",
    "editor": "editor", "administrator": "admin", "admin": "admin",
    "shop manager": "shop_manager", "shop_manager": "shop_manager",
    "custom": "custom",
}
_IN_SCOPE_ROLES = {"unauth", "subscriber", "customer"}
_OOS_ROLES = {"contributor", "author", "editor", "admin", "shop_manager"}
_SCOPE_RANK = {"in_scope": 0, "review": 1, "oos": 2}


def _title_role(title):
    """Normalized effective-attacker role parsed from a Wordfence disclosure title, or None.
    The trailing role clause wins ('Missing Authorization to Authenticated (Editor+)' -> editor;
    '... to Unauthenticated' -> unauth)."""
    t = title or ""
    roles = re.findall(r"Authenticated \(([^)+]+)\+?\)", t)
    if roles:
        r = roles[-1].strip().lower()
        return _ROLE_ALIASES.get(r, r)
    if re.search(r"\bUnauthenticated\b", t):
        return "unauth"
    return None


def _scope_verdict(role, cvss_pr):
    """'in_scope' | 'oos' | 'review'. Conservative — only 'oos' when clearly out of scope,
    so no in-scope lead is dropped. Unknown/custom role falls back to CVSS PR."""
    if role in _IN_SCOPE_ROLES:
        return "in_scope"
    if role in _OOS_ROLES:
        return "oos"
    # role is None or 'custom' (custom capability — could be low or high privilege)
    if cvss_pr == "N":
        return "in_scope"
    if cvss_pr == "H":
        return "oos"
    return "review"  # PR:L / unknown with no title role — keep, flag for manual check


def _priv_rank(role):
    if role == "unauth":
        return 0
    if role in ("subscriber", "customer"):
        return 1
    return 2


# Program install thresholds by vuln class (global CLAUDE.md). A labeled heuristic keyed on
# CWE — the audit still judges the true class/impact. Only the unambiguous file/RCE/auth and
# XSS/SQLi CWEs get a hard floor; impact-dependent classes get an advisory note.
_HIGH_THREAT_CWES = {22, 23, 29, 36, 73, 78, 94, 95, 98, 269, 287, 288, 434, 502, 552}
_COMMON_DANGEROUS_CWES = {79, 89}
_IMPACT_DEPENDENT_CWES = {200, 352, 639, 862}


def _threshold_note(cwe_id, installs):
    """One-line install-threshold hint, only when informative (below floor, or a
    High-Threat/XSS lead clearing its low floor). '' otherwise."""
    if not installs or not cwe_id:
        return ""
    if cwe_id in _IMPACT_DEPENDENT_CWES:
        return "↳ install floor: 25 if file/options/RCE/auth-bypass impact, else 50,000"
    if cwe_id in _HIGH_THREAT_CWES:
        floor, label = 25, "High-Threat"
    elif cwe_id in _COMMON_DANGEROUS_CWES:
        floor, label = 500, "XSS/SQLi"
    else:
        floor, label = 50000, "standard"
    if installs < floor:
        return f"⚠ {installs:,} installs < {floor:,} floor for {label} → OOS by installs"
    if label != "standard":
        return f"✓ {installs:,} installs ≥ {floor:,} floor ({label})"
    return ""


def _feed_age_str():
    """Human age of the cached feed file, or '' if unknown."""
    try:
        age_h = (time.time() - os.path.getmtime(CACHE)) / 3600
    except OSError:
        return ""
    if age_h < 1:
        return f"age {age_h * 60:.0f}m"
    if age_h < 48:
        return f"age {age_h:.0f}h"
    return f"age {age_h / 24:.0f}d"


def _latest_audited(slug):
    av = audited_versions(slug)
    return max(av, key=vkey) if av else None


# --------------------------------------------------------------------------- #
# Lead collection
# --------------------------------------------------------------------------- #
def _in_install_band(installs, min_installs, max_installs):
    """Install-band membership, matching audit_targets.rank_targets. An UNKNOWN
    count (0 — slug audited but not in any tier DB) is never hidden, so banding can't
    silently drop a lead we can't size; max_installs <= 0 means no ceiling."""
    if not installs:
        return True
    if installs < min_installs:
        return False
    if max_installs > 0 and installs > max_installs:
        return False
    return True


def collect_leads(data, since, actionable, db_plugins, slug_author, author_slugs,
                  reported, fetch=False, max_diffs=6, max_siblings=4,
                  min_installs=0, max_installs=0, analyzed_cves=frozenset()):
    leads = []
    n_diffs = 0
    for uuid, rec in data.items():
        if rec.get("informational"):
            continue
        dt = _record_date(rec)
        if dt is None or dt < since:
            continue
        cwe = rec.get("cwe") or {}
        cwe_id = cwe.get("id")
        pr = _cvss_pr(rec)
        role = _title_role(rec.get("title"))
        scope = _scope_verdict(role, pr)
        cvss = rec.get("cvss") or {}
        for sw in rec.get("software", []):
            if sw.get("type") != "plugin":
                continue
            slug = sw.get("slug")
            if not slug or slug not in actionable:
                continue
            inst = db_plugins.get(slug, {}).get("installs", 0)
            if not _in_install_band(inst, min_installs, max_installs):
                continue  # outside the requested install band (batch by tier)

            affected = sw.get("affected_versions") or {}
            last_aff = _last_affected(affected)
            patched = _first_patched(sw.get("patched_versions"))
            audited_v = _latest_audited(slug)
            in_aff = _in_affected(audited_v, affected) if audited_v else False
            missed = bool(in_aff and cwe_id and cwe_id not in reported.get(slug, set()))

            # same-author siblings
            akey = _author_key(slug_author.get(slug, ""))
            siblings = []
            if akey:
                for other in sorted(author_slugs.get(akey, set()) - {slug},
                                    key=lambda s: -(db_plugins.get(s, {}).get("installs", 0))):
                    siblings.append((other, db_plugins.get(other, {}).get("installs", 0)))
                    if len(siblings) >= max_siblings:
                        break

            changed_funcs, changed_files = [], []
            if fetch and last_aff and patched and n_diffs < max_diffs:
                n_diffs += 1
                pa = download_version(slug, last_aff)
                if not pa:  # last-affected tag pruned from WP.org — use nearest pre-patch
                    alt = nearest_published_below(slug, patched)
                    pa = download_version(slug, alt) if alt else None
                pb = download_version(slug, patched)
                if pa and pb:
                    try:
                        res = diff_php(slug, os.path.basename(pa), os.path.basename(pb))
                        changed_funcs = [e["name"] + "()" for e in res["added_entry_points"]
                                         if e["kind"] == "function"][:6]
                        changed_files = [f["path"] for f in res["files"]][:6]
                    except Exception:
                        pass
                time.sleep(0.4)  # rate-limit downloads

            leads.append({
                "uuid": uuid, "slug": slug, "name": sw.get("name") or slug,
                "title": rec.get("title", ""), "cve": rec.get("cve"),
                "description": (rec.get("description") or "").strip(),
                "cve_link": rec.get("cve_link"),
                "cwe_id": cwe_id, "cwe_name": cwe.get("name"),
                "published": (rec.get("published") or rec.get("updated") or "")[:10],
                "affected_ranges": list(affected.keys()),
                "last_affected": last_aff, "patched": patched,
                "references": rec.get("references") or [],
                "installs": inst,
                "pr": pr, "role": role, "scope": scope,
                "cvss_score": cvss.get("score"), "cvss_rating": cvss.get("rating"),
                "audited_version": audited_v, "in_affected": in_aff, "missed_class": missed,
                "analyzed": bool(rec.get("cve") and str(rec.get("cve")).upper() in analyzed_cves),
                "author_name": _author_name(slug_author.get(slug, "")) if akey else None,
                "siblings": siblings,
                "changed_funcs": changed_funcs, "changed_files": changed_files,
            })

    # in-scope first, then unauth before subscriber/customer, then missed-class (you already
    # have an affected copy), then install weight, then recency
    leads.sort(key=lambda L: (_SCOPE_RANK.get(L["scope"], 3), _priv_rank(L.get("role")),
                              not L["missed_class"], -L["installs"], L["published"]))
    return leads


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _trim(s, n):
    """Collapse whitespace and clip to n chars with an ellipsis."""
    s = re.sub(r"\s+", " ", (s or "").strip())
    return s if len(s) <= n else s[:n - 1].rstrip() + "…"


def _cwe_str(L):
    s = f"CWE-{L['cwe_id']}" if L["cwe_id"] else "CWE-?"
    if L["cwe_name"]:
        s += f" ({L['cwe_name'][:46]})"
    return s


_ROLE_LABEL = {
    "unauth": "unauth", "subscriber": "Subscriber+", "customer": "Customer+",
    "contributor": "Contributor+", "author": "Author+", "editor": "Editor+",
    "admin": "Administrator+", "shop_manager": "Shop Manager+", "custom": "Custom capability",
}


def _scope_tag(L):
    """Scope tag driven by the title-parsed role (authoritative), not the CVSS PR field."""
    role, scope = L.get("role"), L.get("scope")
    label = _ROLE_LABEL.get(role)
    if scope == "in_scope":
        return f"[{label or 'unauth'} — in scope]"
    if scope == "oos":
        why = "bounty-ineligible" if role in ("contributor", "author") else "PR:H"
        return f"[{label or 'high-priv'} — OOS, {why}]"
    return f"[{label or 'privilege unclear'} — verify]"


def _render_lead(L, grouped=False):
    if grouped:
        # under a per-plugin heading the slug/installs are already shown; anchor on the CVE
        head = f"- [ ] {L['cve'] or 'disclosure'}  {_cwe_str(L)}"
    else:
        head = f"- [ ] **{L['slug']}**"
        if L["installs"]:
            head += f"  ({L['installs']:,} installs)"
        bits = [b for b in (L["cve"], _cwe_str(L)) if b]
        head += "  " + "  ".join(bits)
    if L["patched"]:
        head += f"  — patched in {L['patched']}"
    head += f"   {_scope_tag(L)}"
    if L["missed_class"]:
        head += "   ★ affected copy on disk"
    last_aff, patched = L["last_affected"], L["patched"]
    prepared = bool(last_aff and patched and has_diff_md(L["slug"], patched))
    if prepared:
        head += "   ✓ DIFF.md ready"
    out = [head]
    tn = _threshold_note(L.get("cwe_id"), L.get("installs"))
    if tn:
        out.append(f"      {tn}")
    if L["title"]:
        out.append(f"      disclosure: {L['title']}   ({L['published']})")
    # why: the Wordfence prose — names the mechanism + privilege (e.g. "missing
    # capability check on a function", "Subscriber-level and above") that CVE+CWE alone
    # don't convey. This is the "what was fixed" lead, read alongside DIFF.md.
    if L["description"]:
        out.append(f"      why:    {_trim(L['description'], 200)}")

    cwe = L["cwe_id"]
    cname = L["cwe_name"] or "the disclosed class"
    cve = L["cve"] or "this disclosure"

    # PREP — one command writes the patch (last-affected -> patched) to DIFF.md and puts
    # both versions on disk. The patch IS the vulnerable code; the session reads it.
    # If a DIFF.md is already on disk, say so instead of re-issuing the command.
    if last_aff and patched:
        diff_ref = f"audit/{L['slug']}/{patched}/DIFF.md"
        if prepared:
            out.append(f"      prep:   ✓ {diff_ref} ready — skip prep; paste audit: below")
        else:
            # --old-fallback: if the author pruned the last-affected tag from WP.org
            # (a 404 that used to kill this copy-paste), diff_audit transparently falls
            # back to the newest published version below the patch — still pre-fix, so
            # the patch-diff is valid. One command, always works.
            out.append(f"      prep:   python diff_audit.py {L['slug']} "
                       f"--old-version {last_aff} --new-version {patched} --old-fallback")
    else:
        diff_ref = "the disclosed file (see ref)"
    fix_clause = f"the fix in {patched}" if patched else "the fix"

    # AUDIT — ONE prompt that hands the WHOLE investigation (confirm + bypass + siblings
    # + your on-disk affected copy) to a fresh session. You do NOT grep/diff by hand.
    # The Wordfence description rides along so the session starts from the disclosed
    # mechanism, not a blank slate; DIFF.md then pins it to the exact code.
    # NB: do not run the Full Audit Pipeline on this plugin — after the patch-diff the
    # highest on-disk version is the PATCHED one, so the pipeline would audit fixed code.
    extra = ""
    if L["missed_class"]:
        extra = (f" I also have plugins/{L['slug']}/{L['audited_version']} on disk (affected, "
                 f"no recorded CWE-{cwe} finding) — confirm the bug there.")
    elif L["in_affected"]:
        extra = (f" My copy plugins/{L['slug']}/{L['audited_version']} is in the affected range — "
                 f"check whether my prior finding already matches this.")
    wf_ctx = ""
    if L["description"]:
        # single-quote the embedded prose (inner " -> ') so it can't close the
        # outer double-quoted prompt or blur where "paste verbatim" ends
        wf_ctx = f" Wordfence's description: '{_trim(L['description'], 480).replace(chr(34), chr(39))}'."
    out.append(
        f"      audit:  (fresh session, paste verbatim) \"Variant-analyze {cve} (CWE-{cwe}, {cname}) "
        f"in {L['slug']}.{wf_ctx} Read {diff_ref} — the fix reveals exactly what was vulnerable. Then: "
        f"(1) confirm the bug and where it lives; (2) judge whether {fix_clause} is COMPLETE or "
        f"BYPASSABLE; (3) grep {L['slug']} for sibling functions/handlers with the same pre-fix pattern "
        f"the patch left untouched.{extra} Report any bypass or unpatched sibling as a NEW finding — "
        f"unauth/subscriber scope only. Note: this disclosure already has a CVE, so confirming it is "
        f"research, not a submittable finding — do not write a disclosure report, PoC, or registry "
        f"row for it; only for a genuinely new bypass or sibling. If neither exists, say so and stop.\"")
    if L["changed_funcs"]:
        out.append(f"              (fix touched: {', '.join(L['changed_funcs'][:5])})")

    # ALSO — the same-author hunt is a separate, FULL audit of a sibling plugin.
    if L["siblings"]:
        sib = ", ".join(s for s, _ in L["siblings"])
        first = L["siblings"][0][0]
        out.append(f"      also:   {L['author_name']} also ships {sib} — same author, likely same bug:")
        out.append(f"              python wp-plugin-downlauditor.py --plugin {first} -m both "
                   f"--config ./semgrep_rules  →  Audit {first} with Full Audit Pipeline (focus CWE-{cwe})")

    ref = next((r for r in L["references"] if "wordfence.com" in r), None) or \
        (L["references"][0] if L["references"] else L["cve_link"])
    if ref:
        out.append(f"      ref:    {ref}")
    return "\n".join(out)


def _band_str(min_installs, max_installs):
    """Human label for the active install band, for the section subtitle."""
    if min_installs and max_installs and max_installs > 0:
        return f" within installs {min_installs:,}–{max_installs:,}"
    if max_installs and max_installs > 0:
        return f" with installs ≤ {max_installs:,}"
    if min_installs:
        return f" with installs ≥ {min_installs:,}"
    return ""


def render_variant_section(leads, top=40, min_installs=0, max_installs=0,
                           include_oos=False, include_analyzed=False, since=None, source=None):
    """Markdown for the 'B. VARIANT LEADS' section (merged into targets.md). By default only
    in-scope/review leads render — OOS-by-role leads (Contributor+/Author+ = bounty-ineligible,
    Editor+/Admin+ = PR:H) are hidden but counted in a footer; pass include_oos to show them.
    When an install band is set it is stated in the subtitle so the scope is never silent."""
    band = _band_str(min_installs, max_installs)
    L = ["## B. VARIANT LEADS — fresh Wordfence disclosures you can chase (Edge 2)"]
    if not leads:
        L.append(f"_(no disclosures{band} in the window for plugins you track)_")
        return "\n".join(L)

    n_oos = sum(1 for x in leads if x.get("scope") == "oos")
    # A lead is hidden if it's OOS-by-role (unless include_oos) or already analyzed
    # (unless include_analyzed). Count already-analyzed among otherwise-visible leads.
    role_visible = [x for x in leads if include_oos or x.get("scope") != "oos"]
    n_analyzed = sum(1 for x in role_visible if x.get("analyzed"))
    visible = [x for x in role_visible if include_analyzed or not x.get("analyzed")]
    scoped = [x for x in visible if x.get("scope") != "oos"]  # in-scope + review only
    # in_scope leads that aren't subscriber/customer are unauth-level (explicit unauth role,
    # or no title role but CVSS PR:N); this makes the three counts sum to len(scoped).
    n_unauth = sum(1 for x in scoped if x["scope"] == "in_scope"
                   and x.get("role") not in ("subscriber", "customer"))
    n_sub = sum(1 for x in scoped if x.get("role") in ("subscriber", "customer"))
    n_review = sum(1 for x in scoped if x["scope"] == "review")

    meta = []
    if since is not None:
        meta.append(f"window since {since:%Y-%m-%d}")
    if source:
        age = _feed_age_str()
        meta.append(f"feed: {source}" + (f" ({age})" if age else ""))
    if meta:
        L.append("_" + " · ".join(meta) + "_")

    shown = min(top, len(visible))
    summary = (f"_{len(scoped)} in-scope/review lead(s){band} "
               f"({n_unauth} unauth, {n_sub} subscriber/customer, {n_review} verify)")
    if n_oos:
        summary += f" · {n_oos} OOS " + ("shown" if include_oos else "hidden")
    if n_analyzed:
        summary += f" · {n_analyzed} already-analyzed " + ("shown" if include_analyzed else "hidden")
    summary += (f" · showing top {shown}. "
                f"Items you already have an affected copy of rank first._")
    L.append(summary)
    L.append("")

    # Group by slug (insertion order = the sorted lead order). A slug with ≥2 visible leads
    # gets one heading with its CVEs nested; singletons stay flat.
    groups = {}
    for x in visible:
        groups.setdefault(x["slug"], []).append(x)
    count = 0
    for slug, gls in groups.items():
        if count >= top:
            break
        if len(gls) >= 2:
            inst = gls[0]["installs"]
            inst_s = f"  ({inst:,} installs)" if inst else ""
            L.append(f"### {slug}{inst_s}  — {len(gls)} disclosures")
            for x in gls:
                if count >= top:
                    break
                L.append(_render_lead(x, grouped=True))
                count += 1
        else:
            L.append(_render_lead(gls[0], grouped=False))
            count += 1

    if n_oos and not include_oos:
        L.append("")
        L.append(f"_{n_oos} lead(s) hidden as OOS (role ≥ Contributor / PR:H). "
                 f"Re-run with --include-oos to show._")
    if n_analyzed and not include_analyzed:
        L.append("")
        L.append(f"_{n_analyzed} lead(s) hidden as already-analyzed "
                 f"(in databases/analyzed_variants.json). Re-run with --include-analyzed to show._")
    return "\n".join(L)


def write_variant_leads_md(leads, top, since, source, path=None,
                           min_installs=0, max_installs=0, include_oos=False):
    path = path or os.path.join(ROOT, "variant-leads.md")
    body = [f"# Variant Leads — {datetime.now().strftime('%Y-%m-%d')}   (generated by wf_variants.py)",
            "",
            f"_Edge 2: variant analysis of Wordfence disclosures since {since.strftime('%Y-%m-%d')} "
            f"(feed source: {source}). Three lead types per item: incomplete-patch/sibling, "
            f"same-author hunt, and you-already-have-it._",
            "",
            render_variant_section(leads, top, min_installs=min_installs, max_installs=max_installs,
                                   include_oos=include_oos, since=since, source=source),
            "",
            ATTRIBUTION, ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(body))
    return path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def get_variant_leads(since=None, refresh=False, fetch=False, max_diffs=6,
                      min_installs=0, max_installs=0, blocked=None,
                      include_blocked=False, analyzed_cves=frozenset()):
    """One-call helper for daily_targets: returns (leads, since_dt, source).
    `min_installs`/`max_installs` bound the leads by install band (max <= 0 = no cap)
    so a day's briefing can batch one install tier at a time. Plugins by out-of-scope
    authors are dropped unless `include_blocked` (pass a precomputed `blocked` slug-set
    to reuse one DB pass). `analyzed_cves` marks leads whose CVE was already analyzed."""
    since = since or (datetime.now() - timedelta(days=14))
    data, source = load_feed(refresh=refresh)
    db_plugins = load_db_plugins()
    actionable = actionable_slugs(db_plugins)
    slug_author, author_slugs = load_db_authors()
    reported = load_reported_cwes()
    if not include_blocked:
        if blocked is None:
            blocked = load_blocked_slugs(author_slugs)
        actionable = actionable - blocked
    leads = collect_leads(data, since, actionable, db_plugins, slug_author, author_slugs,
                          reported, fetch=fetch, max_diffs=max_diffs,
                          min_installs=min_installs, max_installs=max_installs,
                          analyzed_cves=analyzed_cves)
    return leads, since, source


def parse_since(arg):
    if not arg:
        return datetime.now() - timedelta(days=14)
    since = datetime.strptime(arg, "%Y-%m-%d")
    now = datetime.now()
    if since > now:
        raise SystemExit(
            f"[wf_variants] --since {arg} is in the future (today is {now:%Y-%m-%d}) "
            f"-- the window would silently match zero disclosures. Did you mean a date in the past?")
    return since


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", default=None, help="YYYY-MM-DD (default: 14 days ago)")
    ap.add_argument("--refresh", action="store_true", help="force re-download the feed")
    ap.add_argument("--fetch", action="store_true",
                    help="download patched/affected version pairs and diff them to list changed functions")
    ap.add_argument("--max-diffs", type=int, default=6, help="cap on --fetch downloads (rate-limit)")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--min-installs", type=int, default=0,
                    help="only leads for plugins with AT LEAST this many installs (0 = no floor)")
    ap.add_argument("--max-installs", type=int, default=0,
                    help="only leads for plugins with AT MOST this many installs (0 = no cap); "
                         "with --min-installs, batch one install tier per day")
    ap.add_argument("--include-oos", action="store_true",
                    help="also show leads whose disclosure-title role is OOS "
                         "(Contributor+/Author+ = bounty-ineligible, Editor+/Admin+ = PR:H); "
                         "hidden by default")
    ap.add_argument("--include-oos-authors", action="store_true",
                    help="do NOT exclude plugins by out-of-scope authors (Automattic/WooCommerce, "
                         "WordPress Core, Yoast, Google, Facebook, SiteGround); excluded by default")
    ap.add_argument("--out", default="variant-leads.md")
    args = ap.parse_args()

    since = parse_since(args.since)
    leads, since, source = get_variant_leads(since=since, refresh=args.refresh,
                                             fetch=args.fetch, max_diffs=args.max_diffs,
                                             min_installs=args.min_installs,
                                             max_installs=args.max_installs,
                                             include_blocked=args.include_oos_authors)
    n_missed = sum(1 for L in leads if L["missed_class"])
    n_sib = sum(1 for L in leads if L["siblings"])
    n_oos = sum(1 for L in leads if L.get("scope") == "oos")
    n_in = len(leads) - n_oos
    print(f"[wf_variants] feed={source} | since {since:%Y-%m-%d} | "
          f"{n_in} in-scope/review lead(s)"
          + (f" (+{n_oos} OOS hidden)" if n_oos and not args.include_oos else "")
          + f" | {n_missed} you-already-have | {n_sib} with same-author siblings")
    out_path = args.out if os.path.isabs(args.out) else os.path.join(ROOT, args.out)
    write_variant_leads_md(leads, args.top, since, source, out_path,
                           min_installs=args.min_installs, max_installs=args.max_installs,
                           include_oos=args.include_oos)
    print(f"[wf_variants] wrote {out_path}")


if __name__ == "__main__":
    main()
