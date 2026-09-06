#!/usr/bin/env python3
"""
diff_audited_ledger.py - persistent record of plugin versions already DIFF-AUDITED.

targets.md (Section A, Edge 1) lists plugins that shipped a new release since your
last audit. targets.md itself is overwritten every run and keeps no history, so this
module is the durable, accumulating memory that lets daily_targets.py / audit_targets.py
suppress a slug@version once it has been diff-audited. It is a separate file from
targets.md and is never reset on regeneration, so regenerating the briefing several
times a day is safe.

This is the Section-A twin of analyzed_ledger.py (which does the same job for Section-B
variant CVEs). audit_targets._is_real_audit already treats an on-disk audit dir as
"audited", but a finding-first diff-audit that concluded "no vulnerability" leaves no
marker at all, and version-string drift (6.8.6 vs 6.8.6.1) can slip past the dir check;
this ledger closes both gaps with an explicit slug@version record.

Storage: databases/diff_audited.json
  {"version": 1,
   "entries": [{"slug": "learnpress", "version": "4.4.0",
                "marked": "YYYY-MM-DD", "source": "harvest"|"manual"}]}

A pair enters the ledger two ways (both wired in daily_targets.py):
  - auto-harvest: ticked `- [x]` lines in Section A of the previous targets.md
  - manual:       --mark-diff-audited learnpress@4.4.0

The dedup key is "slug@version" (slug lower-cased, version verbatim) — the same string
audit_targets.rank_targets builds from each candidate's resolved current version.

Retention defaults to keep-all (0): the file grows by at most one line per audited
version, and a version-keyed entry is naturally superseded the moment a newer release
ships (the new version simply isn't in the ledger). Pass a positive
--retention-days / retention_days to prune older entries if desired.

This module must NOT import audit_targets — audit_targets imports it (lazily), so a
reverse import would create a cycle.
"""
import json
import os
import re
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.path.join(ROOT, "databases", "diff_audited.json")
DEFAULT_RETENTION_DAYS = 0  # keep-all; version-keyed entries self-supersede

_DATE_FMT = "%Y-%m-%d"


def _today():
    return datetime.now().strftime(_DATE_FMT)


def _norm_pair(slug, version):
    """Canonical (slug, version) with slug lower-cased/trimmed and version trimmed,
    or None if either part is missing."""
    slug = (slug or "").strip().lower()
    version = (version or "").strip()
    if not slug or not version:
        return None
    return slug, version


def _pair_key(slug, version):
    return f"{slug}@{version}"


def _coerce_pairs(pairs):
    """Normalize input into an ordered de-duped list of (slug, version) tuples.

    Accepts: a single "slug@version" str; a comma/space-separated str of them; an
    iterable of "slug@version" strs; or an iterable of {"slug","version"} dicts.
    Tokens without an '@' (or with an empty half) are dropped."""
    if pairs is None:
        return []
    if isinstance(pairs, str):
        items = re.split(r"[,\s]+", pairs)
    elif isinstance(pairs, dict):
        items = [pairs]
    else:
        items = list(pairs)

    out, seen = [], set()
    for item in items:
        if item is None:
            continue
        if isinstance(item, dict):
            np = _norm_pair(item.get("slug"), item.get("version"))
        else:
            tok = str(item).strip()
            if "@" not in tok:
                continue
            slug, _, version = tok.partition("@")
            np = _norm_pair(slug, version)
        if not np:
            continue
        key = _pair_key(*np)
        if key not in seen:
            seen.add(key)
            out.append(np)
    return out


def load_ledger():
    """Return the ledger dict, tolerant of a missing/corrupt file (never raises)."""
    try:
        with open(LEDGER, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"version": 1, "entries": []}
    if not isinstance(data, dict):
        return {"version": 1, "entries": []}
    entries = data.get("entries")
    if not isinstance(entries, list):
        entries = []
    return {
        "version": data.get("version", 1),
        "entries": [e for e in entries
                    if isinstance(e, dict) and _norm_pair(e.get("slug"), e.get("version"))],
    }


def _prune(entries, retention_days):
    """Drop entries older than retention_days. retention_days <= 0 means keep all.
    Undated / unparseable entries are kept (fail safe)."""
    if not retention_days or retention_days <= 0:
        return list(entries)
    cutoff = datetime.now() - timedelta(days=retention_days)
    kept = []
    for e in entries:
        try:
            dt = datetime.strptime((e.get("marked") or "")[:10], _DATE_FMT)
        except ValueError:
            kept.append(e)
            continue
        if dt >= cutoff:
            kept.append(e)
    return kept


def save_ledger(data):
    """Atomically write the ledger."""
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    tmp = LEDGER + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, LEDGER)


def audited_pairs(retention_days=DEFAULT_RETENTION_DAYS):
    """Set of live "slug@version" keys. Prunes on read and persists the trimmed ledger
    (only when retention actually removed something) so the file self-maintains."""
    data = load_ledger()
    kept = _prune(data["entries"], retention_days)
    if len(kept) != len(data["entries"]):
        data["entries"] = kept
        try:
            save_ledger(data)
        except OSError:
            pass
    out = set()
    for e in kept:
        np = _norm_pair(e.get("slug"), e.get("version"))
        if np:
            out.add(_pair_key(*np))
    return out


def mark_diff_audited(pairs, source="manual", retention_days=DEFAULT_RETENTION_DAYS):
    """Add slug@version pair(s) to the ledger (idempotent, deduped by key). `pairs` may
    be a str, a comma/space-separated str, an iterable of "slug@version", or an iterable
    of {"slug","version"} dicts. Returns the list of newly-added "slug@version" keys."""
    norm = _coerce_pairs(pairs)
    if not norm:
        return []
    data = load_ledger()
    data["entries"] = _prune(data["entries"], retention_days)
    have = set()
    for e in data["entries"]:
        np = _norm_pair(e.get("slug"), e.get("version"))
        if np:
            have.add(_pair_key(*np))
    today = _today()
    added = []
    for slug, version in norm:
        key = _pair_key(slug, version)
        if key in have:
            continue
        data["entries"].append({
            "slug": slug, "version": version, "marked": today, "source": source,
        })
        have.add(key)
        added.append(key)
    if added:
        save_ledger(data)
    return added


def forget(pairs, retention_days=DEFAULT_RETENTION_DAYS):
    """Remove slug@version pair(s) from the ledger. Returns the keys actually removed."""
    ids = {_pair_key(s, v) for s, v in _coerce_pairs(pairs)}
    if not ids:
        return []
    data = load_ledger()
    before = data["entries"]
    kept = []
    removed = []
    for e in before:
        np = _norm_pair(e.get("slug"), e.get("version"))
        key = _pair_key(*np) if np else None
        if key in ids:
            removed.append(key)
        else:
            kept.append(e)
    if removed:
        data["entries"] = _prune(kept, retention_days)
        save_ledger(data)
    return sorted(set(removed))


# --------------------------------------------------------------------------- #
# Harvest ticked leads from an existing targets.md (Section A)
# --------------------------------------------------------------------------- #
_SEC_A_RE = re.compile(r"^##\s+A\.", re.IGNORECASE)
_SEC_ANY_RE = re.compile(r"^##\s+[A-Za-z]\.", re.IGNORECASE)
# Section-A item: "- [x] <slug>  (<n> installs)  <old> → <new>  ...". Capture slug and
# the post-arrow (new / audited) version. Arrow is U+2192, as emitted by render_targets_md.
_A_LINE_RE = re.compile(r"^\s*[-*]\s*\[x\]\s+(\S+).*?→\s*(\S+)")


def harvest_from_targets(path):
    """Scan Section A of an existing targets.md for ticked (`- [x]`) items and return a
    list of {"slug","version"} dicts (version = the post-arrow / newly-audited version).
    Only lines inside the `## A.` section are read, so ticks in sections B/C can never be
    mis-harvested. Missing/unreadable file -> []."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    in_a = False
    for line in lines:
        if _SEC_ANY_RE.match(line):
            in_a = bool(_SEC_A_RE.match(line))
            continue
        if not in_a:
            continue
        m = _A_LINE_RE.match(line)
        if m:
            np = _norm_pair(m.group(1), m.group(2))
            if np:
                out.append({"slug": np[0], "version": np[1]})
    return out


# --------------------------------------------------------------------------- #
# Small standalone CLI (daily_targets.py provides the primary interface)
# --------------------------------------------------------------------------- #
def main():
    import argparse
    ap = argparse.ArgumentParser(description="Inspect/edit the diff-audited (Section-A) ledger.")
    ap.add_argument("--list", action="store_true", help="print the current ledger")
    ap.add_argument("--mark", action="append", default=[], metavar="SLUG@VERSION",
                    help="mark slug@version pair(s) diff-audited (repeatable; comma/space-separated ok)")
    ap.add_argument("--forget", action="append", default=[], metavar="SLUG@VERSION",
                    help="remove slug@version pair(s) from the ledger (repeatable)")
    ap.add_argument("--harvest", metavar="TARGETS_MD",
                    help="harvest ticked Section-A items from a targets.md into the ledger")
    ap.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS)
    args = ap.parse_args()

    if args.mark:
        print("marked:", ", ".join(mark_diff_audited(args.mark, source="manual",
                                                      retention_days=args.retention_days)) or "(none new)")
    if args.forget:
        print("forgot:", ", ".join(forget(args.forget, retention_days=args.retention_days)) or "(none)")
    if args.harvest:
        harvested = harvest_from_targets(args.harvest)
        added = mark_diff_audited(harvested, source="harvest", retention_days=args.retention_days)
        print(f"harvested {len(harvested)} ticked item(s); {len(added)} new: "
              + (", ".join(added) if added else "(none new)"))
    if args.list or not (args.mark or args.forget or args.harvest):
        data = load_ledger()
        entries = _prune(data["entries"], args.retention_days)
        print(f"[diff_audited_ledger] {len(entries)} live entr(y/ies) in {LEDGER}")
        for e in sorted(entries, key=lambda x: x.get("marked", ""), reverse=True):
            print(f"  {_pair_key(e.get('slug'), e.get('version')):<40}  "
                  f"{e.get('marked')}  ({e.get('source')})")


if __name__ == "__main__":
    main()
