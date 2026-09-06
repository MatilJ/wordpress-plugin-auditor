#!/usr/bin/env python3
"""
analyzed_ledger.py - persistent record of Wordfence variant CVEs already analyzed.

targets.md (Section B, Edge 2) lists fresh Wordfence disclosures to variant-analyze.
targets.md itself is overwritten every run and keeps no history, so this module is the
durable, accumulating memory that lets daily_targets.py suppress a variant CVE once it
has been analyzed. It is a separate file from targets.md and is never reset on
regeneration, so regenerating the briefing several times a day is safe.

Storage: databases/analyzed_variants.json
  {"version": 1,
   "entries": [{"cve": "CVE-2026-12345", "slug": "some-plugin",
                "marked": "YYYY-MM-DD", "source": "harvest"|"manual"}]}

A CVE enters the ledger two ways (both wired in daily_targets.py):
  - auto-harvest: ticked `- [x]` lines in Section B of the previous targets.md
  - manual:       --mark-analyzed CVE-2026-12345

Entries older than the retention window (default 90 days) are pruned on read/write so
the file stays small; the window has headroom over the default 14-day feed window and
most deeper `--since` runs. Bump it with --analyzed-retention-days for a wide historical
run. The dedup key is the CVE id (uppercased); slug is stored as metadata only.
"""
import json
import os
import re
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.path.join(ROOT, "databases", "analyzed_variants.json")
DEFAULT_RETENTION_DAYS = 90

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_DATE_FMT = "%Y-%m-%d"


def _today():
    return datetime.now().strftime(_DATE_FMT)


def _norm_cve(cve):
    """Uppercase, trimmed CVE id found in `cve`, or None if none is present."""
    if not cve:
        return None
    m = _CVE_RE.search(str(cve))
    return m.group(0).upper() if m else None


def _coerce_cves(cves):
    """Normalize a str / comma-or-space list / iterable into an ordered de-duped list
    of canonical CVE ids. Non-CVE tokens are dropped."""
    if cves is None:
        return []
    if isinstance(cves, str):
        raw = re.split(r"[,\s]+", cves)
    else:
        raw = []
        for item in cves:
            if item is None:
                continue
            raw.extend(re.split(r"[,\s]+", str(item)))
    out, seen = [], set()
    for tok in raw:
        cve = _norm_cve(tok)
        if cve and cve not in seen:
            seen.add(cve)
            out.append(cve)
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
        "entries": [e for e in entries if isinstance(e, dict) and _norm_cve(e.get("cve"))],
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


def analyzed_cves(retention_days=DEFAULT_RETENTION_DAYS):
    """Set of non-expired analyzed CVE ids (uppercased). Prunes on read and persists the
    trimmed ledger so the file self-maintains."""
    data = load_ledger()
    kept = _prune(data["entries"], retention_days)
    if len(kept) != len(data["entries"]):
        data["entries"] = kept
        try:
            save_ledger(data)
        except OSError:
            pass
    return {_norm_cve(e.get("cve")) for e in kept if _norm_cve(e.get("cve"))}


def mark_analyzed(cves, source="manual", slug_by_cve=None,
                  retention_days=DEFAULT_RETENTION_DAYS):
    """Add CVE id(s) to the ledger (idempotent, deduped by id). `cves` may be a str, a
    comma/space-separated str, or an iterable. Returns the list of newly-added CVEs."""
    ids = _coerce_cves(cves)
    if not ids:
        return []
    data = load_ledger()
    data["entries"] = _prune(data["entries"], retention_days)
    have = {_norm_cve(e.get("cve")) for e in data["entries"]}
    slug_by_cve = slug_by_cve or {}
    today = _today()
    added = []
    for cve in ids:
        if cve in have:
            continue
        data["entries"].append({
            "cve": cve, "slug": slug_by_cve.get(cve),
            "marked": today, "source": source,
        })
        have.add(cve)
        added.append(cve)
    if added:
        save_ledger(data)
    return added


def forget(cves, retention_days=DEFAULT_RETENTION_DAYS):
    """Remove CVE id(s) from the ledger. Returns the list actually removed."""
    ids = set(_coerce_cves(cves))
    if not ids:
        return []
    data = load_ledger()
    before = data["entries"]
    present = {_norm_cve(e.get("cve")) for e in before} & ids
    kept = [e for e in before if _norm_cve(e.get("cve")) not in ids]
    if len(kept) != len(before):
        data["entries"] = _prune(kept, retention_days)
        save_ledger(data)
    return sorted(present)


# --------------------------------------------------------------------------- #
# Harvest ticked leads from an existing targets.md
# --------------------------------------------------------------------------- #
_SEC_B_RE = re.compile(r"^##\s+B\.", re.IGNORECASE)
_SEC_ANY_RE = re.compile(r"^##\s+[A-Za-z]\.", re.IGNORECASE)
_GROUP_RE = re.compile(r"^###\s+(\S+)")
_CHECKED_RE = re.compile(r"^\s*[-*]\s*\[x\]", re.IGNORECASE)
_FLAT_SLUG_RE = re.compile(r"\*\*([^*]+)\*\*")


def harvest_from_targets(path):
    """Scan Section B of an existing targets.md for ticked (`- [x]`) leads and return a
    list of {"cve", "slug"} dicts. Only lines inside the `## B.` section are read, so
    ticks in sections A/C can never be mis-harvested. Missing/unreadable file -> []."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    in_b = False
    cur_slug = None
    for line in lines:
        if _SEC_ANY_RE.match(line):
            in_b = bool(_SEC_B_RE.match(line))
            cur_slug = None
            continue
        if not in_b:
            continue
        gm = _GROUP_RE.match(line)
        if gm:
            cur_slug = gm.group(1)
            continue  # a group heading is never itself a checked lead line
        if _CHECKED_RE.match(line):
            # A flat singleton lead carries its own **slug** (authoritative for that
            # line); a grouped lead has no bold slug and inherits the group heading.
            fm = _FLAT_SLUG_RE.search(line)
            slug = fm.group(1).strip() if fm else cur_slug
            for m in _CVE_RE.finditer(line):
                out.append({"cve": m.group(0).upper(), "slug": slug})
    return out


# --------------------------------------------------------------------------- #
# Small standalone CLI (daily_targets.py provides the primary interface)
# --------------------------------------------------------------------------- #
def main():
    import argparse
    ap = argparse.ArgumentParser(description="Inspect/edit the analyzed-CVE ledger.")
    ap.add_argument("--list", action="store_true", help="print the current ledger")
    ap.add_argument("--mark", action="append", default=[], metavar="CVE",
                    help="mark CVE id(s) analyzed (repeatable; comma-separated ok)")
    ap.add_argument("--forget", action="append", default=[], metavar="CVE",
                    help="remove CVE id(s) from the ledger (repeatable)")
    ap.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS)
    args = ap.parse_args()

    if args.mark:
        print("marked:", ", ".join(mark_analyzed(args.mark, source="manual",
                                                  retention_days=args.retention_days)) or "(none new)")
    if args.forget:
        print("forgot:", ", ".join(forget(args.forget, retention_days=args.retention_days)) or "(none)")
    if args.list or not (args.mark or args.forget):
        data = load_ledger()
        entries = _prune(data["entries"], args.retention_days)
        print(f"[analyzed_ledger] {len(entries)} live entr(y/ies) in {LEDGER}")
        for e in sorted(entries, key=lambda x: x.get("marked", ""), reverse=True):
            print(f"  {e.get('cve')}  {e.get('slug') or '-':<28}  "
                  f"{e.get('marked')}  ({e.get('source')})")


if __name__ == "__main__":
    main()
