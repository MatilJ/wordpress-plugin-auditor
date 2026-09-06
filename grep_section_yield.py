#!/usr/bin/env python3
"""grep_section_yield.py — per-section hit-volume + TP yield for grep sections.

The pattern-accumulator DB records ``grep_section`` on confirmed findings only,
so it cannot answer "which grep sections fire a lot but never catch a real bug?"
— the signal needed to prune dead sections from ``grep_scan.py``. This script
supplies that missing signal by reading the on-disk grep output that every audit
writes to ``audit/<slug>/<version>/grep/*.md`` and aggregating, per section:

  * hits        — total ``- ``-prefixed result lines across all audits
  * audits      — distinct audits in which the section fired at least once
  * tp          — confirmed findings attributed to the section in the DB
                  (comma-split ``findings.grep_section``, TP status only)

It then classifies every section defined in ``grep_scan.SECTIONS``:

  NEVER_HIT          defined but 0 hits across every audit  -> dead weight
  HIGH_NOISE_NO_TP   hits >= --min-hits over >= --min-audits, 0 TP -> prune
  LOW_VOLUME         a few hits, 0 TP, below the noise bar -> monitor
  PRODUCTIVE         >= 1 TP -> keep

Read-only. Prune decisions stay human-reviewed (mirrors the accumulator
dashboard's Block 4). Pair with the removal procedure in
docs/accumulator-playbook.md (delete from both SECTIONS and GROUP_SECTION_ORDER).
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

import grep_scan

SCRIPT_DIR = Path(__file__).resolve().parent
AUDIT_DIR = SCRIPT_DIR / "audit"
DB_PATH = SCRIPT_DIR / "databases" / "pattern_accumulator.db"

HEADER_RE = re.compile(r"^## \[([A-Z0-9_]+)\]\s*$")


def parse_grep_file(path: Path) -> dict[str, int]:
    """Return {section_name: hit_count} for one grep results markdown file.

    Only sections with >=1 hit are present in the file (grep_scan skips empty
    sections). Hits are ``- ``-prefixed lines; overflow markers start with ``[+``
    and are naturally excluded.
    """
    counts: dict[str, int] = defaultdict(int)
    current: str | None = None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return counts
    for line in text.splitlines():
        m = HEADER_RE.match(line)
        if m:
            current = m.group(1)
            counts.setdefault(current, 0)
        elif current and line.startswith("- "):
            counts[current] += 1
    return counts


def collect_disk_stats() -> tuple[dict[str, int], dict[str, set[str]]]:
    """Walk every audit's grep/*.md; return (hits_per_section, audits_per_section)."""
    hits: dict[str, int] = defaultdict(int)
    audits: dict[str, set[str]] = defaultdict(set)
    for md in AUDIT_DIR.rglob("grep/*.md"):
        # audit key = the <slug>/<version> segment above grep/
        try:
            audit_key = md.relative_to(AUDIT_DIR).parts[0:2]
            audit_id = "/".join(audit_key)
        except ValueError:
            audit_id = str(md.parent)
        for section, n in parse_grep_file(md).items():
            if n > 0:
                hits[section] += n
                audits[section].add(audit_id)
    return hits, audits


def collect_db_tp() -> dict[str, int]:
    """Return {section_name: TP-finding count} from the accumulator DB.

    findings.grep_section is comma-joined (a finding can match several sections)
    and populated on findings only, so this is a conservative TP signal.
    """
    tp: dict[str, int] = defaultdict(int)
    if not DB_PATH.exists():
        return tp
    conn = sqlite3.connect(str(DB_PATH))
    try:
        rows = conn.execute(
            "SELECT grep_section FROM findings "
            "WHERE status='TP' AND grep_section IS NOT NULL AND TRIM(grep_section) != ''"
        ).fetchall()
    finally:
        conn.close()
    for (gs,) in rows:
        for sec in gs.split(","):
            sec = sec.strip()
            if sec:
                tp[sec] += 1
    return tp


def classify(hits: int, audits: int, tp: int, min_hits: int, min_audits: int) -> str:
    if tp > 0:
        return "PRODUCTIVE"
    if hits == 0:
        return "NEVER_HIT"
    if hits >= min_hits and audits >= min_audits:
        return "HIGH_NOISE_NO_TP"
    return "LOW_VOLUME"


def build(min_hits: int, min_audits: int) -> list[dict]:
    disk_hits, disk_audits = collect_disk_stats()
    db_tp = collect_db_tp()
    sec_group = {name: meta.get("group") for name, meta in grep_scan.SECTIONS.items()}

    # Sections that show up on disk but are no longer defined (renamed/removed)
    # are reported too, so drift is visible rather than silently dropped.
    all_sections = set(sec_group) | set(disk_hits) | set(db_tp)

    rows = []
    for name in all_sections:
        hits = disk_hits.get(name, 0)
        audits = len(disk_audits.get(name, ()))
        tp = db_tp.get(name, 0)
        rows.append({
            "section": name,
            "group": sec_group.get(name),
            "defined": name in sec_group,
            "hits": hits,
            "audits": audits,
            "tp": tp,
            "verdict": classify(hits, audits, tp, min_hits, min_audits),
        })
    rows.sort(key=lambda r: (r["tp"], r["hits"], r["audits"]), reverse=True)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-hits", type=int, default=30,
                    help="hit floor for HIGH_NOISE_NO_TP prune candidates (default 30)")
    ap.add_argument("--min-audits", type=int, default=5,
                    help="distinct-audit floor for HIGH_NOISE_NO_TP (default 5)")
    ap.add_argument("--format", choices=["table", "json"], default="table")
    ap.add_argument("--prune-only", action="store_true",
                    help="show only NEVER_HIT and HIGH_NOISE_NO_TP candidates")
    args = ap.parse_args()

    rows = build(args.min_hits, args.min_audits)

    if args.prune_only:
        rows = [r for r in rows if r["verdict"] in ("NEVER_HIT", "HIGH_NOISE_NO_TP")]

    if args.format == "json":
        print(json.dumps({"min_hits": args.min_hits, "min_audits": args.min_audits,
                          "sections": rows}, indent=2))
        return 0

    from collections import Counter
    tally = Counter(r["verdict"] for r in build(args.min_hits, args.min_audits))
    print("=" * 74)
    print("GREP SECTION YIELD  (hits from audit/*/*/grep/*.md, TP from accumulator DB)")
    print(f"thresholds: HIGH_NOISE_NO_TP = hits>={args.min_hits} over >={args.min_audits} audits")
    print("=" * 74)
    print(f"defined sections: {len(grep_scan.SECTIONS)}   "
          f"PRODUCTIVE {tally['PRODUCTIVE']} | HIGH_NOISE_NO_TP {tally['HIGH_NOISE_NO_TP']} | "
          f"LOW_VOLUME {tally['LOW_VOLUME']} | NEVER_HIT {tally['NEVER_HIT']}")
    print()
    print(f"{'section':<40}{'grp':<10}{'hits':>7}{'aud':>5}{'TP':>5}  verdict")
    print("-" * 74)
    for r in rows:
        flag = "" if r["defined"] else " (UNDEFINED/drift)"
        grp = (r["group"] or "-")[:9]
        print(f"{r['section']:<40}{grp:<10}{r['hits']:>7}{r['audits']:>5}{r['tp']:>5}  "
              f"{r['verdict']}{flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
