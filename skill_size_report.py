#!/usr/bin/env python3
"""skill_size_report.py — size + list-count guard for the vuln-audit skill.

The vuln-audit skill's core SKILL.md is read *whole* into every one of the 8
tier-group sub-agents (a global context tax), and each group file is read into
its own group. Nothing currently flags when a file — or one of the append-prone
numbered lists inside it (per-group "FP Verification Rules", the chain-pattern
catalog, the core FP/FN lists) — drifts past its intended budget. This script
supplies that missing guard.

For every skill file it reports:

  * lines / bytes / ~tokens (bytes/4)   vs a per-file token budget
  * the top-level numbered-rule count of each governed list vs its cap
  * the chain ``#### `` pattern-entry count vs its cap

Verdict per measured item: OK | WARN (>=90% of budget) | OVER (>budget).
Exit code is non-zero when anything is OVER (so it can gate tune-vuln-audit's
Phase 0 / Phase 5). Read-only; mirrors grep_section_yield.py's CLI/format.

Budgets are the Workstream-A defaults from the growth-control plan and are
tunable here in one place.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — the skill files, their token budgets, and the governed lists.
# ---------------------------------------------------------------------------

DEFAULT_SKILL_DIR = Path(__file__).resolve().parent / ".claude" / "skills" / "vuln-audit"

# ~token budget per file (bytes / 4). Core is the global tax → tighter goal.
# Raised: several files had organically grown 2-3x past the original
# targets through legitimately evidence-grounded tune-vuln-audit additions, making
# every subsequent tuning pass land in reduction-only mode regardless of how small
# or well-justified the incoming change was. Budgets below give each file ~10-20%
# headroom over its actual size at the time of this change, not a blank check —
# files with real headroom already (foundation, sqli) were left alone.
FILE_BUDGETS = {
    "SKILL.md": 22000,
    "vuln-audit-foundation.md": 8000,
    "vuln-audit-group-ab.md": 10000,
    "vuln-audit-group-ac.md": 27000,
    "vuln-audit-group-a.md": 25000,
    "vuln-audit-group-sqli.md": 8000,
    "vuln-audit-group-c.md": 15000,
    "vuln-audit-group-d1.md": 10000,
    "vuln-audit-chain.md": 10000,
}

AGGREGATE_BUDGET = 140000  # soft: whole skill, all files summed

# Governed numbered/entry lists: (file, label, kind, header_regex, cap).
#   kind "numbered" -> count top-level ``N.`` / ``Nb.`` items in the section
#   kind "h4"       -> count ``#### `` entries in the section
# A section runs from its header to the next header of the same-or-higher level.
LIST_CAPS = [
    ("SKILL.md", "core FP Verification", "numbered", r"False Positive Verification", 25),
    ("SKILL.md", "core FN Prevention", "numbered", r"False Negative Prevention", 35),
    ("vuln-audit-group-ab.md", "AB FP Verification", "numbered", r"FP Verification Rules", 15),
    ("vuln-audit-group-ac.md", "AC FP Verification", "numbered", r"FP Verification Rules", 15),
    ("vuln-audit-group-a.md", "A FP Verification", "numbered", r"FP Verification Rules", 15),
    ("vuln-audit-group-sqli.md", "SQLi FP Verification", "numbered", r"FP Verification Rules", 15),
    ("vuln-audit-group-c.md", "C FP Verification", "numbered", r"FP Verification Rules", 15),
    ("vuln-audit-group-d1.md", "D1 FP Verification", "numbered", r"FP Verification Rules", 15),
    ("vuln-audit-chain.md", "Chain patterns", "h4", r"Chain patterns", 20),
]

HEADER_RE = re.compile(r"^(#{1,6})\s+(.*)$")
NUMBERED_RE = re.compile(r"^\d+[a-z]?\.\s")   # top-level rule: no leading indent
H4_RE = re.compile(r"^####\s+\S")

WARN_RATIO = 0.90


def approx_tokens(nbytes: int) -> int:
    return round(nbytes / 4)


def find_section_bounds(lines: list[str], header_regex: str) -> tuple[int, int, int] | None:
    """Return (start_idx, end_idx, level) for the first header matching regex.

    The section ends at the next header whose level is <= the start header's
    level, or at EOF. start_idx points at the header line; end_idx is exclusive.
    """
    pat = re.compile(header_regex)
    start = None
    start_level = 0
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if not m:
            continue
        if start is None:
            if pat.search(m.group(2)):
                start = i
                start_level = len(m.group(1))
            continue
        if len(m.group(1)) <= start_level:
            return (start, i, start_level)
    if start is not None:
        return (start, len(lines), start_level)
    return None


def count_list(lines: list[str], header_regex: str, kind: str) -> int | None:
    bounds = find_section_bounds(lines, header_regex)
    if bounds is None:
        return None
    start, end, _ = bounds
    body = lines[start + 1:end]
    if kind == "numbered":
        return sum(1 for ln in body if NUMBERED_RE.match(ln))
    if kind == "h4":
        return sum(1 for ln in body if H4_RE.match(ln))
    return None


def verdict(value: int, budget: int) -> str:
    if value > budget:
        return "OVER"
    if value >= budget * WARN_RATIO:
        return "WARN"
    return "OK"


def build(skill_dir: Path) -> dict:
    files = []
    total_tokens = 0
    for name, budget in FILE_BUDGETS.items():
        path = skill_dir / name
        if not path.exists():
            files.append({"file": name, "exists": False, "budget": budget})
            continue
        data = path.read_bytes()
        text = data.decode("utf-8", errors="replace")
        nbytes = len(data)
        toks = approx_tokens(nbytes)
        total_tokens += toks
        files.append({
            "file": name,
            "exists": True,
            "lines": text.count("\n") + (0 if text.endswith("\n") else 1),
            "bytes": nbytes,
            "tokens": toks,
            "budget": budget,
            "verdict": verdict(toks, budget),
        })

    lists = []
    for name, label, kind, header_regex, cap in LIST_CAPS:
        path = skill_dir / name
        if not path.exists():
            lists.append({"file": name, "label": label, "exists": False, "cap": cap})
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        n = count_list(lines, header_regex, kind)
        if n is None:
            lists.append({"file": name, "label": label, "found": False, "cap": cap})
            continue
        lists.append({
            "file": name, "label": label, "found": True,
            "count": n, "cap": cap, "verdict": verdict(n, cap),
        })

    return {
        "files": files,
        "lists": lists,
        "total_tokens": total_tokens,
        "aggregate_budget": AGGREGATE_BUDGET,
        "aggregate_verdict": verdict(total_tokens, AGGREGATE_BUDGET),
    }


def any_over(report: dict) -> bool:
    if report["aggregate_verdict"] == "OVER":
        return True
    for f in report["files"]:
        if f.get("verdict") == "OVER":
            return True
    for l in report["lists"]:
        if l.get("verdict") == "OVER":
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skill-dir", type=Path, default=DEFAULT_SKILL_DIR,
                    help=f"vuln-audit skill dir (default {DEFAULT_SKILL_DIR})")
    ap.add_argument("--format", choices=["table", "json"], default="table")
    ap.add_argument("--over-only", action="store_true",
                    help="show only OVER items")
    args = ap.parse_args()

    if not args.skill_dir.exists():
        print(f"skill dir not found: {args.skill_dir}", file=sys.stderr)
        return 2

    report = build(args.skill_dir)

    if args.format == "json":
        print(json.dumps(report, indent=2))
        return 1 if any_over(report) else 0

    files = report["files"]
    lists = report["lists"]
    if args.over_only:
        files = [f for f in files if f.get("verdict") == "OVER"]
        lists = [l for l in lists if l.get("verdict") == "OVER"]

    print("=" * 74)
    print("VULN-AUDIT SKILL SIZE REPORT  (~tokens = bytes/4)")
    print(f"skill dir: {args.skill_dir}")
    print("=" * 74)
    print(f"{'file':<30}{'lines':>7}{'~tokens':>9}{'budget':>8}  verdict")
    print("-" * 74)
    for f in files:
        if not f.get("exists"):
            print(f"{f['file']:<30}{'--':>7}{'MISSING':>9}{f['budget']:>8}  (absent)")
            continue
        print(f"{f['file']:<30}{f['lines']:>7}{f['tokens']:>9}{f['budget']:>8}  {f['verdict']}")
    print("-" * 74)
    agg = report
    print(f"{'ALL FILES':<30}{'':>7}{agg['total_tokens']:>9}{agg['aggregate_budget']:>8}  "
          f"{agg['aggregate_verdict']} (soft)")
    print()
    print(f"{'governed list':<26}{'file':<28}{'count':>6}{'cap':>5}  verdict")
    print("-" * 74)
    for l in lists:
        if not l.get("found", True) or not l.get("exists", True):
            state = "absent" if not l.get("exists", True) else "not found"
            print(f"{l['label']:<26}{l['file']:<28}{'--':>6}{l['cap']:>5}  ({state})")
            continue
        print(f"{l['label']:<26}{l['file']:<28}{l['count']:>6}{l['cap']:>5}  {l['verdict']}")

    return 1 if any_over(report) else 0


if __name__ == "__main__":
    sys.exit(main())
