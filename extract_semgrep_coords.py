#!/usr/bin/env python3
"""Extract Semgrep coordinates from JSON output and write tier-filtered files.

Usage: python extract_semgrep_coords.py <semgrep_json_path> <plugin_base_path> <output_dir>

Outputs:
  <output_dir>/semgrep-coordinates.txt   — one relative/path.php:line per entry
  <output_dir>/semgrep-group-a.md        — Tier 1-2 (RCE, file ops, deserialization)
  <output_dir>/semgrep-group-ab.md       — Auth Bypass (CWE-287/288)
  <output_dir>/semgrep-group-ac.md       — Access Control (missing-auth, IDOR, CSRF)
  <output_dir>/semgrep-group-sqli.md     — SQL Injection (Tier 3)
  <output_dir>/semgrep-group-c.md        — Tier 5-6 (XSS, HTML renderers)
  <output_dir>/semgrep-group-d1.md       — Tier 8-10 (SSRF, Email, Info Disclosure)
  <output_dir>/semgrep-unclassified.md   — remaining rules (incl. any race/adversarial;
                                           Group adv collapsed)
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# Group taxonomy is centralised in group_registry.py — the single source of truth shared
# by grep_scan.py / extract_semgrep_coords.py / pattern_accumulator.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import group_registry

# PRIORITY_OVERRIDES resolve auth-bypass/idor/info-disc ahead of the broader
# RULE_GROUP_MAP; classify_rule() then returns the FIRST matching group in RULE_GROUP_MAP
# insertion order (b-derived sqli/ac before e-derived ab, so an access-control rule that
# also matches a loose auth pattern still lands in ac, not ab). Definitions live in the
# registry so the semgrep, grep and accumulator layers cannot drift apart.
PRIORITY_OVERRIDES = group_registry.semgrep_priority_overrides()
RULE_GROUP_MAP = group_registry.semgrep_rule_group_map()


def classify_rule(check_id: str) -> str:
    rule_lower = check_id.lower()
    for pattern, group in PRIORITY_OVERRIDES:
        if re.search(pattern, rule_lower):
            return group
    for group, patterns in RULE_GROUP_MAP.items():
        for pattern in patterns:
            if re.search(pattern, rule_lower):
                return group
    return "unclassified"


def make_relative(path: str, base: str) -> str:
    try:
        return str(Path(path).relative_to(Path(base)))
    except ValueError:
        norm_path = os.path.normpath(path).replace("\\", "/")
        norm_base = os.path.normpath(base).replace("\\", "/")
        if norm_path.startswith(norm_base):
            rel = norm_path[len(norm_base) :]
            return rel.lstrip("/\\")
        return path


def parse_semgrep_json(json_path: str) -> list:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    if not results and isinstance(data, list):
        results = data

    entries = []
    for result in results:
        check_id = result.get("check_id", result.get("rule_id", "unknown"))
        path = result.get("path", "")
        start = result.get("start", {})
        end = result.get("end", {})
        line = start.get("line", 0)
        end_line = end.get("line", line)
        severity = result.get("extra", {}).get("severity", "WARNING")
        message = result.get("extra", {}).get("message", "")
        if not message:
            message = result.get("extra", {}).get("metadata", {}).get("message", "")

        entries.append(
            {
                "check_id": check_id,
                "path": path,
                "line": line,
                "end_line": end_line,
                "severity": severity,
                "message": message[:200],
            }
        )

    return entries


def write_group_file(output_dir: str, group: str, entries: list, base_path: str):
    if group == "unclassified":
        filename = "semgrep-unclassified.md"
    else:
        filename = f"semgrep-group-{group}.md"

    filepath = os.path.join(output_dir, filename)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    entries.sort(key=lambda e: (severity_order.get(e["severity"], 3), e["path"], e["line"]))

    with open(filepath, "w", encoding="utf-8") as f:
        group_labels = group_registry.semgrep_group_labels()
        f.write(f"# Semgrep Leads — {group_labels.get(group, group)}\n\n")
        f.write(f"Total: {len(entries)} finding(s)\n\n")

        by_rule = defaultdict(list)
        for entry in entries:
            by_rule[entry["check_id"]].append(entry)

        for rule_id, rule_entries in by_rule.items():
            f.write(f"## {rule_id} ({len(rule_entries)} hit(s))\n")
            if rule_entries[0]["message"]:
                f.write(f"> {rule_entries[0]['message']}\n\n")
            else:
                f.write("\n")
            for e in rule_entries:
                rel_path = make_relative(e["path"], base_path)
                f.write(f"- `{rel_path}:{e['line']}` [{e['severity']}]\n")
            f.write("\n")


def main():
    if len(sys.argv) < 4:
        print("Usage: python extract_semgrep_coords.py <semgrep_json> <plugin_base_path> <output_dir>")
        sys.exit(1)

    json_path = sys.argv[1]
    base_path = sys.argv[2]
    output_dir = sys.argv[3]

    if not os.path.isfile(json_path):
        print(f"Error: Semgrep JSON not found: {json_path}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    entries = parse_semgrep_json(json_path)

    coords_path = os.path.join(output_dir, "semgrep-coordinates.txt")
    seen_coords = set()
    with open(coords_path, "w", encoding="utf-8") as f:
        for entry in entries:
            rel_path = make_relative(entry["path"], base_path)
            coord = f"{rel_path}:{entry['line']}"
            if coord not in seen_coords:
                seen_coords.add(coord)
                f.write(coord + "\n")

    grouped = defaultdict(list)
    for entry in entries:
        group = classify_rule(entry["check_id"])
        grouped[group].append(entry)

    for group in group_registry.semgrep_write_order():
        write_group_file(output_dir, group, grouped.get(group, []), base_path)

    if grouped.get("unclassified"):
        unclassified_rules = set(e["check_id"] for e in grouped["unclassified"])
        for rule in sorted(unclassified_rules):
            print(f"  WARN: unclassified rule: {rule}", file=sys.stderr)
        unclassified_high = [e for e in grouped["unclassified"]
                             if e.get("severity", "").upper() in ("CRITICAL", "HIGH", "ERROR")]
        if unclassified_high:
            print(f"  WARNING: {len(unclassified_high)} CRITICAL/HIGH severity "
                  f"unclassified finding(s) — review semgrep-unclassified.md")

    total = len(entries)
    print(f"SEMGREP_EXTRACT_COMPLETE")
    print(f"  Input: {json_path}")
    print(f"  Coordinates: {len(seen_coords)} unique file:line pairs")
    for group in group_registry.semgrep_write_order():
        print(f"  {group_registry.semgrep_short_label(group)}: {len(grouped.get(group, []))} hits")
    print(f"  Total: {total} findings")


if __name__ == "__main__":
    main()
