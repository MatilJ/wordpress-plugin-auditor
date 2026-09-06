#!/usr/bin/env python3
"""Single source of truth for the audit pipeline's group taxonomy.

Consumed by grep_scan.py, extract_semgrep_coords.py and pattern_accumulator.py so the
group set, per-layer casing, output filenames, display labels, tier membership, CWE map
and Semgrep rule-id classification live in ONE place instead of drifting across four
independent layers.

Casing note (historical, preserved deliberately for byte-identical output):
  - grep_scan.py            bucket keys use  "group-ab"   (grep_key)
  - extract_semgrep_coords  uses bare         "ab"        (id)
  - pattern_accumulator     uses code         "AB"        (code)
Each impact-group descriptor carries all three; callers pick the field they need.

Load-bearing ordering (do NOT reorder without re-validating byte-identical output):
  - IMPACT_ORDER            — grep GROUP_FILE_MAP order + semgrep write/print order.
  - SEMGREP_CLASSIFY_ORDER  — RULE_GROUP_MAP iteration order (b-derived groups sqli/ac
                              before the e-derived group ab), applied AFTER
                              SEMGREP_PRIORITY_OVERRIDES.
  - ACCUMULATOR_ORDER       — GROUP_LABELS / dashboard yield order.
  - VULN_TYPE_FALLBACKS     — vuln_group() keyword-fallback precedence.
"""

from collections import OrderedDict

# ---------------------------------------------------------------------------
# Impact-group descriptors (canonical file/display order)
# ---------------------------------------------------------------------------

# Canonical order for grep GROUP_FILE_MAP and semgrep write/print loops.
# Group 'adv' (race/adversarial) was collapsed: 0 lifetime TP under its
# own label — its findings reclassify to their impact type (draft-status IDOR -> AC).
# The adversarial methodology folded into the Group AC + Chain prompts; its two grep
# sections moved to group-ac. 'adv' was the last element of every order list, so its
# removal preserves byte-identical output for the surviving groups.
IMPACT_ORDER = ["a", "ab", "ac", "sqli", "c", "d1"]

# Accumulator display / dashboard order (GROUP_LABELS insertion order).
ACCUMULATOR_ORDER = ["ab", "ac", "a", "sqli", "c", "d1"]

# Semgrep RULE_GROUP_MAP iteration order — the b-derived groups (sqli, ac) come before
# the e-derived group (ab) so an access-control rule that also matches a loose auth
# pattern still lands in ac, not ab.
SEMGREP_CLASSIFY_ORDER = ["a", "sqli", "ac", "c", "d1", "ab"]

IMPACT_GROUPS = {
    "a": {
        "code": "A",
        "grep_key": "group-a",
        "semgrep_label": "Group A — Tier 1-2 (RCE, File Ops, Deserialization)",
        "accumulator_label": "Group A   (RCE/file/POI)",
        "cwes": ["CWE-94", "CWE-78", "CWE-434", "CWE-502", "CWE-22", "CWE-98", "CWE-73"],
        "semgrep_rule_patterns": [
            r"file-upload",
            r"unserialize",
            r"code-exec",
            r"file-",
            r"rce",
            r"deserialization",
            r"command-exec",
            r"arbitrary-file",
            r"file-inclusion",
            r"file-write-delete",
            r"ssti",
        ],
    },
    "ab": {
        "code": "AB",
        "grep_key": "group-ab",
        "semgrep_label": "Group AB — Auth Bypass (CWE-287/288)",
        "accumulator_label": "Group AB  (Auth Bypass)",
        "cwes": ["CWE-287", "CWE-288", "CWE-269"],
        "semgrep_rule_patterns": [
            r"auth-bypass",
            r"auth-token",
            r"loose-comparison.*auth",
            r"empty-secret",
            r"app-password",
            r"social-login",
            r"predictable.*token",
            r"jwt.*verify",
            r"strpos.*domain",
            r"domain-validation",
        ],
    },
    "ac": {
        "code": "AC",
        "grep_key": "group-ac",
        "semgrep_label": "Group AC — Access Control (Missing Auth, IDOR, CSRF, Options/Content Writes)",
        "accumulator_label": "Group AC  (Access Control: missing-auth/IDOR/CSRF)",
        "cwes": ["CWE-862", "CWE-639", "CWE-352", "CWE-863", "CWE-285", "CWE-345"],
        "semgrep_rule_patterns": [
            r"missing-capability",
            r"missing-nonce",
            r"csrf",
            r"missing-permission",
            r"broken-auth",
            r"missing-auth",
            r"access-control",
            r"\.auth\.",
            r"idor",
        ],
    },
    "sqli": {
        "code": "SQLi",
        "grep_key": "group-sqli",
        "semgrep_label": "Group SQLi — SQL Injection (Tier 3)",
        "accumulator_label": "Group SQLi",
        "cwes": ["CWE-89"],
        "semgrep_rule_patterns": [
            r"sql-injection",
            r"sqli\.",
        ],
    },
    "c": {
        "code": "C",
        "grep_key": "group-c",
        "semgrep_label": "Group C — Tier 5-6 (XSS, HTML Renderers)",
        "accumulator_label": "Group C   (XSS/HTML render)",
        "cwes": ["CWE-79"],
        "semgrep_rule_patterns": [
            r"xss",
            r"unescaped",
            r"missing-esc",
            r"block-attribute",
            r"stored-xss",
            r"reflected-xss",
        ],
    },
    "d1": {
        "code": "D1",
        "grep_key": "group-d1",
        "semgrep_label": "Group D1 — Tier 8-10 (SSRF, Email Injection, Info Disclosure)",
        "accumulator_label": "Group D1  (SSRF/info-disc/email)",
        "cwes": ["CWE-918", "CWE-200", "CWE-201", "CWE-209"],
        "semgrep_rule_patterns": [
            r"ssrf",
            r"wp-remote",
            r"email-injection",
            r"info-disclosure",
        ],
    },
    # Group 'adv' collapsed (0 lifetime TP) — see IMPACT_ORDER note.
}

# Meta groups that exist only in the grep layer (no semgrep slice, no accumulator code).
GREP_META_ORDER = ["surface", "foundation"]
GREP_META_FILES = {
    "surface": "surface-results.md",
    "foundation": "foundation-results.md",
}

UNCLASSIFIED_SEMGREP_LABEL = "Unclassified (review for all groups / chain analysis)"

# ---------------------------------------------------------------------------
# Semgrep classification (extract_semgrep_coords.py)
# ---------------------------------------------------------------------------

# Regex -> group id, evaluated BEFORE RULE_GROUP_MAP so auth-bypass/idor/race/info-disc
# rules resolve to their re-sliced group.
SEMGREP_PRIORITY_OVERRIDES = [
    (r"auth-bypass|auth-token|social-login|jwt.*verify|empty-secret|app-password|predictable.*token|domain-validation", "ab"),
    (r"idor", "ac"),
    (r"info-disclosure|ssrf|wp-remote|email-injection", "d1"),
]

# ---------------------------------------------------------------------------
# Accumulator vuln_type keyword fallbacks (pattern_accumulator.vuln_group)
# ---------------------------------------------------------------------------

# Evaluated in order, AFTER the CWE map; first group whose keyword set matches wins.
VULN_TYPE_FALLBACKS = [
    (["idor", "csrf", "missing auth", "authorization", "content deletion"], "AC"),
    (["xss", "cross-site scripting"], "C"),
    (["sql"], "SQLi"),
    (["ssrf", "information disclosure", "email", "disclosure"], "D1"),
    (["auth bypass", "authentication bypass", "privilege escalation"], "AB"),
    (["file upload", "file read", "file delet", "rce", "code execution",
      "code injection", "object injection", "traversal", "lfi", "rfi", "file inclusion"], "A"),
    # 'adv' collapsed — race/adversarial vuln_types now fall through to
    # UNMAPPED ('other'); the adversarial methodology lives in the AC + Chain prompts.
]

UNMAPPED_CODE = "other"
UNMAPPED_LABEL = "(unmapped)"


# ---------------------------------------------------------------------------
# Builders — each returns the exact structure a consumer previously declared inline
# ---------------------------------------------------------------------------

def grep_file_map():
    """grep_scan.py GROUP_FILE_MAP: bucket key -> *-results.md filename."""
    m = OrderedDict()
    for meta in GREP_META_ORDER:
        m[meta] = GREP_META_FILES[meta]
    for gid in IMPACT_ORDER:
        gk = IMPACT_GROUPS[gid]["grep_key"]
        m[gk] = f"{gk}-results.md"
    return m


def semgrep_priority_overrides():
    """extract_semgrep_coords.py PRIORITY_OVERRIDES."""
    return list(SEMGREP_PRIORITY_OVERRIDES)


def semgrep_rule_group_map():
    """extract_semgrep_coords.py RULE_GROUP_MAP (insertion order load-bearing)."""
    m = OrderedDict()
    for gid in SEMGREP_CLASSIFY_ORDER:
        m[gid] = list(IMPACT_GROUPS[gid]["semgrep_rule_patterns"])
    return m


def semgrep_group_labels():
    """extract_semgrep_coords.py write_group_file group_labels."""
    labels = {gid: IMPACT_GROUPS[gid]["semgrep_label"] for gid in IMPACT_ORDER}
    labels["unclassified"] = UNCLASSIFIED_SEMGREP_LABEL
    return labels


def semgrep_write_order():
    """extract_semgrep_coords.py per-group write + summary loop (with unclassified)."""
    return IMPACT_ORDER + ["unclassified"]


def semgrep_short_label(gid):
    """'Group A', 'Group AB', ... for the extract summary print block."""
    if gid == "unclassified":
        return "Unclassified"
    return f"Group {IMPACT_GROUPS[gid]['code']}"


def accumulator_cwe_map():
    """pattern_accumulator.vuln_group CWE -> group code."""
    m = {}
    for gid in IMPACT_ORDER:
        code = IMPACT_GROUPS[gid]["code"]
        for cwe in IMPACT_GROUPS[gid]["cwes"]:
            m[cwe] = code
    return m


def accumulator_vt_fallbacks():
    """pattern_accumulator.vuln_group keyword fallbacks (ordered)."""
    return [(list(subs), code) for subs, code in VULN_TYPE_FALLBACKS]


def accumulator_group_labels():
    """pattern_accumulator.GROUP_LABELS."""
    labels = OrderedDict()
    for gid in ACCUMULATOR_ORDER:
        g = IMPACT_GROUPS[gid]
        labels[g["code"]] = g["accumulator_label"]
    labels[UNMAPPED_CODE] = UNMAPPED_LABEL
    return labels


def accumulator_dashboard_order():
    """pattern_accumulator dashboard Block-5 group-code iteration list."""
    return [IMPACT_GROUPS[gid]["code"] for gid in ACCUMULATOR_ORDER]


def vuln_group(cwe, vuln_type):
    """CWE / vuln_type -> pipeline group code (canonical implementation).

    Kept here so grep/semgrep/accumulator all agree on attribution.
    """
    c = (cwe or "").upper()
    vt = (vuln_type or "").lower()
    cmap = accumulator_cwe_map()
    if c in cmap:
        return cmap[c]
    for subs, code in VULN_TYPE_FALLBACKS:
        if any(k in vt for k in subs):
            return code
    return UNMAPPED_CODE


if __name__ == "__main__":
    # Self-check: print the derived structures for eyeballing / diffing.
    import json
    print("IMPACT_ORDER            :", IMPACT_ORDER)
    print("SEMGREP_CLASSIFY_ORDER  :", SEMGREP_CLASSIFY_ORDER)
    print("ACCUMULATOR_ORDER       :", ACCUMULATOR_ORDER)
    print("grep_file_map           :", json.dumps(grep_file_map()))
    print("semgrep_write_order     :", semgrep_write_order())
    print("semgrep_group_labels    :", json.dumps(semgrep_group_labels(), ensure_ascii=False))
    print("accumulator_group_labels:", json.dumps(accumulator_group_labels(), ensure_ascii=False))
    print("accumulator_dashboard   :", accumulator_dashboard_order())
    print("accumulator_cwe_map     :", json.dumps(accumulator_cwe_map()))
