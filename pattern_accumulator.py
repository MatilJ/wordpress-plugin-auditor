#!/usr/bin/env python3
"""
pattern_accumulator.py — Cross-audit pattern database for tune-* skills.

Records per-finding and per-triage metadata across all audits to a SQLite
database. Enables aggregate TP/FP ratio queries that tune-semgrep and
tune-vuln-audit use to evaluate the 90% confidence gate.

Usage:
    python pattern_accumulator.py ingest <audit_dir>
    python pattern_accumulator.py backfill [--dry-run] [--registry-only] [--findings-only] [--invalidated-only]
    python pattern_accumulator.py stats [--semgrep-rule <id>] [--cwe <CWE-NNN>] [--vuln-type <type>] [--format json]
    python pattern_accumulator.py summary [--format json]
    python pattern_accumulator.py dashboard [--format json]   # funnel, EV ranking, dead-rule/section, tier yield
    python pattern_accumulator.py fp-causes [--format json]   # FP reason histogram + prevention backlog
    python pattern_accumulator.py prune-stale [--dry-run] [--format json]   # purge rows for renamed/deleted rules
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DB_PATH = SCRIPT_DIR / "databases" / "pattern_accumulator.db"
REGISTRY_PATH = SCRIPT_DIR / "vuln-registry.md"
AUDIT_DIR = SCRIPT_DIR / "audit"

# Group taxonomy is centralised in group_registry.py — the single source of truth shared
# by grep_scan.py / extract_semgrep_coords.py / pattern_accumulator.py.
sys.path.insert(0, str(SCRIPT_DIR))
import group_registry

SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Vuln-type normalization
# ---------------------------------------------------------------------------

VULN_TYPE_NORMALIZE = {
    "stored cross-site scripting": "Stored XSS",
    "stored xss": "Stored XSS",
    "reflected cross-site scripting": "Reflected XSS",
    "reflected cross-site scripting (xss)": "Reflected XSS",
    "reflected xss": "Reflected XSS",
    "cross-site scripting": "XSS",
    "xss": "XSS",
    "cross-site request forgery": "CSRF",
    "csrf": "CSRF",
    "missing authorization": "Missing Authorization",
    "missing auth": "Missing Authorization",
    "insecure direct object reference": "IDOR",
    "idor": "IDOR",
    "broken authorization": "IDOR",
    "sql injection": "SQL Injection",
    "sqli": "SQL Injection",
    "sensitive information disclosure": "Information Disclosure",
    "sensitive data disclosure": "Information Disclosure",
    "content disclosure": "Information Disclosure",
    "information disclosure": "Information Disclosure",
    "server-side request forgery": "SSRF",
    "ssrf": "SSRF",
    "authentication bypass": "Auth Bypass",
    "auth bypass": "Auth Bypass",
    "privilege escalation": "Privilege Escalation",
    "privilege escalation to admin": "Privilege Escalation",
    "arbitrary options update": "Arbitrary Options Update",
    "arbitrary shortcode execution": "Arbitrary Shortcode Execution",
    "arbitrary file deletion": "Arbitrary File Deletion",
    "arbitrary file upload": "Arbitrary File Upload",
    "arbitrary file read": "Arbitrary File Read",
    "arbitrary file download": "Arbitrary File Read",
    "arbitrary file download/read": "Arbitrary File Read",
    "arbitrary file read/download": "Arbitrary File Read",
    "limited file upload": "Limited File Upload",
    "php object injection": "PHP Object Injection",
    "remote code execution": "RCE",
    "rce": "RCE",
    "code injection": "RCE",
    "email injection": "Email Injection",
    "email header injection": "Email Injection",
    "directory traversal": "Directory Traversal",
    "local file inclusion": "LFI",
    "lfi": "LFI",
}


def normalize_vuln_type(raw):
    if not raw:
        return None
    key = raw.strip().lower()
    key = re.sub(r"\s*\(.*?\)\s*$", "", key)
    if key in VULN_TYPE_NORMALIZE:
        return VULN_TYPE_NORMALIZE[key]
    for prefix, normalized in VULN_TYPE_NORMALIZE.items():
        if key.startswith(prefix):
            return normalized
    return raw.strip()


# ---------------------------------------------------------------------------
# FP reason categorization
# ---------------------------------------------------------------------------

FP_REASON_PATTERNS = [
    ("has_cap_check", re.compile(
        r"capability|current_user_can|has_cap|manage_options.*check|user_can",
        re.IGNORECASE)),
    ("admin_only", re.compile(
        r"admin[_-]only|admin context|admin-only|only.*admin|requires.*admin|manage_options",
        re.IGNORECASE)),
    ("nonce_present", re.compile(
        r"nonce|check_ajax_referer|wp_verify_nonce|check_admin_referer|_wpnonce",
        re.IGNORECASE)),
    ("escaped_output", re.compile(
        r"esc_html|esc_attr|wp_kses|sanitiz|escaped|htmlspecialchars|esc_url",
        re.IGNORECASE)),
    ("safe_sql", re.compile(
        r"prepare\(\)|esc_like|absint|intval|\$wpdb->prepare|properly\s+bound|parameterized",
        re.IGNORECASE)),
    ("hardcoded_data", re.compile(
        r"hardcoded|hard-coded|static|constant|not user[- ]controlled|internal|registry",
        re.IGNORECASE)),
    ("no_impact", re.compile(
        r"no impact|no security impact|read[- ]only|notice dismiss|no state change|"
        r"no CIA|informational|own (user_?meta|data|profile)",
        re.IGNORECASE)),
    ("dead_code", re.compile(
        r"dead code|unreachable|never called|unused",
        re.IGNORECASE)),
]


def categorize_fp_reason(reason_text):
    if not reason_text:
        return "other"
    for category, pattern in FP_REASON_PATTERNS:
        if pattern.search(reason_text):
            return category
    return "other"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(db_path=None):
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            plugin_slug     TEXT NOT NULL,
            version         TEXT NOT NULL,
            audit_date      TEXT,
            cwe             TEXT,
            vuln_type       TEXT,
            auth_floor      TEXT,
            cvss            REAL,
            status          TEXT NOT NULL,
            semgrep_rule    TEXT,
            semgrep_surfaced INTEGER DEFAULT 0,
            grep_section    TEXT,
            source_file     TEXT,
            finding_title   TEXT,
            summary         TEXT,
            installs        INTEGER,
            registry_status TEXT,
            -- cwe is intentionally NOT part of the dedup key: it is frequently
            -- NULL, and SQLite treats NULLs as distinct in UNIQUE constraints,
            -- so including it let every re-ingest of a NULL-cwe finding insert a
            -- fresh duplicate row. Key on the stable (slug, version, title)
            -- triple; cwe is merged in via COALESCE in upsert_finding().
            UNIQUE(plugin_slug, version, finding_title)
        );

        CREATE TABLE IF NOT EXISTS triage_entries (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            plugin_slug     TEXT NOT NULL,
            version         TEXT NOT NULL,
            audit_date      TEXT,
            semgrep_rule    TEXT NOT NULL,
            -- NOT NULL DEFAULT '' so the UNIQUE key below actually dedups:
            -- most triage rows parse no explicit file:line, and a NULL here
            -- (SQLite NULL-distinct) let every re-ingest insert a duplicate.
            file_line       TEXT NOT NULL DEFAULT '',
            verdict         TEXT NOT NULL,
            reason_category TEXT,
            reason_raw      TEXT,
            source_file     TEXT,
            UNIQUE(plugin_slug, version, semgrep_rule, file_line)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_semgrep ON findings(semgrep_rule)
            WHERE semgrep_rule IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe);
        CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
        CREATE INDEX IF NOT EXISTS idx_triage_rule ON triage_entries(semgrep_rule);
        CREATE INDEX IF NOT EXISTS idx_triage_verdict ON triage_entries(verdict);
    """)
    return conn


# ---------------------------------------------------------------------------
# Parsing utilities
# ---------------------------------------------------------------------------

def slug_version_from_path(fpath):
    """Extract plugin_slug and version from audit/{slug}/{version}/..."""
    parts = Path(fpath).parts
    for i, part in enumerate(parts):
        if part == "audit" and i + 2 < len(parts):
            return parts[i + 1], parts[i + 2]
    return None, None


def parse_installs(raw):
    if not raw:
        return None
    raw = raw.strip().lstrip("~").rstrip("+").replace(",", "")
    m = re.search(r"(\d+)", raw)
    return int(m.group(1)) if m else None


def extract_cwe(text):
    m = re.search(r"(CWE-\d+)", text)
    return m.group(1) if m else None


def extract_cvss(text):
    m = re.search(r"(\d+\.?\d*)", text)
    if m:
        val = float(m.group(1))
        if 0 <= val <= 10:
            return val
    return None


# ---------------------------------------------------------------------------
# Semgrep rule-id canonicalization
# ---------------------------------------------------------------------------
# A valid Semgrep rule id is lowercase, starts with a letter, and contains at
# least one internal '.' or '-' separator (e.g. "wp-ajax-hook-missing-auth",
# "claude.php.wordpress.xss.unescaped-meta-output"). Single prose words such as
# "group", "hit", "Stored", "Missing", "All", "3", "-surfaced" are rejected.
# The canonical short id is the LAST dotted segment, so the namespaced form
# "...xss.unescaped-meta-output" and the bare "unescaped-meta-output" collapse
# to one rule.

SEMGREP_RULE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")

SEMGREP_RULES_DIR = SCRIPT_DIR / "semgrep_rules"
_CORPUS_RULE_IDS = None


def corpus_rule_ids():
    """Set of canonical (last-dotted-segment) rule ids declared in the
    semgrep_rules/ corpus. Cached. Empty set if the corpus dir is absent —
    callers then fall back to regex-only validation."""
    global _CORPUS_RULE_IDS
    if _CORPUS_RULE_IDS is None:
        ids = set()
        if SEMGREP_RULES_DIR.is_dir():
            for p in list(SEMGREP_RULES_DIR.rglob("*.yml")) + \
                     list(SEMGREP_RULES_DIR.rglob("*.yaml")):
                try:
                    txt = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                for m in re.finditer(r"^\s*-?\s*id:\s*([A-Za-z0-9_.\-]+)", txt, re.M):
                    ids.add(m.group(1).split(".")[-1].lower())
        _CORPUS_RULE_IDS = ids
    return _CORPUS_RULE_IDS


def canonicalize_semgrep_rule(raw):
    """Validate a Semgrep rule token and return its canonical short id, or None.

    Semgrep check_ids carry a namespace path prefix derived from the rule file
    location (e.g. "semgrep_rules.claude_rules.access-control.claude.php.
    wordpress.auth.nonce-without-capability-check"); those prefix segments use
    underscores and would fail validation. The canonical short id is the LAST
    dotted segment, so the prefix is dropped first and only the leaf validated.

    Beyond the regex shape, the leaf must be a real rule id present in the
    semgrep_rules/ corpus. This rejects 2-word prose fragments that happen to
    match the regex ("render-side", "sub-analysis", "user-controlled",
    "cwe-79", "y-m-d"). If the corpus can't be loaded, validation is
    regex-only.
    """
    if not raw:
        return None
    c = raw.strip().strip("`\"'*").strip().lower()
    c = c.split(".")[-1]
    if not SEMGREP_RULE_RE.match(c):
        return None
    corpus = corpus_rule_ids()
    if corpus and c not in corpus:
        return None
    return c


def extract_semgrep_rules(text):
    """Return the unique canonical rule ids found in `text`, in order of first
    appearance. Used for both findings.md Semgrep fields and triage rule cells
    (which occasionally list two rules separated by ',' or '/')."""
    if not text:
        return []
    found = []
    for tok in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*", text):
        canon = canonicalize_semgrep_rule(tok)
        if canon and canon not in found:
            found.append(canon)
    return found


RE_SEMGREP_FIELD = re.compile(
    r"\*\*\s*(?:Semgrep(?:[-\s]?surfaced)?|Surfaced\s+by)\s*\*?\*?\s*:\s*(.*)",
    re.IGNORECASE,
)


def parse_semgrep_field(line):
    """Parse a findings.md Semgrep field line.

    Returns (semgrep_surfaced:int, semgrep_rule:str|None) when `line` is a
    Semgrep field, else None. A "No"/"independent"/"manual" value yields
    (0, None); a "Yes" value captures and validates the rule token.
    """
    m = RE_SEMGREP_FIELD.search(line)
    if not m:
        return None
    value = m.group(1).strip().strip("*").strip()
    low = value.lower()
    is_no = (re.match(r"(?:no|none|n/?a|independent|manual)\b", low) is not None
             or "not in semgrep" in low or "independent" in low)
    rules = extract_semgrep_rules(value)
    rule = rules[0] if rules else None
    if is_no:
        return (0, None)
    surfaced = 1 if ("yes" in low or rule) else 0
    return (surfaced, rule)


# ---------------------------------------------------------------------------
# Finding-header detection
# ---------------------------------------------------------------------------
# Tolerates: "## Finding 1:", "## Finding B-1:", "## Finding #1 —",
# "## Finding CHAIN-1:", "## Finding A — ", "## Finding 1B — ", "## Finding [2]:".
# A real separator (colon, space+dash, or ". ") is required so prose headers
# like "## Finding Notes (...)" and "## FINDING SUMMARY" are skipped.

RE_FINDING_HEADER = re.compile(
    r"^#{2,}\s+FINDING(?=[\s#\[\-:.])"             # keyword (not "FINDINGS")
    r"[\s#\[\-]*"                                   # #, [, -, spaces before id
    r"([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)?"           # id (1, B-1, 001, CHAIN-1, 1B)
    r"\]?"                                          # optional closing bracket
    r"(?:\s*\([^)]*\))?"                            # optional annotation, e.g. "(Chain)"
    # separator: colon, em/en dash (never inside an id), spaced hyphen, or ". "
    r"(?:\s*:\s*|\s*[—–]\s*|\s+-\s+|\.\s+)"
    r"\s*(.+)$",
    re.IGNORECASE,
)

NON_FINDING_TITLES = {
    "summary", "conclusion", "notes", "triage", "log", "findings",
    "confirmed findings", "no reportable findings", "no confirmed findings",
    "no reportable vulnerabilities", "manual analysis coverage",
    "false positives", "semgrep false positives", "lead triage",
    "2c", "vulnerability chaining", "chain assessment", "chain analysis",
    "triage log", "semgrep triage", "out of scope",
}

RE_TRIAGE_SECTION = re.compile(
    r"^##\s+.*(?:triage|false.positiv|triaged|ruled.out|out.of.scope|"
    r"semgrep.*triage|semgrep.*false|non[- ]?finding|fp\b|dismissed)",
    re.IGNORECASE,
)

RE_SEMGREP_TRIAGE_TABLE_HEADER = re.compile(
    r"^\|.*(?:rule|semgrep|action|finding|handler|issue).*\|",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# findings.md parser
# ---------------------------------------------------------------------------

class FindingsParser:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.slug, self.version = slug_version_from_path(filepath)
        self.audit_date = None
        self.installs = None
        self.findings = []
        self.triage_entries = []

    def parse(self):
        text = self.filepath.read_text(encoding="utf-8", errors="replace")
        lines = text.split("\n")

        self._parse_header(lines)
        self._parse_findings(lines, text)
        if self.findings:
            self._attribute_grep_sections()
        self._parse_triage(lines)

        return self.findings, self.triage_entries

    # --- grep-section attribution -----------------------------------------
    RE_GREP_SECTION = re.compile(r"^##(?!#)\s+\[?\s*(.+?)\s*\]?\s*$")
    RE_GREP_HIT = re.compile(r"^\s*[-*]\s+(\S+?):(\d+)\b")

    def _attribute_grep_sections(self):
        """Map each finding's affected file:line to the owning grep section(s)
        by parsing this audit's grep/*.md output. Section *name* (e.g.
        TIER3_SQL, STANDALONE_PHP) is stored — not the group/file bucket.

        The finding cites the vuln's location while grep cites the
        pattern-match line, so exact file:line rarely coincides. We therefore
        attribute each affected location to the section(s) of the grep hit
        whose line number is *nearest* in the same file (exact match = distance
        0). This keeps attribution to the single most-relevant section rather
        than unioning every section that merely mentions the file. Leaves
        grep_section None when there is no grep/ dir or the file isn't found."""
        grep_dir = self.filepath.parent / "grep"
        if not grep_dir.is_dir():
            return

        hits_by_path = defaultdict(list)   # path     -> [(line:int, section)]
        hits_by_base = defaultdict(list)   # basename -> [(line:int, section)]

        for gp in sorted(grep_dir.glob("*.md")):
            try:
                gtext = gp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            section = None
            for gl in gtext.split("\n"):
                hm = self.RE_GREP_SECTION.match(gl)
                if hm:
                    section = hm.group(1).strip()
                    continue
                em = self.RE_GREP_HIT.match(gl)
                if em and section:
                    path = em.group(1).replace("\\", "/").lstrip("./")
                    base = path.rsplit("/", 1)[-1]
                    hits_by_path[path].append((int(em.group(2)), section))
                    hits_by_base[base].append((int(em.group(2)), section))

        def nearest_sections(hits, line):
            best = min(abs(hl - line) for hl, _ in hits)
            return {sec for hl, sec in hits if abs(hl - line) == best}

        for f in self.findings:
            sections = set()
            for path, line in f.get("_affected", []):
                path = path.replace("\\", "/").lstrip("./")
                base = path.rsplit("/", 1)[-1]
                line = int(line)
                if path in hits_by_path:
                    sections |= nearest_sections(hits_by_path[path], line)
                elif base in hits_by_base:
                    sections |= nearest_sections(hits_by_base[base], line)
            if sections:
                f["grep_section"] = ",".join(sorted(sections))

    def _parse_header(self, lines):
        for line in lines[:30]:
            lower = line.lower().strip()
            if not self.audit_date:
                m = re.search(r"(?:audit[_ ]?date|audited)\s*[:]\s*(\d{4}-\d{2}-\d{2})", lower)
                if m:
                    self.audit_date = m.group(1)
            if not self.installs:
                m = re.search(
                    r"(?:plugin\s+)?installs?\s*[:]\s*([~\d,]+\+?)",
                    line, re.IGNORECASE,
                )
                if m:
                    self.installs = parse_installs(m.group(1))
                if not self.installs:
                    m = re.search(
                        r"([\d,]+)\+?\s*active\s+installs",
                        line, re.IGNORECASE,
                    )
                    if m:
                        self.installs = parse_installs(m.group(1))

    def _parse_findings(self, lines, full_text):
        # A finding block ends at the next finding header (at any depth) or the
        # next level-2 "## " section header — whichever comes first. Using only
        # the next *finding* lets a single-finding file's block run to EOF and
        # slurp Status/Verdict lines from later triage sections (which then
        # falsely veto the finding). Finding headers themselves vary in depth
        # (##, ###, ####), so they must all act as boundaries.
        level2_heads = [i for i, ln in enumerate(lines) if re.match(r"^##(?!#)\s", ln)]

        finding_starts = []
        for i, line in enumerate(lines):
            m = RE_FINDING_HEADER.match(line.strip())
            if m:
                finding_id = m.group(1)
                title = m.group(2).strip()
                title_lower = title.lower().strip().rstrip("—–- ")
                if title_lower in NON_FINDING_TITLES:
                    continue
                finding_starts.append((i, finding_id, title))

        boundaries = sorted(set([s for s, _, _ in finding_starts] + level2_heads))

        for start, fid, title in finding_starts:
            later = [b for b in boundaries if b > start]
            end = later[0] if later else len(lines)
            block = "\n".join(lines[start:end])
            block_lower = block.lower()

            # The finding's PRIMARY status sits on its own Status / Verdict /
            # Vulnerability line. Older audits put it inline on the Vulnerability
            # line ("**Vulnerability:** Missing Auth (CWE-862) — CONFIRMED");
            # newer ones use "**Status:** CONFIRMED [+ VALIDATED]". We take the
            # FIRST occurrence of each (Status preferred, then Verdict, then the
            # inline Vulnerability line) — that is always the finding's own,
            # ignoring verdicts about secondary leads / chains that appear
            # deeper in the block. When none exists we fall back to a positive
            # token anywhere in the block (guarded against "no/not confirmed").
            first = {"status": None, "verdict": None, "vuln": None}
            patt = {
                "status":  r"\*\*\s*Status\s*\*?\*?\s*:?\s*\*{0,2}\s*(.+)",
                "verdict": r"\*\*\s*Verdict\s*\*?\*?\s*:?\s*\*{0,2}\s*(.+)",
                "vuln":    r"\*\*\s*Vulnerabilit(?:y|ies)\s*\*?\*?\s*:?\s*\*{0,2}\s*(.+)",
            }
            for bline in lines[start:end]:
                s = bline.strip()
                for key, pat in patt.items():
                    if first[key] is None:
                        m = re.match(pat, s, re.IGNORECASE)
                        if m:
                            first[key] = m.group(1)
            POS = r"\bconfirmed\b|\blive[\s_-]*validated\b"
            DISQ = (
                r"false\s+positive|\binvalidated\b|\brejected\b|out\s+of\s+scope|"
                r"not\s+a\s+finding|not\s+viable|not\s+report|"
                r"not\s+(?:externally\s+)?exploitable|no\s+(?:exploitable\s+)?vulnerab|"
                r"\bunconfirmed\b|intentional|low\s+impact|code\s+defect|architectural"
            )

            # Dedicated Status/Verdict fields are authoritative. The inline
            # Vulnerability line is only a status decl when it actually carries
            # a status token ("...— CONFIRMED"); a bare "**Vulnerability class:**
            # Stored XSS" type field is NOT a status and must not shadow a
            # CONFIRMED marker elsewhere in the block.
            primary = first["status"] or first["verdict"]
            if not primary and first["vuln"] and \
               re.search(POS + "|" + DISQ, first["vuln"], re.IGNORECASE):
                primary = first["vuln"]
            status_decl_text = (primary or "").lower()

            neg_inline = re.search(r"\b(?:no|not|0|zero)\s+confirmed\b|\bunconfirmed\b",
                                   block_lower) is not None

            if status_decl_text:
                is_confirmed = (re.search(POS, status_decl_text) is not None
                                and re.search(DISQ, status_decl_text) is None)
            else:
                is_confirmed = (re.search(POS, block_lower) is not None) and not neg_inline
            if not is_confirmed:
                continue

            cwe = None
            cvss = None
            auth_floor = None
            semgrep_rule = None
            semgrep_surfaced = 0
            affected = []

            for bline in lines[start:end]:
                bl = bline.strip()
                if not cwe:
                    m = re.search(r"\*\*CWE\*?\*?:?\*?\*?\s*(CWE-\d+)", bl)
                    if m:
                        cwe = m.group(1)
                if not cwe:
                    cwe_m = extract_cwe(bl)
                    if cwe_m and re.match(r".*\*\*CWE", bl):
                        cwe = cwe_m

                if cvss is None and re.search(r"\bCVSS\b", bl, re.IGNORECASE):
                    # Prefer a standalone bold score "**4.3**" (older template,
                    # where the label is "**CVSS 3.1:**" and 3.1 is the version);
                    # else the number right after a "CVSS:" label (newer template).
                    mb = re.search(r"\*\*\s*(\d{1,2}(?:\.\d+)?)\s*\*\*", bl)
                    if mb:
                        cvss = extract_cvss(mb.group(1))
                    else:
                        ml = re.search(r"\bCVSS\b[^:\n]*?:\s*\*{0,2}\s*(\d{1,2}(?:\.\d+)?)",
                                       bl, re.IGNORECASE)
                        if ml:
                            cvss = extract_cvss(ml.group(1))

                if not auth_floor:
                    m = re.search(
                        r"\*\*\s*(?:Auth(?:entication)?[\s_-]*(?:Required|Floor|Level)?"
                        r"(?:\s*\(Attacker\))?|Attacker[\s_-]*(?:Role|Privilege|Level)?)"
                        r"\s*\*?\*?\s*:\s*\*{0,2}\s*(.+)",
                        bl, re.IGNORECASE,
                    )
                    if m:
                        auth_raw = m.group(1).strip().rstrip("*").strip()
                        auth_floor = self._normalize_auth(auth_raw)

                sg = parse_semgrep_field(bl)
                if sg is not None:
                    semgrep_surfaced = sg[0]
                    if sg[1]:
                        semgrep_rule = sg[1]

                # Capture affected file:line references (for grep attribution).
                if re.search(r"\*\*\s*Affected", bl, re.IGNORECASE) or \
                   re.match(r"^[-*]\s", bl):
                    for pm in re.finditer(r"([A-Za-z0-9_][\w./\\-]*\.\w+):(\d+)", bl):
                        affected.append((pm.group(1).replace("\\", "/"), pm.group(2)))

            if not cwe:
                cwe = extract_cwe(block)

            fid = fid or "?"
            finding = {
                "plugin_slug": self.slug,
                "version": self.version,
                "audit_date": self.audit_date,
                "cwe": cwe,
                "vuln_type": normalize_vuln_type(title) if title else None,
                "auth_floor": auth_floor,
                "cvss": cvss,
                "status": "TP",
                "semgrep_rule": semgrep_rule,
                "semgrep_surfaced": semgrep_surfaced,
                "grep_section": None,
                "source_file": str(self.filepath),
                "finding_title": f"Finding {fid}: {title[:100]}",
                "summary": title[:300],
                "installs": self.installs,
                "registry_status": None,
                "_affected": affected,
            }
            self.findings.append(finding)

    def _normalize_auth(self, raw):
        lower = raw.lower()
        if "unauth" in lower or "pr:n" in lower:
            return "Unauthenticated"
        if "subscriber" in lower:
            return "Subscriber"
        if "customer" in lower:
            return "Customer"
        if "contributor" in lower:
            return "Contributor"
        if "author" in lower:
            return "Author"
        if "editor" in lower:
            return "Editor"
        if "admin" in lower:
            return "Administrator"
        return raw.split("(")[0].strip().split(",")[0].strip()

    def _parse_triage(self, lines):
        in_triage = False
        in_table = False
        col_map = {}

        for i, line in enumerate(lines):
            stripped = line.strip()

            if RE_TRIAGE_SECTION.match(stripped):
                in_triage = True
                in_table = False
                col_map = {}
                continue

            if stripped.startswith("## ") and in_triage and not RE_TRIAGE_SECTION.match(stripped):
                if not re.search(r"semgrep|triage|false|fp|triag", stripped, re.IGNORECASE):
                    in_triage = False
                    in_table = False
                    continue

            if stripped.startswith("### ") and in_triage:
                if re.search(r"semgrep", stripped, re.IGNORECASE):
                    in_table = False
                    col_map = {}
                continue

            if in_triage and not in_table and stripped.startswith("|") and \
               RE_SEMGREP_TRIAGE_TABLE_HEADER.match(stripped):
                cols = [c.strip().lower() for c in stripped.split("|")]
                cols = [c for c in cols if c]
                for ci, col in enumerate(cols):
                    if any(kw in col for kw in ["rule", "semgrep rule", "semgrep"]):
                        col_map["rule"] = ci
                    elif any(kw in col for kw in ["file", "location", "line"]):
                        col_map["file"] = ci
                    elif any(kw in col for kw in ["triage", "verdict", "outcome"]):
                        col_map["verdict"] = ci
                    elif any(kw in col for kw in ["reason", "notes", "reason fp"]):
                        col_map["reason"] = ci
                in_table = True
                continue

            if in_triage and in_table and stripped.startswith("|---"):
                continue

            if in_triage and in_table and stripped.startswith("|"):
                cells = [c.strip() for c in stripped.split("|")]
                cells = [c for c in cells if c or cells.index(c) > 0]
                if len(cells) < 2:
                    continue

                rule = cells[col_map["rule"]] if "rule" in col_map and col_map["rule"] < len(cells) else None
                file_line = cells[col_map["file"]] if "file" in col_map and col_map["file"] < len(cells) else None
                verdict_raw = cells[col_map["verdict"]] if "verdict" in col_map and col_map["verdict"] < len(cells) else None
                reason_raw = cells[col_map.get("reason", -1)] if "reason" in col_map and col_map["reason"] < len(cells) else None

                if not verdict_raw and "rule" in col_map and col_map["rule"] < len(cells):
                    for ci, cell in enumerate(cells):
                        if ci not in col_map.values() and re.search(r"FP|false.positive|oos|true.positive|confirmed", cell, re.IGNORECASE):
                            verdict_raw = cell
                            break

                if not rule:
                    for cell in cells:
                        if re.search(r"[a-z]+-[a-z]+-[a-z]+|semgrep", cell, re.IGNORECASE):
                            rule = cell
                            break

                if not rule:
                    continue

                # A cell may list one or two rules (e.g. "rule-a / rule-b");
                # validate + canonicalize each, drop prose that isn't a rule id.
                rules = extract_semgrep_rules(rule)
                if not rules:
                    continue

                verdict = self._normalize_verdict(verdict_raw or "")
                if verdict == "TP":
                    continue

                reason_text = reason_raw or verdict_raw or ""
                reason_text = re.sub(r"^\*?\*?FP\*?\*?\s*[-—:]\s*", "", reason_text, flags=re.IGNORECASE)
                file_line_clean = re.sub(r"[`*]", "", file_line).strip() if file_line else None

                for canon_rule in rules:
                    self.triage_entries.append({
                        "plugin_slug": self.slug,
                        "version": self.version,
                        "audit_date": self.audit_date,
                        "semgrep_rule": canon_rule,
                        "file_line": file_line_clean,
                        "verdict": verdict,
                        "reason_category": categorize_fp_reason(reason_text),
                        "reason_raw": reason_text[:500] if reason_text else None,
                        "source_file": str(self.filepath),
                    })

            elif in_table and stripped and not stripped.startswith("|"):
                in_table = False

        if not self.triage_entries:
            self._parse_narrative_triage(lines)

    def _parse_narrative_triage(self, lines):
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = re.match(
                r"###\s+(?:Semgrep\s+)?(?:Hit|Lead|Entry)\s+\d+\s*[—–:-]\s*"
                r"(?:`)?([a-z0-9_.-]+(?:[a-z0-9_.-]+)*)(?:`)?\s*(?:at\s+|on\s+|@\s*)?"
                r"(?:`)?([^\s`]+:\d+)?",
                line, re.IGNORECASE,
            )
            if not m:
                m = re.match(
                    r"###\s+(?:Semgrep\s+)?(?:Hit|Lead)\s+\d+\s*[—–:-]\s*"
                    r"([^\s]+\.php:\d+)",
                    line, re.IGNORECASE,
                )
                if m:
                    file_line = m.group(1)
                    rule = None
                    for j in range(i + 1, min(i + 10, len(lines))):
                        rule_m = re.search(r"`([a-z0-9_-]+(?:-[a-z0-9_-]+)+)`", lines[j])
                        if rule_m:
                            rule = rule_m.group(1)
                            break
                    if rule:
                        m = type("M", (), {"group": lambda self, n: {1: rule, 2: file_line}[n]})()

            if m:
                rule = m.group(1) if hasattr(m, "group") else None
                file_line = m.group(2) if hasattr(m, "group") else None

                verdict = "FP"
                reason_text = ""
                for j in range(i + 1, min(i + 20, len(lines))):
                    bl = lines[j].strip()
                    if bl.startswith("### ") or bl.startswith("## "):
                        break
                    vm = re.search(r"\*\*Verdict\s*[:]\*?\*?\s*(.+)", bl, re.IGNORECASE)
                    if vm:
                        v_raw = vm.group(1).strip()
                        verdict = self._normalize_verdict(v_raw)
                        reason_text = v_raw
                        break

                canon = canonicalize_semgrep_rule(rule) if rule else None
                if canon and verdict != "TP":
                    self.triage_entries.append({
                        "plugin_slug": self.slug,
                        "version": self.version,
                        "audit_date": self.audit_date,
                        "semgrep_rule": canon,
                        "file_line": file_line,
                        "verdict": verdict,
                        "reason_category": categorize_fp_reason(reason_text),
                        "reason_raw": reason_text[:500] if reason_text else None,
                        "source_file": str(self.filepath),
                    })
            i += 1

    def _normalize_verdict(self, raw):
        lower = raw.lower().strip()
        lower = re.sub(r"[*`]", "", lower)
        if any(kw in lower for kw in ["true positive", "confirmed", "→ finding", "see finding"]):
            return "TP"
        if any(kw in lower for kw in ["out of scope", "oos"]):
            return "OOS"
        return "FP"


# ---------------------------------------------------------------------------
# vuln-registry.md parser
# ---------------------------------------------------------------------------

def parse_registry(registry_path=None):
    path = registry_path or REGISTRY_PATH
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = text.strip().split("\n")

    entries = []
    for line in lines:
        if not line.startswith("|") or line.startswith("| Date") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.split("|")]
        cells = [c for c in cells if c != ""]
        if len(cells) < 11:
            continue

        date_val = cells[0]
        project = cells[1]
        slug = cells[2]
        installs_raw = cells[3]
        auth_required = cells[4]
        vuln_type = cells[5]
        cwe = cells[6]
        cvss_raw = cells[7]
        summary = cells[8]
        _bounty = cells[9]
        reg_status = cells[10] if len(cells) > 10 else ""

        version = ""
        if "/" in project:
            parts = project.rsplit("/", 1)
            version = parts[1] if len(parts) > 1 else ""

        status = "TP"
        reg_lower = reg_status.lower()
        if "rejected" in reg_lower:
            status = "REJECTED"
        elif "duplicate" in reg_lower:
            status = "TP"

        entries.append({
            "plugin_slug": slug,
            "version": version,
            "audit_date": date_val if re.match(r"\d{4}-\d{2}-\d{2}", date_val) else None,
            "cwe": extract_cwe(cwe) if cwe else None,
            "vuln_type": normalize_vuln_type(vuln_type),
            "auth_floor": auth_required.strip(),
            "cvss": extract_cvss(cvss_raw),
            "status": status,
            "semgrep_rule": None,
            "semgrep_surfaced": 0,
            "grep_section": None,
            "source_file": "vuln-registry.md",
            "finding_title": f"Registry: {summary[:80]}",
            "summary": summary[:300],
            "installs": parse_installs(installs_raw),
            "registry_status": reg_status.strip(),
        })

    return entries


# ---------------------------------------------------------------------------
# INVALIDATED PoC parser
# ---------------------------------------------------------------------------

VULN_TYPE_FROM_FILENAME = {
    "missing-auth": "Missing Authorization",
    "missing-authorization": "Missing Authorization",
    "stored-xss": "Stored XSS",
    "reflected-xss": "Reflected XSS",
    "sqli": "SQL Injection",
    "sql-injection": "SQL Injection",
    "idor": "IDOR",
    "csrf": "CSRF",
    "arbitrary-file-deletion": "Arbitrary File Deletion",
    "auth-bypass": "Auth Bypass",
    "arbitrary-file-upload": "Arbitrary File Upload",
    "options-write": "Arbitrary Options Update",
}


def parse_invalidated_pocs(audit_base=None):
    base = Path(audit_base) if audit_base else AUDIT_DIR
    entries = []

    for poc_path in base.rglob("INVALIDATED-*.py"):
        slug, version = slug_version_from_path(poc_path)
        if not slug or not version:
            continue

        fname = poc_path.stem
        vuln_type = None
        for suffix, vtype in VULN_TYPE_FROM_FILENAME.items():
            if suffix in fname.lower():
                vuln_type = vtype
                break

        cwe = None
        cvss = None
        summary = None
        try:
            text = poc_path.read_text(encoding="utf-8", errors="replace")
            doc_m = re.search(r'"""(.*?)"""', text, re.DOTALL)
            if not doc_m:
                doc_m = re.search(r"'''(.*?)'''", text, re.DOTALL)
            if doc_m:
                docstring = doc_m.group(1)
                cwe = extract_cwe(docstring)
                cvss_m = re.search(r"CVSS:\s*(\d+\.?\d*)", docstring)
                if cvss_m:
                    cvss = extract_cvss(cvss_m.group(1))
                title_m = re.match(r"\s*PoC:\s*(.+?)(?:\n|$)", docstring)
                if title_m:
                    summary = title_m.group(1).strip()[:300]
                if not vuln_type:
                    type_m = re.search(r"[—–-]\s*(.+?)(?:\n|$)", docstring)
                    if type_m:
                        vuln_type = normalize_vuln_type(type_m.group(1).strip())
        except Exception:
            pass

        entries.append({
            "plugin_slug": slug,
            "version": version,
            "audit_date": None,
            "cwe": cwe,
            "vuln_type": vuln_type,
            "auth_floor": None,
            "cvss": cvss,
            "status": "INVALIDATED",
            "semgrep_rule": None,
            "semgrep_surfaced": 0,
            "grep_section": None,
            "source_file": str(poc_path),
            "finding_title": f"INVALIDATED: {fname}",
            "summary": summary,
            "installs": None,
            "registry_status": None,
        })

    return entries


# ---------------------------------------------------------------------------
# DB operations
# ---------------------------------------------------------------------------

def upsert_finding(conn, f):
    conn.execute("""
        INSERT INTO findings (
            plugin_slug, version, audit_date, cwe, vuln_type, auth_floor,
            cvss, status, semgrep_rule, semgrep_surfaced, grep_section,
            source_file, finding_title, summary, installs, registry_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(plugin_slug, version, finding_title) DO UPDATE SET
            audit_date = COALESCE(excluded.audit_date, findings.audit_date),
            cwe = COALESCE(excluded.cwe, findings.cwe),
            vuln_type = COALESCE(excluded.vuln_type, findings.vuln_type),
            auth_floor = COALESCE(excluded.auth_floor, findings.auth_floor),
            cvss = COALESCE(excluded.cvss, findings.cvss),
            semgrep_rule = COALESCE(excluded.semgrep_rule, findings.semgrep_rule),
            semgrep_surfaced = MAX(excluded.semgrep_surfaced, findings.semgrep_surfaced),
            grep_section = COALESCE(excluded.grep_section, findings.grep_section),
            source_file = CASE
                WHEN excluded.source_file != 'vuln-registry.md' THEN excluded.source_file
                ELSE findings.source_file
            END,
            summary = COALESCE(excluded.summary, findings.summary),
            installs = COALESCE(excluded.installs, findings.installs),
            registry_status = COALESCE(excluded.registry_status, findings.registry_status)
    """, (
        f["plugin_slug"], f["version"], f["audit_date"], f["cwe"],
        f["vuln_type"], f["auth_floor"], f["cvss"], f["status"],
        f["semgrep_rule"], f["semgrep_surfaced"], f["grep_section"],
        f["source_file"], f["finding_title"], f["summary"],
        f["installs"], f["registry_status"],
    ))


def upsert_triage(conn, t):
    conn.execute("""
        INSERT INTO triage_entries (
            plugin_slug, version, audit_date, semgrep_rule, file_line,
            verdict, reason_category, reason_raw, source_file
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(plugin_slug, version, semgrep_rule, file_line) DO UPDATE SET
            audit_date = COALESCE(excluded.audit_date, triage_entries.audit_date),
            verdict = excluded.verdict,
            reason_category = COALESCE(excluded.reason_category, triage_entries.reason_category),
            reason_raw = COALESCE(excluded.reason_raw, triage_entries.reason_raw)
    """, (
        t["plugin_slug"], t["version"], t["audit_date"], t["semgrep_rule"],
        t["file_line"] or "", t["verdict"], t["reason_category"],
        t["reason_raw"], t["source_file"],
    ))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_ingest(args):
    audit_dir = Path(args.audit_dir)
    findings_path = audit_dir / "findings.md"
    if not findings_path.exists():
        print(f"Error: {findings_path} not found", file=sys.stderr)
        return 1

    parser = FindingsParser(findings_path)
    findings, triage = parser.parse()

    inv_pocs = parse_invalidated_pocs(audit_dir)

    if args.dry_run:
        print(f"[DRY RUN] Would ingest from {audit_dir}:")
        print(f"  Findings:      {len(findings)}")
        print(f"  Triage entries: {len(triage)}")
        print(f"  INVALIDATED:   {len(inv_pocs)}")
        return 0

    conn = init_db()
    try:
        for f in findings:
            upsert_finding(conn, f)
        for t in triage:
            upsert_triage(conn, t)
        for p in inv_pocs:
            upsert_finding(conn, p)
        conn.commit()
    finally:
        conn.close()

    print(f"Ingested from {parser.slug}/{parser.version}:")
    print(f"  Findings:      {len(findings)}")
    print(f"  Triage entries: {len(triage)}")
    print(f"  INVALIDATED:   {len(inv_pocs)}")
    return 0


def cmd_backfill(args):
    total_findings = 0
    total_triage = 0
    total_inv = 0
    total_registry = 0
    errors = []

    conn = None if args.dry_run else init_db()

    try:
        if not args.registry_only and not args.invalidated_only:
            findings_files = list(AUDIT_DIR.rglob("findings.md"))
            print(f"Processing {len(findings_files)} findings.md files...")
            for fpath in findings_files:
                try:
                    parser = FindingsParser(fpath)
                    findings, triage = parser.parse()
                    total_findings += len(findings)
                    total_triage += len(triage)
                    if not args.dry_run:
                        for f in findings:
                            upsert_finding(conn, f)
                        for t in triage:
                            upsert_triage(conn, t)
                except Exception as e:
                    errors.append(f"{fpath}: {e}")

        if not args.findings_only and not args.invalidated_only:
            print("Processing vuln-registry.md...")
            try:
                reg_entries = parse_registry()
                total_registry = len(reg_entries)
                if not args.dry_run:
                    # Registry rows are wholly derived from vuln-registry.md and
                    # never merge with findings.md rows (distinct finding_title
                    # prefix), so they form a clean partition keyed by
                    # source_file. Upsert alone never deletes, so a row removed
                    # from the markdown would otherwise linger forever (orphaned
                    # registry_status keeps it in the holdable EV ranking). Purge
                    # the partition first, then re-insert the current contents so
                    # deletions in the markdown actually propagate. Parsing runs
                    # before the DELETE, so a parse failure leaves the DB intact.
                    conn.execute(
                        "DELETE FROM findings WHERE source_file = 'vuln-registry.md'")
                    for r in reg_entries:
                        upsert_finding(conn, r)
            except Exception as e:
                errors.append(f"vuln-registry.md: {e}")

        if not args.findings_only and not args.registry_only:
            print("Processing INVALIDATED PoCs...")
            try:
                inv_entries = parse_invalidated_pocs()
                total_inv = len(inv_entries)
                if not args.dry_run:
                    for p in inv_entries:
                        upsert_finding(conn, p)
            except Exception as e:
                errors.append(f"INVALIDATED PoCs: {e}")

        if conn:
            conn.commit()

    finally:
        if conn:
            conn.close()

    prefix = "[DRY RUN] " if args.dry_run else ""
    print(f"\n{prefix}Backfill complete:")
    print(f"  Findings from findings.md: {total_findings}")
    print(f"  Triage entries:            {total_triage}")
    print(f"  Registry entries:          {total_registry}")
    print(f"  INVALIDATED PoCs:          {total_inv}")
    if errors:
        print(f"\n  Errors ({len(errors)}):")
        for e in errors[:20]:
            print(f"    - {e}")
    return 0


def cmd_stats(args):
    conn = init_db()
    conn.row_factory = sqlite3.Row

    try:
        if args.semgrep_rule:
            return _stats_semgrep_rule(conn, args)
        elif args.cwe:
            return _stats_cwe(conn, args)
        elif args.vuln_type:
            return _stats_vuln_type(conn, args)
        elif args.status:
            return _stats_status(conn, args)
        else:
            return _stats_all_rules(conn, args)
    finally:
        conn.close()


def _stats_semgrep_rule(conn, args):
    rule = args.semgrep_rule

    findings_rows = conn.execute("""
        SELECT status, COUNT(*) as cnt
        FROM findings WHERE semgrep_rule = ?
        GROUP BY status
    """, (rule,)).fetchall()

    triage_rows = conn.execute("""
        SELECT verdict, COUNT(*) as cnt
        FROM triage_entries WHERE semgrep_rule = ?
        GROUP BY verdict
    """, (rule,)).fetchall()

    audits = conn.execute("""
        SELECT COUNT(DISTINCT plugin_slug || '/' || version) as cnt
        FROM (
            SELECT plugin_slug, version FROM findings WHERE semgrep_rule = ?
            UNION
            SELECT plugin_slug, version FROM triage_entries WHERE semgrep_rule = ?
        )
    """, (rule, rule)).fetchone()["cnt"]

    tp_findings = sum(r["cnt"] for r in findings_rows if r["status"] == "TP")
    inv_findings = sum(r["cnt"] for r in findings_rows if r["status"] == "INVALIDATED")
    fp_triage = sum(r["cnt"] for r in triage_rows if r["verdict"] == "FP")
    oos_triage = sum(r["cnt"] for r in triage_rows if r["verdict"] == "OOS")
    tp_triage = sum(r["cnt"] for r in triage_rows if r["verdict"] == "TP")

    total = tp_findings + fp_triage + oos_triage + inv_findings
    tp_rate = tp_findings / total if total > 0 else 0

    reason_rows = conn.execute("""
        SELECT reason_category, COUNT(*) as cnt
        FROM triage_entries
        WHERE semgrep_rule = ? AND verdict = 'FP'
        GROUP BY reason_category
        ORDER BY cnt DESC
    """, (rule,)).fetchall()

    result = {
        "rule": rule,
        "audits_seen": audits,
        "total_hits": total,
        "tp": tp_findings,
        "fp": fp_triage,
        "oos": oos_triage,
        "invalidated": inv_findings,
        "tp_rate": round(tp_rate, 4),
        "top_fp_reasons": {r["reason_category"]: r["cnt"] for r in reason_rows},
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Rule: {rule}")
        print(f"  Audits seen in:  {audits}")
        print(f"  Total hits:      {total}")
        print(f"  TP:              {tp_findings} ({tp_findings/total*100:.1f}%)" if total else f"  TP:              0")
        print(f"  FP:              {fp_triage} ({fp_triage/total*100:.1f}%)" if total else f"  FP:              0")
        print(f"  OOS:             {oos_triage}")
        print(f"  INVALIDATED:     {inv_findings}")
        print(f"  TP rate:         {tp_rate:.1%}")
        if reason_rows:
            print("  Top FP reasons:")
            for r in reason_rows:
                print(f"    {r['reason_category']:20s} {r['cnt']}")
    return 0


def _stats_cwe(conn, args):
    cwe = args.cwe.upper()
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"

    rows = conn.execute("""
        SELECT status, auth_floor, cvss, semgrep_surfaced
        FROM findings WHERE cwe = ?
    """, (cwe,)).fetchall()

    if not rows:
        print(f"No findings for {cwe}")
        return 0

    by_status = defaultdict(int)
    by_auth = defaultdict(int)
    cvss_vals = []
    semgrep_count = 0

    for r in rows:
        by_status[r["status"]] += 1
        if r["auth_floor"]:
            by_auth[r["auth_floor"]] += 1
        if r["cvss"] is not None:
            cvss_vals.append(r["cvss"])
        if r["semgrep_surfaced"]:
            semgrep_count += 1

    total = len(rows)
    mean_cvss = sum(cvss_vals) / len(cvss_vals) if cvss_vals else 0

    result = {
        "cwe": cwe,
        "total": total,
        "by_status": dict(by_status),
        "by_auth": dict(by_auth),
        "mean_cvss": round(mean_cvss, 1),
        "semgrep_surfaced_pct": round(semgrep_count / total, 3) if total else 0,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"CWE: {cwe}")
        print(f"  Total findings:    {total}")
        for s, c in sorted(by_status.items()):
            print(f"  {s:20s} {c}")
        print(f"  Mean CVSS:         {mean_cvss:.1f}")
        print(f"  Semgrep surfaced:  {semgrep_count} ({semgrep_count/total:.0%})")
        if by_auth:
            print("  By auth floor:")
            for a, c in sorted(by_auth.items(), key=lambda x: -x[1]):
                print(f"    {a:20s} {c}")
    return 0


def _stats_vuln_type(conn, args):
    vtype = args.vuln_type
    normalized = normalize_vuln_type(vtype) or vtype

    rows = conn.execute("""
        SELECT status, auth_floor, cvss, semgrep_surfaced, cwe
        FROM findings WHERE vuln_type = ?
    """, (normalized,)).fetchall()

    if not rows:
        print(f"No findings for vuln type '{normalized}'")
        return 0

    by_status = defaultdict(int)
    by_auth = defaultdict(int)
    by_cwe = defaultdict(int)
    cvss_vals = []
    semgrep_count = 0

    for r in rows:
        by_status[r["status"]] += 1
        if r["auth_floor"]:
            by_auth[r["auth_floor"]] += 1
        if r["cwe"]:
            by_cwe[r["cwe"]] += 1
        if r["cvss"] is not None:
            cvss_vals.append(r["cvss"])
        if r["semgrep_surfaced"]:
            semgrep_count += 1

    total = len(rows)
    mean_cvss = sum(cvss_vals) / len(cvss_vals) if cvss_vals else 0

    result = {
        "vuln_type": normalized,
        "total": total,
        "by_status": dict(by_status),
        "by_auth": dict(by_auth),
        "by_cwe": dict(by_cwe),
        "mean_cvss": round(mean_cvss, 1),
        "semgrep_surfaced_pct": round(semgrep_count / total, 3) if total else 0,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Vuln Type: {normalized}")
        print(f"  Total findings:    {total}")
        for s, c in sorted(by_status.items()):
            print(f"  {s:20s} {c}")
        print(f"  Mean CVSS:         {mean_cvss:.1f}")
        print(f"  Semgrep surfaced:  {semgrep_count} ({semgrep_count/total:.0%})")
        if by_auth:
            print("  By auth floor:")
            for a, c in sorted(by_auth.items(), key=lambda x: -x[1]):
                print(f"    {a:20s} {c}")
    return 0


def _stats_status(conn, args):
    status = args.status.upper()

    rows = conn.execute("""
        SELECT vuln_type, cwe, auth_floor, cvss, plugin_slug
        FROM findings WHERE status = ?
    """, (status,)).fetchall()

    if not rows:
        print(f"No findings with status '{status}'")
        return 0

    by_type = defaultdict(int)
    by_cwe = defaultdict(int)

    for r in rows:
        if r["vuln_type"]:
            by_type[r["vuln_type"]] += 1
        if r["cwe"]:
            by_cwe[r["cwe"]] += 1

    result = {
        "status": status,
        "total": len(rows),
        "by_vuln_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
        "by_cwe": dict(sorted(by_cwe.items(), key=lambda x: -x[1])),
        "unique_plugins": len(set(r["plugin_slug"] for r in rows)),
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Status: {status}")
        print(f"  Total:           {len(rows)}")
        print(f"  Unique plugins:  {result['unique_plugins']}")
        print("  By vuln type:")
        for vt, c in sorted(by_type.items(), key=lambda x: -x[1])[:15]:
            print(f"    {vt:30s} {c}")
        print("  By CWE:")
        for cwe, c in sorted(by_cwe.items(), key=lambda x: -x[1])[:10]:
            print(f"    {cwe:10s} {c}")
    return 0


def _stats_all_rules(conn, args):
    min_audits = args.min_audits or 1

    rows = conn.execute("""
        SELECT
            rule,
            audits,
            tp,
            fp,
            CASE WHEN (tp + fp) > 0 THEN ROUND(CAST(tp AS REAL) / (tp + fp), 4) ELSE 0 END as tp_rate
        FROM (
            SELECT
                combined.rule,
                COUNT(DISTINCT combined.plugin_slug || '/' || combined.version) as audits,
                SUM(CASE WHEN combined.src = 'finding' THEN 1 ELSE 0 END) as tp,
                SUM(CASE WHEN combined.src = 'triage' THEN 1 ELSE 0 END) as fp
            FROM (
                SELECT semgrep_rule as rule, plugin_slug, version, 'finding' as src
                FROM findings WHERE semgrep_rule IS NOT NULL
                UNION ALL
                SELECT semgrep_rule as rule, plugin_slug, version, 'triage' as src
                FROM triage_entries WHERE verdict = 'FP'
            ) combined
            GROUP BY combined.rule
        )
        WHERE audits >= ?
        ORDER BY tp_rate DESC, audits DESC
    """, (min_audits,)).fetchall()

    if not rows:
        print("No semgrep rules found matching criteria")
        return 0

    if args.format == "json":
        result = [
            {"rule": r["rule"], "audits": r["audits"], "tp": r["tp"],
             "fp": r["fp"], "tp_rate": r["tp_rate"]}
            for r in rows
        ]
        print(json.dumps(result, indent=2))
    else:
        print(f"{'Rule':<45s} {'Audits':>6s} {'TP':>5s} {'FP':>5s} {'TP%':>7s}")
        print("-" * 72)
        for r in rows:
            print(f"{r['rule']:<45s} {r['audits']:>6d} {r['tp']:>5d} {r['fp']:>5d} {r['tp_rate']*100:>6.1f}%")
    return 0


# ---------------------------------------------------------------------------
# Expected-value model (mirrors pipeline-stage3-6.md Stage 5a)
# ---------------------------------------------------------------------------

BOUNTY_CONFIG_PATH = SCRIPT_DIR / "bounty_calculator_config.json"


def load_bounty_config():
    try:
        return json.loads(BOUNTY_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def vuln_config_key(cwe, text):
    """Map a finding's CWE (+ summary context) to a vulnerability_types key,
    per the pipeline-stage3-6.md Stage 5a table."""
    c = (cwe or "").upper()
    s = (text or "").lower()
    if c == "CWE-79":
        return "reflected_xss" if "reflect" in s else "stored_xss"
    if c == "CWE-352":
        return "csrf"
    if c == "CWE-862":
        return "arbitrary_options_update" if ("option" in s and ("arbitrary" in s or "settings" in s)) else "missing_authorization"
    if c == "CWE-89":
        return "sql_injection"
    if c == "CWE-639":
        return "insecure_direct_object_reference"
    if c == "CWE-918":
        return None  # SSRF has no bounty_calculator_config.json entry — OOS per current program policy
    if c == "CWE-200":
        return "basic_information_disclosure" if "basic" in s else "information_disclosure"
    if c == "CWE-434":
        return "arbitrary_file_upload"
    if c == "CWE-915":
        return "arbitrary_options_update"
    if c == "CWE-345":
        return "missing_authorization"
    if c == "CWE-502":
        return "php_object_injection"
    if c in ("CWE-94", "CWE-78"):
        # CWE-94/78 also gets used for arbitrary shortcode execution (attacker input
        # reaches do_shortcode()), which Wordfence prices as its own, much lower,
        # category — it is not full RCE and must not fall through to the "rce" key.
        return "arbitrary_shortcode_execution" if "shortcode" in s else "rce"
    if c == "CWE-22":
        return "directory_traversal"
    if c in ("CWE-269", "CWE-287", "CWE-288"):
        # CWE-269 = Privilege Escalation, CWE-287/288 = Authentication Bypass — each
        # has separate admin/non-admin bounty tiers. A plain "admin" substring check
        # misfires on "non-admin" text, so match the negated form first.
        is_non_admin = re.search(r"non[\s-]?admin", s) is not None
        if c == "CWE-269":
            return "privilege_escalation_non_admin" if is_non_admin else "privilege_escalation_admin"
        return "authorization_bypass_non_admin" if is_non_admin else "authorization_bypass_admin"
    # Fallback by normalized vuln-type text
    vt_key = {
        "stored xss": "stored_xss", "reflected xss": "reflected_xss", "xss": "stored_xss",
        "csrf": "csrf", "missing authorization": "missing_authorization",
        "idor": "insecure_direct_object_reference", "sql injection": "sql_injection",
        "information disclosure": "information_disclosure",
        "arbitrary file upload": "arbitrary_file_upload", "limited file upload": "arbitrary_file_upload",
        "arbitrary file read": "arbitrary_file_read", "arbitrary file deletion": "arbitrary_file_deletion",
        "rce": "rce", "php object injection": "php_object_injection",
        "arbitrary shortcode execution": "arbitrary_shortcode_execution",
        "auth bypass": "authorization_bypass_admin", "privilege escalation": "privilege_escalation_admin",
        "directory traversal": "directory_traversal", "lfi": "file_inclusion",
        "email injection": "information_disclosure", "arbitrary options update": "arbitrary_options_update",
    }
    norm = (normalize_vuln_type(text) or "").lower()
    return vt_key.get(norm)


def auth_divisor_key(auth_floor):
    """Returns 'none'/'low'/'mid'/'high', or None when auth_floor is missing or
    unrecognized. Callers must treat None as ineligible/unknown — silently
    defaulting an unrecorded auth level to "none" (Unauthenticated) would
    optimistically hand a data gap the single best-paying divisor."""
    a = (auth_floor or "").strip().lower()
    if not a:
        return None
    if "unauth" in a or "pr:n" in a or a == "no authentication":
        return "none"
    if "subscriber" in a or "customer" in a or "student" in a:
        return "low"
    if "contributor" in a or "author" in a:
        return "mid"
    if any(k in a for k in ("admin", "editor", "shop manager", "super")):
        return "high"
    return None


def install_multiplier(installs, config):
    if installs is None:
        return None
    for tier in config["install_count_tiers"].values():
        lo, hi = tier["min_count"], tier["max_count"]
        if installs >= lo and (hi is None or installs <= hi):
            return tier["multiplier"]
    return None


# Per global CLAUDE.md: "If researcher tier not set in project CLAUDE.md, assume
# Standard Researcher and flag the finding." No tier is set in this project's
# CLAUDE.md, so Standard Researcher drives the install-count floor below for
# every vuln type without its own category-specific override.
DEFAULT_RESEARCHER_TIER = "Standard Researcher"


def _researcher_tier(config, tier_name):
    for t in config.get("researcher_tiers", []):
        if t.get("name") == tier_name:
            return t
    return None


def _min_installs_for(key, auth_bucket, config, tier_name):
    """Wordfence's install floor for bounty eligibility (global CLAUDE.md table):
    High Threat categories (RCE, file upload/read/delete, options update, auth
    bypass/privesc to admin) = 25; Common & Dangerous (stored XSS, SQLi) = 500;
    everything else uses the researcher tier's general minimum (Standard 50,000 /
    Resourceful 10,000 / 1337 500). bounty_calculator_config.json encodes the
    first two via authentication_level_min_install_counts; the third was
    previously unimplemented here, which let low-install "other" category
    findings (CSRF, IDOR, missing authorization, info disclosure, ...) show a
    nonzero EV below the researcher's actual eligibility floor."""
    overrides = config["vulnerability_types"][key].get("authentication_level_min_install_counts") or {}
    for min_str, buckets in overrides.items():
        if auth_bucket in buckets:
            return int(min_str)
    tier = _researcher_tier(config, tier_name)
    return tier["min_install_count"] if tier else 0


def compute_ev(cwe, vuln_type, auth_floor, installs, summary, config, researcher_tier=DEFAULT_RESEARCHER_TIER):
    """Return (low_est, high_est) bounty range, or None if ineligible/unknown.
    Mirrors Stage 5a: base / divisor * install_mult * impact (0.25..1.0)."""
    key = vuln_config_key(cwe, vuln_type or summary)
    if not key or key not in config["vulnerability_types"]:
        return None
    auth_bucket = auth_divisor_key(auth_floor)
    if auth_bucket is None:    # auth level missing/unrecognized → unknown, not "unauthenticated"
        return None
    divisor = config["authentication_levels"][auth_bucket]["divisor"]
    if divisor is None:        # contributor/author/admin-tier auth → ineligible
        return None
    if installs is None:
        return None
    mult = install_multiplier(installs, config)
    if mult is None:           # unknown install count
        return None
    min_required = _min_installs_for(key, auth_bucket, config, researcher_tier)
    if mult == 0 or installs < min_required:
        return (0, 0)
    base = config["vulnerability_types"][key]["value"]
    tier = _researcher_tier(config, researcher_tier) or {}
    tier_bonus = tier.get("bounty_multiplier")
    tier_bonus = float(tier_bonus) if tier_bonus not in (None, "") else 1.0
    gmult = (config.get("global_multiplier") or 1) * tier_bonus
    gmin = config.get("global_minimum", 5)
    low = int(base / divisor * mult * 0.25 * gmult)
    high = int(base / divisor * mult * 1.0 * gmult)
    low = max(low, gmin) if low > 0 else 0
    high = max(high, gmin) if high > 0 else 0
    return (low, high)


# vuln_type / CWE -> pipeline tier-group (for yield attribution & relay collapse).
# Canonical mapping lives in group_registry so the semgrep/grep/accumulator layers agree.
def vuln_group(cwe, vuln_type):
    return group_registry.vuln_group(cwe, vuln_type)


GROUP_LABELS = group_registry.accumulator_group_labels()


def cmd_dashboard(args):
    conn = init_db()
    conn.row_factory = sqlite3.Row
    config = load_bounty_config()
    out = {}
    try:
        # ---- Block 1: submission funnel -------------------------------------
        total = conn.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
        tp = conn.execute("SELECT COUNT(*) n FROM findings WHERE status='TP'").fetchone()["n"]
        has_reg = conn.execute(
            "SELECT COUNT(*) n FROM findings WHERE status='TP' AND registry_status IS NOT NULL "
            "AND TRIM(registry_status) != ''").fetchone()["n"]
        submitted = conn.execute(
            "SELECT COUNT(*) n FROM findings WHERE status='TP' AND registry_status LIKE '%Submitted%'"
        ).fetchone()["n"]
        sub_clean = conn.execute(
            "SELECT COUNT(*) n FROM findings WHERE status='TP' AND registry_status LIKE '%Submitted%' "
            "AND registry_status NOT LIKE '%Duplicate%'").fetchone()["n"]
        funnel = {
            "total_findings": total, "tp": tp, "has_registry_status": has_reg,
            "submitted": submitted, "submitted_not_duplicate": sub_clean,
            "stuck_ready_unsubmitted": has_reg - submitted,
            "duplicate_rate_of_submitted": round((submitted - sub_clean) / submitted, 2) if submitted else 0,
        }
        out["funnel"] = funnel

        # ---- Block 2: EV ranking of holdable (registry-logged, unsubmitted) -
        holdable = []
        if config:
            rows = conn.execute(
                "SELECT plugin_slug, version, cwe, vuln_type, auth_floor, installs, summary, "
                "registry_status FROM findings WHERE status='TP' "
                "AND registry_status IS NOT NULL AND TRIM(registry_status) != '' "
                "AND registry_status NOT LIKE '%Submitted%'").fetchall()
            for r in rows:
                ev = compute_ev(r["cwe"], r["vuln_type"], r["auth_floor"],
                                r["installs"], r["summary"], config)
                if ev is None:
                    continue
                holdable.append({
                    "plugin": r["plugin_slug"], "cwe": r["cwe"],
                    "vuln_type": r["vuln_type"], "auth": r["auth_floor"],
                    "installs": r["installs"], "ev_low": ev[0], "ev_high": ev[1],
                    "summary": (r["summary"] or "")[:70],
                })
            holdable.sort(key=lambda x: (x["ev_high"], x["ev_low"]), reverse=True)
        out["researcher_tier_assumed"] = DEFAULT_RESEARCHER_TIER
        out["holdable_top"] = holdable[:15]

        # ---- Block 3: dead-rule kill-list -----------------------------------
        rule_rows = conn.execute("""
            SELECT rule, tp, fp,
                   CASE WHEN (tp+fp)>0 THEN CAST(tp AS REAL)/(tp+fp) ELSE 0 END rate
            FROM (
                SELECT combined.rule,
                       SUM(CASE WHEN src='finding' THEN 1 ELSE 0 END) tp,
                       SUM(CASE WHEN src='triage' THEN 1 ELSE 0 END) fp
                FROM (
                    SELECT semgrep_rule rule, 'finding' src FROM findings WHERE semgrep_rule IS NOT NULL
                    UNION ALL
                    SELECT semgrep_rule rule, 'triage' src FROM triage_entries WHERE verdict='FP'
                ) combined GROUP BY combined.rule
            )
        """).fetchall()
        dead_rules = []
        for r in rule_rows:
            if (r["fp"] >= 10 and r["tp"] == 0) or (r["rate"] < 0.05 and (r["tp"] + r["fp"]) >= 3):
                dead_rules.append({"rule": r["rule"], "tp": r["tp"], "fp": r["fp"],
                                   "tp_pct": round(r["rate"] * 100, 1)})
        dead_rules.sort(key=lambda x: (x["fp"], -x["tp_pct"]), reverse=True)
        out["dead_rules"] = dead_rules

        # ---- Block 4: dead-section prune-list -------------------------------
        sec_hits, sec_tp = defaultdict(int), defaultdict(int)
        for r in conn.execute("SELECT grep_section, status FROM findings WHERE grep_section IS NOT NULL"):
            for sec in (r["grep_section"] or "").split(","):
                sec = sec.strip()
                if not sec:
                    continue
                sec_hits[sec] += 1
                if r["status"] == "TP":
                    sec_tp[sec] += 1
        sections = sorted(({"section": s, "hits": sec_hits[s], "tp": sec_tp[s]} for s in sec_hits),
                          key=lambda x: x["hits"], reverse=True)
        dead_sections = [s for s in sections if s["hits"] >= 10 and s["tp"] == 0]
        out["sections_by_hits"] = sections
        out["dead_sections"] = dead_sections

        # ---- Block 5: tier-group yield + relay-collapse verdict -------------
        grp_tp = defaultdict(int)
        for r in conn.execute("SELECT cwe, vuln_type FROM findings WHERE status='TP'"):
            grp_tp[vuln_group(r["cwe"], r["vuln_type"])] += 1
        group_yield = []
        for g in group_registry.accumulator_dashboard_order():
            n = grp_tp.get(g, 0)
            verdict = "EARNS" if n >= 5 else ("COLLAPSE CANDIDATE" if n < 2 else "KEEP")
            group_yield.append({"group": g, "label": GROUP_LABELS[g], "tp": n, "verdict": verdict})
        out["group_yield"] = group_yield
        out["group_other_tp"] = grp_tp.get("other", 0)

        if args.format == "json":
            print(json.dumps(out, indent=2))
            return 0

        # ---- text rendering -------------------------------------------------
        print("=" * 74)
        print("PATTERN ACCUMULATOR DASHBOARD")
        print("=" * 74)

        print("\n[1] SUBMISSION FUNNEL")
        print(f"    total findings .................. {funnel['total_findings']}")
        print(f"     └─ TP (confirmed) .............. {funnel['tp']}")
        print(f"         └─ logged to registry ...... {funnel['has_registry_status']}")
        print(f"             └─ Submitted ........... {funnel['submitted']}")
        print(f"                 └─ not Duplicate ... {funnel['submitted_not_duplicate']}")
        print(f"    => {funnel['stuck_ready_unsubmitted']} ready-to-submit but NOT submitted (slot backlog)")
        print(f"    => duplicate rate of submitted: {funnel['duplicate_rate_of_submitted']*100:.0f}%")

        print("\n[2] EV RANKING — top holdable (registry-logged, unsubmitted)")
        print(f"    (assumes {DEFAULT_RESEARCHER_TIER} — edit DEFAULT_RESEARCHER_TIER in "
              f"pattern_accumulator.py if that's not your actual tier)")
        if not config:
            print("    (bounty_calculator_config.json not found — EV unavailable)")
        elif not holdable:
            print("    (no eligible unsubmitted findings with computable EV)")
        else:
            print(f"    {'EV $low-$high':>14s}  {'auth':<14s} {'installs':>9s}  plugin / summary")
            for h in holdable[:15]:
                ev = f"${h['ev_low']}-${h['ev_high']}"
                print(f"    {ev:>14s}  {(h['auth'] or '?')[:14]:<14s} {str(h['installs'] or '?'):>9s}  "
                      f"{h['plugin']}: {h['summary']}")

        print("\n[3] DEAD-RULE KILL-LIST (Semgrep: FP≥10 & TP=0, or TP%<5%)")
        if not dead_rules:
            print("    (none)")
        else:
            print(f"    {'rule':<46s} {'TP':>4s} {'FP':>4s} {'TP%':>6s}")
            for d in dead_rules:
                print(f"    {d['rule']:<46s} {d['tp']:>4d} {d['fp']:>4d} {d['tp_pct']:>5.1f}%")

        print("\n[4] DEAD-SECTION PRUNE-LIST (grep section: hits≥10 & TP=0)")
        if not dead_sections:
            print("    (none meet the hits≥10 & TP=0 bar — grep_section is finding-only,")
            print("     so the signal is conservative; see top sections by hits below)")
        else:
            for s in dead_sections:
                print(f"    {s['section']:<40s} hits={s['hits']} tp=0")
        print("    Top grep sections by attributed findings (hits / TP):")
        for s in sections[:12]:
            print(f"      {s['section']:<40s} {s['hits']:>3d} / {s['tp']:>3d} TP")

        print("\n[5] TIER-GROUP YIELD (lifetime TP) + relay-collapse verdict")
        for g in group_yield:
            print(f"    {g['label']:<48s} {g['tp']:>3d} TP   {g['verdict']}")
        if out["group_other_tp"]:
            print(f"    {'(unmapped vuln types)':<48s} {out['group_other_tp']:>3d} TP")
        print("=" * 74)
    finally:
        conn.close()
    return 0


def cmd_fp_causes(args):
    """Histogram of FP reason_category across all dismissed leads, with the top
    rules per category — a ranked 'prevention backlog' for tune-vuln-audit."""
    conn = init_db()
    conn.row_factory = sqlite3.Row
    try:
        cats = conn.execute("""
            SELECT reason_category, COUNT(*) n FROM triage_entries
            WHERE verdict='FP' GROUP BY reason_category ORDER BY n DESC
        """).fetchall()
        total_fp = sum(r["n"] for r in cats)
        result = {"total_fp": total_fp, "categories": []}
        for c in cats:
            cat = c["reason_category"]
            top_rules = conn.execute("""
                SELECT semgrep_rule, COUNT(*) n FROM triage_entries
                WHERE verdict='FP' AND reason_category=?
                GROUP BY semgrep_rule ORDER BY n DESC LIMIT 5
            """, (cat,)).fetchall()
            result["categories"].append({
                "category": cat, "count": c["n"],
                "pct": round(c["n"] / total_fp * 100, 1) if total_fp else 0,
                "top_rules": {r["semgrep_rule"]: r["n"] for r in top_rules},
            })

        if args.format == "json":
            print(json.dumps(result, indent=2))
            return 0

        print("=" * 74)
        print(f"FP-CAUSE MINING  —  {total_fp} dismissed (FP) leads")
        print("=" * 74)
        print("Ranked prevention backlog (each category = effort the pipeline spends")
        print("dismissing; the top ones are candidate FP-prevention rules for")
        print("tune-vuln-audit SKILL.md Phase 4):\n")
        for i, c in enumerate(result["categories"], 1):
            print(f"{i}. {c['category']:<16s} {c['count']:>4d}  ({c['pct']:.0f}%)")
            rules = ", ".join(f"{k} ×{v}" for k, v in c["top_rules"].items() if k)
            if rules:
                print(f"     top rules: {rules}")
        print("=" * 74)
    finally:
        conn.close()
    return 0


def cmd_prune_stale(args):
    """Purge/reclassify rows whose semgrep_rule no longer exists in the
    current semgrep_rules/ corpus.

    Rules get renamed or deleted (e.g. after a false-positive audit), but
    ingest()/backfill() only UPSERT — they never delete a triage_entries row
    or clear a findings row for a plugin+version already in the DB. Old rows
    recorded under a since-renamed/deleted rule id linger forever and keep
    resurfacing in dashboard's dead-rule kill-list even though there is
    nothing left to act on. This command is the one-time (and repeatable)
    cleanup: triage_entries rows are always FP/OOS (never TP — see
    _normalize_verdict), so a stale one is pure noise and gets deleted
    outright. A findings row is a real confirmed vulnerability regardless of
    whether the rule that surfaced it still exists, so it is never deleted —
    only reclassified back to "independent discovery" (semgrep_rule=NULL,
    semgrep_surfaced=0), which is the accurate bookkeeping state once the
    original rule attribution can no longer be verified against the corpus.
    """
    corpus = corpus_rule_ids()
    conn = init_db()
    conn.row_factory = sqlite3.Row
    try:
        triage_counts = conn.execute("""
            SELECT semgrep_rule, COUNT(*) as cnt FROM triage_entries
            WHERE semgrep_rule IS NOT NULL GROUP BY semgrep_rule
        """).fetchall()
        stale_triage = {r["semgrep_rule"]: r["cnt"] for r in triage_counts
                         if r["semgrep_rule"] not in corpus}

        finding_counts = conn.execute("""
            SELECT semgrep_rule, COUNT(*) as cnt FROM findings
            WHERE semgrep_rule IS NOT NULL GROUP BY semgrep_rule
        """).fetchall()
        stale_findings = {r["semgrep_rule"]: r["cnt"] for r in finding_counts
                           if r["semgrep_rule"] not in corpus}

        all_stale = sorted(set(stale_triage) | set(stale_findings))
        total_triage = sum(stale_triage.values())
        total_findings = sum(stale_findings.values())

        preview = {
            "corpus_rule_count": len(corpus),
            "stale_rule_count": len(all_stale),
            "triage_rows_to_delete": total_triage,
            "finding_rows_to_reclassify": total_findings,
            "by_rule": {
                r: {"triage_rows": stale_triage.get(r, 0),
                    "finding_rows": stale_findings.get(r, 0)}
                for r in all_stale
            },
        }

        if args.format == "json" and args.dry_run:
            print(json.dumps(preview, indent=2))
            return 0

        if args.format != "json":
            print("=" * 74)
            print(f"{'[DRY RUN] ' if args.dry_run else ''}PRUNE STALE SEMGREP RULE REFERENCES")
            print("=" * 74)
            print(f"Corpus rules loaded:      {len(corpus)}")
            print(f"Stale rule names found:   {len(all_stale)}")
            print(f"  triage_entries rows to delete:       {total_triage}")
            print(f"  findings rows to reclassify (NULL):  {total_findings}")
            if all_stale:
                print(f"\n{'rule':<48s} {'triage':>7s} {'findings':>9s}")
                for r in all_stale:
                    print(f"{r:<48s} {stale_triage.get(r, 0):>7d} {stale_findings.get(r, 0):>9d}")
            if args.dry_run:
                print("\n[DRY RUN] No changes made. Re-run without --dry-run to apply.")
                return 0

        if not all_stale:
            return 0

        deleted_triage = 0
        for r in stale_triage:
            cur = conn.execute("DELETE FROM triage_entries WHERE semgrep_rule = ?", (r,))
            deleted_triage += cur.rowcount
        reclassified = 0
        for r in stale_findings:
            cur = conn.execute(
                "UPDATE findings SET semgrep_rule = NULL, semgrep_surfaced = 0 "
                "WHERE semgrep_rule = ?", (r,))
            reclassified += cur.rowcount
        conn.commit()

        if args.format == "json":
            print(json.dumps({
                "deleted_triage_rows": deleted_triage,
                "reclassified_finding_rows": reclassified,
            }, indent=2))
        else:
            print(f"\nDeleted {deleted_triage} stale triage_entries rows.")
            print(f"Reclassified {reclassified} findings rows to independent-discovery "
                  f"(semgrep_rule=NULL, semgrep_surfaced=0).")
    finally:
        conn.close()
    return 0


def cmd_summary(args):
    conn = init_db()
    conn.row_factory = sqlite3.Row

    try:
        total = conn.execute("SELECT COUNT(*) as n FROM findings").fetchone()["n"]
        by_status = conn.execute("""
            SELECT status, COUNT(*) as cnt FROM findings GROUP BY status ORDER BY cnt DESC
        """).fetchall()
        by_type = conn.execute("""
            SELECT vuln_type, COUNT(*) as cnt FROM findings
            WHERE status = 'TP' GROUP BY vuln_type ORDER BY cnt DESC LIMIT 15
        """).fetchall()
        by_cwe = conn.execute("""
            SELECT cwe, COUNT(*) as cnt FROM findings
            WHERE status = 'TP' GROUP BY cwe ORDER BY cnt DESC LIMIT 10
        """).fetchall()
        triage_total = conn.execute("SELECT COUNT(*) as n FROM triage_entries").fetchone()["n"]
        triage_by_verdict = conn.execute("""
            SELECT verdict, COUNT(*) as cnt FROM triage_entries GROUP BY verdict ORDER BY cnt DESC
        """).fetchall()
        unique_plugins = conn.execute("""
            SELECT COUNT(DISTINCT plugin_slug) as n FROM findings
        """).fetchone()["n"]
        unique_audits = conn.execute("""
            SELECT COUNT(DISTINCT plugin_slug || '/' || version) as n FROM findings
        """).fetchone()["n"]

        if args.format == "json":
            result = {
                "total_findings": total,
                "by_status": {r["status"]: r["cnt"] for r in by_status},
                "top_vuln_types": {r["vuln_type"]: r["cnt"] for r in by_type},
                "top_cwes": {r["cwe"]: r["cnt"] for r in by_cwe},
                "triage_total": triage_total,
                "triage_by_verdict": {r["verdict"]: r["cnt"] for r in triage_by_verdict},
                "unique_plugins": unique_plugins,
                "unique_audits": unique_audits,
            }
            print(json.dumps(result, indent=2))
        else:
            print("=== Pattern Accumulator Summary ===")
            print(f"\nFindings: {total} total across {unique_audits} audits ({unique_plugins} plugins)")
            print("\nBy status:")
            for r in by_status:
                print(f"  {r['status']:20s} {r['cnt']}")
            print("\nTop vuln types (TP only):")
            for r in by_type:
                vt = r["vuln_type"] or "(unknown)"
                print(f"  {vt:30s} {r['cnt']}")
            print("\nTop CWEs (TP only):")
            for r in by_cwe:
                c = r["cwe"] or "(unknown)"
                print(f"  {c:10s} {r['cnt']}")
            print(f"\nTriage entries: {triage_total}")
            for r in triage_by_verdict:
                print(f"  {r['verdict']:10s} {r['cnt']}")

    finally:
        conn.close()
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cross-audit pattern database for tune-* skills",
    )
    sub = parser.add_subparsers(dest="command")

    p_ingest = sub.add_parser("ingest", help="Ingest a single audit directory")
    p_ingest.add_argument("audit_dir", help="Path to audit/<slug>/<version>/ directory")
    p_ingest.add_argument("--dry-run", action="store_true", help="Parse only, don't write to DB")

    p_backfill = sub.add_parser("backfill", help="Bulk-load from all sources")
    p_backfill.add_argument("--dry-run", action="store_true", help="Parse only, don't write to DB")
    p_backfill.add_argument("--registry-only", action="store_true")
    p_backfill.add_argument("--findings-only", action="store_true")
    p_backfill.add_argument("--invalidated-only", action="store_true")

    p_stats = sub.add_parser("stats", help="Query aggregate statistics")
    p_stats.add_argument("--semgrep-rule", help="Stats for a specific Semgrep rule")
    p_stats.add_argument("--cwe", help="Stats for a CWE (e.g. CWE-862)")
    p_stats.add_argument("--vuln-type", help="Stats for a vuln type (e.g. 'Missing Authorization')")
    p_stats.add_argument("--status", help="Filter by status (TP/FP/INVALIDATED/REJECTED)")
    p_stats.add_argument("--min-audits", type=int, help="Only show rules seen in N+ audits")
    p_stats.add_argument("--format", choices=["table", "json"], default="table")

    p_summary = sub.add_parser("summary", help="Global summary")
    p_summary.add_argument("--format", choices=["table", "json"], default="table")

    p_dash = sub.add_parser("dashboard", help="Operator dashboard (read-only): funnel, "
                                              "EV ranking, dead-rule/section lists, tier yield")
    p_dash.add_argument("--format", choices=["table", "json"], default="table")

    p_fp = sub.add_parser("fp-causes", help="FP reason-category histogram + prevention backlog")
    p_fp.add_argument("--format", choices=["table", "json"], default="table")

    p_prune = sub.add_parser("prune-stale", help="Delete/reclassify DB rows whose semgrep_rule "
                                                  "no longer exists in the semgrep_rules/ corpus")
    p_prune.add_argument("--dry-run", action="store_true", help="Show what would change, don't write")
    p_prune.add_argument("--format", choices=["table", "json"], default="table")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "ingest":
        return cmd_ingest(args)
    elif args.command == "backfill":
        return cmd_backfill(args)
    elif args.command == "stats":
        return cmd_stats(args)
    elif args.command == "summary":
        return cmd_summary(args)
    elif args.command == "dashboard":
        return cmd_dashboard(args)
    elif args.command == "fp-causes":
        return cmd_fp_causes(args)
    elif args.command == "prune-stale":
        return cmd_prune_stale(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
