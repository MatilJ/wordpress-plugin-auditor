#!/usr/bin/env python3
"""
diff_audit.py - Edge 1: turn a NEW plugin release into a cheap, focused audit by
isolating the PHP changeset between the version you already audited and the new one.

A new release is the highest-EV target (fresh, uncontested code) but re-running the
full pipeline over the whole plugin wastes effort on unchanged code. This script
diffs old->new (PHP only), flags new/changed entry points (the priority targets),
and writes audit/<slug>/<new_v>/DIFF.md so a Claude session can focus on the delta.

CLI:
  python diff_audit.py <slug>                          # diff audited version -> current WP release
  python diff_audit.py <slug> --new-version 1.2.4      # diff against a specific version
  python diff_audit.py <slug> --scan                   # + Semgrep pre-scan the new version (pipeline-ready)
  python diff_audit.py <slug> --old-version 4.1.0 --new-version 4.1.1
                                                       # read a Wordfence patch (last-affected -> patched)

Importable helpers (reused by wf_variants.py / daily_targets.py):
  download_version(slug, version) -> path|None     # ensure source on disk
  diff_php(slug, old_v, new_v)    -> dict          # structured PHP-only diff
"""
import argparse
import bisect
import json
import os
import re
import subprocess
import sys
import zipfile
import io
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
PLUGINS_DIR = os.path.join(ROOT, "plugins")
AUDIT_DIR = os.path.join(ROOT, "audit")
DOWNLOADER = os.path.join(ROOT, "wp-plugin-downlauditor.py")

sys.path.insert(0, ROOT)  # allow `import audit_targets` regardless of cwd
from audit_targets import (vkey, audited_versions, online_current_version,  # noqa: E402
                           ensure_semgrep_scan, newest_local_version)

ZIP_URL = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
INFO_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"

# Entry-point signatures: an added one is new attack surface; a removed one was
# patched away. These are the lines a diff-audit should examine first.
_RX = {
    "function":     re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\("),
    "add_action":   re.compile(r"\badd_action\s*\(\s*['\"]([^'\"]+)['\"]"),
    "add_filter":   re.compile(r"\badd_filter\s*\(\s*['\"]([^'\"]+)['\"]"),
    "rest_route":   re.compile(r"\bregister_rest_route\s*\(\s*['\"]([^'\"]*)['\"]"),
    "add_shortcode": re.compile(r"\badd_shortcode\s*\(\s*['\"]([^'\"]+)['\"]"),
    "ajax":         re.compile(r"wp_ajax(?:_nopriv)?_([A-Za-z0-9_\-]+)"),
}


# --------------------------------------------------------------------------- #
# Version resolution
# --------------------------------------------------------------------------- #
def resolve_old_version(slug):
    """Highest version present under plugins/<slug>/ that ALSO has an audit dir."""
    pdir = os.path.join(PLUGINS_DIR, slug)
    if not os.path.isdir(pdir):
        return None
    local = [v for v in os.listdir(pdir) if os.path.isdir(os.path.join(pdir, v))]
    audited = set(audited_versions(slug))
    both = [v for v in local if v in audited]
    return max(both, key=vkey) if both else None


def resolve_new_version(slug, arg=None):
    return arg or online_current_version(slug)


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #
def _zip_fallback(slug, version):
    """Direct download from downloads.wordpress.org; returns path or None on 404."""
    try:
        import requests
    except ImportError:
        return None
    url = ZIP_URL.format(slug=slug, version=version)
    try:
        r = requests.get(url, timeout=30,
                         headers={"User-Agent": "wordpress-plugin-auditor/1.0"})
        if r.status_code != 200:
            return None
        dest = os.path.join(PLUGINS_DIR, slug, version)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            tmp = dest + ".tmp_extract"
            if os.path.isdir(tmp):
                import shutil
                shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp, exist_ok=True)
            zf.extractall(tmp)
            inner = os.path.join(tmp, slug)
            import shutil
            shutil.move(inner if os.path.isdir(inner) else tmp, dest)
            if os.path.isdir(tmp):
                shutil.rmtree(tmp, ignore_errors=True)
        return dest if os.path.isdir(dest) else None
    except Exception:
        return None


def download_version(slug, version):
    """Ensure plugins/<slug>/<version>/ exists; return its path (or None on failure).

    Reuses the project downloader (handles zip/extract); falls back to a direct
    downloads.wordpress.org fetch. Idempotent."""
    path = os.path.join(PLUGINS_DIR, slug, version)
    if os.path.isdir(path):
        return path
    cmd = [sys.executable, DOWNLOADER, "--plugin", slug, "--version", version, "-d", ROOT]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        pass
    if os.path.isdir(path):
        return path
    # downloader sanitises the version dir name; check that spelling too
    san = re.sub(r"[^a-zA-Z0-9._-]", "", version)
    sp = os.path.join(PLUGINS_DIR, slug, san)
    if san != version and os.path.isdir(sp):
        return sp
    return _zip_fallback(slug, version)


# --------------------------------------------------------------------------- #
# Download-failure diagnostics
# --------------------------------------------------------------------------- #
# A specific version zip 404s for two very different reasons that the old
# "zip 404 / network" message conflated: (a) the author pruned that release tag
# (WP.org keeps only a SUBSET of past versions — the downloads host AND SVN both
# 404), or (b) a transient network error. Case (a) is unrecoverable from WP.org
# and needs a DIFFERENT --old-version; case (b) just needs a retry. Tell them apart.
def available_versions(slug, timeout=15):
    """Version strings WP.org will actually serve for `slug`, ascending by version key.

    Returns None on API/network failure (lets callers separate a pruned tag from
    being offline). Excludes the 'trunk' pseudo-version."""
    import urllib.request
    try:
        with urllib.request.urlopen(INFO_API.format(slug=slug), timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None
    vs = data.get("versions") or {}
    keys = [k for k in vs if k and k.lower() != "trunk"]
    keys.sort(key=vkey)
    return keys


def _nearest_versions(target, versions, n=6):
    """Up to `n` published versions bracketing `target` (by version key)."""
    if not versions:
        return []
    keys = [vkey(v) for v in versions]
    i = bisect.bisect_left(keys, vkey(target))
    start = max(0, i - n // 2)
    end = min(len(versions), start + n)
    start = max(0, end - n)  # keep a full window when target sits near an edge
    return versions[start:end]


def _download_failure_reason(slug, version):
    """Actionable message for a failed download_version(slug, version)."""
    avail = available_versions(slug)
    if avail is None:
        return (f"could not obtain {slug} {version}: WP.org API unreachable "
                f"(network/offline?). Retry when online.")
    if version in avail:
        return (f"{slug} {version} IS published on WP.org but the download failed "
                f"(transient network / extract error) — retry.")
    near = _nearest_versions(version, avail)
    local = newest_local_version(slug)
    msg = (f"{slug} {version} is NOT published on WordPress.org — the author pruned "
           f"that release tag (downloads host AND SVN both 404 for it; WP.org keeps "
           f"only a subset of past versions). It cannot be fetched from WP.org.")
    if near:
        msg += f" Published versions near it: {', '.join(near)}."
    msg += f" Newest published: {avail[-1]}."
    if local:
        msg += f" On disk you could diff from: {local} (--old-version {local})."
    return msg


def nearest_published_below(slug, version):
    """Newest version WP.org still serves that is strictly BELOW `version`.

    This is the ideal downloadable baseline for a patch-diff when the exact
    last-affected tag was pruned: since `version` is the first PATCHED release, the
    newest published version under it is guaranteed to be pre-fix (still vulnerable)
    AND actually fetchable. Returns None if the API is unreachable or nothing
    qualifies (author pruned everything below the patch)."""
    avail = available_versions(slug)
    if not avail:
        return None
    below = [v for v in avail if vkey(v) < vkey(version)]
    return below[-1] if below else None  # avail is ascending -> last = newest below


# --------------------------------------------------------------------------- #
# Diff
# --------------------------------------------------------------------------- #
def _run_git_diff(old_rel, new_rel):
    cmd = ["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false",
           "diff", "--no-index", "--no-color", "-U3", "--", old_rel, new_rel]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True)
    # git diff --no-index exits 1 when there ARE differences (>1 = real error)
    if proc.returncode > 1:
        err = proc.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"git diff failed (rc={proc.returncode}): {err[:300]}")
    return proc.stdout.decode("utf-8", "replace")


def _split_sections(diff_text):
    sections, cur = [], []
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git ") and cur:
            sections.append("".join(cur))
            cur = [line]
        else:
            cur.append(line)
    if cur:
        sections.append("".join(cur))
    return sections


def _strip_prefix(path, prefixes):
    for p in prefixes:
        if path and path.startswith(p):
            return path[len(p):]
    return path


def _section_meta(section, old_prefix, new_prefix):
    """Return (relpath, status, is_php) for one diff section."""
    old_path = new_path = None
    status = "modified"
    for ln in section.splitlines()[:10]:
        if ln.startswith("--- "):
            p = ln[4:].strip()
            old_path = None if p == "/dev/null" else (p[2:] if p[:2] in ("a/", "b/") else p)
        elif ln.startswith("+++ "):
            p = ln[4:].strip()
            new_path = None if p == "/dev/null" else (p[2:] if p[:2] in ("a/", "b/") else p)
        elif ln.startswith("new file"):
            status = "added"
        elif ln.startswith("deleted file"):
            status = "deleted"
        elif ln.startswith("rename to "):
            status = "renamed"

    raw = new_path or old_path or ""
    rel = _strip_prefix(raw, [new_prefix, old_prefix])
    if new_path is None and old_path is not None:
        status = "deleted"
    elif old_path is None and new_path is not None and status != "added":
        status = "added"
    is_php = rel.lower().endswith(".php") and "semgrep-scan/" not in rel
    return rel, status, is_php


def _is_translation(rel):
    """WP translation caches (.l10n.php) and lang/languages dirs: machine-generated,
    no auditable logic, and they churn every release. Excluded from the real diff."""
    rl = rel.lower()
    if rl.endswith(".l10n.php"):
        return True
    segs = rl.split("/")
    return any(s in ("lang", "languages") for s in segs[:-1])


def _count_changes(section):
    added = deleted = 0
    for ln in section.splitlines():
        if ln.startswith("+") and not ln.startswith("+++"):
            added += 1
        elif ln.startswith("-") and not ln.startswith("---"):
            deleted += 1
    return added, deleted


def _extract_entry_points(rel, section):
    """Find added/removed entry points (functions, hooks, REST routes, shortcodes, ajax)."""
    found = []
    seen = set()
    for ln in section.splitlines():
        if ln.startswith("+++") or ln.startswith("---") or ln.startswith("@@"):
            continue
        if ln.startswith("+"):
            sign = "+"
        elif ln.startswith("-"):
            sign = "-"
        else:
            continue
        body = ln[1:]
        for kind, rx in _RX.items():
            for m in rx.finditer(body):
                name = m.group(1) if m.groups() else ""
                key = (sign, kind, name, rel)
                if key in seen:
                    continue
                seen.add(key)
                found.append({"path": rel, "kind": kind, "name": name, "sign": sign})
    return found


def diff_php(slug, old_v, new_v):
    """Structured PHP-only diff between two on-disk versions of a plugin.

    Requires plugins/<slug>/<old_v>/ and plugins/<slug>/<new_v>/ to exist.
    Returns a dict with per-file diffs, changed entry points and totals."""
    old_rel = f"plugins/{slug}/{old_v}"
    new_rel = f"plugins/{slug}/{new_v}"
    old_prefix, new_prefix = old_rel + "/", new_rel + "/"

    diff_text = _run_git_diff(old_rel, new_rel)
    files, entry_points = [], []
    php_chunks = []
    n_translation = 0
    for section in _split_sections(diff_text):
        rel, status, is_php = _section_meta(section, old_prefix, new_prefix)
        if not is_php:
            continue
        if _is_translation(rel):
            n_translation += 1
            continue
        added, deleted = _count_changes(section)
        files.append({"path": rel, "status": status, "added": added,
                      "deleted": deleted, "diff": section})
        entry_points.extend(_extract_entry_points(rel, section))
        php_chunks.append(section)

    files.sort(key=lambda f: (f["status"] != "added", f["path"]))
    return {
        "slug": slug, "old_v": old_v, "new_v": new_v,
        "files": files,
        "entry_points": entry_points,
        "added_entry_points": [e for e in entry_points if e["sign"] == "+"],
        "removed_entry_points": [e for e in entry_points if e["sign"] == "-"],
        "n_files": len(files),
        "n_added": sum(f["added"] for f in files),
        "n_deleted": sum(f["deleted"] for f in files),
        "n_entry_points": len(entry_points),
        "n_translation": n_translation,
        "full_diff": "".join(php_chunks),
    }


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
_EP_LABEL = {
    "function": "function", "add_action": "add_action", "add_filter": "add_filter",
    "rest_route": "register_rest_route", "add_shortcode": "add_shortcode", "ajax": "ajax",
}
_DIFF_LINE_CAP = 6000   # keep the embedded unified diff readable; note truncation past this
_FILE_CAP = 80          # cap the changed-files table
_EP_CAP = 50            # cap each of the added / removed entry-point lists
_STALE_FILES = 120      # above this, the baseline is too stale for a focused diff-audit


def _fmt_ep(e):
    label = _EP_LABEL.get(e["kind"], e["kind"])
    name = f" {e['name']}()" if e["kind"] == "function" else (f" '{e['name']}'" if e["name"] else "")
    return f"`{e['path']}`: {label}{name}"


def render_diff_md(result):
    slug, old_v, new_v = result["slug"], result["old_v"], result["new_v"]
    L = [f"# DIFF - {slug}  {old_v} → {new_v}", ""]
    L.append(f"_Generated by diff_audit.py on {datetime.now().strftime('%Y-%m-%d %H:%M')}. "
             f"PHP-only changeset between the last-audited version ({old_v}) and the new "
             f"release ({new_v}). Prioritize the files and entry points below — they are "
             f"the fresh, uncontested code._")
    L.append("")
    L.append("## Summary")
    L.append(f"- **{result['n_files']} auditable PHP file(s) changed** "
             f"(+{result['n_added']} / -{result['n_deleted']} lines)")
    L.append(f"- **{len(result['added_entry_points'])} added** + "
             f"{len(result['removed_entry_points'])} removed entry point(s)")
    if result.get("n_translation"):
        L.append(f"- _{result['n_translation']} translation/l10n file(s) changed "
                 f"(omitted — no auditable logic)_")
    if result["n_files"] > _STALE_FILES:
        L.append("")
        L.append(f"> ⚠️ **Stale baseline:** {result['n_files']} PHP files changed between "
                 f"{old_v} and {new_v}. That is too large for a focused diff-audit — a full "
                 f"`Audit {slug} with Full Audit Pipeline` run is probably the better call; "
                 f"use the lists below only to spot newly-added entry points.")
    L.append("")

    if not result["files"]:
        extra = (f" Only {result['n_translation']} translation/l10n file(s) changed."
                 if result.get("n_translation") else "")
        L.append("_No auditable PHP changes between these versions (changes were assets/"
                 f"config/translations/non-PHP only).{extra} A full diff-audit is probably "
                 "not warranted._")
        L.append("")
        return "\n".join(L)

    L.append("## Changed PHP files (priority order: added first)")
    L.append("")
    L.append("| File | Status | +adds | -dels |")
    L.append("|------|--------|------:|------:|")
    for f in result["files"][:_FILE_CAP]:
        L.append(f"| `{f['path']}` | {f['status']} | {f['added']} | {f['deleted']} |")
    if len(result["files"]) > _FILE_CAP:
        L.append(f"| _... {len(result['files']) - _FILE_CAP} more files_ | | | |")
    L.append("")

    added = result["added_entry_points"]
    removed = result["removed_entry_points"]
    if added or removed:
        L.append("## Changed entry points (audit these first)")
        L.append("")
        if added:
            L.append("**Added (new attack surface):**")
            for e in added[:_EP_CAP]:
                L.append(f"- {_fmt_ep(e)}")
            if len(added) > _EP_CAP:
                L.append(f"- _... {len(added) - _EP_CAP} more added entry points_")
            L.append("")
        if removed:
            L.append("**Removed (was the old code patched away?):**")
            for e in removed[:_EP_CAP]:
                L.append(f"- {_fmt_ep(e)}")
            if len(removed) > _EP_CAP:
                L.append(f"- _... {len(removed) - _EP_CAP} more removed entry points_")
            L.append("")

    diff_lines = result["full_diff"].splitlines()
    L.append("## Unified diff (PHP only)")
    L.append("")
    L.append("```diff")
    if len(diff_lines) > _DIFF_LINE_CAP:
        L.extend(diff_lines[:_DIFF_LINE_CAP])
        L.append(f"... [truncated {len(diff_lines) - _DIFF_LINE_CAP} more lines — "
                 f"run: git diff --no-index plugins/{slug}/{old_v} plugins/{slug}/{new_v}]")
    else:
        L.extend(diff_lines)
    L.append("```")
    L.append("")
    return "\n".join(L)


def write_diff_md(result):
    out_dir = os.path.join(AUDIT_DIR, result["slug"], result["new_v"])
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "DIFF.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_diff_md(result))
    return out_path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def run(slug, new_version=None, old_version=None, scan=False, verbose=True,
        progress=False, old_fallback=False):
    """Full Edge-1 flow. Returns (md_path, result) or (None, reason).

    `old_version` overrides the auto-resolved baseline (your latest audited version),
    letting you diff an ARBITRARY pair — e.g. a Wordfence disclosure's last-affected ->
    patched version to read exactly what the fix changed:
        run(slug, new_version=patched, old_version=last_affected)
    `old_fallback=True`: if that exact old version was pruned from WP.org (a common
    case — authors keep only a subset of past tags), transparently substitute the
    newest PUBLISHED version below `new_version` instead of failing. That version is
    still pre-fix, so the patch-diff stays valid, and the copy-paste command that
    daily_targets/wf_variants emit never dies on a 404.
    `scan=True` also runs the project's Semgrep rules over the new version so the Full
    Audit Pipeline has a pre-scan to consume."""
    old_v = old_version or resolve_old_version(slug)
    if not old_v:
        return None, (f"no prior audit found for '{slug}' (need a version present in BOTH "
                      f"plugins/{slug}/ and audit/{slug}/). Pass --old-version <v>, or use "
                      f"the full pipeline instead.")
    new_v = resolve_new_version(slug, new_version)
    if not new_v:
        return None, (f"could not determine the new version for '{slug}' (offline?). "
                      f"Pass --new-version <v>.")
    if vkey(new_v) <= vkey(old_v):
        return None, (f"new version {new_v} is not newer than the baseline {old_v} — "
                      f"nothing to diff.")
    if verbose:
        print(f"[diff_audit] {slug}: {old_v} -> {new_v}")
    # Ensure BOTH sides are on disk. The baseline is usually already present (you
    # audited it); an explicit --old-version (e.g. a disclosure's last-affected) may not be.
    if not download_version(slug, old_v):
        alt = nearest_published_below(slug, new_v) if old_fallback else None
        if alt and alt != old_v and download_version(slug, alt):
            if verbose:
                print(f"[diff_audit] {old_v} not published on WP.org (pruned tag) — "
                      f"falling back to nearest published pre-patch version {alt}.")
            old_v = alt
        else:
            return None, _download_failure_reason(slug, old_v)
    if not download_version(slug, new_v):
        return None, _download_failure_reason(slug, new_v)
    result = diff_php(slug, old_v, new_v)
    md_path = write_diff_md(result)
    if scan:
        ensure_semgrep_scan(slug, new_v, verbose=verbose, progress=progress)
    return md_path, result


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("slug", help="plugin slug")
    ap.add_argument("--new-version", default=None,
                    help="diff against this version (default: current version from WP API)")
    ap.add_argument("--old-version", default=None,
                    help="baseline to diff FROM (default: your latest audited version on disk). "
                         "Use with --new-version to diff an arbitrary pair, e.g. a Wordfence "
                         "disclosure's last-affected -> patched version.")
    ap.add_argument("--scan", action="store_true",
                    help="also run the project Semgrep rules over the new version so the Full "
                         "Audit Pipeline has a pre-scan (writes plugins/<slug>/<new>/semgrep-scan/)")
    ap.add_argument("--old-fallback", action="store_true",
                    help="if --old-version was pruned from WP.org (404), diff against the newest "
                         "PUBLISHED version below --new-version instead of failing. It is still "
                         "pre-fix, so a patch-diff stays valid. Used by the wf_variants prep "
                         "command so a disclosure's pruned last-affected tag never 404s.")
    args = ap.parse_args()

    md_path, result = run(args.slug, args.new_version, args.old_version, scan=args.scan,
                          old_fallback=args.old_fallback)
    if md_path is None:
        print(f"[diff_audit] {result}", file=sys.stderr)
        sys.exit(2)
    print(f"[diff_audit] {result['n_files']} PHP file(s) changed, "
          f"{len(result['added_entry_points'])} new entry point(s) -> {md_path}")


if __name__ == "__main__":
    main()
