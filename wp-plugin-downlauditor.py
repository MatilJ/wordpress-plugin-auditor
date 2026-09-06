import requests
import argparse
import logging
import os
import signal
import subprocess
import zipfile
import json
import urllib.parse
import sqlite3
import time
import re
import shutil
import tempfile
import threading
from collections import defaultdict
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from io import BytesIO
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

logger = logging.getLogger(__name__)

timeout = 10
db_plugin_table = "Plugins"
db_result_table = "Audit"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/135.0.0.0 Safari/537.36"
)

_thread_local = threading.local()


def get_session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json, */*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            # Let requests/urllib3 manage Accept-Encoding so it only advertises
            # encodings it can actually decompress. Setting it manually can cause
            # the server to return brotli/zstd that urllib3 can't handle.
        })
        _thread_local.session = s
    return _thread_local.session


def setup_logging(verbose=False, log_file=None):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s - %(levelname)s - %(message)s"
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(logging.StreamHandler())
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.WARNING)
        fh.setFormatter(logging.Formatter(fmt))
        root.addHandler(fh)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Wordpress Plugin Downloader and Auditor")
    parser.add_argument(
        "-m", "--mode",
        default="download",
        choices=("download", "audit", "both"),
        help="Operative mode: download / audit / both",
    )
    parser.add_argument(
        "-d", "--download-dir",
        type=str, default=".",
        help="Directory containing the plugins folder (default: current directory)",
    )
    parser.add_argument(
        "--db",
        dest="sqlite_db",
        default=False,
        help="Store plugins and audit data in the specified SQLite database",
    )
    parser.add_argument(
        "--clear-results",
        action="store_true", default=False,
        help="Clear the Audit table before running",
    )
    parser.add_argument(
        "--last-updated",
        type=int, default=24,
        help="Max months since last_updated (default: 24)",
    )
    parser.add_argument(
        "--active-installs-min",
        type=int, default=50,
        help="Min active_installs (default: 50)",
    )
    parser.add_argument(
        "--active-installs-max",
        type=int, default=None,
        help="Max active_installs (default: no limit)",
    )
    parser.add_argument(
        "--author",
        type=str, default="",
        help="Author username filter",
    )
    parser.add_argument(
        "--tag",
        type=str, default="",
        help="Tag filter",
    )
    parser.add_argument(
        "--search",
        type=str, default="",
        help="Search term filter",
    )
    parser.add_argument(
        "--config",
        dest="configs",
        action="append",
        default=None,
        metavar="CONFIG",
        help="Semgrep config/rule (can be repeated, default: p/php) [audit mode only]",
    )
    parser.add_argument(
        "--download-workers",
        type=int, default=4,
        help="Parallel download workers (default: 4)",
    )
    parser.add_argument(
        "--scan-workers",
        type=int, default=2,
        help="Parallel semgrep scan workers (default: 2)",
    )
    parser.add_argument(
        "--log-file",
        type=str, default=None,
        help="Write warnings and errors to this log file",
    )
    parser.add_argument(
        "--verbose",
        action="store_true", default=False,
        help="Print detailed messages",
    )
    parser.add_argument(
        "--generate-summaries",
        action="store_true", default=False,
        help="Generate .md summaries for all existing semgrep-scan JSON files, then exit",
    )
    parser.add_argument(
        "--plugin",
        type=str, default=None,
        help="Download/audit a single plugin by slug (bypasses API search filters)",
    )
    parser.add_argument(
        "--version",
        type=str, default=None,
        help="Specific version to download (requires --plugin; default: latest)",
    )
    return parser.parse_args()


def create_plugins_table(cur):
    try:
        cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {db_plugin_table} (
            slug VARCHAR(255),
            version VARCHAR(255),
            author VARCHAR(255),
            active_installs INT,
            downloaded INT,
            last_updated DATETIME,
            added_date DATE,
            download_link TEXT,
            last_time_scanned DATE,
            PRIMARY KEY(slug, version)
        )
        """)
    except Exception as e:
        logger.error(f"Can't create {db_plugin_table} table: {e}")


def create_audit_table(cur):
    try:
        cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {db_result_table} (
            slug VARCHAR(255),
            version VARCHAR(255),
            file_path VARCHAR(255),
            check_id VARCHAR(255),
            severity VARCHAR(25),
            impact VARCHAR(25),
            likelihood VARCHAR(25),
            confidence VARCHAR(25),
            start_line INT,
            end_line INT,
            vuln_lines TEXT,
            message TEXT,
            date_discovered DATE,
            triaged BOOLEAN,
            PRIMARY KEY(slug, version, file_path, check_id, start_line, end_line),
            FOREIGN KEY (slug, version) REFERENCES {db_plugin_table}(slug, version)
        )
        """)
    except Exception as e:
        logger.error(f"Can't create {db_result_table} table: {e}")


def insert_plugins_row(con, cur, plugin, db_lock=None):
    sql = f"""
    INSERT OR REPLACE INTO {db_plugin_table}
    (slug, version, author, active_installs, downloaded, last_updated, added_date, download_link, last_time_scanned)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    plug_last_updated = plugin.get("last_updated")
    plug_added_date = plugin.get("added")

    if plug_last_updated:
        try:
            plug_last_updated = datetime.strptime(plug_last_updated, "%Y-%m-%d %I:%M%p %Z").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError as e:
            logger.warning(f"Can't parse last_updated for {plugin.get('slug')}: {e}")
            plug_last_updated = None

    if plug_added_date:
        try:
            plug_added_date = datetime.strptime(plug_added_date, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError as e:
            logger.warning(f"Can't parse added date for {plugin.get('slug')}: {e}")
            plug_added_date = None

    data = (
        plugin["slug"],
        plugin.get("version", "NA"),
        plugin["author"],
        int(plugin.get("active_installs", 0)),
        int(plugin.get("downloaded", 0)),
        plug_last_updated,
        plug_added_date,
        plugin["download_link"],
        plugin.get("last_time_scanned", 0),
    )

    try:
        with db_lock if db_lock else nullcontext():
            cur.execute(sql, data)
            con.commit()
        logger.info(f"Updated DB for {plugin['slug']} {plugin.get('version', 'NA')}")
    except sqlite3.IntegrityError as e:
        logger.error(f"DB integrity error writing plugin {plugin['slug']}: {e}")
    except sqlite3.OperationalError as e:
        logger.error(f"DB operational error writing plugin {plugin['slug']}: {e}")
    except Exception as e:
        logger.error(f"DB write failed for plugin {plugin['slug']}: {e}")


def insert_result_row(con, cur, item, plugin_name, last_version, db_lock=None):
    sql = f"""
    INSERT OR IGNORE INTO {db_result_table}
    (slug, version, file_path, check_id, severity, impact, likelihood, confidence,
     start_line, end_line, vuln_lines, message, date_discovered, triaged)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    metadata = item["extra"].get("metadata", {})
    data = (
        plugin_name,
        last_version,
        item["path"],
        item["check_id"],
        item["extra"]["severity"],
        metadata.get("impact", "N/A"),
        metadata.get("likelihood", "N/A"),
        metadata.get("confidence", "N/A"),
        item["start"]["line"],
        item["end"]["line"],
        item["extra"]["lines"],
        item["extra"]["message"],
        datetime.now().strftime("%Y-%m-%d"),
        False,
    )

    try:
        with db_lock if db_lock else nullcontext():
            cur.execute(sql, data)
            con.commit()
        logger.info(f"Updated audit DB for {plugin_name} {last_version}")
    except sqlite3.IntegrityError as e:
        logger.error(f"DB integrity error writing audit result for {plugin_name}: {e}")
    except sqlite3.OperationalError as e:
        logger.error(f"DB operational error writing audit result for {plugin_name}: {e}")
    except Exception as e:
        logger.error(f"DB audit write failed for {plugin_name}: {e}")


def get_filtered_plugins(con, author=None, last_updated=24, active_installs_min=50000, active_installs_max=None):
    try:
        query = f"SELECT slug FROM {db_plugin_table}"
        conditions = []
        params = []

        if author:
            conditions.append("author LIKE ?")
            params.append("%" + author + "%")

        if last_updated is not None:
            conditions.append("last_updated >= ?")
            threshold = datetime.now() - timedelta(days=last_updated * 30)
            params.append(threshold.strftime("%Y-%m-%d %H:%M:%S"))

        if active_installs_min is not None:
            conditions.append("active_installs >= ?")
            params.append(active_installs_min)

        if active_installs_max is not None:
            conditions.append("active_installs <= ?")
            params.append(active_installs_max)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        cur = con.cursor()
        cur.execute(query, params)
        return cur.fetchall()
    except Exception as e:
        logger.error(f"DB query error in get_filtered_plugins: {e}")
        return []


def get_all_slugs_from_api(active_installs_min=0, per_page=250):
    """Return plugin slugs from WP API ordered by popularity.

    Stops early once active_installs drops below active_installs_min so
    high-threshold queries (e.g. 1 M+) finish in just a few pages.
    """
    slugs = []
    page = 1
    while True:
        url = (
            f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins"
            f"&request[page]={page}&request[per_page]={per_page}"
            f"&request[browse]=popular"
            f"&request[fields][active_installs]=1"
        )
        logger.info(f"Querying {url}")
        try:
            response = get_session().get(url, timeout=timeout)
            if response.status_code != 200:
                logger.error(f"Failed to retrieve page {page}: HTTP {response.status_code}")
                break
            data = response.json()
        except (requests.RequestException, ValueError) as e:
            logger.error(f"Error fetching page {page}: {e}")
            break

        plugins = data.get("plugins", [])
        if not plugins:
            break

        for plugin in plugins:
            try:
                installs = int(plugin.get("active_installs", 0))
            except (ValueError, TypeError):
                installs = 0
            if active_installs_min and installs < active_installs_min:
                logger.info(f"Stopping pagination: active_installs {installs} < {active_installs_min}")
                return slugs
            slugs.append(plugin["slug"])

        total_pages = data.get("info", {}).get("pages", 1)
        if page >= total_pages:
            break
        page += 1

    return slugs


def get_slugs_from_svn_wp_api(page=1, per_page=25, search="", author="", tag=""):
    url = (
        f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins"
        f"&request[page]={page}&request[per_page]={per_page}"
        f"&request[search]={urllib.parse.quote_plus(search)}"
        f"&request[author]={urllib.parse.quote_plus(author)}"
        f"&request[tag]={urllib.parse.quote_plus(tag)}"
    )
    logger.info(f"Querying {url}")

    while True:
        try:
            response = get_session().get(url, timeout=timeout)
        except requests.RequestException as e:
            logger.error(f"Network error fetching page {page}: {e}. Retrying in 3s...")
            time.sleep(3)
            continue

        if response.status_code != 200:
            logger.error(f"Failed to retrieve page {page}: HTTP {response.status_code}")
            return None

        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(
                f"Invalid JSON on page {page}: {e}. "
                f"Response ({response.status_code}): {response.text[:300]!r}"
            )
            return None


def get_wp_plugin(slug, verbose=False):
    url = (
        f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information"
        f"&request[slug]={slug}&request[fields][downloaded]=1"
    )
    if verbose:
        logger.info(f"Querying {url}")

    sleep = 10
    while True:
        try:
            response = get_session().get(url, timeout=timeout)
        except requests.RequestException as e:
            logger.error(f"Network error for {slug}: {e}. Retrying in {sleep}s...")
            time.sleep(sleep)
            sleep = min(sleep + 10, 60)
            continue

        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(
                f"Invalid JSON for {slug} (HTTP {response.status_code}): {e}. "
                f"Response: {response.text[:300]!r}"
            )
            return None

        if response.status_code == 200:
            return data
        elif response.status_code == 404:
            if verbose:
                msg = data.get("error") or data.get("description", "unknown")
                logger.error(f"Plugin {slug} not found: {msg}")
            return None
        else:
            logger.error(f"Unexpected HTTP {response.status_code} for {slug}. Retrying in {sleep}s...")
            time.sleep(sleep)
            sleep = min(sleep + 10, 60)


def save_plugin(plugin, download_dir, verbose=False, max_retries=3):
    slug = plugin["slug"]
    version = re.sub(r"[^a-zA-Z0-9._-]", "", plugin["version"])
    download_link = plugin["download_link"]

    plugin_path = os.path.join(download_dir, "plugins", slug)
    version_path = os.path.join(plugin_path, version)
    plugins_dir = os.path.join(download_dir, "plugins")

    if os.path.exists(version_path):
        if verbose:
            logger.info(f"Already exists, skipping: {version_path}")
        return 0

    os.makedirs(plugin_path, exist_ok=True)

    for attempt in range(max_retries):
        tmp_dir = None
        try:
            response = get_session().get(download_link, timeout=timeout)
            response.raise_for_status()

            # Extract to a temp dir first; move atomically on success to prevent
            # half-extracted directories from being treated as complete on retry.
            tmp_dir = tempfile.mkdtemp(dir=plugins_dir)
            with zipfile.ZipFile(BytesIO(response.content)) as zf:
                zf.extractall(tmp_dir)

            extracted = os.path.join(tmp_dir, slug)
            if os.path.isdir(extracted):
                shutil.move(extracted, version_path)
            else:
                shutil.move(tmp_dir, version_path)
                tmp_dir = None

            if verbose:
                logger.info(f"Downloaded and extracted: {slug} {version}")
            return 0

        except requests.RequestException as e:
            delay = 5 * (2 ** attempt)
            logger.error(f"Download failed for {slug} (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {delay}s...")
            time.sleep(delay)
        except zipfile.BadZipFile:
            logger.error(f"Corrupt zip for {slug}, skipping.")
            return 1
        except Exception as e:
            logger.error(f"Unexpected error saving {slug}: {e}")
            return 1
        finally:
            if tmp_dir and os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)

    logger.error(f"Giving up on {slug} after {max_retries} attempts.")
    return 1


def _process_plugin_download(slug, download_dir, last_updated, active_installs_min, active_installs_max, verbose, con, cur, db_lock):
    """Returns True if the plugin was downloaded, False otherwise."""
    plugin = get_wp_plugin(slug, verbose)
    if plugin is None:
        return False

    try:
        last_updated_dt = datetime.strptime(plugin["last_updated"], "%Y-%m-%d %I:%M%p %Z")
        if (datetime.now() - last_updated_dt).days > (last_updated * 30):
            if verbose:
                logger.info(f"Skipping {slug}: last updated {plugin['last_updated']}")
            return False
    except ValueError:
        logger.error(f"Invalid last_updated format for {slug}: {plugin.get('last_updated')}")
        return False

    try:
        installs = int(plugin["active_installs"])
        if active_installs_min is not None and installs < active_installs_min:
            if verbose:
                logger.info(f"Skipping {slug}: {installs} installs < {active_installs_min}")
            return False
        if active_installs_max is not None and installs > active_installs_max:
            if verbose:
                logger.info(f"Skipping {slug}: {installs} installs > {active_installs_max}")
            return False
    except (ValueError, TypeError):
        logger.error(f"Invalid active_installs for {slug}: {plugin.get('active_installs')}")
        return False

    if save_plugin(plugin, download_dir, verbose) == 0:
        if con is not None:
            insert_plugins_row(con, cur, plugin, db_lock)
        return True
    return False


def download_plugins(search="", author="", tag="", download_dir=".", last_updated=24,
                     active_installs_min=5000, active_installs_max=None, sqlite_db=False, verbose=False, workers=4):
    """Returns the number of plugins successfully downloaded."""
    os.makedirs(os.path.join(download_dir, "plugins"), exist_ok=True)

    con, cur, db_lock = None, None, None
    if sqlite_db:
        con = sqlite3.connect(sqlite_db, check_same_thread=False)
        cur = con.cursor()
        db_lock = threading.Lock()
        create_plugins_table(cur)

    slug_list = []
    if not author and not tag and not search:
        slug_list = get_all_slugs_from_api(active_installs_min=active_installs_min)
        total_plugins = len(slug_list)
    else:
        first = get_slugs_from_svn_wp_api(page=1, search=search, author=author, tag=tag)
        if first is None:
            logger.error("Failed to fetch plugin list from WP API.")
            if con:
                con.close()
            return 0
        total_pages = first["info"]["pages"]
        total_plugins = first["info"]["results"]
        for record in first["plugins"]:
            slug_list.append(record["slug"])
        for page in range(2, total_pages + 1):
            data = get_slugs_from_svn_wp_api(page=page, search=search, author=author, tag=tag)
            if data:
                for record in data["plugins"]:
                    slug_list.append(record["slug"])

    if total_plugins == 0:
        logger.info("No plugins found.")
        if con:
            con.close()
        return 0

    logger.info(f"Total plugins: {total_plugins}")

    downloaded = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _process_plugin_download,
                slug, download_dir, last_updated, active_installs_min, active_installs_max, verbose, con, cur, db_lock
            ): slug
            for slug in slug_list
        }
        for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading plugins"):
            slug = futures[future]
            try:
                if future.result():
                    downloaded += 1
            except Exception as e:
                logger.error(f"Unexpected worker error for {slug}: {e}")

    if con:
        con.close()

    logger.info(f"Downloaded {downloaded} plugin(s).")
    return downloaded


def slim_semgrep_json(json_path):
    """Drop verbose Semgrep fields to reduce token cost when Claude reads the file."""
    _EXTRA_KEEP = {"message", "severity", "lines", "metadata"}
    _TOP_DROP = {"paths", "explanations", "time", "engine_requested", "skipped_rules"}
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for result in data.get("results", []):
            extra = result.get("extra", {})
            result["extra"] = {k: v for k, v in extra.items() if k in _EXTRA_KEEP}
        for key in _TOP_DROP:
            data.pop(key, None)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
    except Exception as e:
        logger.warning(f"Could not slim Semgrep JSON at {json_path}: {e}")


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_semgrep_summary(json_path):
    """Write a compact Markdown summary alongside the JSON for AI consumption."""
    md_path = os.path.splitext(json_path)[0] + ".md"
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.warning(f"Could not read Semgrep JSON for summary at {json_path}: {e}")
        return

    results = data.get("results", [])
    basename = os.path.splitext(os.path.basename(json_path))[0]

    path_prefix = ""
    if results:
        parts = results[0].get("path", "").replace("\\", "/").split("/")
        if len(parts) >= 3:
            path_prefix = "/".join(parts[:3]) + "/"

    def _rel(p):
        p = p.replace("\\", "/")
        return p[len(path_prefix):] if path_prefix and p.startswith(path_prefix) else p

    groups = defaultdict(list)
    for r in results:
        groups[r["check_id"]].append(r)

    sorted_groups = sorted(
        groups.items(),
        key=lambda pair: _SEVERITY_ORDER.get(
            pair[1][0].get("extra", {}).get("severity", "LOW"), 5
        ),
    )

    lines = [f"# Semgrep Summary: {basename}", "",
             f"{len(results)} results across {len(groups)} rules.", "",
             "## SEMGREP_COORDINATES", "```"]

    seen = set()
    for r in results:
        coord = f"{_rel(r.get('path', ''))}:{r.get('start', {}).get('line', '?')}"
        if coord not in seen:
            seen.add(coord)
            lines.append(coord)
    lines.extend(["```", ""])

    if not results:
        lines.append("No Semgrep results.")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return

    for check_id, items in sorted_groups:
        short_rule = check_id.rsplit(".", 1)[-1]
        extra = items[0].get("extra", {})
        sev = extra.get("severity", "?")
        meta = extra.get("metadata", {})
        conf = meta.get("confidence", "?")
        cwe_raw = meta.get("cwe", "?")
        if isinstance(cwe_raw, list):
            cwe = ", ".join(str(c).split(":")[0].strip() for c in cwe_raw)
        else:
            cwe = str(cwe_raw).split(":")[0].strip() if ":" in str(cwe_raw) else str(cwe_raw)
        msg_first = extra.get("message", "").strip().split("\n")[0].strip()[:120]

        lines.append(f"### {short_rule} ({len(items)}x)")
        lines.append(f"**Severity:** {sev} | **Confidence:** {conf} | **CWE:** {cwe}")
        lines.append(f"> {msg_first}")
        lines.append("")
        lines.append("| File | Line | Code |")
        lines.append("|------|------|------|")

        for item in items:
            rel = _rel(item.get("path", ""))
            ln = item.get("start", {}).get("line", "?")
            code_raw = item.get("extra", {}).get("lines", "")
            code_line = ""
            for cl in code_raw.split("\n"):
                s = cl.strip()
                if s:
                    code_line = s[:80] + ("..." if len(s) > 80 else "")
                    break
            code_line = code_line.replace("|", "\\|").replace("`", "'")
            lines.append(f"| {rel} | {ln} | `{code_line}` |")

        lines.append("")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _normalize_slug(name):
    return name.lower().replace("_", "-").strip("-")


def _write_semgrepignore(scan_path, plugin_slug):
    """Write a .semgrepignore that keeps genuine third-party vendor/ deps
    excluded from the scan but re-includes a first-party subpackage a
    plugin ships under vendor/<own-slug>/ — a common Composer pattern for a
    shared "core" library published by the same vendor as the plugin
    itself, not a real third-party dependency (mirrors grep_scan.py's
    identical vendor/ handling; see that file's _load_php_files for the
    corpus-validated rationale).

    Supplying a custom .semgrepignore replaces Semgrep's built-in ignore
    template entirely (it does not merge with it), so common exclusions are
    restated here. Third-party siblings are excluded by explicit name
    rather than a 'vendor/*' wildcard + '!vendor/<slug>/' negation:
    empirically, Semgrep's ignore matcher does not reliably re-include a
    directory previously excluded by a trailing-slash negation pattern, so
    that idiom is avoided in favor of listing what should stay excluded.
    """
    ignore_path = os.path.join(scan_path, ".semgrepignore")
    lines = ["node_modules/", ".git/"]

    vendor_dir = os.path.join(scan_path, "vendor")
    if os.path.isdir(vendor_dir):
        target = _normalize_slug(plugin_slug)
        try:
            children = sorted(os.listdir(vendor_dir))
        except OSError:
            children = []

        first_party = next(
            (c for c in children
             if os.path.isdir(os.path.join(vendor_dir, c)) and _normalize_slug(c) == target),
            None,
        )
        for child in children:
            if child == first_party:
                continue
            child_path = os.path.join(vendor_dir, child)
            lines.append(f"vendor/{child}/" if os.path.isdir(child_path) else f"vendor/{child}")

    try:
        with open(ignore_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        logger.warning(f"Could not write .semgrepignore at {ignore_path}: {e}")


def _scan_plugin(plugin_dir, config_list, sqlite_db, verbose, db_lock, target_version=None):
    versions = [c.name for c in os.scandir(plugin_dir.path) if not os.path.isfile(c.path)]
    if not versions:
        logger.warning(f"No version directories found for {plugin_dir.name}, skipping.")
        return

    if target_version:
        if target_version not in versions:
            logger.error(f"Version {target_version} not found for {plugin_dir.name}.")
            return
        local_last_version = target_version
    else:
        versions.sort(reverse=True)
        local_last_version = versions[0]

    if verbose:
        logger.info(f"Scanning {plugin_dir.name} {local_last_version}")

    scan_path = os.path.join(plugin_dir.path, local_last_version)
    scan_result_folder = os.path.join(scan_path, "semgrep-scan")
    scan_result_file = os.path.join(scan_result_folder, f"{plugin_dir.name}.{local_last_version}")

    os.makedirs(scan_result_folder, exist_ok=True)
    _write_semgrepignore(scan_path, plugin_dir.name)

    config_args = []
    for cfg in config_list:
        if cfg.startswith(".") or os.path.isabs(cfg) or os.sep in cfg:
            cfg = os.path.abspath(cfg)
            if not os.path.exists(cfg):
                logger.error(f"Semgrep config path not found: {cfg!r} — skipping {plugin_dir.name}")
                return
        config_args.extend(["--config", cfg])

    command = [
        "semgrep", "scan",
        *config_args,
        "--json-output", f"{scan_result_file}.json",
        "--no-git-ignore",
        "--dataflow-traces",
        "--metrics=off",
        "--timeout=60",
        "--quiet",
        scan_path,
    ]

    try:
        subprocess.run(command, check=True)
        slim_semgrep_json(f"{scan_result_file}.json")
        generate_semgrep_summary(f"{scan_result_file}.json")
        if verbose:
            logger.info(f"Semgrep done: {plugin_dir.name} {local_last_version}")
    except subprocess.CalledProcessError as e:
        if e.returncode == -signal.SIGINT:
            raise KeyboardInterrupt() from e
        logger.error(f"Semgrep failed for {plugin_dir.name} {local_last_version}: {e}")
        return

    if not sqlite_db:
        return

    con = sqlite3.connect(sqlite_db, check_same_thread=False)
    cur = con.cursor()
    try:
        plugin = get_wp_plugin(plugin_dir.name, verbose)
        if plugin is None:
            logger.warning(f"Could not fetch WP metadata for {plugin_dir.name}, skipping DB update.")
            return

        if plugin.get("version") != local_last_version:
            logger.warning(
                f"Scanned {plugin_dir.name} {local_last_version} but WP has {plugin.get('version')}"
            )
            insert_plugins_row(con, cur, plugin, db_lock)

        plugin["version"] = local_last_version
        plugin["last_time_scanned"] = datetime.now().strftime("%Y-%m-%d")
        insert_plugins_row(con, cur, plugin, db_lock)

        json_path = f"{scan_result_file}.json"
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                json_content = json.load(f)
            for item in json_content.get("results", []):
                insert_result_row(con, cur, item, plugin_dir.name, local_last_version, db_lock)

    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error for {plugin_dir.name} {local_last_version}: {e}")
    except Exception as e:
        logger.error(f"Unexpected post-scan error for {plugin_dir.name} {local_last_version}: {e}")
    finally:
        con.close()


def audit_plugins(download_dir, config_list, author, last_updated, active_installs_min, active_installs_max=None,
                  sqlite_db=False, verbose=False, workers=2):
    db_lock = threading.Lock()
    plugins = []

    con = None
    if sqlite_db:
        con = sqlite3.connect(sqlite_db, check_same_thread=False)
        cur = con.cursor()
        create_plugins_table(cur)
        create_audit_table(cur)

    if (author or last_updated or active_installs_min or active_installs_max) and con is not None:
        plugins_slugs = get_filtered_plugins(con, author, last_updated, active_installs_min, active_installs_max)
        slugs_set = {s[0] for s in plugins_slugs}
        for item in os.scandir(os.path.join(download_dir, "plugins")):
            if item.is_dir() and item.name in slugs_set:
                plugins.append(item)

    if not plugins:
        if con is not None:
            logger.warning("No plugins matched DB filters. Falling back to full plugins directory.")
        plugins = [p for p in os.scandir(os.path.join(download_dir, "plugins")) if p.is_dir()]

    if con:
        con.close()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_plugin, plugin_dir, config_list, sqlite_db, verbose, db_lock): plugin_dir.name
            for plugin_dir in plugins
        }
        for future in tqdm(as_completed(futures), total=len(futures), desc="Auditing plugins"):
            name = futures[future]
            try:
                future.result()
            except Exception as e:
                logger.error(f"Scan worker error for {name}: {e}")


class _DirEntry:
    """Minimal os.DirEntry stand-in for _scan_plugin."""
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)


def _handle_single_plugin(args, config_list):
    slug = args.plugin
    download_dir = args.download_dir
    verbose = args.verbose

    plugin = get_wp_plugin(slug, verbose=True)
    if plugin is None:
        logger.error(f"Plugin '{slug}' not found on wordpress.org.")
        return

    if args.version:
        version = args.version
        plugin["version"] = version
        plugin["download_link"] = f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
    else:
        version = plugin["version"]

    logger.info(f"Plugin: {plugin.get('name', slug)} | Version: {version} "
                f"| Installs: {plugin.get('active_installs', '?')}")

    if args.mode in ("download", "both"):
        result = save_plugin(plugin, download_dir, verbose)
        if result != 0:
            logger.error(f"Download failed for {slug} {version}.")
            return
        if args.sqlite_db:
            con = sqlite3.connect(args.sqlite_db, check_same_thread=False)
            cur = con.cursor()
            create_plugins_table(cur)
            insert_plugins_row(con, cur, plugin, threading.Lock())
            con.close()

    plugin_path = os.path.join(download_dir, "plugins", slug)
    if not os.path.isdir(plugin_path):
        logger.error(f"Plugin directory not found: {plugin_path}")
        return

    if args.mode in ("audit", "both"):
        logger.info(f"Scanning {slug} {version}...")
        db_lock = threading.Lock()
        _scan_plugin(_DirEntry(plugin_path), config_list, args.sqlite_db, verbose, db_lock,
                     target_version=version)
        logger.info(f"Scan complete: {slug} {version}")


def main():
    args = parse_arguments()
    config_list = args.configs or ["p/php"]

    if args.sqlite_db:
        db_dir = os.path.join(args.download_dir, "databases")
        os.makedirs(db_dir, exist_ok=True)
        args.sqlite_db = os.path.join(db_dir, args.sqlite_db)

    if args.log_file:
        log_dir = os.path.join(args.download_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        args.log_file = os.path.join(log_dir, args.log_file)

    setup_logging(args.verbose, args.log_file)

    if args.generate_summaries:
        plugins_dir = os.path.join(args.download_dir, "plugins")
        count = 0
        for root, _dirs, files in os.walk(plugins_dir):
            if not root.endswith("semgrep-scan"):
                continue
            for fn in files:
                if not fn.endswith(".json"):
                    continue
                json_path = os.path.join(root, fn)
                md_path = os.path.splitext(json_path)[0] + ".md"
                if os.path.exists(md_path):
                    continue
                generate_semgrep_summary(json_path)
                count += 1
        logger.info(f"Generated {count} summary file(s) from existing scans.")
        return

    if args.clear_results:
        if not args.sqlite_db:
            logger.error("--clear-results requires --db")
            return
        con = sqlite3.connect(args.sqlite_db)
        try:
            con.execute(f"DELETE FROM {db_result_table}")
            con.execute(f"UPDATE {db_plugin_table} SET last_time_scanned = 0")
            con.commit()
            logger.info("Cleared audit results.")
        except Exception as e:
            logger.error(f"Failed to clear results: {e}")
        finally:
            con.close()

    if args.version and not args.plugin:
        logger.error("--version requires --plugin")
        return

    if args.plugin:
        _handle_single_plugin(args, config_list)
        return

    downloaded = 0
    if args.mode in ("download", "both"):
        logger.info("Started downloading.")
        downloaded = download_plugins(
            args.search, args.author, args.tag, args.download_dir,
            args.last_updated, args.active_installs_min, args.active_installs_max,
            args.sqlite_db, args.verbose, args.download_workers,
        )

    if args.mode == "audit" or (args.mode == "both" and downloaded > 0):
        logger.info("Started auditing.")
        audit_plugins(
            args.download_dir, config_list, args.author, args.last_updated,
            args.active_installs_min, args.active_installs_max,
            args.sqlite_db, args.verbose, args.scan_workers,
        )
    elif args.mode == "both" and downloaded == 0:
        logger.warning("Skipping audit: no plugins were downloaded.")


if __name__ == "__main__":
    main()
