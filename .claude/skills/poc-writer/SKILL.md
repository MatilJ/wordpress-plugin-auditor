# Skill: PoC Writer (Sub-agent)

## Purpose
Write a complete Python PoC script by slotting caller-provided exploit logic into the standard boilerplate template. No vulnerability analysis — formatting and file writing only.

Invoked as sub-agent (model: haiku) by the pipeline after main agent writes `detect()` and `exploit()` logic.

## Input (provided in spawn prompt)

All fields required. If absent, write `[MISSING]` in that position.

```
OUTPUT_PATH:     ./audit/poc/[slug]-[vuln-type]-poc.py
PLUGIN_NAME:     [full display name]
PLUGIN_VERSION:  [e.g. <= 2.4.1]
VULN_TYPE:       [e.g. Stored XSS / SQLi / File Upload / BAC]
AFFECTED_FILE:   [plugin-path/file.php, line N]
AUTH_REQUIRED:   [Unauthenticated / Subscriber / Customer / Contributor]
VULN_DESCRIPTION: [One paragraph]
IMPACT:          [What attacker gains]
USAGE_DETECT:    [Example detect command]
USAGE_EXPLOIT:   [Example exploit command]
EXTRA_CLI_FLAGS: [argparse flags or "none"]
DETECT_FUNCTION: [Complete Python body, 4-space indent]
EXPLOIT_FUNCTION: [Complete Python body, 4-space indent]
AUTH_BLOCK:      [UNAUTHENTICATED / AUTHENTICATED]
```

## Task

1. Read input fields from spawn prompt
2. Substitute into template below
3. Write completed script to `OUTPUT_PATH`
4. Print: `[poc-writer] Written: OUTPUT_PATH`

## Template

```python
#!/usr/bin/env python3
"""
PoC: {{PLUGIN_NAME}} {{PLUGIN_VERSION}} — {{VULN_TYPE}}

Vulnerability:
    {{VULN_DESCRIPTION}}

Impact:
    {{IMPACT}}

References:
    - Affected file: {{AFFECTED_FILE}}

Usage:
    # Detect only:
    {{USAGE_DETECT}}

    # Full exploit:
    {{USAGE_EXPLOIT}}
"""

import argparse
import re
import sys
import urllib3
import requests
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def discover_wp_paths(session: requests.Session, base_url: str, verbose: bool) -> dict:
    if verbose:
        print(f"[*] Fetching {base_url} to discover WordPress paths...")
    try:
        resp = session.get(base_url, timeout=session.timeout_val)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Failed to reach {base_url}: {e}")
        sys.exit(1)

    rest_base = None
    match = re.search(
        r"<link[^>]+rel=['\"]https://api\.w\.org/['\"][^>]+href=['\"]([^'\"]+)['\"]",
        resp.text, re.IGNORECASE,
    )
    if not match:
        match = re.search(
            r"<link[^>]+href=['\"]([^'\"]+)['\"][^>]+rel=['\"]https://api\.w\.org/['\"]",
            resp.text, re.IGNORECASE,
        )
    if match:
        rest_base = match.group(1).rstrip("/")
        if verbose:
            print(f"[+] REST API base discovered: {rest_base}")
    else:
        for candidate in [urljoin(base_url + "/", "wp-json"), base_url + "/?rest_route=/"]:
            try:
                r = session.get(candidate, timeout=session.timeout_val)
                if r.status_code == 200 and "wp/v2" in r.text:
                    rest_base = candidate.rstrip("/")
                    if verbose:
                        print(f"[+] REST API base (fallback): {rest_base}")
                    break
            except requests.RequestException:
                continue

    if not rest_base:
        print("[!] Could not discover WordPress REST API base URL.")
        sys.exit(1)

    parsed = urlparse(rest_base)
    path = parsed.path
    wp_root = rest_base[: -len("/wp-json")] if path.endswith("/wp-json") else base_url
    return {
        "rest_base": rest_base,
        "ajax_url":  urljoin(wp_root + "/", "wp-admin/admin-ajax.php"),
        "login_url": urljoin(wp_root + "/", "wp-login.php"),
        "home_url":  wp_root,
    }


def wp_login(session, login_url, username, password, verbose):
    if verbose:
        print(f"\n[*] Authenticating as '{username}' via {login_url}")
    data = {"log": username, "pwd": password, "wp-submit": "Log In",
            "redirect_to": "/wp-admin/", "testcookie": "1"}
    session.get(login_url, timeout=session.timeout_val)
    try:
        resp = session.post(login_url, data=data, allow_redirects=True,
                            timeout=session.timeout_val)
    except requests.RequestException as e:
        print(f"[!] Login request failed: {e}")
        return False
    logged_in = any(n.startswith("wordpress_logged_in_") for n in session.cookies.keys())
    if logged_in:
        if verbose:
            print(f"[+] Login successful.")
        return True
    print(f"[!] Login failed for '{username}'. Check credentials.")
    if verbose:
        print(f"    Response URL: {resp.url}  Status: {resp.status_code}")
    return False


def scrape_nonce(session: requests.Session, nonce_source_url: str,
                 nonce_action: str, verbose: bool) -> str:
    """Scrape a WordPress nonce from a page the attacker role can access."""
    if verbose:
        print(f"\n[*] Scraping nonce '{nonce_action}' from: {nonce_source_url}")
    try:
        resp = session.get(nonce_source_url, timeout=session.timeout_val)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Could not fetch nonce source page: {e}")
        return None
    patterns = [
        rf"""['"]{re.escape(nonce_action)}['"]\s*:\s*['"]([a-f0-9]{{6,12}})['"]""",
        rf"""data-{re.escape(nonce_action)}=['"]([ a-f0-9]{{6,12}})['"]""",
        rf"""name=['"]{re.escape(nonce_action)}['"][^>]*value=['"]([a-f0-9]{{6,12}})['"]""",
        rf"""value=['"]([a-f0-9]{{6,12}})['"][^>]*name=['"]{re.escape(nonce_action)}['"]""",
    ]
    for pattern in patterns:
        match = re.search(pattern, resp.text, re.IGNORECASE)
        if match:
            nonce = match.group(1)
            if verbose:
                print(f"[+] Nonce found: {nonce}")
            return nonce
    if verbose:
        print(f"[-] Nonce '{nonce_action}' not found on {nonce_source_url}")
    return None



def get_wp_rest_nonce(session, paths, verbose):
    """
    X-WP-Nonce for cookie-authenticated REST API calls.
    WP REST hard-fails (403) with invalid nonce, succeeds silently with none.
    After calling: session.headers.update({"X-WP-Nonce": nonce})
    """
    candidates = [
        paths["home_url"] + "/wp-admin/post-new.php",
        paths["home_url"] + "/wp-admin/widgets.php",
        paths["home_url"] + "/wp-admin/",
    ]
    patterns = [
        r'createNonceMiddleware\(\s*["\']([a-f0-9]{10,12})["\']',
        r'wpApiSettings\s*=\s*\{[^}]{0,300}"nonce"\s*:\s*"([a-f0-9]{10,12})"',
    ]
    for url in candidates:
        try:
            r = session.get(url, timeout=session.timeout_val)
        except requests.RequestException:
            continue
        for pat in patterns:
            m = re.search(pat, r.text)
            if m:
                nonce = m.group(1)
                if verbose:
                    print(f"[+] REST nonce acquired from {url}: {nonce}")
                return nonce
    if verbose:
        print("[-] REST nonce not found — proceeding without X-WP-Nonce")
    return None


def make_session(insecure, proxy, timeout):
    session = requests.Session()
    session.verify = not insecure
    session.timeout_val = timeout
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                             "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        print(f"[*] Proxy active: {proxy}")
    if insecure:
        print("[!] TLS verification disabled (--insecure).")
    return session


def rest_url(rest_base: str, endpoint: str) -> str:
    """Build REST endpoint URL for both pretty and ugly permalink forms."""
    endpoint = endpoint.lstrip("/")
    if "rest_route=" in rest_base:
        return rest_base.rstrip("/") + "/" + endpoint
    return urljoin(rest_base.rstrip("/") + "/", endpoint)


# ─── VULNERABILITY-SPECIFIC LOGIC ────────────────────────────────────────────

def detect(session: requests.Session, paths: dict, args: argparse.Namespace) -> bool:
# --- DETECT BODY ---


def exploit(session: requests.Session, paths: dict, args: argparse.Namespace) -> bool:
# --- EXPLOIT BODY ---


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PoC: {{PLUGIN_NAME}} {{PLUGIN_VERSION}} — {{VULN_TYPE}}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  {{USAGE_DETECT}}
  {{USAGE_EXPLOIT}}
        """,
    )
    parser.add_argument("--url",      required=True, help="Target WordPress base URL")
    parser.add_argument("--username", default=None,  help="WordPress username")
    parser.add_argument("--password", default=None,  help="WordPress password")
    parser.add_argument("--detect",   action="store_true", help="Probe without exploiting")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--proxy",    default=None,  help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--verbose",  action="store_true", help="Print raw requests/responses")
    parser.add_argument("--timeout",    type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--nonce",    default=None, help="Pre-scraped nonce value (skip auto-scraping)")
    {{EXTRA_CLI_FLAGS}}
    args = parser.parse_args()

    args.url = normalize_url(args.url)
    session  = make_session(args.insecure, args.proxy, args.timeout)
    print(f"[*] Target: {args.url}")

    paths = discover_wp_paths(session, args.url, args.verbose)

    {{AUTH_BLOCK_PLACEHOLDER}}

    if args.detect:
        vulnerable = detect(session, paths, args)
        sys.exit(0 if vulnerable else 1)
    else:
        success = exploit(session, paths, args)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
```

## AUTH_BLOCK substitution

If `Unauthenticated` → replace `{{AUTH_BLOCK_PLACEHOLDER}}` with:
```python
    # Unauthenticated vulnerability — no login required.
```

If authenticated + **plugin AJAX** (`admin-ajax.php`) →:
```python
    if not args.username or not args.password:
        parser.error("--username and --password are required for this vulnerability.")
    if not wp_login(session, paths["login_url"], args.username, args.password, args.verbose):
        sys.exit(1)
```

If authenticated + **REST API** (`/wp-json/`) →:
```python
    if not args.username or not args.password:
        parser.error("--username and --password are required for this vulnerability.")
    if not wp_login(session, paths["login_url"], args.username, args.password, args.verbose):
        sys.exit(1)
    nonce = get_wp_rest_nonce(session, paths, args.verbose)
    if nonce:
        session.headers.update({"X-WP-Nonce": nonce})
```

Never send guessed/hardcoded nonce to REST API — WP returns 403 for invalid nonce but succeeds silently with none.

## EXTRA_CLI_FLAGS substitution

If `none` → empty line. Otherwise insert argparse `add_argument` lines verbatim.

## detect()/exploit() indentation

Function bodies from caller are 4-space indented (function body level). Insert after `def` lines, remove placeholder comments. No blank `pass` left.
