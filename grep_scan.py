#!/usr/bin/env python3
"""
grep_scan.py — WordPress plugin vulnerability grep scanner.

Replaces the Haiku AI sub-agent grep scanner. Walks all .php files in a
target directory, runs 400+ regex pattern sections, and writes tier-segmented
output files (one per analysis group, plus a foundation aggregate) for the
Full Audit Pipeline.

Usage:
    python grep_scan.py <target_dir> <output_dir> [--semgrep-coords <file>]

Output files:
    foundation-results.md  — auth / reachability / custom-sink facts (Foundation phase)
    surface-results.md     — attack surface patterns
    group-a-results.md     — Tier 1-2 (RCE, file upload/read/write/delete, POI)
    group-ab-results.md    — Auth Bypass (CWE-287/288)
    group-ac-results.md    — Access Control (missing-auth, IDOR, CSRF, options/content
                             writes, adversarial draft-status / parse_args patterns)
    group-sqli-results.md  — SQL injection (Tier 3)
    group-c-results.md     — Tier 5-6 (HTML renderers, XSS)
    group-d1-results.md    — Tier 8-10 (SSRF, email injection, info disclosure)
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path

# Group taxonomy (the group set + output filenames) is centralised in group_registry.py —
# the single source of truth shared by grep_scan.py / extract_semgrep_coords.py /
# pattern_accumulator.py. The big per-group SECTION lists below stay local (grep-domain
# knowledge), but the bucket set they key into comes from the registry.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import group_registry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_LIMIT = 60
LINE_TRUNCATE = 120
# Generated/minified code (Symfony DI containers, Doctrine proxy classes, compiled
# Twig templates, etc.) can pack a single line with thousands of chars of nested
# calls. Regex patterns in this scanner are written and tested against normal
# hand-authored PHP lines; against pathological line lengths, some can hit
# catastrophic backtracking and hang for hours on one file. Lines longer than
# this are skipped for matching — this is display/generated boilerplate, never
# hand-written sink code a manual audit would act on.
MAX_MATCH_LINE_LENGTH = 2000
EXCLUDED_DIRS = {"vendor", "node_modules", "freemius"}
# Dirs pruned even inside a first-party vendor/<own-slug>/ subpackage (see
# _load_php_files) — these are never plugin business logic regardless of nesting.
ALWAYS_EXCLUDED_DIRS = {"node_modules", "freemius"}


def _normalize_slug(name: str) -> str:
    """Loosely normalize a directory/slug name for first-party vendor-package matching."""
    return name.lower().replace("_", "-").strip("-")

# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------
# Each entry:
#   group          — output file bucket
#   patterns       — list of regex strings (ORed within a section)
#   invert         — report files NOT matching ANY pattern (bool)
#   limit          — max hits (default DEFAULT_LIMIT)
#   exclude_patterns — skip lines matching any of these regexes
#   cross_file_filter — only search files that also contain this regex
#   case_insensitive — use re.IGNORECASE
#   glob_override  — comma-separated glob list; search THESE files instead of all PHP
#   line_filter    — additional regex the matched line must also satisfy
#   exclude_path_patterns — skip files whose relative path matches any of these

SECTIONS = {
    # ===== SURFACE =====
    "STANDALONE_PHP": {
        "group": "surface",
        "patterns": [
            r"(require|include)(_once)?\s*\(?\s*['\"][^'\"]*wp-(load|blog-header)\.php",
        ],
        "limit": 40,
    },
    "AJAX_HOOKS": {
        "group": "surface",
        "patterns": [
            r"wp_ajax_nopriv_",
            r"wp_ajax_",
            r"admin_post_nopriv_",
            r"admin_post_",
        ],
    },
    "WC_AJAX_HOOKS": {
        "group": "surface",
        "patterns": [r"add_action.*wc_ajax_"],
    },
    "ADMIN_HOOKS": {
        "group": "surface",
        "patterns": [
            r"add_action.*admin_init",
            r"add_action.*admin_menu",
            r"add_action.*admin_notices",
            r"add_action.*wp_dashboard_setup",
        ],
    },
    "INIT_HOOKS": {
        "group": "surface",
        "patterns": [
            r"add_action.*\binit\b",
            r"add_action.*wp_loaded",
            r"add_action.*parse_request",
            r"add_action.*plugins_loaded",
            r"add_action.*template_redirect",
            r"add_action.*after_setup_theme",
        ],
    },
    "PAGEBUILDER_HOOKS": {
        "group": "surface",
        "patterns": [
            r"add_action.*elementor/editor|add_filter.*elementor/editor|add_action.*fl_builder_|add_action.*et_builder_|add_action.*vc_before_init|add_action.*bricks/",
        ],
    },
    "REST_ENDPOINTS": {
        "group": "surface",
        "patterns": [r"register_rest_route", r"rest_api_init"],
    },
    "SHORTCODES": {
        "group": "surface",
        "patterns": [r"add_shortcode", r"do_shortcode", r"apply_shortcodes"],
    },
    "DO_SHORTCODE_CONTENT_FILTER": {
        "group": "surface",
        "patterns": [
            r"add_filter\s*\(.*['\"](?:do_shortcode|apply_shortcodes)['\"]",
        ],
        "exclude_patterns": [
            r"the_content",
        ],
    },
    "OUTBOUND_HTTP": {
        "group": "surface",
        "patterns": [r"wp_remote_get", r"wp_remote_post", r"wp_remote_request"],
        "exclude_patterns": [r"wp_safe_remote"],
    },
    "REDIRECTS": {
        "group": "surface",
        "patterns": [r"wp_redirect|header.*Location"],
        "exclude_patterns": [r"wp_safe_redirect"],
    },
    "EMAIL": {
        "group": "surface",
        "patterns": [r"wp_mail\b|mail\("],
    },
    "INPUT_SUPERGLOBALS": {
        "group": "surface",
        "patterns": [
            r"\$_POST|\$_GET|\$_REQUEST|\$_COOKIE|\$_FILES|\$_SERVER|\$_SESSION"
        ],
    },
    "INPUT_STREAMS": {
        "group": "surface",
        "patterns": [r"php://input", r"filter_input\("],
    },
    "DB_READS": {
        "group": "surface",
        "patterns": [
            r"get_option\b",
            r"get_user_meta\b",
            r"get_post_meta\b",
            r"get_comment_meta\b",
        ],
    },
    "CRYPTO_OPS": {
        "group": "surface",
        "patterns": [
            r"decrypt|base64_decode|json_decode|unserialize|jwt_decode|openssl_|sodium_"
        ],
    },
    "REST_FIELD_REGISTRATIONS": {
        "group": "surface",
        "patterns": [r"register_rest_field"],
    },
    "REST_NONCE_EXPOSURE": {
        "group": "surface",
        "patterns": [r'wp_create_nonce.*wp_rest|wp_create_nonce.*"wp_rest"'],
    },
    "CSV_EXPORT_SURFACE": {
        "group": "surface",
        "patterns": [r"fputcsv|text/csv|\.csv|spreadsheet|export"],
    },
    "WP_CLI_COMMANDS": {
        "group": "surface",
        "patterns": [r"WP_CLI::add_command"],
    },
    "NON_AJAX_DISPATCHERS": {
        "group": "surface",
        "patterns": [r"wp_send_json_success|wp_send_json_error|wp_send_json\("],
    },
    "RAW_ACTION_PARAM_DISPATCH": {
        "group": "surface",
        "patterns": [
            r"\$_POST\[['\"](?:action|task|do|cmd|op|event|trigger)['\"]\]",
            r"\$_REQUEST\[['\"](?:action|task|do|cmd|op|event|trigger)['\"]\]",
            # Nested-array variant: the action-style key sits one level down in
            # a sub-array of request options (e.g. $_POST['options']['action']),
            # the shape used by central router/dispatch functions that switch on
            # the resulting value to invoke sensitive sub-actions.
            r"\$_POST\[['\"]\w+['\"]\]\[['\"](?:action|task|do|cmd|op|event|trigger)['\"]\]",
            r"\$_REQUEST\[['\"]\w+['\"]\]\[['\"](?:action|task|do|cmd|op|event|trigger)['\"]\]",
        ],
        "limit": 60,
    },
    "SQL_FILTER_HOOKS": {
        "group": "surface",
        "patterns": [
            r"add_filter.*posts_where|add_filter.*posts_join|add_filter.*posts_having|add_filter.*posts_orderby|add_filter.*posts_groupby|add_filter.*get_meta_sql|add_filter.*posts_clauses|add_filter.*comments_clauses|add_filter.*comment_feed_where"
        ],
    },
    "BLOCK_TYPES": {
        "group": "surface",
        "patterns": [r"register_block_type|register_block_type_from_metadata"],
    },
    "JSON_ENCODE_SURFACE": {
        "group": "surface",
        "patterns": [r"json_encode|wp_json_encode"],
        "exclude_patterns": [r"JSON_HEX_APOS|esc_attr|esc_html"],
    },
    "JSON_WRAPPER_METHOD_ECHO": {
        # Separate section from JSON_ENCODE_SURFACE: that section's shared
        # exclude_patterns (any esc_attr/esc_html anywhere on the line) is too
        # coarse here — a co-located, unrelated esc_attr() call for a different
        # attribute on the same line would false-suppress this pattern's real
        # hits, so this section pairs the pattern with its own tightly-scoped
        # exclude that requires the escaping call to directly wrap the match.
        "group": "surface",
        "patterns": [
            # Indirect wrapper: a getter/helper (method or bare function) whose
            # name contains "json" echoed directly — the json_encode() call
            # lives inside the callee, so it carries no literal json_encode
            # token on this line.
            r"echo\s+(?:\$\w+->)?\w*[Jj][Ss][Oo][Nn]\w*\s*\(",
        ],
        "exclude_patterns": [
            r"(?:esc_attr|esc_html)\s*\(\s*(?:\$\w+->)?\w*[Jj][Ss][Oo][Nn]"
        ],
    },
    "ADMIN_LIST_TABLES": {
        "group": "surface",
        "patterns": [r"extends WP_List_Table|WP_List_Table"],
    },
    "WP_USER_QUERY": {
        "group": "surface",
        "patterns": [r"new WP_User_Query|WP_User_Query\("],
    },
    "ADMIN_GET_DISPATCHERS": {
        "group": "surface",
        "patterns": [
            r"\$_GET\[['\"](?:action|view|task|do)['\"]\]",
            # filter_input(INPUT_GET, ...) is an equally common alternative to a
            # direct $_GET[] array read for the same dispatch idiom.
            r"filter_input\s*\(\s*INPUT_GET\s*,\s*['\"](?:action|view|task|do)['\"]",
        ],
        "exclude_patterns": [
            r"wp_verify_nonce|check_admin_referer|check_ajax_referer"
        ],
    },
    "ROLE_CAPABILITY_MAPPING": {
        "group": "surface",
        "patterns": [
            r"add_role\(",
            r"add_cap\(|remove_cap\(|wp_user_roles",
            r"set_role\(",
            r"wp_create_user|wp_insert_user|user_register",
            r"update_user_meta\([^,]+,\s*['\"][^'\"]*(capabilit|role|permission)[^'\"]*['\"]",
            r"(?:update|add)_user_meta\([^,]+,\s*['\"][^'\"]*(admin|is_pro|access_level|user_level)[^'\"]*['\"]",
            r"parent::prepare_(?:object|item)_for_database\(",
        ],
    },
    "ROLE_ARRAY_MEMBERSHIP_CHECK": {
        "group": "surface",
        "patterns": [
            r"array_intersect\(.*->roles",
            r"in_array\(.*->roles\)",
        ],
    },
    "WC_STORE_API_ENDPOINTS": {
        "group": "surface",
        "patterns": [
            r"woocommerce_store_api_register_update_callback\(",
            r"register_endpoint_data\(",
            r"extend_endpoint_data\(",
        ],
    },
    "BROKEN_AUTH_LOGIC": {
        "group": "surface",
        "patterns": [
            r"is_user_logged_in.*&&.*current_user_can",
            r"is_user_logged_in.*&&.*is_admin.*&&.*current_user_can",
            r"if.*is_admin\(\)|is_admin\(\).*return|is_admin\(\).*die|is_admin\(\).*wp_die",
            r'check_ajax_referer.*false\)',
            r"kses_remove_filters|remove_filter.*content_save_pre.*wp_filter",
            r"""\? ['"]true['"] : ['"]false['"]""",
            r"user_can\(.*->post_author",
            r"!\s*\$\w+\s*&&\s*in_array\(",
        ],
    },
    "NOPRIV_WP_QUERY_POST_STATUS": {
        "group": "surface",
        "patterns": [r"new WP_Query|get_posts\("],
        "cross_file_filter": r"wp_ajax_nopriv_",
    },
    "NOPRIV_CUSTOM_TABLE_POST_STATUS": {
        "group": "surface",
        "patterns": [r"get_post_meta\b|::where\(|->where\("],
        "cross_file_filter": r"wp_ajax_nopriv_",
    },
    "WPQUERY_PERM_READABLE": {
        "group": "surface",
        "patterns": [r"'perm'\s*=>\s*'readable'"],
    },
    "SHORTCODE_WP_QUERY_POST_STATUS": {
        "group": "surface",
        "patterns": [r"new WP_Query|get_posts\("],
        "cross_file_filter": r"add_shortcode",
    },
    "CAPABILITY_HANDLER_CROSSREF": {
        "group": "surface",
        "patterns": [
            r"add_cap\(|add_role\(|\$role->add_cap",
            r"current_user_can\(",
            r"wp_create_nonce\(|wp_nonce_field\(|wp_localize_script",
        ],
        # second pattern has its own exclusion — handled via per-pattern excludes below
        # We implement this as a combined search; the sub-pattern exclusion for
        # current_user_can is handled in _CAPABILITY_HANDLER_CROSSREF_EXCLUDES
    },
    "NOPRIV_AJAX_SQL_CROSSREF": {
        "group": "surface",
        "patterns": [
            r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col"
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "REST_SQL_CROSSREF": {
        "group": "surface",
        "patterns": [
            r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col"
        ],
        "cross_file_filter": r"register_rest_route",
    },
    "REST_ARRAY_MERGE_INJECTION": {
        "group": "surface",
        "patterns": [
            r"array_merge.*param|array_merge.*request|array_merge.*get_params",
            r"\$params\s*=\s*array_merge|\$args\s*=\s*array_merge",
        ],
    },
    "TAXONOMY_WRITES": {
        "group": "surface",
        "patterns": [
            r"wp_insert_term\(",
            r"wp_set_object_terms\(",
            r"wp_create_term\(",
            r"wp_update_term\(",
        ],
    },
    "SLIM_FASTROUTE_ROUTER": {
        "group": "surface",
        "patterns": [
            r"use\s+Slim\\",
            r"use\s+FastRoute\\",
            r"FastRoute\\simpleDispatcher|FastRoute\\cachedDispatcher",
            r"\$app->get\s*\(\s*['\"]",
            r"\$app->post\s*\(\s*['\"]",
            r"\$app->map\s*\(",
            r"\$app->group\s*\(",
        ],
    },
    "POI_BUNDLED_LIBRARIES": {
        "group": "surface",
        "patterns": [
            r"use\s+GuzzleHttp\\",
            r"use\s+Monolog\\",
            r"use\s+TCPDF\b|new\s+TCPDF\b",
            r"use\s+Faker\\",
            r"use\s+Symfony\\Component\\",
            r"use\s+Doctrine\\",
            r"use\s+Illuminate\\",
            r"use\s+Swift_|use\s+Swiftmailer\\",
            r"use\s+Dompdf\\|new\s+Dompdf\b",
            r"use\s+PHPMailer\\PHPMailer\\",
        ],
        "limit": 20,
    },
    "COMPOSER_DEPENDENCY_FILES": {
        "group": "surface",
        "patterns": [
            r"\"require\":\s*\{",
        ],
        "glob_override": "**/composer.json,**/composer.lock",
        "limit": 10,
    },
    # ===== GROUP A (Tier 1-2) =====
    "TIER1_CODE_EXEC": {
        "group": "group-a",
        "patterns": [
            r"eval\(",
            r"assert\(",
            r"preg_replace.*\/e",
            r"create_function",
            r"call_user_func\b",
            r"call_user_func_array",
        ],
    },
    "TIER1_DESERIALIZATION": {
        "group": "group-a",
        "patterns": [r"unserialize\(", r"maybe_unserialize\(", r"session_decode\("],
    },
    # do_action()/apply_filters() (or their _ref_array variants) invoked with
    # a bare variable as the ENTIRE hook-name argument (no static prefix) in
    # a file that also touches a request superglobal - the "hook injection"
    # shape where a request-derived action name is both the nonce action AND
    # the hook actually executed, letting a requester trigger any registered
    # hook by name. CVE-2024-0867 (email-log check_nonce), CVE-2024-0866
    # (sibling plugin, same author/pattern).
    "DYNAMIC_HOOK_NAME_EXECUTION": {
        "group": "group-a",
        "patterns": [
            r"\bdo_action\s*\(\s*\$\w+\s*[,)]",
            r"\bdo_action_ref_array\s*\(\s*\$\w+\s*[,)]",
            r"\bapply_filters\s*\(\s*\$\w+\s*[,)]",
            r"\bapply_filters_ref_array\s*\(\s*\$\w+\s*[,)]",
        ],
        "cross_file_filter": r"\$_POST|\$_GET|\$_REQUEST",
        "limit": 40,
    },
    # extract() without EXTR_SKIP silently overwrites any pre-existing
    # variable in scope whose name matches an array key. If a dangerous
    # sink (include/require path, capability flag) reads a same-named
    # variable afterward, the extracted array can clobber it even when
    # the array's own contents were never validated as a file path.
    "EXTRACT_VARIABLE_CLOBBER": {
        "group": "group-a",
        "patterns": [
            # Negative lookbehind excludes "->extract(" / "::extract(" method
            # calls and "my_extract(" identifiers - only the bare builtin call.
            r"(?<![-:>\w])extract\(\s*\$",
        ],
        "exclude_patterns": [
            r"extract\([^;]*,\s*EXTR_SKIP",
            r"function\s+extract\s*\(",
        ],
        "limit": 30,
    },
    "TIER1_COMMAND_EXEC": {
        "group": "group-a",
        "patterns": [
            r"\bexec\(|\bsystem\(|\bpassthru\(|shell_exec\(|\bpopen\(|proc_open\(|pcntl_exec\("
        ],
    },
    "TIER1_TEMPLATE_ENGINES": {
        "group": "group-a",
        "patterns": [
            r"new Twig_Environment|Twig_Loader_String|new Smarty|new Mustache_Engine|new League\\Plates|new Blade",
            r"->render\(|->display\(|->fetch\(|->parse\(",
        ],
    },
    # Request-superglobal read in a file that also instantiates a Twig string
    # loader (Twig_Loader_String / a Twig_Environment wrapping one) — the loader
    # compiles arbitrary strings as executable template *source*, not just
    # variable data. If a request value reaches the template body (commonly via
    # a form-builder's "prefill"/"default value" feature that splices generated
    # field HTML into an admin-editable template string before render()), an
    # attacker controls Twig syntax and gets SSTI/RCE (CWE-94, CWE-1336).
    # sanitize_text_field() alone does not strip '{'/'}' and is not a fix.
    # cross_file_filter narrows the broad superglobal-read token to only the
    # (rare) files that also set up this dangerous string-template primitive.
    # CVE-2026-4257 (contact-form-by-supsystic <= 1.7.36): an unauthenticated
    # 'cfsPreFill' GET-param flow reached a Twig_Loader_String render() as
    # unescaped template markup — fixed by escaping '{'/'}' at the source.
    "TWIG_LOADER_TAINTED_FIELD_VALUE": {
        "group": "group-a",
        "patterns": [
            r"sanitize_text_field\(\s*\$_(?:GET|POST|REQUEST)\[",
            r"\$_(?:GET|POST|REQUEST)\s*\[[^\]]+\]",
        ],
        "cross_file_filter": r"new Twig_Environment|Twig_Loader_String",
        "limit": 30,
    },
    "TIER1_FILE_WRITE": {
        "group": "group-a",
        "patterns": [
            r"move_uploaded_file",
            r"wp_handle_upload",
            r"media_handle_upload\(",
            r"media_sideload_image\(",
            r"wp_upload_bits",
            r"file_put_contents",
            r"\bfwrite\(",
            r"\bcopy\(",
            r"\brename\(",
            r"download_url\(",
            r"->move\(",
            r"->copy\(",
            r"->put_contents\(",
            # Multi-file $_FILES-shaped array iteration feeding an upload sink
            # per loop iteration — a leg on this loop with no accompanying
            # count()-based ceiling lets a single request create an unbounded
            # number of uploads/attachments (resource exhaustion, CWE-434/770).
            r"foreach\s*\(\s*\$\w+\[\s*['\"]name['\"]\s*\]",
            r"foreach\s*\(\s*\$_FILES\[",
            # preg_replace() whose pattern argument targets a define(...)
            # statement — the "regenerate a PHP constants/config file"
            # idiom. Cross-reference the replacement value's source: if it
            # is request data with no quote-escaping (addslashes()/
            # var_export()/json_encode()) before the write, this is
            # Code Injection (CWE-94) via config-file poisoning, not a
            # simple file-write bug — CVE-2025-8723.
            r"preg_replace\([^,]*define\\?\(",
        ],
    },
    # Opening line of a PHP-built Apache/Nginx directive that sets a header
    # or rule from a quoted, concatenation-fed value (`Header set X "..."`,
    # `add_header X "...";`). Plugins that generate `.htaccess`/`nginx.conf`
    # blocks from admin settings (custom CSP/security-header, CORS,
    # cache-control) commonly build these lines by string concatenation; if
    # the concatenated value is a stored option/config string with no
    # CR/LF/quote-stripping sanitizer, a value containing `\r\n` terminates
    # the directive and injects a new one once the file is (re)written —
    # web-server directive injection (CWE-94), RCE-capable on Apache/
    # LiteSpeed. Cross-reference every hit against TIER1_FILE_WRITE for a
    # nearby file_put_contents()/->put_contents() call writing the buffer to
    # a `.htaccess`/`*.conf` path, then trace the concatenated value back to
    # its source and confirm/deny a sanitizer sits between source and sink.
    "WEBSERVER_DIRECTIVE_HEADER_CONCAT": {
        "group": "group-a",
        "patterns": [
            r"(?i)(?:Header\s+(?:always\s+)?(?:set|append|add|unset|merge|edit)|add_header)\s+[\w-]+\s*\\?[\"']",
        ],
        "cross_file_filter": r"file_put_contents|->put_contents\(|fwrite\(",
        "limit": 30,
    },
    "TIER2_FILE_READ": {
        "group": "group-a",
        "patterns": [
            r"file_get_contents",
            r"\breadfile\(",
            r"\bfopen\(",
            r"\binclude\(|\binclude_once\b",
            r"\brequire\(|\brequire_once\b",
            r"\bimagecreatefrom(jpeg|png|gif|webp|bmp|xbm|xpm|gd2|gd|file)\(",
            r"\bgetimagesize\(",
        ],
    },
    "TIER2_FILE_DELETE": {
        "group": "group-a",
        "patterns": [
            r"\bunlink\(",
            r"wp_delete_file",
            r"\brmdir\(",
            r"wp_delete_attachment\(",
        ],
    },
    # URL/referer path component (parse_url()/wp_parse_url()) concatenated
    # into a directory argument that is scanned and wiped by a nearby
    # scandir()/unlink()/rmdir() delete sink, with no realpath()-based
    # containment check narrowing it back to an intended cache/temp root.
    # CVE-2026-56066 (shortpixel-adaptive-images <= 3.11.4): an attacker-
    # controlled 'referer' value reached CacheCleaner::clear(), which built
    # a cache directory from parse_url($url)['path'] and passed it straight
    # to a scandir()+unlink() loop with zero path validation. cross_file_filter
    # narrows the broad parse_url() token to files that also perform a
    # directory-listing or delete call.
    "URL_PATH_DERIVED_CACHE_DELETE": {
        "group": "group-a",
        "patterns": [
            r"(?:wp_parse_url|parse_url)\s*\(",
            r"\bPHP_URL_PATH\b",
        ],
        "cross_file_filter": r"@?(?:unlink|rmdir|wp_delete_file)\s*\(|\bscandir\s*\(",
        "limit": 30,
    },
    "FILE_EXISTS_BEFORE_DELETE": {
        "group": "group-a",
        "patterns": [
            r"file_exists\s*\(\s*\$\w+(?:\[[^\]]+\]|->\w+)+\s*\.\s*\$",
            # Bare variable / array / property access with NO concatenation —
            # the whole path string (not just a suffix) may be attacker-set,
            # which is the shape PHAR stream-wrapper deserialization needs.
            r"(?:file_exists|is_file)\s*\(\s*\$\w+(?:\[[^\]]+\]|->\w+)*\s*\)",
        ],
        "cross_file_filter": r"@?(?:unlink|wp_delete_file|rmdir|copy|readfile|getimagesize|file_get_contents)\s*\(",
        "limit": 30,
    },
    "WP_FILESYSTEM_DELETE": {
        "group": "group-a",
        "patterns": [
            # Plugins commonly wrap WP_Filesystem() in a helper (e.g. get_filesystem(),
            # my_plugin_filesystem()) and assign the instance to an arbitrarily-named
            # variable rather than the literal $wp_filesystem global — match any
            # variable/method-chain containing "filesystem" to catch these aliases.
            r"(?i)\$\w*filesystem\w*->delete\(",
            r"(?i)get_filesystem\(\s*\)\s*->\s*delete\(",
        ],
        "limit": 30,
    },
    "STRPOS_PATH_PREFIX_CONTAINMENT": {
        "group": "group-a",
        "patterns": [
            # A strpos()-based prefix/containment check on a path variable against
            # a base-directory variable, either comparison order. strpos() is a raw
            # substring match — it does not resolve ".." segments or symlinks, so a
            # value normalized only via wp_normalize_path() (not realpath()) survives
            # this check while still traversing outside the intended directory.
            r"(?i)0\s*(?:===?|!==?)\s*strpos\s*\(\s*\$\w*(?:path|file)\w*\s*,\s*\$\w*(?:dir|base|upload|root|allow)\w*\s*\)",
            r"(?i)strpos\s*\(\s*\$\w*(?:path|file)\w*\s*,\s*\$\w*(?:dir|base|upload|root|allow)\w*\s*\)\s*(?:===?|!==?)\s*0",
            # Arg-position-agnostic variant keyed on a whole-word dir-token name —
            # catches strpos()/str_starts_with() calls where the base-dir argument
            # is not literally the second parameter, or the path-side variable
            # name doesn't itself contain "path"/"file".
            r"strpos\s*\([^)]*\$\w*(?:basedir|base_dir|upload_dir|uploads_dir|safe_dir|safedir|allowed_dir|allowlist_dir|root_dir|target_dir|plugin_dir|content_dir|attachments?)\w*",
            r"str_starts_with\s*\([^)]*\$\w*(?:basedir|base_dir|upload_dir|uploads_dir|safe_dir|safedir|allowed_dir|allowlist_dir|root_dir|target_dir|plugin_dir|content_dir|attachments?)\w*",
            # Property-access base-dir variant (CVE-2026-42737): the base-dir
            # side is an object property ("$this->attachmentsPath") rather
            # than a bare variable, so the two patterns above -- which
            # anchor "$\w*" directly against the keyword -- never reach past
            # the "->" token boundary.
            r"strpos\s*\([^)]*\$\w+\s*->\s*\w*(?:dir|base|upload|root|allow|attachments?)\w*",
            r"str_starts_with\s*\([^)]*\$\w+\s*->\s*\w*(?:dir|base|upload|root|allow|attachments?)\w*",
        ],
        "limit": 30,
    },
    # Mirror-image bug of STRPOS_PATH_PREFIX_CONTAINMENT above: realpath() IS
    # called on a request-influenced path (the self-reassignment idiom
    # "$path = realpath($path);" is the dominant real-world shape), but
    # realpath() alone only resolves ".." segments/symlinks -- it enforces no
    # directory boundary. Developers frequently treat a truthy/is_readable()
    # check on the realpath()'d result as sufficient, omitting the
    # strpos()/str_starts_with() prefix comparison against the base/allowed
    # directory that STRPOS_PATH_PREFIX_CONTAINMENT looks for (CWE-22).
    # CVE-2026-14352 (AR for WooCommerce <= 8.40): ar_validate_and_serve_file()
    # built $full_file_path from $allowed_directory . '/' . $file_path
    # (decrypted from the 'file' GET parameter), reassigned it via
    # realpath($full_file_path), and checked only is_readable() before
    # serving the file -- no containment check against $allowed_directory.
    "REALPATH_REASSIGN_NO_CONTAINMENT": {
        "group": "group-a",
        "patterns": [
            # Self-reassignment idiom: $path = realpath($path);
            r"(\$\w+)\s*=\s*realpath\s*\(\s*\1\s*\)",
            # Direct assignment: realpath() applied straight to a
            # base-directory concatenation, no intermediate variable.
            r"=\s*realpath\s*\(\s*\$\w*(?:basedir|base_dir|upload_dir|uploads_dir|safe_dir|safedir|allowed_dir|allowlist_dir|root_dir|target_dir|plugin_dir|content_dir)\w*\s*\.",
            # A third, more direct misuse of the same "realpath() = safe"
            # assumption: realpath() applied INLINE, directly as the argument
            # to include/require(_once), rather than assigned to a variable
            # first. realpath() only canonicalizes ".." segments -- it does
            # not confine the result to any directory -- so this is CWE-98
            # Local File Inclusion whenever the wrapped path is built from a
            # request-influenced or shortcode/widget-attribute selector.
            # CVE-2025-39526 (Hotel Booking <= 3.6): nd_booking_ss_rooms()
            # built $nd_booking_layout_selected from a 'layout' shortcode
            # attribute concatenated onto dirname(__FILE__), then called
            # "include realpath($nd_booking_layout_selected);" with no
            # allow-list check at all.
            r"\b(?:include|include_once|require|require_once)\s*\(?\s*realpath\s*\(",
            # Constant-base variant of the direct-assignment pattern above:
            # the base directory is a bareword PHP constant (a plugin's own
            # define()'d root, e.g. "MY_PLUGIN_INC"/"MY_PLUGIN_VIEWS") rather
            # than a $variable, concatenated with a remainder and passed
            # straight to realpath(), then checked only for existence
            # (file_exists()/is_file()) before the resolved path is included
            # or read elsewhere in the function -- no strpos()/containment
            # check against the same constant. CVE-2025-60200 (LearnPress
            # Export Import <= 4.1.2): lpie_admin_view() built
            # "$path = realpath(LP_ADDON_IMPORT_EXPORT_INC . "admin/views/{$name}.php")"
            # and returned early only on "!$path || !file_exists($path)"
            # before "include $path;".
            r"=\s*realpath\s*\(\s*[A-Z_][A-Z0-9_]{2,}\s*\.",
        ],
        "limit": 30,
    },
    "DELETE_HANDLER_REGISTRATION": {
        "group": "group-a",
        "patterns": [
            r"wp_ajax_(?:nopriv_)?.*(?:delete|remove).*(?:file|attachment|image|media|upload|document)",
            r"admin_post_(?:nopriv_)?.*(?:delete|remove).*(?:file|attachment|image|media|upload|document)",
            # Reversed token order (file/attachment token BEFORE delete/remove token) —
            # e.g. "..._temp_file_delete", "..._attachment_file_remove". Closes a false
            # negative confirmed on CVE-2025-7341 (ht-contactform): the two patterns
            # above only match a hook registration whose literal string has the
            # delete/remove token first.
            r"wp_ajax_(?:nopriv_)?.*(?:file|attachment|image|media|upload|document).*(?:delete|remove)",
            r"admin_post_(?:nopriv_)?.*(?:file|attachment|image|media|upload|document).*(?:delete|remove)",
        ],
        "case_insensitive": True,
        "limit": 30,
    },
    # Raw HTTP-method-based dispatch to a delete action, bypassing
    # WordPress's native admin-ajax/REST nonce+capability idioms entirely.
    # Recurs in plugins that vendor a third-party upload/file-manager
    # library (adapted from the blueimp jQuery-File-Upload PHP class or
    # similar) largely unmodified — the class inspects
    # $_SERVER['REQUEST_METHOD'] or a $_REQUEST['_method'] override itself
    # instead of relying on a WP hook registration, so DELETE_HANDLER_
    # REGISTRATION's wp_ajax_*/admin_post_* hook-name patterns never see
    # it. cross_file_filter narrows to files that also perform a file
    # delete, to skip legitimate REST/HTTP verb routing that never reaches
    # a delete sink. CVE-2026-22448 (pitchprint <= 11.1.2):
    # UploadHandler::post() dispatched to delete() off
    # $_REQUEST['_method'] === 'DELETE' with no capability check anywhere
    # in the call chain.
    "REQUEST_METHOD_DELETE_DISPATCH": {
        "group": "group-a",
        "patterns": [
            r"\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\]\s*(?:===?|==)\s*['\"]DELETE['\"]",
            r"\$_REQUEST\s*\[\s*['\"]_method['\"]\s*\]\s*(?:===?|==)\s*['\"]DELETE['\"]",
            r"case\s*['\"]DELETE['\"]\s*:",
        ],
        "cross_file_filter": r"(?i)\bunlink\s*\(|wp_delete_file\s*\(|\brmdir\s*\(|\$wp_filesystem->delete\s*\(",
        "limit": 30,
    },
    "FILE_DELETE_USER_INPUT_DIRECT": {
        "group": "group-a",
        "patterns": [
            r"unlink\s*\(.*\$_(GET|POST|REQUEST)",
            r"wp_delete_file\s*\(.*\$_(GET|POST|REQUEST)",
            r"rmdir\s*\(.*\$_(GET|POST|REQUEST)",
            r"\$wp_filesystem->delete\s*\(.*\$_(GET|POST|REQUEST)",
            # Indirect variant (CVE-2026-57709, membership-for-woocommerce):
            # the request superglobal is assigned to a variable through a
            # weak text-only sanitizer (sanitize_text_field()/
            # sanitize_textarea_field(), optionally wp_unslash()-wrapped) —
            # neither strips '/', '\\', or '..' — and that variable reaches
            # the delete sink on a LATER line, so it never appears inline
            # with unlink()/wp_delete_file()/rmdir() the way the four
            # patterns above require. cross_file_filter narrows to files
            # that also perform a file-delete call.
            # wc_clean() added (CVE-2026-9725, printcart-integration): it is
            # literally sanitize_text_field(wp_unslash($v)) under a
            # different name in WooCommerce-ecosystem plugins and shares the
            # same non-stripping-of-'..'  weakness.
            r"(?:sanitize_text_field|sanitize_textarea_field|wc_clean)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST)\b",
        ],
        # Widened for CVE-2026-9725: the delete sink is often a custom
        # recursive-delete wrapper (e.g. Nbdesigner_IO::delete_folder()),
        # not literally unlink()/wp_delete_file()/rmdir()/$wp_filesystem-
        # >delete() — same name-heuristic used by the sibling Semgrep rule
        # (claude.php.wordpress.file-write-delete.weak-sanitizer-request-
        # param-to-delete-call): a call whose name combines a
        # file/attachment/upload/temp/folder/dir noun with a
        # delete/remove/unlink/rmdir verb.
        "cross_file_filter": r"(?i)\bunlink\s*\(|wp_delete_file\s*\(|\brmdir\s*\(|\$wp_filesystem->delete\s*\(|(?:->|::)\s*\w*(?:file|attachment|upload|temp|folder|dir)\w*(?:delete|remove|unlink|rmdir)\w*\s*\(|(?:->|::)\s*\w*(?:delete|remove|unlink|rmdir)\w*(?:file|attachment|upload|temp|folder|dir)\w*\s*\(",
        "limit": 30,
    },
    "FILE_WRITE_USER_INPUT_DIRECT": {
        "group": "group-a",
        "patterns": [
            r"mkdir\s*\(.*\$_(GET|POST|REQUEST)",
            r"fopen\s*\(.*\$_(GET|POST|REQUEST)",
            # Indirect variant (CVE-2025-69325, primer-mydata): the request
            # superglobal is assigned to a variable through a weak text-only
            # sanitizer (sanitize_text_field()/sanitize_textarea_field(),
            # optionally wp_unslash()-wrapped) — neither strips '/', '\\',
            # or '..' — and that variable is concatenated onto a base
            # directory (e.g. "$upload_dir . '/' . $var") that reaches
            # mkdir()/fopen()/file_put_contents() on a LATER line, often
            # inside a sibling method the value was passed into rather than
            # inline with the write call itself. cross_file_filter narrows
            # to files that also perform a file/directory-write call.
            r"(?:sanitize_text_field|sanitize_textarea_field|wc_clean)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST)\b",
            # Framework Request-wrapper variant (CVE-2025-30834, bit-assist):
            # a bundled routing/request library's all()/post()/request()
            # convenience accessor stands in for $_POST/$_GET — the
            # superglobal itself never appears in the vulnerable file — and
            # is weakly sanitized the same way (sanitize_text_field() etc.
            # do not strip '/', '\\', or '..'). cross_file_filter (widened
            # below to include wp_mkdir_p()/move_uploaded_file() and a
            # store/move naming heuristic) narrows to files that also
            # perform a file/directory-write call.
            r"(?:sanitize_text_field|sanitize_textarea_field|wc_clean|array_map)\s*\(\s*(?:['\"]sanitize_text_field['\"]\s*,\s*)?\$\w+->(?:all|post|request|input)\s*\(\s*\)",
            # Concatenation-onto-base-dir variant (CVE-2025-2941, drag-and-
            # drop-multiple-file-upload-for-woocommerce): the weak sanitizer
            # wraps an already-tainted loop/array variable (not the bare
            # superglobal literal the two patterns above require) and the
            # result is concatenated directly onto a base directory in the
            # SAME expression, e.g. "$dir . wc_clean(wp_unslash($file))" —
            # the concatenated value then reaches rename()/move_uploaded_file()
            # as the source or destination path with no realpath()/
            # containment check. cross_file_filter (widened below to include
            # rename()) narrows to files that also perform a file move.
            r"\$\w+\s*\.\s*(?:sanitize_text_field|sanitize_textarea_field|wc_clean)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$\w+\s*\)",
        ],
        # Same name-heuristic used by the sibling Semgrep rule
        # (claude.php.wordpress.file-write-delete.weak-sanitizer-request-
        # param-to-write-call): a call whose name combines a
        # file/export/report/dir/folder/upload/path noun with a
        # write/save/generate/create/build/export verb, to also catch the
        # common two-method split where the actual mkdir()/fopen() call
        # lives inside a sibling method the tainted value is passed into.
        # wp_mkdir_p()/move_uploaded_file() and the store/move verbs were
        # added for CVE-2025-30834 (bit-assist): the WordPress-native
        # directory-create wrapper and the raw upload-persist call, plus
        # storeFiles()/moveUploadedFiles()-style delegate method names.
        # rename() added for CVE-2025-2941 (drag-and-drop-multiple-file-
        # upload-for-woocommerce): the plain PHP file-move primitive used
        # directly on a request-derived path with no realpath() containment.
        "cross_file_filter": r"(?i)\bmkdir\s*\(|\bwp_mkdir_p\s*\(|\bfopen\s*\(|file_put_contents\s*\(|move_uploaded_file\s*\(|\brename\s*\(|(?:->|::)\s*\w*(?:file|export|report|dir|folder|upload|invoice|attachment|path)\w*(?:write|save|generate|create|build|export|store|move)\w*\s*\(|(?:->|::)\s*\w*(?:write|save|generate|create|build|export|store|move)\w*(?:file|export|report|dir|folder|upload|invoice|attachment|path)\w*\s*\(",
        "limit": 30,
    },
    "BATCH_FILE_DELETE": {
        "group": "group-a",
        "patterns": [
            r"array_map\s*\(\s*['\"]@?unlink['\"]",
        ],
        "limit": 20,
    },
    "RECURSIVE_DIRECTORY_DELETE": {
        "group": "group-a",
        "patterns": [
            r"function\s+rrmdir\s*\(",
            r"function\s+(?:recursive_?)?delete_?(?:dir(?:ectory)?|folder)\s*\(",
            r"function\s+(?:remove|delete)_?(?:dir(?:ectory)?|folder)_?recurs(?:ive(?:ly)?)?\s*\(",
        ],
        "case_insensitive": True,
        "limit": 20,
    },
    "TIER2_CONTENT_DELETE": {
        "group": "group-a",
        "patterns": [
            r"wp_delete_post\s*\(",
            r"wp_trash_post\s*\(",
            r"wp_delete_attachment\s*\(",
            r"wp_delete_comment\s*\(",
            r"wp_trash_comment\s*\(",
            r"wp_delete_term\s*\(",
            r"wp_delete_user\s*\(",
            r"delete_comment_meta\s*\(",
            r"delete_term_meta\s*\(",
            r"delete_user_meta\s*\(",
        ],
    },
    "CONTENT_DELETE_HANDLER_REGISTRATION": {
        "group": "group-a",
        "patterns": [
            r"wp_ajax_(?:nopriv_)?.*(?:delete|remove|trash).*(?:post|page|comment|review|term|categor|tag|entry|record|item|user|submission|booking|form|listing|event|order|result)",
            r"admin_post_(?:nopriv_)?.*(?:delete|remove|trash).*(?:post|page|comment|review|term|categor|tag|entry|record|item|user|submission|booking|form|listing|event|order|result)",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    "CONTENT_DELETE_USER_INPUT_DIRECT": {
        "group": "group-a",
        "patterns": [
            r"wp_delete_post\s*\(.*\$_(GET|POST|REQUEST)",
            r"wp_trash_post\s*\(.*\$_(GET|POST|REQUEST)",
            r"wp_delete_comment\s*\(.*\$_(GET|POST|REQUEST)",
            r"wp_trash_comment\s*\(.*\$_(GET|POST|REQUEST)",
            r"wp_delete_term\s*\(.*\$_(GET|POST|REQUEST)",
            r"wp_delete_user\s*\(.*\$_(GET|POST|REQUEST)",
            r"wp_delete_attachment\s*\(.*\$_(GET|POST|REQUEST)",
        ],
        "limit": 30,
    },
    "FILE_DOWNLOAD_ENDPOINTS": {
        "group": "group-a",
        "patterns": [
            r"Content-Disposition.*attachment",
            r"application/octet-stream",
            r"application/force-download",
        ],
        "cross_file_filter": r"\breadfile\(|file_get_contents|fpassthru\(|fread\(",
        "limit": 40,
    },
    "FILE_READ_STREAM_FUNCTIONS": {
        "group": "group-a",
        "patterns": [
            r"\bfpassthru\(",
            r"\bfread\(",
            r"\bfgets\(",
        ],
        "exclude_patterns": [
            r"fread\s*\(\s*\$this->",
        ],
        "limit": 40,
    },
    "DOWNLOAD_HANDLER_REGISTRATION": {
        "group": "group-a",
        "patterns": [
            r"wp_ajax_(?:nopriv_)?.*(?:download|export_file|serve_file|get_file)",
            r"admin_post_(?:nopriv_)?.*(?:download|export_file|serve_file|get_file)",
        ],
        "case_insensitive": True,
        "limit": 30,
    },
    "WP_FILESYSTEM_READ": {
        "group": "group-a",
        "patterns": [
            r"\$wp_filesystem->get_contents\(",
            r"\$wp_filesystem->get_contents_array\(",
        ],
        "limit": 30,
    },
    # A base/root directory concatenated with ltrim($X, '/') is the common
    # PHP path-join idiom for combining a directory with a request-derived
    # remainder. If the resulting path is returned/used with no realpath()
    # + prefix-containment check anywhere nearby, traversal segments in the
    # remainder escape the intended directory (CWE-22/CWE-98). realpath()
    # alone is not the check - it normalizes the path, it does not restrict
    # it; a containment comparison against the base directory must follow.
    # WP core's own path_join() is the same idiom under a different name and
    # carries an extra bypass: it returns its second argument UNCHANGED
    # whenever path_is_absolute() is true, so a blacklist check for '../' or
    # './' never catches an absolute-path remainder (e.g. "/etc/passwd").
    # CVE-2026-4347 (MW WP Form): generate_user_filepath() joined a form
    # field value via path_join() with only a '../'/'./'/null-byte blacklist
    # and no basename/containment check, enabling arbitrary file move.
    "PATH_CONCAT_LTRIM_JOIN": {
        "group": "group-a",
        "patterns": [
            r"\.\s*ltrim\s*\(\s*\$\w+\s*,\s*(?:'/+'|\"/+\"|'/'|\"/\")\s*\)",
            r"\bpath_join\s*\(",
        ],
        "limit": 30,
    },
    # CVE-2026-6320 (Salon Booking System <= 10.30.25): a "file" custom-field
    # value captured from an unauthenticated public checkout/booking form is
    # stored raw (no basename()) and later joined onto wp_upload_dir()/
    # wp_get_upload_dir()'s 'basedir' — via implode()/array_filter() or plain
    # string concatenation — then appended straight into the array later
    # handed to wp_mail()'s $attachments argument. PHPMailer fopen()s whatever
    # path lands in that array, so an unstripped "../" in the field value
    # exfiltrates an arbitrary file's contents to the email recipient (often
    # the submitter's own attacker-controlled address). The fix added
    # basename() on the filename component plus a realpath()+prefix
    # containment check before the array append (CWE-22).
    "MAIL_ATTACHMENT_BASEDIR_CONCAT": {
        "group": "group-a",
        "patterns": [
            r"\[\s*['\"]attachments['\"]\s*\]\s*\[\s*\]\s*=\s*implode\s*\(",
            r"\$attachments\s*\[\s*\]\s*=\s*implode\s*\(",
            r"\[\s*['\"]attachments['\"]\s*\]\s*\[\s*\]\s*=\s*\$\w+(?:\[[^\]]+\]|->\w+)*\s*\.\s*",
            r"\$attachments\s*\[\s*\]\s*=\s*\$\w+(?:\[[^\]]+\]|->\w+)*\s*\.\s*",
            # CVE-2026-5710 (Drag and Drop Multiple File Upload for Contact
            # Form 7 <= 1.3.9.6): a second shape where the base directory
            # never appears directly at the append site — it is consumed one
            # statement earlier (e.g. str_replace()'s URL->path "conversion"
            # idiom) and only a bare result variable, with no trailing
            # concatenation, reaches the attachments array
            # ($components['attachments'][] = $new_file_name;). The three
            # patterns above all require a trailing "." after the variable,
            # so they miss this shape entirely. Bare-variable append is a
            # broader signal (also matches an already-realpath()'d safe
            # variable) — cross_file_filter plus manual verification narrows
            # it, consistent with grep being leads-only.
            r"\[\s*['\"]attachments['\"]\s*\]\s*\[\s*\]\s*=\s*\$\w+\s*;",
            r"\$attachments\s*\[\s*\]\s*=\s*\$\w+\s*;",
        ],
        "cross_file_filter": r"wp_upload_dir\(|wp_get_upload_dir\(|basedir",
        "limit": 30,
    },
    "READFILE_USER_INPUT_DIRECT": {
        "group": "group-a",
        "patterns": [
            r"readfile\s*\(.*\$_(GET|POST|REQUEST)",
            r"file_get_contents\s*\(.*\$_(GET|POST|REQUEST)",
            r"fopen\s*\(.*\$_(GET|POST|REQUEST)",
            # CVE-2025-13801 (Yoco Payments <= 3.9.0, REST /logs route): the
            # request object's ->get_param() accessor is called a second time
            # directly inside the read sink, re-fetching the raw, unsanitized
            # value even when an EARLIER call to the same accessor was passed
            # through a realpath()+prefix containment check into a different
            # local variable that the sink then ignores. Superglobal-only
            # patterns above miss this WP_REST_Request idiom entirely.
            r"readfile\s*\(.*->get_param\s*\(",
            r"file_get_contents\s*\(.*->get_param\s*\(",
            r"fopen\s*\(.*->get_param\s*\(",
            r"filesize\s*\(.*\$_(GET|POST|REQUEST)",
            # Indirect variant (CVE-2026-49112, shared-files <= 1.7.64): the
            # request superglobal is assigned to a variable through a weak
            # text-only sanitizer (sanitize_text_field()/
            # sanitize_textarea_field(), optionally wp_unslash()-wrapped) —
            # neither strips '/', '\\', or '..' — and that variable reaches
            # a file-read/stat sink (file_get_contents()/readfile()/fopen()/
            # filesize()) on a LATER line, often after being packed into an
            # array under a 'file'-style key that mimics wp_upload_bits()'s
            # own return shape and is trusted by a downstream helper without
            # re-validation, so it never appears inline with the read call
            # the way the patterns above require. cross_file_filter narrows
            # to files that also perform a file-read/stat call.
            r"(?:sanitize_text_field|sanitize_textarea_field|wc_clean)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST)\b",
            # Stored/second-order variant (CVE-2026-49061, WPC Product Options
            # for WooCommerce <= 3.2.1): the tainted value never appears on the
            # same request as the read sink at all. An earlier request stores
            # an attacker-supplied array wholesale (e.g. a cart/session/order-
            # item-meta entry keyed by a request field name) with no key
            # allowlist, so a 'file'-style key added by the attacker survives
            # untouched; a LATER, unauthenticated request retrieves that
            # persisted entry and extracts the same key straight into a local
            # variable that reaches readfile()/file_get_contents()/fopen().
            # Matches the extraction itself — a nested array/property access
            # ending in a file-reference-shaped key assigned to a variable —
            # since neither superglobal- nor sanitizer-adjacency patterns
            # above see anything on this line. cross_file_filter (read/stat
            # sink present in file) still applies.
            r"=\s*.*\[\s*['\"](?:file|filepath|file_path|tmp_file|tmp_path)['\"]\s*\]\s*;",
        ],
        "cross_file_filter": r"\breadfile\s*\(|file_get_contents\s*\(|\bfopen\s*\(|\bfilesize\s*\(",
        "limit": 30,
    },
    # CVE-2024-10585 (InfiniteWP Client <= 1.13.0, debug-chart/index.php):
    # a raw $_GET-derived value (no int cast) is concatenated directly
    # between two string literals to build a log/export filename, e.g.
    # 'DE_clMemoryUsage.'.$id.'.txt' — the fopen()/readfile() consuming
    # this string is frequently in a different function or class method
    # (a front-controller-style include handing the path to a helper),
    # so READFILE_USER_INPUT_DIRECT above (same-line $_GET+fopen) misses
    # it. This matches the concatenation itself: a quoted literal, a bare
    # variable, then another quoted literal ending in a common data-file
    # extension. cross_file_filter requires the file to also read request
    # superglobals somewhere, since the filename-shaped concat alone is
    # not proof the variable is unsanitized.
    "REQUEST_PARAM_FILENAME_CONCAT_NO_CAST": {
        "group": "group-a",
        "patterns": [
            r"""['"][^'"]*['"]\s*\.\s*\$\w+\s*\.\s*['"][^'"]*\.(?:txt|log|csv|json|xml|dat|ini|ser)['"]""",
        ],
        "cross_file_filter": r"\$_(?:GET|POST|REQUEST)\b",
        "limit": 30,
    },
    "REQUEST_ARRAY_FILE_LIST_LOOP": {
        "group": "group-a",
        "patterns": [
            r"foreach\s*\(\s*\$_(?:GET|POST|REQUEST)\[",
            r"\$\w+\s*=\s*\$_(?:GET|POST|REQUEST)\[['\"]\w*(?:files?|f_array|assets?|paths?)\w*['\"]\]",
            # array_map()/foreach decode-passthrough: a json_decode() result is
            # returned/kept once it passes only an is_array() type check, with
            # no path-containment validation, before the caller merges it into
            # a trusted file/entry list (CVE-2026-5478-class "resume upload /
            # keep previous file" reference trust).
            r"return\s+is_array\s*\(\s*\$\w+\s*\)\s*\?\s*\$\w+\s*:\s*(?:array\s*\(\s*\)|\[\s*\])\s*;",
        ],
        "cross_file_filter": r"\bis_file\(|\brealpath\(|\bfile_exists\(|json_decode\(",
        "limit": 30,
    },
    "CUSTOM_PATH_SEGMENT_COLLAPSE": {
        "group": "group-a",
        "patterns": [r"array_pop\s*\("],
        "cross_file_filter": r"(['\"])\.\.\1",
    },
    "UPLOAD_TEST_TYPE_FALSE": {
        "group": "group-a",
        "patterns": [r"['\"]test_type['\"]\s*=>\s*false"],
    },
    # A file-type/extension validation check reads only literal index [0] of
    # a $_FILES upload field (directly, or via a local var assigned from
    # $_FILES[...] earlier in the file) — the array shape only occurs for
    # array-style HTML input names (e.g. "files[]"), so the field natively
    # accepts multiple files while validation covers just the first. Manually
    # confirm downstream processing is not itself hard-restricted to index 0
    # (CVE-2026-6555 class). CWE-434.
    "FILES_ARRAY_INDEX_ZERO_ONLY_VALIDATION": {
        "group": "group-a",
        "patterns": [
            r"\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"](?:name|tmp_name|type)['\"]\s*\]\s*\[\s*0\s*\]",
            r"\$\w+\s*\[\s*['\"](?:name|tmp_name)['\"]\s*\]\s*\[\s*0\s*\]",
        ],
        "cross_file_filter": r"\$_FILES",
        "limit": 30,
    },
    # CVE-2024-8856 (wp-time-capsule, CWE-434): the extension allow-list check
    # feeds strpos()/strrpos() directly into arithmetic with strlen() instead
    # of an anchored suffix comparison — e.g.
    # strrpos($name, $ext) + strlen($ext) === strlen($name). strpos()/strrpos()
    # return the boolean false (not an integer) when the needle is absent;
    # PHP coerces false to 0 in the '+' expression, so a candidate filename
    # whose length exactly equals one of the allowed extension strings
    # satisfies the comparison regardless of its real extension, bypassing
    # the allow-list entirely.
    "STRPOS_ARITHMETIC_EXTENSION_CHECK": {
        "group": "group-a",
        "patterns": [
            r"strr?pos\s*\([^)]*\)\s*\+\s*strlen\s*\(",
            r"strlen\s*\([^)]*\)\s*={2,3}\s*strr?pos\s*\(",
        ],
        "limit": 30,
    },
    # An upload handler validates a detected/reported MIME type via
    # in_array($mimeType, explode(...)) against an extension-keyed allow-list
    # (extension => pipe/comma-separated MIME string), typically inside a
    # foreach ($map as $ext => $mimes) loop. The bug class: the loop accepts
    # a match against ANY entry in the whole map instead of restricting the
    # test to the entry keyed by the file's OWN extension, so a dangerous
    # extension (e.g. .php) whose detected MIME happens to match a
    # different, unrelated allowed extension's MIME string passes validation
    # (CVE-2020-24186 class — wpDiscuz <= 7.0.4 unauthenticated arbitrary
    # file upload via the comment-attachment uploader). CWE-434. Lead only:
    # a same-file `$ext === $extension`/`$ext == $extension` gate (in either
    # operand order) inside the loop is the fix and clears the hit — verify
    # manually before reporting.
    "MIME_ALLOWLIST_LOOP_EXTENSION_UNBOUND": {
        "group": "group-a",
        "patterns": [
            r"in_array\s*\(\s*\$\w*mime\w*\s*,\s*explode\s*\(",
        ],
        "case_insensitive": True,
        "limit": 30,
    },
    # An upload handler's "allowed extensions/types" list is assigned directly
    # from request data ($_POST/$_REQUEST/$_GET) — often only as the fallback
    # of an empty() check — and later used as the haystack in an in_array()
    # extension check. The client thus controls which file types are
    # "allowed"; a separate hardcoded blacklist elsewhere does not fix this
    # (CVE-2024-1567 class). CWE-434.
    "REQUEST_CONTROLLED_UPLOAD_ALLOWLIST": {
        "group": "group-a",
        "patterns": [
            r"\$\w*(?:allow(?:ed)?|accept(?:ed)?|valid)\w*(?:_?type|_?ext)\w*\s*=\s*\$_(?:POST|REQUEST|GET)\[",
        ],
        "cross_file_filter": r"in_array\s*\(",
        "limit": 30,
    },
    # A hardcoded upload-extension denylist (variable or dedicated "not
    # allowed"/blacklist function) lists 'phtml'/'php3'/'php4' — proving
    # intent to block PHP execution — but denylist-based validation is
    # routinely incomplete: surfaces candidates for a manual check that the
    # array also covers '.pht', '.php5', '.php7', '.php8' (still
    # PHP-executable on many hosts) (CVE-2026-3459 class). CWE-434/CWE-184.
    "PHP_EXTENSION_DENYLIST_ARRAY": {
        "group": "group-a",
        "patterns": [
            r"['\"]phtml['\"]",
            r"['\"]php3['\"]",
            r"['\"]php4['\"]",
        ],
        "cross_file_filter": r"in_array\s*\(|move_uploaded_file\s*\(|wp_handle_upload\s*\(",
        "limit": 30,
    },
    # exif_imagetype()/getimagesize() only inspect the leading bytes of a
    # source for a known image signature — they do not validate the saved
    # filename/extension. When paired with a disk-write in the same file, a
    # remote source with attacker-controlled name/extension but valid image
    # magic bytes can be saved with an executable extension (CVE-2024-3229
    # class GIF89a-style bypass).
    "EXIF_IMAGETYPE_WEAK_UPLOAD_GATE": {
        "group": "group-a",
        "patterns": [r"exif_imagetype\s*\("],
        "cross_file_filter": r"fwrite\s*\(|file_put_contents\s*\(|fopen\s*\([^)]*['\"]w",
    },
    # $wp_filesystem->copy()/->move()/->put_contents() or file_put_contents()
    # persists a file to a new location with no WordPress file type
    # validation anywhere in the file. CWE-434 (CVE-2025-14800 class, widened
    # for the put_contents()/file_put_contents() variant: a custom "save
    # attachment/import" helper hashes or timestamps the destination name but
    # concatenates the original filename's extension unchanged via
    # basename(), then writes with no wp_check_filetype()/
    # wp_check_filetype_and_ext()/wp_handle_upload() anywhere in the file —
    # a bespoke in_array()/finfo() allow-list check elsewhere does not
    # suppress this lead, so still verify manually). File-level lead only
    # (no function-scoping in grep); verify manually whether the source
    # path/content is attacker-influenced.
    "WP_FILESYSTEM_COPY_NO_FILETYPE_CHECK": {
        "group": "group-a",
        "patterns": [r"wp_check_filetype\(|wp_check_filetype_and_ext\(|wp_handle_upload\("],
        "invert": True,
        "cross_file_filter": r"\$wp_filesystem->(?:copy|move|put_contents)\s*\(|file_put_contents\s*\(",
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 30,
    },
    # A base64/data-URI upload widget (e.g. an image cropper) posts the
    # client-side "original filename" under an 'org'/'orig'/'original' array
    # key, and the file containing that key access has no
    # wp_check_filetype()/wp_check_filetype_and_ext()/wp_handle_upload() call
    # anywhere in it (CWE-434, CVE-2025-11391 class: PPOM for WooCommerce
    # <= 33.0.15 image-cropper save handler wrote the decoded payload under
    # this filename with zero extension/type validation). File-level lead
    # only; verify manually that the key's value actually reaches a disk-
    # write sink (file_put_contents()/$wp_filesystem->put_contents(), or a
    # same-purpose save/write delegate call) — the source and sink are often
    # split across two functions/files rather than inline.
    "ORIGINAL_FILENAME_KEY_NO_FILETYPE_CHECK": {
        "group": "group-a",
        "patterns": [r"wp_check_filetype\(|wp_check_filetype_and_ext\(|wp_handle_upload\("],
        "invert": True,
        "cross_file_filter": r"\[\s*['\"](?:org|orig|original)['\"]\s*\]",
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 30,
    },
    # A data-URI ("data:<mime>;base64,<payload>") string has its prefix
    # stripped (via preg_replace() matching a 'data:' scheme, or the
    # substr()+strpos(',')+1 idiom) ahead of base64_decode(), in a file that
    # also calls fopen()/fwrite()/file_put_contents() in write mode (CWE-434,
    # CVE-2026-14894 class: Super Forms <= 6.3.313 unauthenticated arbitrary
    # file upload — the decoded bytes were written via fopen()/fwrite() using
    # a caller-supplied basename with no sanitize_file_name()/extension
    # allow-list and no magic-byte/content-type check on the decoded bytes).
    # Distinct from ORIGINAL_FILENAME_KEY_NO_FILETYPE_CHECK above: that
    # section keys on the 'org'/'orig'/'original' array-key convention and is
    # file-wide inverted on wp_check_filetype*() presence, which misses
    # plugins (this CVE included) that call wp_check_filetype() in a
    # DIFFERENT, unrelated function elsewhere in the same file. File-level
    # lead only (grep has no function-scoping) — verify manually that the
    # fopen()/fwrite() destination and content actually trace back to the
    # same decoded data-URI value, not an unrelated write elsewhere.
    "DATA_URI_DECODE_RAW_FILE_WRITE": {
        "group": "group-a",
        "patterns": [
            r"preg_replace\s*\(\s*['\"]#?\^?data:",
            r"substr\s*\(\s*\$\w+\s*,\s*strpos\s*\(\s*\$\w+\s*,\s*['\"],['\"]\s*\)\s*\+\s*1\s*\)",
        ],
        "cross_file_filter": r"fopen\s*\([^)]*['\"][wax]|fwrite\s*\(|file_put_contents\s*\(",
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 30,
    },
    # A small helper function reassigns its own filename parameter through
    # sanitize_file_name()/basename() and hands the value onward (e.g. as a
    # FILTER_CALLBACK 'options' callback, or a plain validator called before a
    # write) with no file-extension allow-list check anywhere in the file
    # (CWE-434, CVE-2026-1306 class: midi-Synth <= 1.1.0 unauthenticated
    # arbitrary file upload via the 'export' AJAX action — the write call and
    # the incomplete validator often live in different functions, so a
    # same-function scoped check misses this; this is a file-level lead).
    # sanitize_file_name()/basename() only strip illegal characters and
    # directory components — neither restricts or re-checks the extension.
    # Widened cross_file_filter also catches basename() called INLINE and
    # directly on a request superglobal (no separate reassignment/validator
    # function at all — e.g. `save_file(basename($_REQUEST['x']), ...)`),
    # the shape behind CWE-434, CVE-2021-4443 class: QuadMenu <= 2.0.6
    # unauthenticated arbitrary file creation via its "compiler_save" AJAX
    # action — a request-controlled import path was basename()'d straight
    # into a save-to-disk call with no extension check anywhere in the file.
    "FILENAME_VALIDATOR_NO_EXTENSION_CHECK": {
        "group": "group-a",
        "patterns": [
            r"pathinfo\s*\([^)]*PATHINFO_EXTENSION",
            r"wp_check_filetype\(|wp_check_filetype_and_ext\(|wp_handle_upload\(",
            r"in_array\s*\(\s*\$?\w*ext",
            r"exif_imagetype\s*\(",
            r"getimagesize\s*\(",
            r"finfo_file\s*\(|new\s+finfo\s*\(",
            r"mime_content_type\s*\(",
        ],
        "invert": True,
        "cross_file_filter": r"(\$\w+)\s*=\s*sanitize_file_name\s*\(\s*\1\s*\)|(\$\w+)\s*=\s*basename\s*\(\s*\2\s*\)|basename\s*\(\s*\$_(?:REQUEST|POST|GET)\s*\[",
        "case_insensitive": True,
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 30,
    },
    # wp_check_filetype_and_ext() IS present in the file (unlike the inverted
    # section above) but that alone does not prove the failure halts execution:
    # a rename()/move_uploaded_file() call may still run unconditionally after
    # the check result is only logged to an error accumulator (CWE-434,
    # CVE-2025-1128 class — everest-forms <= 3.0.9.4: check result was written
    # to an error array/option flag with no return/die/throw before rename()).
    # Widened cross_file_filter also flags a file containing a log-only catch
    # block (catch { error_log(...) — no function name required, so it fires
    # regardless of what the plugin calls its own validation helper) — the
    # generic try/throw/catch-swallow shape behind CWE-434, CVE-2023-6316
    # class: a validation check throws on failure inside a try, but the catch
    # only logs, so an upload-processing function still reaches its
    # rename()/move_uploaded_file() sink. Grep cannot see control flow between
    # the check and the sink; every hit is a lead — read the enclosing
    # function to confirm whether an unconditional exit actually gates the
    # rename/move call.
    "FILETYPE_CHECK_NO_HALT_BEFORE_PERSIST": {
        "group": "group-a",
        "patterns": [r"\brename\s*\(|move_uploaded_file\s*\("],
        "cross_file_filter": r"wp_check_filetype_and_ext\s*\(|catch\s*\([^)]*\)\s*\{\s*(?:error_log|Logger?::(?:error|warning|write|log))\s*\(",
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 40,
    },
    "ZIP_HANDLING": {
        "group": "group-a",
        "patterns": [
            r"new\s+ZipArchive",
            r"new\s+PclZip",
            r"->extractTo\s*\(",
            r"PCLZIP_OPT_PATH",
            # A directory-to-archive source path is built by concatenating a
            # WP root/base-dir helper (get_theme_root(), plugin_dir_path(),
            # optionally trailingslashit()-wrapped) directly with a variable,
            # with no basename()/sanitize_file_name() in between — the
            # source directory handed to a zip/recursive-copy routine is
            # then attacker-steerable if that variable traces to request
            # data (CWE-22). Codified from CVE-2026-6403 (quick-playground
            # <= 1.3.3): qckply_zip_theme($stylesheet) built
            # get_theme_root() . '/' . $stylesheet with no containment
            # check; fixed in 1.3.4 by gating the function on
            # current_user_can('manage_options').
            r"\$\w+\s*=\s*(?:trailingslashit\s*\(\s*)?(?:get_theme_root|get_stylesheet_directory|get_template_directory|plugin_dir_path|dirname\s*\(\s*plugin_dir_path)\s*\([^;]*\)\)?\s*\.[^;]*\$\w+\s*;",
        ],
    },
    "PHAR_WRAPPER": {
        "group": "group-a",
        "patterns": [r"phar://"],
    },
    "PHP_STREAM_WRAPPERS": {
        "group": "group-a",
        "patterns": [
            r"php://filter",
            r"data://",
            r"expect://",
            r"zip://",
        ],
        "exclude_patterns": [
            r"file_get_contents\s*\(\s*['\"]php://input['\"]",
        ],
    },
    "FILE_PUT_CONTENTS_USER_PATH": {
        "group": "group-a",
        "patterns": [r"file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)"],
    },
    "INCLUDE_REQUIRE_USER_INPUT": {
        "group": "group-a",
        "patterns": [
            r"(?:include|require)(?:_once)?\s*[\(]?\s*\$_(GET|POST|REQUEST)",
            # Dynamic PHP constant-NAME resolution feeding an include/require
            # path: constant($var) with a variable (not literal) argument
            # right after include/require lets a caller who controls the
            # constant's name pull the value of ANY already-defined PHP
            # constant into the path. Literal-name calls (constant('FOO'))
            # are intentionally excluded — only the variable-argument shape
            # signals attacker-influenced constant selection.
            r"(?:include|require)(?:_once)?\s*[\(]?\s*constant\s*\(\s*\$",
        ],
    },
    "TEMPLATE_LOADING_USER_INPUT": {
        "group": "group-a",
        "patterns": [
            r"get_template_part\s*\(\s*\$",
            r"locate_template\s*\(\s*\$",
            r"locate_template\s*\(\s*array\s*\(\s*\$",
            r"load_template\s*\(\s*\$",
            # Same sinks, but the selector is concatenated onto a
            # hardcoded directory/prefix literal rather than passed bare
            # (e.g. get_template_part('dir/' . $template . '/index')) —
            # a bare-$ prefix match above misses this shape entirely.
            r"get_template_part\s*\(\s*['\"][^'\"]*['\"]\s*\.\s*\$",
            r"locate_template\s*\(\s*['\"][^'\"]*['\"]\s*\.\s*\$",
            r"load_template\s*\(\s*['\"][^'\"]*['\"]\s*\.\s*\$",
            # Same "literal prefix . $selector" concat shape, but handed to a
            # project-specific (non-core) template-loading wrapper function
            # instead of get_template_part/locate_template/load_template —
            # a function whose name signals it resolves and includes a
            # template internally (e.g. "xyz_get_template", "theme_render_view").
            r"\b\w*(?:get_|load_|include_|render_|locate_)(?:template|view|partial|layout)\w*\s*\(\s*['\"][^'\"]*['\"]\s*\.\s*\$",
        ],
    },
    "INCLUDE_CONCAT_VARIABLE": {
        "group": "group-a",
        "patterns": [
            r"(?:include|require)(?:_once)?\s*[\(]?\s*(?:[A-Z_]+\s*\.\s*)?\$\w+",
            # Same sink, but the leading path segment is built from a
            # directory-anchor call/constant (dirname(__FILE__), __DIR__,
            # plugin_dir_path(__FILE__)) rather than a bare uppercase
            # constant — the common "file-scope router/dispatcher" idiom
            # where a request-derived selector variable is concatenated
            # onto the current directory to build the include path
            # (CVE-2024-53800, rezgo).
            r"(?:include|require)(?:_once)?\s*\(?\s*(?:dirname\s*\(\s*__FILE__\s*\)|__DIR__|plugin_dir_path\s*\(\s*__FILE__\s*\))\s*\.[^;]*\$\w+",
        ],
        "exclude_patterns": [
            r"(?:include|require)(?:_once)?\s*[\(]?\s*\$this->",
            r"(?:include|require)(?:_once)?\s*[\(]?\s*\$__",
        ],
        "limit": 40,
    },
    "CLASS_FACTORY_ROUTER_PARAM": {
        "group": "group-a",
        "patterns": [
            # A static or instance "factory-by-name" dispatcher call
            # (Class::get_model($x), $this->load_module($x), ...) fed a
            # variable argument — the common AJAX/router idiom that
            # resolves and includes a per-module handler class by request-
            # supplied name (CVE-2025-26985, majestic-support: unauth LFI
            # via Class::get_model($module)->$task()). Leads only; confirm
            # the argument traces to request input and the factory builds
            # an include path from the name with no containment check.
            r"(?:::|->)\s*\w*(?:get|load|fetch|resolve)_?(?:model|module|class|component|controller|object|addon|handler)s?\s*\(\s*\$",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    "SHORTCODE_ATTR_TEMPLATE_INCLUDE": {
        "group": "group-a",
        "patterns": [
            # "design" added alongside the existing template/view/layout
            # selector tokens: the same "$atts[<key>] selects which template
            # variant to include" idiom, just named after the visual design/
            # skin rather than "template" (CVE-2025-31082, blog-designer-pack
            # — unauthenticated LFI via $atts['design'] used unsanitized to
            # build an include() path).
            r"\$atts\[.*(?:template|tmpl|view|layout|file|path|page|partial|section|design)\b",
            r"\$instance\[.*(?:template|tmpl|view|layout|file|path|page|design)\b",
            r"\$attributes\[.*(?:template|tmpl|view|layout|file|path|page|design)\b",
        ],
        "cross_file_filter": r"(?:include|require)(?:_once)?\b|load_template|locate_template|get_template_part",
    },
    "WP_TEMPLATE_PARAM_NAMES": {
        "group": "group-a",
        "patterns": [
            r"\$_(GET|POST|REQUEST)\[.*(?:template|tmpl|view|layout|tpl|template_path)\b",
            r"->get_param\s*\(\s*['\"](?:template|tmpl|view|layout|tpl|template_path)['\"]",
        ],
    },
    # A request superglobal value is assigned to a variable whose NAME
    # (not the $_GET/$_POST key) matches the template/view/layout selector
    # convention, sanitized ONLY with sanitize_text_field()/
    # sanitize_textarea_field() — a text-only sanitizer that does not strip
    # '/', '\\', or '..'. The eventual include/require sink is frequently in
    # a different function or file (e.g. a `global $template` consumed by a
    # separately include_once'd template file), so no cross_file_filter is
    # applied here (CVE-2024-43328, embedpress). The same weak-sanitizer
    # shape recurs under "pluggable backend by name" naming (an OAuth/
    # social-login "app" selector, a payment/SMS "provider"/"gateway"/
    # "engine" — CVE-2025-62075, Simple Payment: $engine, sanitized only
    # with sanitize_text_field(), concatenated into a require_once path
    # guarded solely by file_exists()) rather than a template/layout
    # selector — same missing charset/
    # allow-list restriction, different variable-name convention. Also
    # recurs under WP admin-page "tab"/"subtab" dispatch naming, where the
    # subtab value is concatenated into an "<area>.<subtab>.php" include
    # path guarded only by is_file()/file_exists() (CVE-2025-48338,
    # wp-abstracts-manuscripts-manager). Also recurs as an object-PROPERTY
    # assignment ("$this->active_tab = sanitize_text_field(...)") rather
    # than a local/global variable — a settings/wizard-page class caching
    # its request-derived selector as instance state for a sibling render
    # method (invoked later via a WP action) to consume.
    # Also recurs with get_query_var() (a public query var / rewrite tag)
    # as the source instead of a superglobal — WordPress applies NO
    # path-safety filtering to query vars at all, so an unsanitized
    # get_query_var() read into a tab/view selector is strictly worse than
    # the weak-sanitizer shape above, not just an alternate source
    # (CVE-2026-9290, wp-user-manager: unauthenticated LFI via the 'tab'
    # query var feeding an unvalidated profile-template selector). The
    # selector-name prefix is widened to tolerate a leading qualifier word
    # (e.g. "profile_tab", "account_view") since get_query_var()-driven
    # selectors are commonly named after the feature they belong to, not
    # just "active_"/"current_".
    "TEMPLATE_SELECTOR_WEAK_SANITIZER": {
        "group": "group-a",
        "patterns": [
            r"\$(?:layout|template|tpl|view|page|section|module|widget|partial|style|tab|subtab)\w*\s*=[^;]*(?:sanitize_text_field|sanitize_textarea_field)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST)\b",
            r"\$(?:appname|app_name|social_app|provider|gateway|engine)\w*\s*=[^;]*(?:sanitize_text_field|sanitize_textarea_field)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST)\b",
            r"\$\w+->\w*(?:layout|template|tpl|view|page|section|module|widget|partial|style|tab|subtab)\w*\s*=[^;]*(?:sanitize_text_field|sanitize_textarea_field)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST)\b",
            r"\$(?:\w+_)?(?:layout|template|tpl|view|page|section|module|widget|partial|style|tab|subtab)\w*\s*=[^;]*get_query_var\s*\(",
            r"\$\w+->\w*(?:layout|template|tpl|view|page|section|module|widget|partial|style|tab|subtab)\w*\s*=[^;]*get_query_var\s*\(",
            # filter_input()/FILTER_SANITIZE_STRING variant: same weak-sanitizer
            # idiom as sanitize_text_field() above, but reading the request
            # value through PHP's own filter_input() instead of $_GET[]/$_POST[]
            # array access. FILTER_SANITIZE_STRING strips tags only, never
            # traversal sequences.
            r"\$(?:\w+_)?(?:layout|template|tpl|view|page|section|module|widget|partial|style|tab|subtab)\w*\s*=[^;]*filter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE)\s*,[^;]*FILTER_SANITIZE_STRING",
            r"\$\w+->\w*(?:layout|template|tpl|view|page|section|module|widget|partial|style|tab|subtab)\w*\s*=[^;]*filter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE)\s*,[^;]*FILTER_SANITIZE_STRING",
        ],
        # "page" (a legitimate selector token) is also a substring-prefix of
        # "paged" — WordPress's extremely common get_query_var('paged')
        # pagination idiom, which the get_query_var() patterns above would
        # otherwise flag on nearly every plugin. Excluded specifically
        # rather than dropping "page" from the token list, since "page" is
        # still a real selector name for the sanitize_text_field()-wrapped
        # patterns above.
        "exclude_patterns": [
            r"get_query_var\s*\(\s*['\"]paged?['\"]",
        ],
        "limit": 30,
    },
    "DB_STORED_PATH_TO_INCLUDE": {
        "group": "group-a",
        "patterns": [
            r"\b(?:include|require)(?:_once)?\s*[\(]?\s*get_option\s*\(",
            r"\b(?:include|require)(?:_once)?\s*[\(]?\s*get_post_meta\s*\(",
            r"\b(?:include|require)(?:_once)?\s*[\(]?\s*get_user_meta\s*\(",
            r"\b(?:include|require)(?:_once)?\s*[\(]?\s*\$\w+\s*\.\s*get_option\s*\(",
            r"\b(?:include|require)(?:_once)?\s*[\(]?\s*\$\w+\s*\.\s*get_post_meta\s*\(",
            r"load_template\s*\(\s*get_option\s*\(",
            r"load_template\s*\(\s*get_post_meta\s*\(",
        ],
        "limit": 30,
    },
    "AJAX_TEMPLATE_PARAM_INCLUDE": {
        "group": "group-a",
        "patterns": [
            r"\$_(POST|GET|REQUEST)\s*\[\s*['\"](?:template|tmpl|tpl|file|filename|path|view|layout|template_path|content_path)['\"]",
        ],
        "cross_file_filter": r"wp_ajax_(?:nopriv_)?|admin_post_(?:nopriv_)?",
        "limit": 40,
    },
    "NESTED_ARRAY_INPUT_TO_INCLUDE": {
        "group": "group-a",
        "patterns": [
            r"\$_(POST|GET|REQUEST)\s*\[['\"][^'\"]+['\"]\]\s*\[\s*['\"](?:template|tmpl|tpl|file|filename|path|view|layout|template_path|content_path|include|partial)['\"]",
            r"\$_(POST|GET|REQUEST)\s*\[\s*['\"](?:args|form|data|params|settings)['\"\]]\s*\[\s*['\"][^'\"]*(?:template|path|file|view)[^'\"]*['\"]",
        ],
        "cross_file_filter": r"(?:include|require)(?:_once)?\b|load_template|locate_template|get_template_part",
        "limit": 30,
    },
    "FILE_EXISTS_BEFORE_INCLUDE": {
        "group": "group-a",
        "patterns": [
            # \w* padding on both sides catches naming variants beyond the
            # exact literal ($target_file, $tpl_file, $dest_path, ...) that
            # a fixed-prefix match would miss while the sink is still
            # file_exists()/is_file() used as the sole guard before include/
            # require (CWE-98) — see claude.php.wordpress.file.file-exists-
            # not-sanitizer for the matching Semgrep rule. "fallback" covers
            # the ternary "resolve first existing candidate across N
            # fallback locations" idiom's own naming convention
            # ($fallback = ...; $template = file_exists($fallback) ?
            # $fallback : '';), which the path/file/template/tpl/include/
            # located tokens above do not already cover.
            r"file_exists\s*\(\s*\$\w*(?:path|file|template|tpl|include|located|fallback)\w*\b",
            r"is_file\s*\(\s*\$\w*(?:path|file|template|tpl|include|located|fallback)\w*\b",
        ],
        "cross_file_filter": r"(?:include|require)(?:_once)?\b",
        "exclude_patterns": [
            r"file_exists\s*\(\s*\$this->",
            r"!\s*file_exists",
        ],
        "limit": 40,
    },
    # Negated/deferred sibling of FILE_EXISTS_BEFORE_INCLUDE: a "reject if
    # missing" guard clause (`if (!file_exists(...))  { throw/return; }`)
    # on a path built by concatenating a base dir with a variable, where the
    # concatenated path is then stored (property or local var) for use by a
    # DIFFERENT statement/method rather than an adjacent include/require.
    # file_exists()/is_file() only confirm the target exists — they do not
    # constrain it to the intended directory, so a traversal value that
    # resolves to any real file on disk still passes (CWE-22 -> CWE-98 when
    # later included, or arbitrary file read when later passed to
    # file_get_contents()/readfile()/fopen()). No cross_file_filter here
    # because the eventual sink is frequently in a different method than the
    # guard, so co-occurrence in the same file cannot be assumed.
    "FILE_EXISTS_NEGATED_GUARD_CONCAT": {
        "group": "group-a",
        "patterns": [
            r"!\s*file_exists\s*\([^)]*\.\s*\$\w+",
            r"!\s*is_file\s*\([^)]*\.\s*\$\w+",
        ],
        "exclude_patterns": [
            r"!\s*file_exists\s*\(\s*(?:ABSPATH|__DIR__|dirname\s*\(\s*__FILE__\s*\))",
            r"!\s*is_file\s*\(\s*(?:ABSPATH|__DIR__|dirname\s*\(\s*__FILE__\s*\))",
        ],
        "limit": 30,
    },
    "DYNAMIC_FILE_EXTENSION_INCLUDE": {
        "group": "group-a",
        "patterns": [
            r"(?:include|require)(?:_once)?\s*[\(]?\s*\$\w+\s*\.\s*\$\w+\s*[);]",
        ],
        "exclude_patterns": [
            r"(?:include|require)(?:_once)?\s*[\(]?\s*\$this->",
        ],
        "limit": 30,
    },
    "CUSTOM_TEMPLATE_LOADER_FUNCTIONS": {
        "group": "group-a",
        "patterns": [
            r"function\s+\w*(?:load_template|include_template|render_template|load_view|include_view|load_partial|include_partial)\w*\s*\(",
            r"function\s+get_template\s*\(",
            r"function\s+get_view\s*\(",
            r"function\s+get_partial\s*\(",
        ],
        "cross_file_filter": r"(?:include|require)(?:_once)?\b",
        "exclude_patterns": [
            r"^\s*\*",
            r"^\s*//",
        ],
        "limit": 40,
    },
    "WP_KSES_ON_FILE_PATH": {
        "group": "group-a",
        "patterns": [
            r"wp_kses(?:_post)?\s*\(.*(?:_path|_file|_dir|file_path|dir_path|template_path)\b",
            r"(?:_path|_file|file_path|template_path)\w*\s*=\s*wp_kses(?:_post)?\s*\(",
        ],
        "cross_file_filter": r"(?:include|require)(?:_once)?\b|load_template|file_get_contents|readfile",
        "limit": 20,
    },
    "BASE64_TO_UNSERIALIZE": {
        "group": "group-a",
        "patterns": [
            r"(?:unserialize|maybe_unserialize)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress)",
            # Same sink, no decode wrapper — unserialize() directly on a request
            # superglobal (e.g. an async-task/AJAX postback handler's $_POST read).
            r"(?:unserialize|maybe_unserialize)\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[",
        ],
    },
    "RECURSIVE_UNSERIALIZE_REPLACE": {
        "group": "group-a",
        "patterns": [
            r"recursive_unserialize_replace\(",
            r"recursive_unserialized_replace\(",
        ],
    },
    "POI_MAGIC_METHODS": {
        "group": "group-a",
        "patterns": [
            r"function\s+__destruct\s*\(",
            r"function\s+__wakeup\s*\(",
            r"function\s+__toString\s*\(",
            r"function\s+__call\s*\(",
            r"function\s+__unserialize\s*\(",
        ],
        "limit": 40,
    },
    "SHORTCODE_ATTR_UNSERIALIZE": {
        "group": "group-a",
        "patterns": [
            r"(?:unserialize|maybe_unserialize)\s*\(\s*\$atts\[",
            r"(?:unserialize|maybe_unserialize)\s*\(\s*\$instance\[",
            r"(?:unserialize|maybe_unserialize)\s*\(\s*\$attributes\[",
        ],
    },
    "COOKIE_DESERIALIZATION": {
        "group": "group-a",
        "patterns": [
            r"(?:unserialize|maybe_unserialize)\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_COOKIE\[",
        ],
    },
    # unserialize()/maybe_unserialize() on a row field named like a
    # database meta-table value column, indicating a plugin-defined
    # key/value table read outside WP core's own meta/options API.
    "CUSTOM_META_TABLE_UNSERIALIZE": {
        "group": "group-a",
        "patterns": [
            r"(?:unserialize|maybe_unserialize)\s*\(\s*\$\w+\[\s*['\"](?:meta_value|option_value|field_value|setting_value|data_value)['\"]\s*\]",
            r"(?:unserialize|maybe_unserialize)\s*\(\s*\$\w+\[.*?\.\s*['\"]_field['\"]\s*\]",
        ],
    },
    # Write-side companion of CUSTOM_META_TABLE_UNSERIALIZE: an external-data
    # accessor (getter call or array/subscript access) passed unwrapped into a
    # plugin-defined save/meta/token persistence call, or into a literal
    # 'meta_value' array-literal slot — the CWE-502 root cause when any read
    # path for the same column later deserializes it raw.
    "TOKEN_META_WRITE_NO_SERIALIZE": {
        "group": "group-a",
        "patterns": [
            r"->\w*(?:save|meta|token)\w*\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\$\w+->get_\w+\s*\(\s*\)",
            r"->\w*(?:save|meta|token)\w*\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\$\w+\[",
            r"['\"]meta_value['\"]\s*=>\s*\$\w+\s*[,)]",
        ],
        "exclude_patterns": [
            r"serialize\s*\(|wp_json_encode\s*\(|json_encode\s*\(",
        ],
    },
    "JSON_DECODE_TO_CODE_EXEC": {
        "group": "group-a",
        "patterns": [
            r"json_decode.*(?:call_user_func|eval\s*\(|assert\s*\(|create_function)"
        ],
    },
    "PLUGIN_ACTIVATION_CALLS": {
        "group": "group-a",
        "patterns": [r"activate_plugin\s*\(", r"deactivate_plugins\s*\("],
    },
    "ATTACHMENT_METADATA_UNLINK": {
        "group": "group-a",
        "patterns": [
            r"wp_get_attachment_metadata.*(?:unlink|wp_delete_file|rmdir)",
            r"wp_get_attachment_(?:metadata|url|thumb_file)",
        ],
        "cross_file_filter": r"\bunlink\(|wp_delete_file|rmdir\(|\$wp_filesystem->delete\(",
        "limit": 30,
    },
    "REGISTER_SETTING_NO_SANITIZE": {
        "group": "group-a",
        "patterns": [r"register_setting.*sanitize_callback.*(?:null|false)"],
    },
    "EXTRACT_SUPERGLOBALS": {
        "group": "group-a",
        "patterns": [r"extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)"],
    },
    # Variable function calls: $var() — functionally identical to call_user_func($var)
    # but bypasses call_user_func detection. CVE-2026-3584 (Kali Forms).
    "VARIABLE_FUNCTION_CALLS": {
        "group": "group-a",
        "patterns": [
            r"\$\w+\s*\(",
        ],
        "exclude_patterns": [
            r"\$this->",
            r"\$self::",
            r"\$wpdb->",
            r"\$wp_query->",
            r"\$wp_object_cache->",
            r"\$wp_filesystem->",
            r"\$response->",
            r"\$request->",
            r"\$widget->",
            r"\$GLOBALS\[",
            r"^\s*\$\w+\s*=\s*new\s",
            r"^\s*\$\w+\s*=\s*\$",
            r"function\s*\(",
            r"^\s*(\*|//|#|/\*)",
            r"@param\s",
            r"@return\s",
            r"@var\s",
            r"@type\s",
            r"new\s+\$",
            r"__\s*\(",
            r"_e\s*\(",
            r"esc_html__\s*\(",
            r"esc_attr__\s*\(",
            r"this\.\$\w+\(",
            r"['\"].*\$\w+.*['\"]",
        ],
        "exclude_path_patterns": [r"\.l10n\.php$", r"\.js$"],
        "limit": 40,
    },
    # A bare variable is invoked directly as a callable ($var() — PHP accepts
    # either a function-name string or a [class-or-object, method] array here)
    # and its return value is IMMEDIATELY member-accessed on the same line.
    # VARIABLE_FUNCTION_CALLS already targets $var() generally, but its
    # exclude list (^\s*\$\w+\s*=\s*\$ — meant for plain `$x = $y;` aliasing)
    # incidentally swallows this exact shape, since `$content = $response()->`
    # also starts with `$word = $`. This narrower pattern does not share that
    # exclude, closing the false negative. CVE-2025-10679 (ReviewX <= 2.2.12):
    # Helper::saasResponse($response) does
    # `$content = $response()->get()->toArray();` where $response was the raw
    # REST request-parameter array passed straight through, unauthenticated,
    # by ReviewController::bulkTenReviews(); a JSON body of the form
    # ["SomeClass","someMethod"] is a valid PHP callable and gets invoked with
    # zero validation. Chained closure invocation is rare in legitimate code
    # (a real closure's return is normally assigned/used on its own line, not
    # chained inline), so requiring the immediate `->` keeps this section's
    # noise low relative to the general VARIABLE_FUNCTION_CALLS pattern.
    "CALLABLE_VARIABLE_CHAINED_INVOCATION": {
        "group": "group-a",
        "patterns": [
            r"\$\w+\([^()]*\)\s*->",
        ],
        "exclude_patterns": [
            r"^\s*(\*|//|#|/\*)",
            r"@param\s",
            r"@return\s",
            r"@var\s",
            r"@type\s",
            r"function\s*\(",
            r"is_callable\s*\(",
            r"instanceof\s+\\?Closure",
        ],
        "exclude_path_patterns": [r"\.l10n\.php$", r"\.js$"],
        "limit": 30,
    },
    # A function name assembled from a fixed literal prefix plus an interpolated
    # or concatenated variable, assigned to a variable later invoked as $var().
    # Constraining only the prefix does not constrain the variable suffix.
    "PREFIXED_DYNAMIC_FUNCTION_NAME": {
        "group": "group-a",
        "patterns": [
            r'\$\w+\s*=\s*"[^"$]*\$\{?[A-Za-z_]',
            r"\$\w+\s*=\s*['\"][^'\"]*['\"]\s*\.\s*\$\w+",
        ],
        "exclude_patterns": [
            r"^\s*(\*|//|#|/\*)",
            r"@param\s",
            r"@return\s",
            r"esc_html\s*\(",
            r"esc_attr\s*\(",
            r"sprintf\s*\(",
            r"__\s*\(",
            r"_e\s*\(",
        ],
        "exclude_path_patterns": [r"\.l10n\.php$", r"\.js$"],
        "limit": 30,
    },
    # PHP functions accepting callbacks where the callback arg is a variable
    # (not a string literal or [$obj, 'method']). CVE-2025-9501 (W3 Total Cache).
    "CALLBACK_ACCEPTING_FUNCTIONS": {
        "group": "group-a",
        "patterns": [
            r"array_map\s*\(\s*\$",
            r"array_filter\s*\(\s*[^,]+,\s*\$",
            r"array_walk\s*\(\s*[^,]+,\s*\$",
            r"array_walk_recursive\s*\(\s*[^,]+,\s*\$",
            r"usort\s*\(\s*[^,]+,\s*\$",
            r"uasort\s*\(\s*[^,]+,\s*\$",
            r"uksort\s*\(\s*[^,]+,\s*\$",
            r"preg_replace_callback\s*\(\s*[^,]+,\s*\$",
            r"ob_start\s*\(\s*\$",
            r"register_shutdown_function\s*\(\s*\$",
            r"spl_autoload_register\s*\(\s*\$",
            r"set_error_handler\s*\(\s*\$",
            r"set_exception_handler\s*\(\s*\$",
            r"array_reduce\s*\(\s*[^,]+,\s*\$",
        ],
        "exclude_patterns": [
            r"array_map\s*\(\s*\$this->",
            r"array_map\s*\(\s*\[",
            r"array_walk\s*\(\s*[^,]+,\s*\[",
            r"array_filter\s*\(\s*[^,]+,\s*\[",
            r"usort\s*\(\s*[^,]+,\s*\[",
            r"uasort\s*\(\s*[^,]+,\s*\[",
            r"uksort\s*\(\s*[^,]+,\s*\[",
        ],
        "limit": 40,
    },
    # Function/closure definitions with a $matches/$match parameter — the
    # conventional preg_match()/preg_replace_callback() capture-array name.
    # Complements CALLBACK_ACCEPTING_FUNCTIONS, which only flags VARIABLE
    # callback arguments (attacker picks the callback); this section finds
    # the callback DEFINITION itself regardless of how it was registered
    # (named method via array($this, 'method'), plain function name, or
    # inline closure all define a $matches/$match parameter identically),
    # so a developer-fixed callback whose own body is unsafe on the matched
    # text isn't missed just because the registration site used a fixed
    # array-callable. CVE-2026-57623 (W3 Total Cache) — _parse_dynamic_mfunc/
    # _parse_dynamic_mclude took $matches and passed captured content to
    # eval()/include(). Read each hit's function body for eval()/assert()/
    # include()/require() reachable from the parameter.
    "REGEX_CAPTURE_CALLBACK_HANDLERS": {
        "group": "group-a",
        "patterns": [
            r"function\s+\w+\s*\(\s*&?\$match(es)?\b",
            r"function\s*\(\s*&?\$match(es)?\b",
            # Legacy PHP<7.2 dynamic-callback equivalent: create_function()'s
            # code is a plain string, invisible to normal function-signature
            # matching above, but is the same regex-capture-callback idiom.
            r"create_function\s*\(",
        ],
        "limit": 40,
    },
    # A secret/security/token constant is concatenated raw (no preg_quote())
    # into a preg_match()/preg_match_all()/preg_replace()/preg_replace_callback()
    # pattern string, weakening what is meant to be an exact-match
    # authorization gate (commonly protecting eval()/include() of the
    # matched capture) into a loosely-matching regex. CWE-94.
    "UNESCAPED_SECRET_REGEX_GATE": {
        "group": "group-a",
        "patterns": [
            r"preg_(?:match(?:_all)?|replace(?:_callback)?)\s*\(\s*['\"][^'\"]*['\"]\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:SECRET|SECURITY|TOKEN)[A-Za-z0-9_]*\s*\.",
        ],
        "limit": 30,
    },
    # do_shortcode()/apply_shortcodes() with user-controlled input in unauthenticated contexts.
    # CVE-2024-13346 (Avada), CVE-2024-11733 (WP Popular Posts), CVE-2025-2801 (Create Custom Forms),
    # CVE-2025-3472 (Ocean Extra <= 2.4.6): sink wraps directly around wp_kses_post()/
    # sanitize_text_field() rather than a bare variable/superglobal — neither sanitizer
    # strips shortcode bracket syntax, and the tainted value can arrive from a
    # different function several calls upstream (an AJAX handler building an
    # attribute array), so the sanitizer-adjacent-to-sink shape is matched directly.
    "DO_SHORTCODE_RCE": {
        "group": "group-a",
        "patterns": [
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$_(GET|POST|REQUEST)",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$content",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$input",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$body",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$text",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$html",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$data",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$value",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$message",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$string",
            # Variable named *shortcode* (e.g. $views_count_shortcode) built by
            # concatenating REST/request-derived values, then passed straight to
            # the sink. CVE-2024-11733 (WordPress Popular Posts <= 7.1.0):
            # $request->get_param('id') is unsanitized on the /v2/views/(?P<id>)
            # GET route (missing from that route's args schema — the WP REST API
            # query-string param takes precedence over the URL-regex-matched
            # value at get_param() resolution, so the [\d]+ route regex does not
            # constrain it), concatenated into '[wpp_views_count post_id=' . $id
            # . ...']', then do_shortcode()'d — unauthenticated arbitrary
            # shortcode execution via shortcode-tag injection. The fix added a
            # sanitize_callback (absint) for that arg in a sibling method's
            # route-registration schema, invisible to this line — verify by
            # tracing the *shortcode variable's construction back to its source.
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$\w*[Ss]hortcode\w*\b",
            # Variable named *preview* — the "live preview" AJAX-handler idiom
            # common to shortcode/page-builder plugins (a callback bound to
            # wp_ajax_nopriv_* that renders a user-submitted shortcode string
            # so an editor can see it rendered before saving). CVE-2025-22677
            # (Uix Shortcodes <= 2.0.3): $previewcode built via
            # isset($_POST['previewcode']) ? $_POST['previewcode'] : '' several
            # lines above the sink, so neither the direct-superglobal nor the
            # named-holder-variable patterns above match it; the vendor's fix
            # wrapped the source in sanitize_text_field(), which strips HTML
            # tags but not shortcode bracket syntax, so the endpoint is still
            # reachable post-patch — verify by tracing the *preview variable's
            # construction back to its source and checking the enclosing
            # capability gate, since sanitize_text_field() alone is not a fix.
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*\$\w*[Pp]review\w*\b",
            # apply_filters() on a Core hook WP itself binds do_shortcode() to
            # (the_content / widget_text_content / widget_block_content, all
            # @priority 11) executes shortcodes with no explicit do_shortcode()
            # call anywhere in the plugin. CVE-2026-2582 (Germanized for
            # WooCommerce <= 3.20.5): unauthenticated 'account_holder' GET
            # param substituted into a mandate-text template then rendered via
            # apply_filters('the_content', $text) — patch swapped the sink for
            # wptexturize()/wpautop() and added strip_shortcodes() on the value.
            r"apply_filters\s*\(\s*['\"](?:the_content|widget_text_content|widget_block_content)['\"]\s*,\s*\$(?:content|text|input|body|html|data|value|message|string)\b",
            # Property-access sibling of the local-variable shape above: a
            # fetched post-like object's own post_content property passed
            # directly into the same do_shortcode-bound apply_filters() call,
            # one hop past a bare local variable. CVE-2025-57928 (AWP
            # Classifieds <= 4.4.3): unauthenticated ad-preview AJAX handler
            # (wp_ajax_nopriv_awpcp_generate_listing_preview) fetched an
            # attacker-chosen listing by ID with no ownership/capability check
            # and rendered apply_filters('the_content', $listing->post_content);
            # the front-end submission form sanitized text with
            # wp_kses_post()/wp_strip_all_tags() but never called
            # strip_shortcodes(), so shortcode syntax planted by the submitter
            # survived into post_content. Fires identically on the patched
            # line too (the patch added an earlier nonce/authorization guard,
            # not a change to this line) — same acknowledged limitation as
            # STRIPSLASHES_SUPERGLOBAL_MISSING_STRIP_SHORTCODES: a leads-only
            # heuristic always requiring manual triage of the surrounding
            # function for an authorization check.
            r"apply_filters\s*\(\s*['\"](?:the_content|widget_text_content|widget_block_content)['\"]\s*,\s*\$\w+->post_content\b",
        ],
        # Request-object array/method access (\$request['x'] / \$request->get_param('x'))
        # added: in REST-controller-style plugin architectures the
        # register_rest_route() call (and its permission_callback) commonly lives
        # in a separate router file/class from the controller method that reads
        # the parameter and builds the shortcode — the original file-scoped
        # cross_file_filter alone misses the controller file in that split, since
        # neither register_rest_route nor add_shortcode appears in it. Matched
        # against the same request-named-variable set used by the sibling Semgrep
        # source constraint (request/req/rest_request/wp_request/the_request).
        # \$\w+->post_content added (CVE-2025-57928, AWP Classifieds <= 4.4.3):
        # the property-access sink pattern directly above requires this exact
        # token on its own matching line, so this alternative is trivially
        # satisfied whenever that pattern would otherwise fire — the AJAX
        # handler that reads the request (a custom AWPCP_Request wrapper's
        # ->post() method, not a bare $request[]/->get_param() access) lives
        # in the same file as the sink itself, but carries none of the other
        # cross_file_filter tokens (no wp_ajax_nopriv_/register_rest_route/
        # add_shortcode literal in that file — the wp_ajax_nopriv_ hook
        # registration lives in a separate class file), so without this
        # addition the section's file-wide gate silently discarded the hit
        # (confirmed via a real grep_scan.py run before this change: 0 hits).
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_|register_rest_route|add_shortcode|\$(?:request|req|rest_request|wp_request|the_request)\s*(?:\[|->get_param\()|\$\w+->post_content\b",
    },
    # A settings/defaults array key named like *shortcode* is assigned boolean
    # `true` — an insecure-default toggle that (elsewhere in the same class)
    # gates a do_shortcode()/apply_shortcodes() call or a the_content-style
    # apply_filters() chain WordPress/ACF binds do_shortcode to by default.
    # No literal do_shortcode()/apply_shortcodes() token needs to appear on
    # this line — the vulnerable/patched diff is the boolean literal itself.
    # CVE-2025-15463 (ACF Extended <= 0.9.2.3): 'success' => array('shortcode'
    # => true, 'message' => ...) let a merge-tag-substituted, request-influenced
    # success message run through do_shortcode() by default; patch flipped the
    # default to false.
    "SHORTCODE_TOGGLE_DEFAULT_ENABLED": {
        "group": "group-a",
        "patterns": [
            r"['\"]\w*shortcode\w*['\"]\s*=>\s*true\b",
        ],
        "case_insensitive": True,
        "limit": 30,
    },
    # add_filter('comment_text', 'do_shortcode') enables ASE via public comments.
    # CVE-2023-4549. Comments are writable by unauthenticated visitors.
    "COMMENT_TEXT_DO_SHORTCODE": {
        "group": "group-a",
        "patterns": [
            r"add_filter\s*\(\s*['\"]comment_text['\"].*(?:do_shortcode|apply_shortcodes)",
            r"add_filter\s*\(\s*['\"]get_comment_text['\"].*(?:do_shortcode|apply_shortcodes)",
            r"add_filter\s*\(\s*['\"]comment_excerpt['\"].*(?:do_shortcode|apply_shortcodes)",
        ],
    },
    # Superglobal (cookie/GET/POST/REQUEST) unslashed via stripslashes()/wp_unslash()
    # ONLY — no strip_shortcodes() — then typically persisted as a flash/notice
    # message for later display. sanitize_text_field()/wp_kses_post()/esc_html() do
    # NOT strip shortcode bracket syntax; if the eventual render path (directly, or
    # via a the_content-hijacking theme-compat filter that inherits WP Core's own
    # do_shortcode binding on 'the_content' at priority 11) ever processes
    # shortcodes, this is arbitrary shortcode execution (CWE-94) with no explicit
    # do_shortcode() call anywhere in the vulnerable plugin itself.
    # CVE-2024-11976 (BuddyPress bp_core_setup_message() / 'bp-message' cookie).
    "STRIPSLASHES_SUPERGLOBAL_MISSING_STRIP_SHORTCODES": {
        "group": "group-a",
        "patterns": [
            r"(?:stripslashes|wp_unslash)\s*\(\s*\$_(?:COOKIE|GET|POST|REQUEST)\s*\[",
        ],
        "exclude_patterns": [
            r"strip_shortcodes\s*\(",
        ],
        "limit": 30,
    },
    # Shortcode-named callback captures buffered template output via
    # ob_get_clean() and returns/echoes it as-is. If a field rendered into the
    # buffer holds previously-submitted free-text data (a comment, display
    # name, or similar), an attacker can plant literal shortcode bracket
    # syntax in it; esc_html()/sanitize_text_field() do not strip brackets,
    # so it survives into the callback's return value. When that value is
    # substituted back into post content, WP Core's own do_shortcode() pass
    # on 'the_content' re-scans it and executes the planted tag — second-order
    # arbitrary shortcode execution with no explicit do_shortcode() call in
    # the vulnerable plugin. CVE-2025-66533 (GiveWP donor-wall shortcode).
    "SHORTCODE_CALLBACK_OB_BUFFER_MISSING_STRIP_SHORTCODES": {
        "group": "group-a",
        "patterns": [
            r"\$\w+\s*=\s*ob_get_clean\s*\(\s*\)\s*;",
        ],
        "cross_file_filter": r"add_shortcode\s*\(",
        "exclude_patterns": [
            r"strip_shortcodes\s*\(",
        ],
        "limit": 30,
    },
    # User input concatenated into shortcode string construction.
    # Attacker can inject ']' to close a shortcode tag and open a new one.
    # CVE-2024-10075 (Jetpack). Pattern: '[' . $user_input or "[$var".
    # Attribute-value quote-breakout variant added (CVE-2025-1119, Simply
    # Schedule Appointments <= 1.6.8.5): a hardcoded '<attr>="' prefix
    # concatenated with an unescaped value and a closing-quote literal —
    # appending an unescaped attribute onto an already-open shortcode tag,
    # not just the opening-bracket concatenation the earlier patterns cover.
    # The value is often a stored/model property (booking/order/profile data
    # written by an earlier low-privilege request), not a superglobal at this
    # exact line, so the concatenation shape itself is the detection anchor.
    # Excludes the leading-'[' shape (already covered above) via the
    # negative-lookahead-equivalent character class on the opening literal.
    "SHORTCODE_CONSTRUCTION_INJECTION": {
        "group": "group-a",
        "patterns": [
            r"'\['\s*\.\s*\$",
            r'"\["\s*\.\s*\$',
            r'"\[\$',
            r"sprintf\s*\(\s*['\"].*\[%s",
            r"['\"](?!\[)[^'\"]*=[\"'][\"']?\s*\.\s*\$\w+\s*\.\s*['\"][\"']*['\"]",
            # String-interpolation sibling of the concatenation shape above:
            # a bare or curly-brace-interpolated variable ($var / {$var})
            # embedded directly inside literal shortcode-bracket syntax
            # (e.g. "[tag id='{$pid}']"), rather than built via '.'
            # concatenation. CVE-2024-11740 (Download Manager <= 3.3.03):
            # $pid = wpdm_query_var('__wpdmxp') (no sanitize-type argument)
            # interpolated into do_shortcode("[wpdm_package id='{$pid}']").
            r"\[[A-Za-z_][\w-]*\b[^\[\]]*\{?\$[A-Za-z_]\w*\}?[^\[\]]*\]",
            # sprintf()-based attribute-pair serialization: a foreach loop
            # building 'key="value"' pairs via a two-placeholder format
            # string (e.g. sprintf(' %s="%s"', $arg, $value)), accumulated
            # into a string later embedded in the literal '[tag ...]'
            # shortcode expression. This is the "generic run-a-shortcode-
            # with-these-args" utility idiom common to WP plugins that
            # programmatically construct and execute a shortcode from a
            # caller-supplied attribute array — catches the actual
            # bracket-breakout injection line itself (the attribute loop),
            # not just the wrapping do_shortcode(sprintf('[%s...')) sink line
            # the earlier sprintf pattern above already covers.
            # CVE-2024-13495 (GamiPress <= 7.2.1): gamipress_do_shortcode()'s
            # attribute-building loop uses this exact sprintf shape on values
            # sanitized only with sanitize_text_field() (which does not strip
            # '[' / ']') immediately before the do_shortcode() sink.
            r"sprintf\s*\(\s*['\"]\s*%s\s*=\s*[\"']",
        ],
        "cross_file_filter": r"do_shortcode|apply_shortcodes",
        "exclude_patterns": [
            r"add_shortcode",
            r"has_shortcode",
            r"shortcode_exists",
            r"get_shortcode_regex",
            r"preg_match",
            r"esc_attr|sanitize_key|intval|absint",
        ],
        "limit": 40,
    },
    # REST endpoints with __return_true permission_callback — unauthenticated.
    # Hunk Companion, Essential Plugin backdoor.
    "REST_RETURN_TRUE_CODE_EXEC": {
        "group": "group-a",
        "patterns": [
            r"__return_true",
        ],
        "cross_file_filter": r"register_rest_route",
        "line_filter": r"permission_callback",
    },
    # Plugin/theme installation in files with unauthenticated REST endpoints.
    # Hunk Companion plugin install chain.
    "REST_RETURN_TRUE_PLUGIN_INSTALL": {
        "group": "group-a",
        "patterns": [
            r"activate_plugin\s*\(",
            r"Plugin_Upgrader\s*\(",
            r"Theme_Upgrader\s*\(",
        ],
        "cross_file_filter": r"__return_true.*permission_callback|permission_callback.*__return_true",
    },
    # call_user_func with placeholder/map variables — two-step RCE flow.
    # CVE-2026-3584 (Kali Forms): user input → placeholder storage → call_user_func.
    "PLACEHOLDER_CODE_EXEC": {
        "group": "group-a",
        "patterns": [
            r"(?:call_user_func|call_user_func_array)\s*\(\s*\$\w*(?:placeholder|tag|field|token|macro|dynamic|replacement)",
            r"(?:call_user_func|call_user_func_array)\s*\(\s*\$\w*\[\s*\$",
            # Object-property variant of the first pattern above: the two prior
            # patterns only match a bare $var whose OWN name starts with the
            # keyword, or a $var[$dynamicKey] shape. Neither matches the real
            # CVE-2026-3584 sink, which reads the callable off a PROPERTY
            # (e.g. $this->placeholdered_data) via a single string-literal key
            # (e.g. ['{entryCounter}']) — a dictionary of built-in callables
            # merged with request-derived per-field values under attacker-
            # chosen keys, then blindly invoked. Requires the bracketed access
            # to be the entire first argument (no further '[' before the
            # closing ',' or ')') so it does NOT match two-level registry
            # dispatch like $this->fields[$key]['sanitize'] — a confirmed FP
            # shape in this same plugin (class-meta-save.php:172).
            r"(?:call_user_func|call_user_func_array)\s*\(\s*\$\w+->\w*(?:placeholder|tag|field|token|macro|dynamic|replacement)\w*\s*\[[^][]*\]\s*[,)]",
        ],
        "cross_file_filter": r"\$_POST|\$_GET|\$_REQUEST|get_param",
        "limit": 30,
    },
    # File move/copy with user-controlled destination path.
    # CVE-2026-0740 (Ninja Forms): source type-checked, destination user-controlled.
    "UPLOAD_DESTINATION_FROM_USER": {
        "group": "group-a",
        "patterns": [
            r"move_uploaded_file\s*\([^,]+,\s*.*\$_(GET|POST|REQUEST|FILES)",
            r"rename\s*\(\s*.*tmp.*,\s*.*\$_(GET|POST|REQUEST)",
            r"copy\s*\(\s*.*tmp.*,\s*.*\$_(GET|POST|REQUEST)",
            # Chunked/resumable-upload finalize shape: destination built inline
            # from a raw 'name'/'filename'/'file_name' key of a request-derived
            # array (e.g. a decoded JSON body), not a $_* superglobal directly.
            r"(?:rename|copy|move_uploaded_file)\s*\(.*\$\w+\[['\"](?:name|filename|file_name)['\"]\]",
            r"fopen\s*\(.*\$\w+\[['\"](?:name|filename|file_name)['\"]\][^)]*,\s*['\"][wax]",
            # Double-extension bypass shape (CVE-2023-0714, metform): a
            # timestamp/uniqid prefix concatenated onto the raw client
            # filename, preserving embedded extension tokens (e.g.
            # shell.php.jpg) verbatim in the destination filename var.
            r"\$\w+\s*=\s*(?:time|uniqid|microtime|date)\s*\([^)]*\)\s*\.\s*['\"][^'\"]*['\"]\s*\.\s*\$\w+(?:\[[^\]]+\])*\[['\"](?:name|filename|file_name)['\"]\]",
        ],
        "limit": 30,
    },
    # Custom plugin-defined upload/move helper method — a two-arg (src, dest)
    # wrapper mirroring move_uploaded_file()'s own signature, reimplemented
    # inside the plugin's own file-abstraction class — called from a file that
    # also reads a raw ['file']['name']/$_FILES[...]['name'] upload-array
    # filename. Neither UPLOAD_DESTINATION_FROM_USER nor
    # DIRECT_FILES_SUPERGLOBAL_UPLOAD fire here because the sink is never the
    # literal move_uploaded_file()/rename()/copy() builtin — it's one call
    # indirection away, inside the wrapper. CVE-2026-14483 (WPL Real Estate)
    # class: wpl_file::upload($image, $path) with $path built from the raw
    # per-file 'name' entry and no extension/MIME check anywhere in the file.
    "CUSTOM_UPLOAD_WRAPPER_RAW_FILENAME": {
        "group": "group-a",
        "patterns": [
            r"(?:->|::)\s*\w*(?:upload|move_file|move_uploaded|save_file|store_file|write_file)\w*\s*\(\s*\$\w+\s*,\s*\$\w+\s*\)",
        ],
        "cross_file_filter": r"\[['\"]file['\"]\]\s*\[['\"]name['\"]\]|\$_FILES\s*\[[^\]]+\]\s*\[['\"]name['\"]\]",
        "exclude_patterns": [
            r"wp_check_filetype|wp_handle_upload|wp_handle_sideload|PATHINFO_EXTENSION|finfo_file|mime_content_type|exif_imagetype|getimagesize",
        ],
        "limit": 30,
    },
    # unserialize in import/migration/backup contexts without allowed_classes.
    # CVE-2026-0726 (Nexter), CVE-2026-2020 (JS Archive List).
    "IMPORT_HANDLER_UNSERIALIZE": {
        "group": "group-a",
        "patterns": [
            r"unserialize\s*\(",
            r"maybe_unserialize\s*\(",
        ],
        "cross_file_filter": r"(?i)import|migrate|restore|backup",
        "exclude_patterns": [
            r"allowed_classes.*false",
        ],
        "limit": 30,
    },
    "CUSTOM_UNSERIALIZE_WRAPPERS": {
        "group": "group-a",
        "patterns": [
            r"function\s+\w*unserialize\w*\s*\(",
        ],
        "exclude_patterns": [
            r"function\s+__unserialize\s*\(",
        ],
        "limit": 20,
    },
    # Plugins expanding allowed upload types via upload_mimes filter.
    # Adding SVG, PHP-adjacent, or executable extensions expands attack surface.
    "UPLOAD_MIMES_FILTER": {
        "group": "group-a",
        "patterns": [
            r"add_filter\s*\(\s*['\"]upload_mimes['\"]",
        ],
        "limit": 30,
    },
    # Plugins overriding wp_check_filetype_and_ext() results via filter.
    # Can bypass ALL WordPress file type validation when ext/type forced.
    "FILETYPE_AND_EXT_FILTER_OVERRIDE": {
        "group": "group-a",
        "patterns": [
            r"add_filter\s*\(\s*['\"]wp_check_filetype_and_ext['\"]",
        ],
        "limit": 30,
    },
    # Direct move_uploaded_file() in files with $_FILES but no WP upload functions.
    # Signals raw PHP upload handling bypassing all WordPress type validation.
    "DIRECT_FILES_SUPERGLOBAL_UPLOAD": {
        "group": "group-a",
        "patterns": [
            r"move_uploaded_file\s*\(",
        ],
        "cross_file_filter": r"\$_FILES",
        "exclude_patterns": [
            r"wp_handle_upload\s*\(",
            r"media_handle_upload\s*\(",
        ],
        "limit": 40,
    },
    # REST API endpoints accepting file uploads via get_file_params().
    "REST_FILE_PARAMS": {
        "group": "group-a",
        "patterns": [
            r"->get_file_params\s*\(",
        ],
        "cross_file_filter": r"register_rest_route",
        "limit": 30,
    },
    # wp_handle_sideload / media_handle_sideload — accept server-side files
    # (from download_url or temp files), not direct browser uploads.
    "SIDELOAD_HANDLERS": {
        "group": "group-a",
        "patterns": [
            r"wp_handle_sideload\s*\(",
            r"media_handle_sideload\s*\(",
        ],
        "limit": 30,
    },
    # Plugins hooking upload prefilters to modify/weaken validation.
    "UPLOAD_PREFILTER_HOOKS": {
        "group": "group-a",
        "patterns": [
            r"add_filter\s*\(\s*['\"]wp_handle_upload_prefilter['\"]",
            r"add_filter\s*\(\s*['\"]wp_handle_sideload_prefilter['\"]",
        ],
        "limit": 20,
    },
    # wp_upload_bits() in files with user input — extension-only validation
    # (wp_check_filetype, no content check). User-controlled filename = type bypass.
    "WP_UPLOAD_BITS_USER_FILENAME": {
        "group": "group-a",
        "patterns": [
            r"wp_upload_bits\s*\(",
        ],
        "cross_file_filter": r"\$_POST|\$_GET|\$_REQUEST|\$_FILES|->get_param",
        "limit": 30,
    },
    # Third-party form-builder integration accessing a submitted field's raw,
    # generic value — a common companion sink is trusting it as an uploaded
    # file's path without checking a separate validated-upload accessor.
    "FORM_RECORD_RAW_VALUE_ACCESS": {
        "group": "group-a",
        "patterns": [
            r"\[\s*['\"]raw_value['\"]\s*\]",
        ],
        "limit": 30,
    },
    # ===== GROUP B (Tier 3-4) =====
    "TIER3_SQL": {
        "group": "group-b",
        "patterns": [
            r"\$wpdb->query",
            r"\$wpdb->get_results",
            r"\$wpdb->get_row",
            r"\$wpdb->get_var",
            r"\$wpdb->get_col",
            r"\$wpdb->prepare",
            r"\$wpdb->insert",
            r"\$wpdb->update",
            r"\$wpdb->delete",
        ],
    },
    "ORDERBY_PARAMETER_HANDLING": {
        "group": "group-b",
        "patterns": [
            r"\$_(GET|POST|REQUEST)\[.*order",
            # CVE-2026-2495 (wpnakama): the superglobal-only regex above misses
            # the equally-common REST-request-object array-access form
            # ($req['order']/$request['order']), where "order" is the SORT
            # DIRECTION (ASC/DESC) rather than the sort column — plugins
            # routinely allow-list the column but validate the direction with
            # only an empty()/isset() check, letting any non-empty string
            # (e.g. "ASC, (SELECT ...)") reach a raw ORDER BY clause.
            r"\$(?:req|request|rest_request|wp_request|the_request)\[.*(?:order|direction|sort_dir)",
        ],
        "exclude_path_patterns": [r"vendor/", r"node_modules/"],
    },
    "RAW_QUERY_KEY_SQL": {
        "group": "group-sqli",
        "patterns": [r"\[['\"](query|sql|sql_query|raw_query)['\"]\]"],
        # Matches the DB-execution method call on any receiver (bare $wpdb or a
        # wrapper/chained accessor) — see WPDB_WRAPPER_SQL for the aliased-sink gap.
        "cross_file_filter": r"->(query|get_var|get_results|get_row|get_col)\s*\(",
    },
    # REST API arg schema's 'validate_callback' declared with ZERO parameters.
    # WP core calls validate_callback as callable($value, $request, $param) and
    # only rejects the arg when the return value is a WP_Error; a common bug
    # shape wraps the real validator in an outer zero-arg closure that just
    # returns an inner closure (e.g. `function () use ($validator) { return
    # function ($value) use ($validator) {...}; }`) — the returned Closure
    # object is always truthy, so validation silently never runs regardless of
    # $value. CVE-2026-49772 (the-events-calendar 6.16.2): this let an
    # unvalidated 'orderby' REST param reach a raw ORDER BY SQL fragment.
    "REST_VALIDATE_CALLBACK_EMPTY_PARAMS": {
        "group": "group-sqli",
        "patterns": [
            r"['\"]validate_callback['\"]\s*=>\s*function\s*\(\s*\)",
            r"\[\s*['\"]validate_callback['\"]\s*\]\s*=\s*function\s*\(\s*\)",
        ],
        "limit": 30,
    },
    "WP_QUERY_VAR_SQL": {
        "group": "group-b",
        "patterns": [r"\$wp_query->get\(", r"get_query_var\("],
        "cross_file_filter": r"\$wpdb->get_var|\$wpdb->get_row|\$wpdb->get_results|\$wpdb->query",
    },
    "WP_UNSLASH_SQL_CONTEXT": {
        "group": "group-b",
        "patterns": [r"wp_unslash\("],
    },
    "ESC_LIKE_USAGE": {
        "group": "group-b",
        "patterns": [r"esc_like\("],
    },
    "ADVANCED_SEARCH_PATHS": {
        "group": "group-b",
        "patterns": [r"strpos|str_contains|substr"],
        "line_filter": r"(?i)search|query|filter",
    },
    "WPDB_LOOP_SQL_BUILD": {
        "group": "group-b",
        "patterns": [
            r"foreach.*\$row\b|foreach.*\$rows\b|foreach.*\$results\b"
        ],
        "cross_file_filter": r"\$wpdb->query",
    },
    # An array literal holds one or more regex strings matching SQL DML
    # keyword pairs (SELECT/FROM, DELETE/FROM, UPDATE/SET, INSERT/INTO,
    # UNION/SELECT) — the array-of-patterns idiom, typically iterated with
    # foreach() + preg_match($pattern, $input), used as a denylist sanitizer
    # for a search/filter parameter instead of $wpdb->prepare(). Bare
    # time-based functions (SLEEP/BENCHMARK) or any payload avoiding the
    # listed keyword PAIRS bypasses every entry. Lead only — confirm the
    # checked value reaches SQL unparameterized before treating as a finding.
    "SQL_KEYWORD_BLOCKLIST_REGEX_ARRAY": {
        "group": "group-sqli",
        "patterns": [
            r"['\"]/.*(?:select.{0,30}from|delete.{0,30}from|update.{0,30}set|insert.{0,30}into|union.{0,30}select).*/[a-zA-Z]*['\"]",
            r"['\"]/.*\\?(?:sleep|benchmark|extractvalue|updatexml|get_lock)\\?\(.*/[a-zA-Z]*['\"]",
        ],
        "case_insensitive": True,
        "cross_file_filter": r"preg_match",
        "limit": 30,
    },
    "COOKIE_SQL_INPUT": {
        "group": "group-b",
        "patterns": [
            r"\$_COOKIE\[",
            # Iterating ALL cookies (with/without an (array) cast) to find one
            # matching a dynamic/hashed name (e.g. wordpress_logged_in_<hash>,
            # whose suffix varies per site) instead of direct bracket access.
            # CVE-2023-6063 (WP Fastest Cache <=1.2.1): foreach((array)$_COOKIE
            # as $k=>$v){ if(preg_match('/wordpress_logged_in/i',$k)){ $u =
            # preg_replace(...,$v);} } then $wpdb->get_var("...\"$u\"...").
            # Common shape across caching/session-aware plugins.
            r"foreach\s*\(\s*(?:\(array\)\s*)?\$_COOKIE\s+as",
        ],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
    },
    "SHORTCODE_ATTR_SQL": {
        "group": "group-b",
        "patterns": [
            r"\$atts\[",
            r"\$attributes\[",
            r"\$instance\[",
            # Query-args style DB-helper parameter — a reusable get_items($args)/
            # get_object_locations($query_args)-style function trusts its own
            # array parameter's 'sort'/'orderby' key without re-validating it,
            # relying on (not all) callers to have pre-sanitized. CVE-2026-4060
            # (geo-mashup, unauthenticated time-based SQLi via 'sort'): a search
            # helper passed raw request data straight into such a function.
            r"\$query_args\[",
            # Same shape, 'opts'-named parameter. CVE-2026-5073 (armember-
            # membership, unauthenticated SQLi via 'orderby'): an
            # arm_get_directory_members($tempData, $opts) DB-helper read
            # isset($opts['orderby']) ? $opts['orderby'] : $default with no
            # allow-list, straight into an unprepared ORDER BY concatenation.
            r"\$opts\[",
        ],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        "limit": 40,
    },
    "ESC_ATTR_SQL_CONTEXT": {
        "group": "group-b",
        "patterns": [r"esc_attr\("],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        "line_filter": r"(?i)WHERE|SELECT|ORDER BY|query|sql",
        "limit": 30,
    },
    "ESC_URL_RAW_SQL_CONTEXT": {
        "group": "group-b",
        "patterns": [r"esc_url_raw\("],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        "limit": 20,
    },
    "SPRINTF_SQL_BUILD": {
        "group": "group-b",
        "patterns": [r"sprintf\s*\("],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        # Also catch sprintf() building only a WHERE-clause FRAGMENT ("AND col
        # = '%s'" / "OR col LIKE '%s'") to be spliced into a base query
        # elsewhere — no SELECT/WHERE/FROM keyword appears on the fragment's
        # own line, so the original keyword-only filter missed this shape.
        "line_filter": r"(?i)SELECT|INSERT|UPDATE|DELETE|WHERE|FROM.*wpdb|\bAND\s+\w+\s*(=|LIKE|IN\s*\()|\bOR\s+\w+\s*(=|LIKE|IN\s*\()",
        "limit": 40,
    },
    "CONCAT_ASSIGN_SQL_BUILD": {
        "group": "group-b",
        "patterns": [r"\.\=.*(?:SELECT|WHERE|AND|OR\s|ORDER BY|LIMIT|FROM|JOIN|HAVING|GROUP BY)"],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        "case_insensitive": True,
        "limit": 40,
    },
    "WP_UNSLASH_BEFORE_SQL": {
        "group": "group-b",
        "patterns": [r"wp_unslash\(.*\$_(GET|POST|REQUEST|COOKIE)"],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
    },
    "FILTER_INPUT_SQL_CONTEXT": {
        "group": "group-b",
        "patterns": [r"filter_input\s*\("],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        "limit": 30,
    },
    # Aliased / wrapper $wpdb SQL sinks. Every other SQLi section matches only the
    # literal "$wpdb->"; plugins routinely stash the global in an object property
    # (global $wpdb; $this->wpdb = $wpdb;) or in $GLOBALS, then run SQL through the
    # alias — invisible to "$wpdb->" greps. Confirmed shape: better-search-replace
    # BSR_DB ($this->wpdb->get_var("...$table...")). Restricted to DYNAMIC queries
    # (string interpolation, concatenation, or a pre-built $sql/$query var) and
    # excludes ->prepare()-wrapped calls, so fully-parameterized ORMs don't flood.
    # Lead generation: confirm the alias is $wpdb AND that user input reaches it.
    "WPDB_WRAPPER_SQL": {
        "group": "group-b",
        "patterns": [
            # interpolated query string through a wrapper/aliased handle
            r"\$this->(?:wpdb|db|dbh|database)->(?:query|get_results|get_row|get_var|get_col)\s*\(\s*\"[^\"]*\$",
            # concatenated query through a wrapper handle
            r"\$this->(?:wpdb|db|dbh|database)->(?:query|get_results|get_row|get_var|get_col)\s*\([^)]*\.\s*\$",
            # pre-built query variable through a wrapper handle
            r"\$this->(?:wpdb|db|dbh|database)->(?:query|get_results|get_row|get_var|get_col)\s*\(\s*\$(?:sql|query|q|stmt|statement|where|sql_query)\b",
            # definitive $wpdb aliases (any dynamic form) — $GLOBALS / static property
            r"\$GLOBALS\[\s*['\"]wpdb['\"]\s*\]->(?:query|get_results|get_row|get_var|get_col)\s*\(",
            r"(?:self|static)::\$(?:wpdb|db|database)->(?:query|get_results|get_row|get_var|get_col)\s*\(",
        ],
        "exclude_patterns": [
            r"->prepare\s*\(",
        ],
        "limit": 50,
    },
    # User input reaching $wpdb->prepare()'s FIRST argument (the format/query
    # string). prepare() protects only values passed for %s/%d/%f/%i placeholders;
    # text in the format string itself is interpolated verbatim (non-placeholder
    # bytes pass through unescaped — verified WP 7.0 class-wpdb.php::prepare()).
    # The wpdb-query-user-input-taint rule treats prepare() as a sanitizer, so this
    # class is a blind spot there. Also covers prepare() on a wrapper (->prepare).
    "PREPARE_USER_INPUT_FORMAT_STRING": {
        "group": "group-b",
        "patterns": [
            r"->prepare\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b",
            r"->prepare\s*\(\s*(?:wp_unslash|sanitize_\w+|esc_\w+|stripslashes|trim|strval|urldecode)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            r"->prepare\s*\(\s*\$\w+->get_(?:param|params|json_params|body_params|query_params|query)\s*\(",
            # CVE-2026-57726 (kirki): the tainted value isn't the literal argument
            # to prepare() at all — it's interpolated/concatenated INSIDE the query
            # string that IS the format-string argument, e.g.
            #   $wpdb->prepare("SELECT ... ORDER BY {$order_by} {$order} LIMIT %d, %d", $offset, $limit);
            # A per-line scan can't see across the `->prepare(` line to the string
            # literal line, so this targets the string literal itself: an ORDER/GROUP
            # BY keyword followed by a variable, either interpolated in the same
            # quoted string or concatenated immediately after it closes.
            r'"[^"]*(?i:ORDER\s+BY|GROUP\s+BY)[^"]*\$\w+',
            r'"[^"]*(?i:ORDER\s+BY|GROUP\s+BY)[^"]*"\s*\.\s*\$\w+',
            # CVE-2024-11722 (acf-frontend-form-element / Frontend Admin <=
            # 3.25.1, unauthenticated SQLi via 'orderby'): the two patterns
            # above require the concatenated value to be a BARE variable and
            # (for the concat-after-close form) a double-quoted literal. This
            # plugin's pre-fix shape instead wraps the superglobal in a
            # quote-only escaper before concatenating it onto a SINGLE-quoted
            # 'ORDER BY'/'GROUP BY' literal — e.g. $wpdb->prepare(' ORDER BY '
            # . esc_sql($_REQUEST['orderby'])). esc_sql()/esc_attr()/
            # sanitize_text_field()/etc. only strip quotes or HTML, never SQL
            # keywords/parentheses, so this "looks sanitized" shape is exactly
            # as injectable as the bare-variable form. The official fix
            # replaced esc_sql() with sanitize_sql_orderby() at this same
            # concat site, which is why that function is deliberately absent
            # from the alternation below.
            r"""['"][^'"]*(?i:ORDER\s+BY|GROUP\s+BY)[^'"]*['"]\s*\.\s*(?:esc_sql|esc_attr|esc_url_raw|sanitize_text_field|sanitize_key|wp_unslash|stripslashes|trim|strval|urldecode)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b""",
            # CVE-2022-0867 (arprice-responsive-pricing-table): same blind spot,
            # WHERE-clause variant — a bare (non-placeholder) value is concatenated
            # immediately after a WHERE-clause equality closes the quoted string,
            # e.g. $wpdb->prepare("... WHERE pricing_table_id = " . $id . " AND
            # ip_address ='" . $ip . "' ... AND session_id = %s", $ses_id); only
            # the trailing %s is protected — $id/$ip are baked into the format
            # string text itself and never pass through a placeholder.
            r'"[^"]*\bWHERE\b[^"]*=\s*"\s*\.\s*\$\w+',
        ],
        "limit": 30,
    },
    # Custom query-builder objects (plugin ORMs / bundled Illuminate, Doctrine)
    # that bypass "$wpdb->" greps. Raw-fragment methods (*Raw) accept literal SQL;
    # ->where/->order_by/->having/->select fed a superglobal interpolate it.
    # CVE-2024-13496 GamiPress (orderby via custom CT_Query). Lead generation;
    # cross_file_filter limits to files that also do SQL.
    "SQL_QUERY_BUILDER_METHODS": {
        "group": "group-b",
        "patterns": [
            r"->(?:whereRaw|where_raw|orderByRaw|orderbyRaw|havingRaw|having_raw|rawWhere|raw_where|selectRaw|groupByRaw|fromRaw|joinRaw)\s*\(",
            r"->(?:where|or_where|and_where|order_by|orderby|having|group_by|select|from|join)\s*\([^)]*\$_(?:GET|POST|REQUEST)",
            r"->(?:where|or_where|order_by|orderby|having|group_by|select)\s*\([^)]*->get_param",
        ],
        "cross_file_filter": r"\$wpdb|mysqli_query|new\s+PDO|->get_results\s*\(|->query\s*\(|SELECT\s",
        "limit": 40,
    },
    # A sprintf()-built SQL fragment's format string uses "%s" as the
    # placeholder for a pre-joined comma-separated IN() list. Unlike
    # $wpdb->prepare()'s %s (which quotes/escapes a single scalar value),
    # sprintf()'s %s never escapes anything — if the joined list (implode())
    # isn't per-element integer-cast (array_map('intval'/'absint',...)) before
    # the join, the whole IN() clause is attacker-controlled. Common in
    # plugins with a custom query-builder/ORM: the fragment is stored in a
    # variable and executed several calls later via a raw-fragment method
    # (whereRaw/rawWhere/havingRaw) instead of a same-line $wpdb call, so a
    # same-line $wpdb cross-check misses it. Confirm the joined array's cast
    # before treating as a finding.
    "SPRINTF_IN_CLAUSE_FORMAT_STRING": {
        "group": "group-sqli",
        "patterns": [
            r"""['"][^'"]{0,200}\bIN\s*\(\s*%s\s*\)""",
        ],
        "case_insensitive": True,
        "cross_file_filter": r"implode\s*\(",
        "limit": 40,
    },
    # Hand-rolled PDO-style named-placeholder binders that splice prepare()'d
    # values into a query string via a self-reassigning str_replace() call
    # (e.g. inside a foreach over a bindings map) instead of one simultaneous
    # substitution over the original template. Backreference requires the
    # assigned variable to also appear as str_replace()'s subject argument —
    # the signature of sequential (non-atomic) placeholder substitution.
    "SELF_REASSIGN_STR_REPLACE_SQL_BUILD": {
        "group": "group-sqli",
        "patterns": [
            r"(\$\w+)\s*=\s*str_replace\([^;]*,\s*\1\s*\)\s*;",
        ],
        "cross_file_filter": r"->prepare\s*\(|\$wpdb",
        "limit": 30,
    },
    # Custom query-builder condition maps that concatenate a per-iteration
    # key/column/field variable onto another expression to form a new
    # identifier, in files that also do custom SQL query building. Flags the
    # site where the KEY (not the value) of a filter/condition array may be
    # used as a raw SQL fragment without being checked against an allow-list
    # of permitted operators/columns first.
    "DYNAMIC_WHERE_KEY_CONCAT": {
        "group": "group-sqli",
        "patterns": [
            r"\$\w+\s*=\s*[^;=]+\.\s*\$\w*(?:key|column|field)\w*\s*;",
        ],
        "cross_file_filter": r"->where\s*\(|build_conditions|build_where|\$wpdb",
        "limit": 40,
    },
    # A custom query/ORM WHERE-builder treats an arguments-array key whose
    # name signals a raw SQL passthrough (combines "where" with "sql"/"raw",
    # e.g. an "append_where_sql"-style escape hatch) as literal SQL text,
    # concatenating it (or its per-iteration loop value) directly onto a
    # WHERE-clause accumulator with no wrapping sanitizer/prepare() call at
    # all — a stronger, zero-escaping variant of DYNAMIC_WHERE_KEY_CONCAT.
    "RAW_WHERE_ARRAY_KEY_PASSTHROUGH": {
        "group": "group-sqli",
        "patterns": [
            r"foreach\s*\([^)]*\[\s*['\"][a-z_]*(?:where[a-z_]*(?:sql|raw)|(?:sql|raw)[a-z_]*where)[a-z_]*['\"]\s*\]\s*as\b",
            r"\$\w*(?:where|sql|clause|conditions?)\w*\s*\.=\s*\$\w+\s*;",
        ],
        "case_insensitive": True,
        "cross_file_filter": r"\$wpdb|->where\s*\(|build_conditions|build_where",
        "limit": 40,
    },
    # An elseif branch validates a foreach loop's KEY via array_key_exists()
    # against the same allow-list array a sibling branch already validates the
    # loop's VALUE against (in_array()) — key-vs-value confusion in an ORDER
    # BY / GROUP BY column allow-list helper. Unsafe when the allow-list array
    # is a plain list (array_keys()/array_merge()), since any small integer
    # key then "exists" regardless of the value, letting an attacker-supplied
    # indexed array (e.g. field[]=payload) bypass the allow-list entirely.
    # CVE-2025-6970 (events-manager, orderby parameter). Lead only — confirm
    # the allow-list array's own construction and the eventual SQL sink.
    "ORDERBY_ALLOWLIST_KEY_VALUE_CONFUSION": {
        "group": "group-sqli",
        "patterns": [
            r"else\s*if\s*\(\s*array_key_exists\s*\(\s*\$\w+\s*,\s*\$\w+",
        ],
        "exclude_patterns": [
            r"!\s*is_numeric\s*\(\s*\$\w+\s*\)\s*&&",
            r"array_key_exists\s*\([^)]*\)\s*&&\s*!?\s*is_numeric",
            r"is_string\s*\(\s*\$\w+\s*\)\s*&&",
        ],
        "cross_file_filter": r"in_array\s*\(",
        "limit": 30,
    },
    # A per-field validator loop (foreach ($rules as $field => $rule)) gates a
    # per-item sanitizer/allow-list dispatch with isset()/array_key_exists()/
    # !empty() tested against a plural-named OUTER collection variable and a
    # literal per-item attribute key (sanitize/allowed_values/callback/etc.)
    # instead of the singular per-iteration loop-item variable — a one-letter
    # variable-name typo that permanently disables the guarded branch on every
    # iteration, since the outer collection's own top-level keys are caller
    # field names, never per-item attribute names. CVE-2024-13496 (gamipress
    # <= 7.3.1, unauthenticated SQLi via 'orderby'): the allow-list guard read
    # isset($rules['allowed_values']) instead of isset($rule['allowed_values']).
    # Lead only — confirm the outer collection has no genuine top-level key of
    # that literal name, and trace the guarded field to its eventual SQL sink.
    "RULES_COLLECTION_VS_LOOP_ITEM_ISSET": {
        "group": "group-sqli",
        "patterns": [
            r"\bisset\(\s*\$\w*s\[\s*['\"](?:sanitize|sanitize_callback|validate_callback|allowed_values|allowed|callback|required|default|type|options|filter|cast)['\"]\s*\]\s*\)",
            r"\barray_key_exists\(\s*['\"](?:sanitize|sanitize_callback|validate_callback|allowed_values|allowed|callback|required|default|type|options|filter|cast)['\"]\s*,\s*\$\w*s\s*\)",
            r"!\s*empty\(\s*\$\w*s\[\s*['\"](?:sanitize|sanitize_callback|validate_callback|allowed_values|allowed|callback|required|default|type|options|filter|cast)['\"]\s*\]\s*\)",
        ],
        "cross_file_filter": r"foreach\s*\(\s*\$\w+\s+as\s+\$\w+\s*=>\s*\$\w+",
        "limit": 30,
    },
    # $wpdb->prepare()'s format-string argument builds an IN() clause with a
    # bare %s placeholder — no quote characters immediately surrounding it in
    # the query template. Older/non-auto-quoting wpdb paths only escape
    # quote/backslash characters inside the substituted value; they do not
    # add the enclosing quotes the template omitted. When the argument is a
    # comma-joined implode() of values never cast to int/float, the whole
    # list lands as one long, only-partially-escaped token — parentheses,
    # boolean keywords, and comment sequences reach the query as live SQL
    # syntax. CVE-2022-0657 (5-stars-rating-funnel <= 1.2.53, unauthenticated
    # rrtngg_delete_leads AJAX action): `$wpdb->prepare("DELETE FROM {$t}
    # WHERE ID IN (%s)", $ids_in)` with $ids_in an implode() of
    # sanitize_text_field()'d POST array values. Lead only — confirm the
    # implode()'d argument is not already array_map('intval'/'absint',...)
    # or wp_parse_id_list(), and check current reachability (this exact CVE's
    # own vendor patch gated the AJAX caller rather than fixing this line, so
    # the identical sink can legitimately persist in "fixed" releases).
    "PREPARE_UNQUOTED_IN_CLAUSE_PLACEHOLDER": {
        "group": "group-sqli",
        "patterns": [
            r"->prepare\s*\([^;]*\bIN\s*\(\s*%s\s*\)",
        ],
        "cross_file_filter": r"\$wpdb",
        "limit": 30,
    },
    # A CSV IN() list already quoted/escaped per element by a helper (a custom
    # "build a safe IN clause" function, or an inline $wpdb->prepare('%s',...)/
    # esc_sql() map) is re-wrapped in an extra, redundant pair of literal single
    # quotes when concatenated into a raw $wpdb query string — the leading
    # adjacent quote pair collapses into an empty-string SQL token, exposing the
    # rest of the first list element as unquoted, executable SQL.
    "WPDB_IN_CLAUSE_DOUBLE_QUOTE_WRAP": {
        "group": "group-sqli",
        "patterns": [
            r"""IN\s*\(\s*'"\s*\.\s*\$\w+\s*\.\s*"'""",
        ],
        "cross_file_filter": r"\$wpdb",
        "limit": 30,
    },
    # A hand-rolled WHERE/HAVING-clause value builder decides quoting with only
    # an is_numeric()-style ternary: numeric values pass through bare, anything
    # else is wrapped in a literal pair of single quotes via '.'-concatenation,
    # with NO escaping function ever applied to that same value. The
    # non-numeric branch never actually escapes the value's content, only
    # wraps it — a single embedded quote breaks out the moment the fragment
    # reaches a $wpdb call, even one nested inside $wpdb->prepare()'s own
    # format-string argument. CVE-2025-13673 (Tutor LMS <= 3.9.6): the
    # 'coupon_code' checkout parameter reached this exact idiom in a custom
    # query-builder's default WHERE-clause branch.
    "NUMERIC_TERNARY_UNESCAPED_QUOTE_WRAP": {
        "group": "group-sqli",
        "patterns": [
            r"""is_numeric\s*\(\s*\$\w+(?:\[[^\]]+\])?\s*\)\s*\?\s*\$\w+(?:\[[^\]]+\])?\s*:\s*"'"\s*\.\s*\$\w+""",
            r"""!\s*is_numeric\s*\([^)]*\)\s*\?\s*"'"\s*\.\s*\$\w+[^:]*:\s*\$\w+""",
        ],
        "cross_file_filter": r"\$wpdb",
        "limit": 30,
    },
    # A bare (unwrapped) variable sits directly between two string-literal
    # quote boundaries in a '.'-concatenation — the classic "value = '$VAR'"
    # breakout shape used to build a raw SQL string. Distinct from
    # CONCAT_ASSIGN_SQL_BUILD (requires a literal '.=' operator): this
    # catches the plain '=' initial assignment / inline-argument form.
    # Common second-order shape: $VAR is a function parameter carrying
    # previously-stored data (e.g. a WP core wp_privacy_personal_data_
    # exporters/erasers callback replaying a requester-submitted email)
    # rather than a same-request superglobal, so first-order SQLi greps
    # keyed to $_GET/$_POST miss it entirely. CVE-2024-0685 (ninja-forms
    # 3.7.1->3.7.2): `... WHERE m.meta_value = '" . $email_address . "'`.
    # WIDENED (CVE-2026-49080, wpdatatables 6.5.1.1->6.5.1.2): the
    # value between the quote boundaries is not always a bare variable — an
    # is_numeric()-branched search-value builder wrapped the same request
    # value in sanitize_text_field() in BOTH branches before the '.'-concat
    # quote-wrap. sanitize_text_field()/sanitize_textarea_field() strip HTML
    # but pass SQL metacharacters (quotes) through unchanged, so the quote
    # wrap is still a bare breakout once it reaches the $wpdb call. Second
    # pattern below catches this "looks-sanitized, isn't SQL-safe" variant.
    "QUOTED_VALUE_CONCAT_SQL_BUILD": {
        "group": "group-sqli",
        "patterns": [
            r"""['"]\s*\.\s*\$\w+\s*\.\s*['"]""",
            r"""['"]\s*\.\s*(?:sanitize_text_field|sanitize_textarea_field)\s*\([^)]*\)\s*\.\s*['"]""",
            # Tail-position variant: bare variable is the LAST concatenated
            # element (no trailing quote), closing the call argument or
            # statement directly — e.g. $wpdb->get_col('...WHERE id = '.$id);
            # CVE-2022-0773 (Documentor Lite <= 1.5.3, unauthenticated).
            r"""['"]\s*\.\s*\$\w+\s*[\);]""",
            # WIDENED (CVE-2025-26988, sms-alert 3.7.8->3.7.9,
            # unauthenticated): same tail-position shape, but the bare
            # variable is followed by a comma and one or more further call
            # arguments (e.g. a fetch-mode constant) before the closing
            # paren, rather than closing the call directly — e.g.
            # $wpdb->get_results('...affiliateId ='.$affiliate_id, ARRAY_A).
            # The strict "[\);]" terminator above requires the bare variable
            # to be the LAST token in the call and misses this.
            r"""['"]\s*\.\s*\$\w+\s*,\s*\w+\s*\)""",
        ],
        "line_filter": r"(?i)SELECT|WHERE|INSERT|UPDATE|DELETE|FROM|JOIN",
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        "exclude_patterns": [r"->prepare\s*\("],
        "limit": 40,
    },
    # A raw SQL clause fragment (JOIN/WHERE/SELECT/FROM-shaped) is built by
    # direct assignment/append of a double-quoted string with another
    # variable interpolated inside single quotes ('$var'), instead of
    # $wpdb->prepare()+placeholder or esc_sql(). Deliberately has NO
    # cross_file_filter requiring a literal "$wpdb" in the same file: the
    # confirmed CVE shape (CVE-2026-2413, Ally – Web Accessibility <= 4.0.3)
    # builds the fragment in one class and only reaches the actual $wpdb
    # call inside an unrelated custom DB-wrapper class in a DIFFERENT file
    # ("Table::select($cols, $where, ..., $join)"), so a same-file wpdb
    # filter would have missed the real vulnerable line entirely. A common
    # source for the interpolated variable is a URL-path-derived value
    # (current-page-URL helpers built from $_SERVER['REQUEST_URI']/
    # PATH_INFO), which is easy to overlook because it looks "internal"
    # rather than request-controlled — check that possibility first.
    "RAW_SQL_CLAUSE_QUOTED_VAR": {
        "group": "group-sqli",
        "patterns": [
            r"\$\w+\s*\.?=\s*\"[^\"]*\b(?:SELECT|FROM|JOIN|WHERE)\b[^\"]*=\s*'\$\w+'",
        ],
        "exclude_path_patterns": [r"vendor/", r"node_modules/"],
        "case_insensitive": True,
        "limit": 40,
    },
    # A raw SQL condition fragment (AND/OR/WHERE-shaped) is built by direct
    # assignment/append of a double-quoted string with a BARE variable
    # interpolated directly after "=" — no surrounding quotes, no array/
    # object access (that shape is UNQUOTED_INTERPOLATED_ARRAY_KEY_SQL) and
    # no single-quote wrap (that shape is RAW_SQL_CLAUSE_QUOTED_VAR). This is
    # the plain-scalar sibling of both: an ID-like variable spliced straight
    # after "=" with zero escaping, so an attacker does not even need to
    # break out of a string literal. CVE-2022-0788 (WP Fundraising Donation
    # and Crowdfunding Platform <= 1.4.2, unauthenticated): the
    # 'payment-redirect' REST route read $request['id'] with no cast, built
    # `$wrere = " AND donate_id = $id";`, then handed $wrere to a custom
    # query-helper method that spliced it unprepared into $wpdb->get_results().
    # Deliberately excludes $wpdb->prop interpolation (WP-Core-internal table
    # names, never attacker data). Lead only — the fragment variable is
    # frequently consumed by a same-class helper method rather than $wpdb
    # directly at this line; confirm the eventual sink and the variable's
    # origin manually.
    "UNQUOTED_BARE_VARIABLE_SQL_FRAGMENT_INTERP": {
        "group": "group-sqli",
        "patterns": [
            r"\$\w+\s*\.?=\s*\"[^\"]*\b(?:AND|OR|WHERE)\b[^\"]*=\s*\$(?!wpdb\b)\w+\b(?!\s*(?:->|\[))",
            # Ternary variant of the same shape: $frag = $cond ? "AND x = $var" : ...;
            # CVE-2025-13192 (PopupKit / Popup Builder Block <= 2.2.0, unauthenticated):
            # multiple REST 'popup/logs?type=' analytics getters built
            # `$campaign = $campaign_id ? " AND campaign_id = $campaign_id" : '';`
            # then spliced $campaign straight into a $wpdb->prepare() format
            # string alongside legitimate %s/%i placeholders — the ternary
            # right-hand-side is a string literal, so the non-ternary pattern
            # above (which requires "=\s*\"" right after the assignment
            # operator) does not match it.
            r"\$\w+\s*=\s*[^;\"]*\?\s*\"[^\"]*\b(?:AND|OR|WHERE)\b[^\"]*=\s*\$(?!wpdb\b)\w+\b(?!\s*(?:->|\[))",
            # Direct-argument variant of the same shape: the bare variable is
            # spliced straight inside the $wpdb call's own string-literal
            # argument, with no intermediate $frag assignment at all — e.g.
            # $wpdb->get_results("SELECT ... WHERE post_id = $post_id ...").
            # WIDENED (CVE-2022-0747, infographic-and-list-builder-
            # ilist <= 4.3.7, unauthenticated qcld_upvote_action AJAX action):
            # sanitize_text_field()'d $_POST['post_id'] was spliced unquoted
            # directly into $wpdb->get_results()'s own string argument; the
            # vendor fix wrapped it in absint() without changing this line, so
            # this variant, like its siblings above, cannot see prior-line
            # casting and should be treated as a lead only.
            r"\$wpdb->(?:get_results|get_row|get_var|get_col|query)\s*\(\s*\"[^\"]*\b(?:AND|OR|WHERE)\b[^\"]*=\s*\$(?!wpdb\b)\w+\b(?!\s*(?:->|\[))",
        ],
        "exclude_path_patterns": [r"vendor/", r"node_modules/"],
        "case_insensitive": True,
        "limit": 40,
    },
    # A foreach loop iterates over $_POST/$_REQUEST/$_GET (or a local copy of
    # one of them) using the loop's KEY; when that key is later folded into an
    # array passed to $wpdb->insert()/update()/replace(), it becomes an
    # unescaped raw column identifier (array_keys($data) is only
    # backtick-wrapped, never escaped) — SQL injection via the array KEY even
    # when every VALUE is sanitized. Lead generation; confirm the loop's array
    # ends up as the $data argument of an insert/update/replace call.
    "FOREACH_REQUEST_KEY_WPDB_WRITE": {
        "group": "group-sqli",
        "patterns": [
            r"foreach\s*\(\s*\$_(?:POST|REQUEST|GET)\s+as\s+\$\w+\s*=>\s*\$\w+\s*\)",
            r"\$\w+\s*=\s*\$_(?:POST|REQUEST)\s*;",
        ],
        "cross_file_filter": r"\$wpdb->insert\s*\(|\$wpdb->update\s*\(|\$wpdb->replace\s*\(",
        "limit": 40,
    },
    # An array-key or object-property value is spliced directly into a SQL
    # string via PHP curly-brace interpolation ({$arr['key']} / {$obj->prop})
    # OR via plain '.'-concatenation of the bare array access, immediately
    # after "=", with NO surrounding quotes — an attacker doesn't even need
    # to break out of a string literal since there is no quote delimiter to
    # escape past. Excludes {$wpdb->prop} (WP-Core-internal table-name
    # properties, never attacker data). CVE-2022-0651 (WP Statistics <=
    # 13.1.5): unauthenticated REST "hit" callback copied $_REQUEST into an
    # object with zero sanitization; a filter callback returned
    # current_page_id verbatim into an array later interpolated unquoted
    # into a WHERE clause equality ($wpdb->get_row("... AND `id` =
    # {$current_page['id']}")). CVE-2022-0694 (Advanced Booking Calendar <=
    # 1.6.9): the same class via '.'-concatenation instead of interpolation
    # — an unauthenticated AJAX handler's request-array parameter spliced
    # straight into a WHERE-clause numeric value ("...calendar_id = '"
    # . $atts['calendar'] . "'..."), fixed by wrapping it in intval().
    "UNQUOTED_INTERPOLATED_ARRAY_KEY_SQL": {
        "group": "group-sqli",
        "patterns": [
            r"=\s*\{\$(?!wpdb\b)\w+(?:\[[^\]]*\]|->\w+)\}(?!')",
            # '.'-concatenation form: array-key value sits between two quote
            # boundaries with no cast — mid-chain (more clauses follow) or
            # tail (the array access is the last concatenated element).
            r"""=\s*['"]\s*\.\s*\$\w+\[[^\]]+\]\s*\.\s*['"]""",
            r"""=\s*['"]\s*\.\s*\$\w+\[[^\]]+\]\s*[,);]""",
        ],
        "line_filter": r"(?i)SELECT|WHERE|AND\s|OR\s|INSERT|UPDATE|DELETE|FROM|JOIN",
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col",
        "limit": 40,
    },
    # A variable is interpolated directly into a CREATE/DROP/ALTER/RENAME/
    # TRUNCATE TABLE statement's table-name (identifier) position, executed
    # raw via a $wpdb (or wpdb-wrapper) query method. $wpdb->prepare()'s
    # %s/%d placeholders quote a VALUE, not an identifier, so even an
    # "escaped" value is exploitable here. Excludes the sole-{$wpdb->prefix}
    # dbDelta-style idiom via the wpdb-negative-lookahead. Common in staging/
    # cloning/migration plugins where the identifier is a user-suppliable
    # table prefix/alias stored via an options round-trip several calls
    # earlier, not read from a superglobal at the vulnerable line itself.
    # CVE-2024-1981 (WPvivid Backup and Migration <= 0.9.68): an unauth
    # 'table_prefix' POST parameter flowed unsanitized into a staging task's
    # db_connect option, later read back and spliced into
    # "DROP TABLE IF EXISTS {$new_table_name}".
    "DDL_TABLE_STATEMENT_RAW_VAR_INTERP": {
        "group": "group-sqli",
        "patterns": [
            r"\b(?:CREATE|DROP|ALTER|RENAME|TRUNCATE)\s+TABLE\b.*\{?\$(?!wpdb\b)\w+",
        ],
        "cross_file_filter": r"\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var|\$wpdb->get_col|->query\s*\(|->get_results\s*\(",
        "case_insensitive": True,
        "exclude_patterns": [r"->prepare\s*\("],
        "limit": 40,
    },
    # An HTTP-header-derived $_SERVER value (Host, Referer, User-Agent,
    # X-Forwarded-For, REQUEST_URI/PHP_SELF/QUERY_STRING/SERVER_NAME — all
    # attacker-controlled request data, not "internal" plumbing) is passed
    # directly as an argument inside the SAME $wpdb->query/get_results/
    # get_row/get_var/get_col(...) call, with no $wpdb->prepare()/esc_sql()
    # anywhere on that line. Common in "current page / canonical URL" lookup
    # logic (SEO, redirect, phone/referrer-swap, analytics plugins) that
    # LIKE-matches the current request against stored page URLs — reachable
    # unauthenticated on every front-end page view, no AJAX or login needed.
    # CVE-2022-0771 (sitesupercharger <= 5.1.10, unauthenticated): a
    # page-lookup helper hooked to WP's 'init' action built
    # `... guid LIKE '%".($_SERVER["HTTP_HOST"].$_SERVER["REQUEST_URI"])."'`
    # and handed it straight to $wpdb->get_row(); fixed by extracting the
    # values through sanitize_text_field()/sanitize_url() on prior lines and
    # rebuilding the call as $wpdb->prepare("... LIKE '%s' ...", $term).
    # Lead only — same-line co-occurrence catches the direct-splice shape;
    # confirm no prepare()/esc_sql() applies earlier to the same value.
    "SERVER_HEADER_RAW_SQL_CONCAT": {
        "group": "group-sqli",
        "patterns": [
            r"\$wpdb->(?:query|get_results|get_row|get_var|get_col)\s*\([^;]*\$_SERVER\s*\[\s*['\"](?:HTTP_HOST|REQUEST_URI|PHP_SELF|QUERY_STRING|HTTP_REFERER|HTTP_X_FORWARDED_FOR|HTTP_USER_AGENT|SERVER_NAME)['\"]\s*\]",
        ],
        "exclude_patterns": [r"->prepare\s*\("],
        "limit": 40,
    },
    # A bare (unquoted, uncast) variable sits directly between the SELECT and
    # FROM keywords, splicing an entire column-list in as raw SQL identifier
    # text — a COLUMN/FIELD-NAME (identifier) position injection, distinct
    # from value-position SQLi. Commonly the imploded result of a request-
    # controlled "fields"/"columns" array (a REST "sparse fieldset" param);
    # neither esc_sql() nor a bare $wpdb->prepare() call (with no placeholder
    # bound for this value) protects this position. Second pattern catches
    # the request-side source: splitting a comma-separated fields/columns
    # parameter straight out of a superglobal before any allow-list check.
    "REQUEST_FIELDS_RAW_SELECT_COLUMN_LIST": {
        "group": "group-sqli",
        "patterns": [
            r"select\s+\$\w+\s+from\b",
            r"explode\s*\(\s*['\"],['\"]\s*,\s*\$_(?:GET|POST|REQUEST)\[\s*['\"](?:fields?|columns?)['\"]\s*\]",
        ],
        "cross_file_filter": r"\$wpdb",
        "case_insensitive": True,
        "limit": 40,
    },
    # Inside a foreach over a DB result set, a row property is written to a
    # stream/file as part of generated SQL text (a database export/backup
    # "dump" feature building an INSERT ... VALUES fragment row-by-row) via
    # raw string interpolation inside a quoted SQL string-literal position
    # (\"{$row->field}\" or '{$row->field}'), with no esc_sql() escaping.
    # This is a "generate-then-re-execute" second-order SQL injection: the
    # row value may have been written to the DB safely via $wpdb->prepare(),
    # but a stored value that ever contains a literal quote (e.g. because it
    # originated from an unauthenticated public form/tracking event) still
    # breaks out of the SQL literal when re-embedded, unescaped, into freshly
    # generated SQL text — typically re-executed later by a companion
    # import/restore feature via $wpdb->query() with no further escaping.
    # CVE-2026-22850 (Koko Analytics <= 2.1.2, unauthenticated): the
    # database-export feature wrote each stored path/referrer-URL value
    # (originating from the unauthenticated tracking-pixel endpoint) straight
    # into a generated INSERT statement via fwrite() with no esc_sql(),
    # fixed by switching to fprintf() with a %s placeholder and esc_sql().
    "SQL_DUMP_ROW_PROPERTY_INTERPOLATION": {
        "group": "group-sqli",
        "patterns": [
            r'f(?:write|puts|printf)\s*\([^;]*\\"\{\$[A-Za-z_][A-Za-z0-9_]*->[A-Za-z_][A-Za-z0-9_]*\}\\"',
            r"f(?:write|puts|printf)\s*\([^;]*'\{\$[A-Za-z_][A-Za-z0-9_]*->[A-Za-z_][A-Za-z0-9_]*\}'",
        ],
        "limit": 40,
    },
    # A request-array parameter is passed straight into implode() as the join
    # target (the classic "IN() list from a checkbox/multi-select id array"
    # idiom: `implode(',', $_REQUEST['id'])`), with NO array_map('intval'/
    # 'absint'/'floatval'/'sanitize_key', ...) cast wrapped around the request
    # array first. Distinct from WPDB_UNSAFE_IN_CLAUSE-shaped sections (which
    # require the implode() call itself to sit inline inside the $wpdb call):
    # this is the two-step "$list = implode(...); ...; $sql = \"...IN($list)...\";
    # $wpdb->get_results($sql)" assign-then-interpolate shape, where the
    # request array and the eventual SQL sink are on different lines/statements.
    # CVE-2021-24931 (secure-copy-content-protection <= 2.8.1, unauthenticated
    # ays_sccp_results_export_file AJAX action, wp_ajax_nopriv_-registered):
    # `implode(',', $_REQUEST['sccp_id'])` fed an unprepared `WHERE subscribe_id
    # IN ($short_id)` string later passed to $wpdb->get_results(). Fixed by
    # wrapping the request array in array_map('intval', ...) before the join.
    # Second pattern (CVE-2023-23490, survey-maker <= 3.1.1, authenticated
    # Subscriber+ ays_surveys_export_json AJAX action, wp_ajax_-registered with
    # no capability/nonce check): the request array is first run through
    # `array_map('sanitize_text_field', $_REQUEST['surveys_ids'])` — a per-
    # element sanitizer that strips HTML but passes SQL metacharacters
    # (quotes, parens, keywords) through unchanged — before being implode()'d
    # into a `WHERE id IN (...)` fragment several statements later. The
    # sanitize_text_field() wrapper defeats plain implode-of-superglobal
    # detection while providing no SQL protection; only an integer-cast
    # array_map (intval/absint/floatval/sanitize_key) is safe here.
    "REQUEST_ARRAY_IMPLODE_UNCAST_IN_CLAUSE": {
        "group": "group-sqli",
        "patterns": [
            r"implode\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\$_(?:GET|POST|REQUEST)\s*\[",
            r"array_map\s*\(\s*['\"]sanitize_text_field['\"]\s*,\s*\$_(?:GET|POST|REQUEST)\s*\[",
        ],
        "exclude_patterns": [
            r"array_map\s*\(\s*['\"](?:intval|absint|floatval|sanitize_key)['\"]",
        ],
        "cross_file_filter": r"\$wpdb->(?:query|get_results|get_row|get_var|get_col)\s*\(",
        "limit": 40,
    },
    # A comma- or plus-separated string is split via explode() and the
    # resulting array is not immediately int-cast (array_map('absint'/
    # 'intval', ...) or wp_parse_id_list()) before it can reach a tax_query-
    # shaped 'terms' filter row. Plugins that reimplement their own taxonomy-
    # term-to-SQL resolution (custom search/relevance engines, caching layers)
    # instead of handing this array to a real WP_Query commonly skip the
    # cast WP_Tax_Query::clean_query() performs internally. cross_file_filter
    # requires a 'terms' =>/'terms':  tax_query row key somewhere in the same
    # file as a coarse correlation signal. CVE-2025-4396 (relevanssi <=
    # 4.24.4, unauthenticated time-based SQLi via the 'cats'/'tags' search
    # query params): `$cat = explode(',', $cat);` / `$tag = explode('+'|','
    # , $tag);` fed a 'terms' tax_query row whose values later reached a raw
    # $wpdb->get_col() IN() clause with no prepare()/absint() anywhere in the
    # chain. Lead only — confirm the exploded array is not consumed by a real
    # WP_Query()/get_posts() call (which absint-casts internally) before
    # reporting.
    "EXPLODE_CSV_UNCAST_TAX_QUERY_TERMS": {
        "group": "group-sqli",
        "patterns": [
            r"explode\s*\(\s*['\"][,+]['\"]\s*,\s*\$\w+\s*\)",
        ],
        "exclude_patterns": [
            r"array_map\s*\(\s*['\"](?:absint|intval|floatval)['\"]\s*,\s*explode\s*\(",
        ],
        "cross_file_filter": r"['\"]terms['\"]\s*(?:=>|:)",
        "limit": 40,
    },
    "TIER4_CAPABILITY_CHECKS": {
        "group": "group-b",
        "patterns": [
            r"current_user_can\(|wp_verify_nonce\(|check_ajax_referer\(|check_admin_referer\("
        ],
    },
    "CPT_CUSTOM_CAPABILITIES": {
        "group": "group-b",
        "patterns": [r"'capability_type'\s*=>|'capabilities'\s*=>\s*\["],
        "cross_file_filter": r"register_post_type",
    },
    "CPT_PAGE_CAPABILITY_TYPE": {
        "group": "foundation",
        "patterns": [r"'capability_type'\s*=>\s*['\"]page['\"]"],
        "cross_file_filter": r"register_post_type",
    },
    "REST_POST_TYPE_PARAM": {
        "group": "group-b",
        "patterns": [r"[\"']post_type[\"']\s*=>\s*\$"],
        "cross_file_filter": r"get_param|->get_param|_GET\[|_POST\[",
    },
    "TEMPLATE_REDIRECT_LOGIN_GATE": {
        "group": "group-b",
        "patterns": [r"is_user_logged_in\(\)"],
        "cross_file_filter": r"template_redirect",
    },
    "REST_PERMISSION_CHECK_HAS_CAP": {
        "group": "group-b",
        "patterns": [r"->has_cap\s*\("],
        "cross_file_filter": r"register_rest_route|extends WP_REST_Controller",
    },
    # Named REST permission_callback method (WP_REST_Controller convention:
    # get_item(s)_permission(s)_check, create/update/delete_item_permissions_check,
    # or any custom *_permission(s)_check). Surfaces every such definition as a
    # candidate so the auditor opens it and confirms a real current_user_can()/
    # capability gate is present — a name containing "permission" does NOT mean
    # WordPress enforces anything; a stub body of only `return true;` grants
    # unauthenticated access to the whole route regardless of the name
    # (CVE-2026-32520: rewardswp 1.0.4 get_products_permissions_check() /
    # get_rewards_permissions_check() were exactly this — always `return true;`,
    # fixed in 1.0.5 by adding current_user_can('manage_options')).
    "REST_PERMISSION_CHECK_NAMED_ALWAYS_TRUE": {
        "group": "group-ac",
        "case_insensitive": True,
        "patterns": [r"function\s+\w*permissions?_check\s*\("],
        "cross_file_filter": r"register_rest_route|permission_callback",
    },
    # A permission/access-check branch returns true immediately after
    # comparing a plugin option/setting value to a string sentinel (e.g. the
    # plugin's own "no role restriction configured" marker), with no
    # is_user_logged_in()/current_user_can() check visible on that same
    # line. If the surrounding function never checks login state at all
    # (confirm manually — this is a single-line grep, not a whole-function
    # check), a default/realistic config value equalling the sentinel makes
    # the gate unconditionally pass for unauthenticated callers (CWE-862 /
    # CWE-287). CVE-2025-68015 (event-tickets-with-ticket-scanner <= 2.8.5):
    # `if (!$flag && $allowed_role == "-") return true;` inside a REST
    # permission_callback with no is_user_logged_in() anywhere in the
    # function — the callback gated a route that dispatched a raw request
    # "action" parameter to a privileged internal command router, chaining
    # to unauthenticated RCE.
    "REST_PERMISSION_OPTION_SENTINEL_RETURN_TRUE": {
        "group": "group-ac",
        "patterns": [
            r"==\s*['\"][^'\"]{0,20}['\"]\s*\)\s*return\s+true\s*;",
        ],
        "cross_file_filter": r"register_rest_route|permission_callback",
    },
    "REST_LOGIN_ONLY_PERMISSION": {
        "group": "group-b",
        "patterns": [
            r"is_user_logged_in\(\)",
            r"get_current_user_id\(\)",
        ],
        "cross_file_filter": r"register_rest_route|permission_callback",
    },
    # wp_verify_nonce($X, 'wp_rest') only proves the caller holds a valid
    # same-session nonce, not a capability — WP Core mints it for every
    # authenticated role. Flags candidate permission_callback methods so a
    # missing current_user_can() alongside it can be triaged manually.
    # No cross_file_filter: 'wp_rest' is WP Core's own REST nonce action
    # string, virtually never used outside a permission-check context, so
    # this pattern is already specific without a same-file co-occurrence
    # requirement — unlike is_user_logged_in()/get_current_user_id() below,
    # which need one. A same-file filter would also miss the common shared
    # base-class architecture where the nonce check lives in one file
    # (e.g. an abstract route class) and register_rest_route()/
    # permission_callback appear only in a separate subclass file.
    "REST_NONCE_ONLY_PERMISSION": {
        "group": "group-ac",
        "patterns": [
            r"wp_verify_nonce\([^)]*['\"]wp_rest['\"]",
        ],
    },
    "REST_REFLECTION_PERMISSION_WIRING": {
        "group": "group-ac",
        "patterns": [
            r"\$\w+\s*===?\s*\$\w+->class\b",
            r"\$\w+->class\s*===?\s*\$\w+\b",
            r"getDeclaringClass\(\)",
        ],
        "cross_file_filter": r"register_rest_route|permission_callback",
    },
    "REST_ITEMS_PERM_ON_WRITE_ROUTE": {
        "group": "group-ac",
        "patterns": [
            r"['\"]permission_callback['\"]\s*=>\s*array\(\s*\$\w+,\s*['\"]\w*get_items_permissions_check['\"]",
        ],
        "cross_file_filter": r"WP_REST_Server::(CREATABLE|EDITABLE|DELETABLE)|['\"](POST|PUT|PATCH|DELETE)['\"]",
    },
    # Single-item REST permission check defined in a file that also defines the
    # plural (collection) permission check — surfaces the pair so an auditor can
    # confirm both apply the same context=edit capability gate. CVE-2026-57318
    # (site-reviews): the collection check gated 'edit' context behind edit_posts,
    # the single-item check never referenced context at all, letting any logged-in
    # user request ?context=edit on the single-item route and receive schema
    # fields restricted to context=edit (email, IP address).
    "REST_ITEM_PERMISSION_NO_CONTEXT_CHECK": {
        "group": "group-ac",
        "patterns": [
            r"function\s+\w*get_item_permissions_check\s*\(",
        ],
        "cross_file_filter": r"function\s+\w*get_items_permissions_check\s*\(",
    },
    "REST_PERMISSION_TYPE_DISCRIMINATOR_NULL_DEFAULT": {
        "group": "group-ac",
        "patterns": [
            r"default\s*(=>|:)\s*(null|return\s+null)\s*[,;]?\s*$",
        ],
        "cross_file_filter": r"permission_callback|WP_REST_Controller|register_rest_route",
        "limit": 40,
    },
    # The literal '__return_true' string (WP Core's own convenience callback)
    # used directly as permission_callback, in a file that also names a
    # third-party integration provider — surfaces the credential-proxy
    # sub-class of CWE-862 distinct from a named wrapper function that
    # happens to return true (see REST_PERMISSION_CHECK_NAMED_ALWAYS_TRUE
    # above). See CVE-2026-15827 in VARIANT-PROVENANCE.md.
    "REST_RETURN_TRUE_INTEGRATION_PROXY": {
        "group": "group-ac",
        "case_insensitive": True,
        "patterns": [
            r"['\"]permission_callback['\"]\s*=>\s*['\"]__return_true['\"]",
        ],
        "cross_file_filter": r"mailchimp|sendgrid|sendinblue|brevo|constant.?contact|getresponse|aweber|convertkit|klaviyo|mailerlite|activecampaign|hubspot|salesforce|zoho|pipedrive|drip|infusionsoft|campaign.?monitor|stripe|paypal|braintree|square|razorpay|twilio|zapier|integromat|api.?key|api.?integration",
    },
    # get_user_meta()/get_post_meta() assigned without the third $single
    # argument (returns an array) and then compared with a strict operator,
    # or compared inline right after the call — an array is never === to a
    # scalar and always !== to one, so the check silently produces a constant
    # result. cross_file_filter narrows to files that also perform a nonce
    # check, matching the nonce-or-token authorization-gate context this bug
    # recurs in. See CVE-2026-13332 in VARIANT-PROVENANCE.md.
    "META_GETTER_UNSINGLE_STRICT_COMPARE": {
        "group": "group-ac",
        "patterns": [
            r"\$\w+\s*=\s*get_(?:user|post)_meta\s*\(\s*[^,()]+,\s*[^,()]+\)\s*;",
            r"get_(?:user|post)_meta\s*\([^,()]+,\s*[^,()]+\)\s*[!=]==",
            r"[!=]==\s*get_(?:user|post)_meta\s*\(",
        ],
        "cross_file_filter": r"wp_verify_nonce\s*\(|check_ajax_referer\s*\(",
    },
    "TIER4_OPTION_WRITES": {
        "group": "group-b",
        "patterns": [
            r"update_option\(",
            r"update_site_option\(",
            r"update_user_meta\(",
            r"add_option\(",
            r"delete_option\(",
            r"delete_site_option\(",
        ],
    },
    "NOPRIV_OPTION_WRITES": {
        "group": "group-b",
        "patterns": [
            r"update_option\(",
            r"add_option\(",
            r"delete_option\(",
            r"update_site_option\(",
            r"delete_site_option\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "NOPRIV_USER_WRITES": {
        "group": "group-b",
        "patterns": [
            r"wp_update_user\s*\(",
            r"wp_set_auth_cookie\s*\(",
            r"wp_set_current_user\s*\(",
            r"wp_insert_user\s*\(",
            r"wp_create_user\s*\(",
            r"->set_role\s*\(",
            r"->add_role\s*\(",
            r"wp_set_password\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    # A capability-check call (current_user_can()/user_can(), or a plugin-defined
    # is_capable()/has_cap()-style wrapper around them) is passed a capability NAME
    # taken directly from request input rather than a hardcoded string — letting the
    # caller decide for themselves which capability gets verified ("self-attested"
    # check). cross_file_filter requires the file to ALSO register a
    # wp_ajax_nopriv_/admin_post_nopriv_ hook, so the bypass is reachable by fully
    # unauthenticated visitors. CVE-2026-39587 class (WP BASE Booking of
    # Appointments, Services and Events — unauthenticated privilege escalation via a
    # client-supplied "cap" POST field trusted by check_cap()/is_capable()).
    "NOPRIV_SELF_ATTESTED_CAPABILITY": {
        "group": "group-ac",
        "patterns": [
            r"(current_user_can|user_can|is_capable|has_cap)\s*\([^;{}]{0,100}\$_(GET|POST|REQUEST)\s*\[",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
        "limit": 30,
    },
    "ROLE_KEY_ASSIGNED_FROM_REQUEST_LOOP": {
        "group": "group-ac",
        "patterns": [
            # A role/capability-denoting array or meta key is assigned a bare
            # variable (not a hardcoded literal) — the shape behind
            # unauthenticated self-registration flows that copy a hidden
            # form field's role value straight into a meta array without an
            # allowlist or hash_equals()-verified signature (CWE-266).
            r"\[\s*['\"][^'\"]*(?:user[_-]?role|wp_capabilities)['\"]\s*\]\s*=\s*\$\w",
            r"['\"]role['\"]\s*=>\s*\$\w",
            # Bracket-assignment (not array-literal =>) of the 'role' key to
            # any expression — e.g. $user_data['role'] = sanitize_text_field($role) —
            # the shape used by *_new_customer_data/user_register-style filters
            # that set a new user's role from a stored per-field submission value.
            r"\[\s*['\"]role['\"]\s*\]\s*=(?!=)",
            # Array-literal 'role' key whose value is a ternary/boolean
            # expression that itself references a request superglobal on the
            # same line — e.g. 'role' => !empty($_POST['role']) &&
            # array_key_exists(..., wp_roles()->get_names()) ? ... : 'subscriber'
            # (CVE-2026-7284 class: an existence-only check against the full
            # role list is not a safe-role allowlist).
            r"['\"]role['\"]\s*=>\s*[^,]*\$_(?:POST|GET|REQUEST)\b",
            # Plugin-private usergroup/groupid variant of the same shape —
            # e.g. $profile_fields['groupid'] = $member['groupid']; — a
            # forum/membership plugin's own privilege-tier identifier copied
            # from request-derived data into the array a persistence call
            # will write, with no allowlist check on the value itself
            # (CVE-2023-47868 class, wpForo unauthenticated privesc).
            r"\[\s*['\"](?:usergroup|group_?id|secondary_group_?ids)['\"]\s*\]\s*=\s*\$\w",
        ],
        # Also fires when the request body is a decoded JSON payload
        # (php://input) rather than $_POST/$_GET/$_REQUEST — the shape of
        # REST API registration handlers, e.g.
        # json_decode(file_get_contents('php://input')) (CVE-2023-3076-class).
        "cross_file_filter": r"foreach\s*\(\s*\$_(POST|GET|REQUEST)|\$_(POST|GET|REQUEST)\s*\[|file_get_contents\s*\(\s*['\"]php://input",
        "limit": 30,
    },
    # A role-denoting array key is assigned unconditionally from the
    # SAME-named key of the function's own input data (bracket-assignment,
    # isset()-ternary or null-coalescing passthrough) — the request/JSON-
    # decode origin of that input parameter may live in a different
    # function/file than this assignment (unlike
    # ROLE_KEY_ASSIGNED_FROM_REQUEST_LOOP, no same-file $_POST/$_GET/
    # $_REQUEST/php://input corroboration is required here).
    # CVE-2026-1492 (user-registration, unauthenticated privesc via
    # membership registration).
    "ROLE_KEY_CONDITIONAL_OVERRIDE_ONLY": {
        "group": "group-ac",
        "patterns": [
            r"\[\s*['\"]role['\"]\s*\]\s*=\s*isset\s*\(\s*\$\w+\[\s*['\"]role['\"]\s*\]\s*\)\s*\?",
            r"\[\s*['\"]role['\"]\s*\]\s*=\s*\$\w+\[\s*['\"]role['\"]\s*\]\s*\?\?",
            # Object-property variant (CVE-2025-11457 class): $this->role = isset($args['role']) ? ...
            # instead of an array-key destination.
            r"->\w+\s*=\s*isset\s*\(\s*\$\w+\[\s*['\"]role['\"]\s*\]\s*\)\s*\?",
        ],
        "limit": 30,
    },
    # Two-arg WP_Roles::add_cap($role, $cap) granting a capability to a
    # non-'administrator' role slug, in a file that also grants the SAME
    # style capability to 'administrator' — the shape of a role-registration
    # routine that duplicates an admin-gating capability onto a custom
    # (often self-registerable) role with no privilege check involved
    # (CWE-266). WP_Role::add_cap($cap) called on a role OBJECT is a
    # single-arg call and does not match. CVE-2025-10038 (Binary MLM Plan).
    "ROLE_REGISTRATION_ADMIN_CAP_PARITY": {
        "group": "group-ac",
        "patterns": [
            r"(?:->|::)add_cap\s*\(\s*['\"](?!administrator['\"])[\w-]+['\"]\s*,\s*\S",
        ],
        "cross_file_filter": r"add_cap\s*\(\s*['\"]administrator['\"]",
        "limit": 30,
    },
    # A REST-route-registered file also creates or promotes a WordPress account
    # with a non-default role — wp_create_user()/wp_insert_user()/wp_update_user()
    # + ->set_role()/->add_role()/the 'role' array key — a distinct false-negative
    # gap from NOPRIV_USER_WRITES above, which only fires on wp_ajax_nopriv_/
    # admin_post_nopriv_ hooks and misses this same sink reached via
    # register_rest_route() with a permission_callback checking a plugin-defined
    # custom capability instead of a WP core one (CVE-2025-68027 class).
    "REST_USER_CREATION_ROLE_ELEVATION": {
        "group": "group-ac",
        "patterns": [
            r"wp_create_user\s*\(",
            r"wp_insert_user\s*\(",
            r"->set_role\s*\(",
            r"->add_role\s*\(",
            r"['\"]role['\"]\s*=>\s*['\"][\w-]+['\"]",
        ],
        "cross_file_filter": r"register_rest_route\s*\(",
        "limit": 30,
    },
    # A hook name that is itself a runtime variable/expression (not a literal
    # string) is registered via add_filter()/add_action() only when a request-
    # array key is checked for non-emptiness — the "developer backdoor" shape:
    # the actual hook wired up (and therefore the callback that runs) is not
    # visible as a string anywhere near the registration call.
    # CVE-2026-0920 (lastudio-element-kit, unauthenticated privesc via a
    # dynamically-aliased insert_user_meta hook gated on a hidden POST field).
    "DYNAMIC_HOOK_GATE_ROLE_WRITE": {
        "group": "group-ac",
        "patterns": [
            r"add_(?:filter|action)\s*\(\s*\$\w+\s*,",
        ],
        "cross_file_filter": r"wp_insert_user\s*\(|wp_create_user\s*\(",
        "limit": 30,
    },
    # An admin-configurable "premoderation/approval" option is the ONLY option
    # read in the file that gates a role write — a lead for CVE-2024-5973-class
    # bugs where a self-service role-upgrade flow checks a premoderation flag
    # but omits a separate master "is this feature enabled at all" toggle,
    # letting the role write proceed whenever premoderation also defaults to
    # off (CWE-269). Manual verification required: confirm no second, distinct
    # get_option()-derived flag also gates the same wp_update_user()/
    # wp_insert_user() call.
    "PREMODERATION_ONLY_GATE_ROLE_WRITE": {
        "group": "group-ac",
        "patterns": [
            r"get_option\s*\(\s*['\"][\w-]*(?:premoderation|require_approval|pending_approval)['\"]",
        ],
        "cross_file_filter": r"wp_update_user\s*\(|wp_insert_user\s*\(",
        "limit": 30,
    },
    "DASHBOARD_WIDGET_REGISTRATION": {
        "group": "group-ac",
        "patterns": [
            r"wp_add_dashboard_widget\s*\(",
        ],
    },
    "NOPRIV_CONTENT_DELETES": {
        "group": "group-b",
        "patterns": [
            r"wp_delete_post\s*\(",
            r"wp_trash_post\s*\(",
            r"wp_delete_attachment\s*\(",
            r"wp_delete_comment\s*\(",
            r"wp_trash_comment\s*\(",
            r"wp_delete_term\s*\(",
            r"wp_delete_user\s*\(",
            r"\$wpdb->delete\s*\(",
            r"->\s*(?:delete|remove|destroy|purge)\w*\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "NOPRIV_CONTENT_WRITES": {
        "group": "group-b",
        "patterns": [
            r"wp_update_post\s*\(",
            r"wp_insert_post\s*\(",
            r"wp_publish_post\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "NOPRIV_COMMENT_WRITES": {
        "group": "group-ac",
        "patterns": [
            r"wp_insert_comment\s*\(",
            r"wp_update_comment\s*\(",
            r"wp_new_comment\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "NOPRIV_COMMENT_READS": {
        "group": "group-ac",
        "patterns": [
            r"get_comments\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "NOPRIV_TERM_WRITES": {
        "group": "group-b",
        "patterns": [
            r"wp_set_object_terms\s*\(",
            r"wp_update_term\s*\(",
            r"wp_insert_term\s*\(",
            r"wp_set_post_terms\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "NOPRIV_THUMBNAIL_WRITES": {
        "group": "group-b",
        "patterns": [
            r"set_post_thumbnail\s*\(",
            r"delete_post_thumbnail\s*\(",
            r"update_post_meta\s*\(.*_thumbnail_id",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_|wp_ajax_",
    },
    # File-write sinks in a file that also registers an authenticated-only
    # (non-nopriv) wp_ajax_ hook. A capability check alone does not stop CSRF —
    # session auth rides straight through current_user_can(). Manual triage:
    # confirm no wp_verify_nonce()/check_ajax_referer()/check_admin_referer()
    # guards the sink. Signal, not proof — see CVE-2026-11784 (Optimole).
    "AJAX_AUTHENTICATED_FILE_WRITE_SIGNAL": {
        "group": "group-ac",
        "patterns": [
            r"move_uploaded_file\s*\(",
            r"file_put_contents\s*\(",
            r"(?<!->)(?<!::)\bcopy\s*\(",
            r"(?<!->)(?<!::)\brename\s*\(",
            r"wp_handle_upload\s*\(",
        ],
        "cross_file_filter": r"add_action\(\s*['\"]wp_ajax_(?!nopriv_)\w+",
        "limit": 30,
    },
    # ---- Plugin/Theme Installation or Activation (Missing Authorization -> RCE) ----
    # Complement group-a PLUGIN_ACTIVATION_CALLS (activate_plugin/deactivate_plugins)
    # and REST_RETURN_TRUE_PLUGIN_INSTALL; cover the install/activate sinks/contexts
    # those miss. CVE-2024-9234 (GutenKit), CVE-2024-9707 (Hunk Companion),
    # CVE-2025-1562 (FunnelKit), CVE-2025-8418 (B Slider), CVE-2025-64374 (Motors),
    # CVE-2025-25101 (Munk Sites), CVE-2023-22699 (MainWP Wordfence Extension).
    # Sink catalog: WP-API install/activate + TGMPA. Verified shapes: OCDI
    # PluginInstaller.php uses `new \Plugin_Upgrader(...)` then `->install($source)`
    # (note the namespace backslash), and `activate_plugin()` (already in group-a).
    "PLUGIN_THEME_INSTALL_SINKS": {
        "group": "group-b",
        "patterns": [
            r"\bactivate_plugins\s*\(",
            r"\bswitch_theme\s*\(",
            r"new\s+\\?Plugin_Upgrader\b",
            r"new\s+\\?Theme_Upgrader\b",
            r"new\s+\\?WP_Upgrader\b",
            r"->install\s*\(",
            r"do_plugin_install\s*\(",
            r"new\s+\\?TGM_Plugin_Activation\b",
        ],
        "exclude_patterns": [
            r"->install_dependencies",
            r"function\s+install\s*\(",
        ],
        "limit": 50,
    },
    # Manual install: download_url + unzip_file into the plugins/themes directory
    # (no Plugin_Upgrader). The actual sink in CVE-2024-9234 (GutenKit):
    # `unzip_file($tmp, WP_PLUGIN_DIR)`. cross_file_filter confirms a plugin/theme dir.
    "MANUAL_PLUGIN_THEME_INSTALL": {
        "group": "group-b",
        "patterns": [
            r"\bunzip_file\s*\(",
        ],
        "cross_file_filter": r"WP_PLUGIN_DIR|get_theme_root|WP_CONTENT_DIR|wp-content/(?:plugins|themes)",
        "limit": 30,
    },
    # Entry-point half: hook/route registrations whose action/route name implies
    # install or activate. Pair with the sink sections to confirm the chain.
    # wp_ajax_ocdi_install_plugin (OCDI), REST 'install-active-plugin' (GutenKit),
    # REST 'plugin/install_and_activate' (FunnelKit, CVE-2025-1562).
    "INSTALL_ACTIVATE_HANDLER_REGISTRATION": {
        "group": "group-b",
        "patterns": [
            r"add_action\s*\(\s*['\"]wp_ajax_(?:nopriv_)?[^'\"]*(?:install|activate|switch_theme|add[_-]?on)[^'\"]*['\"]",
            r"add_action\s*\(\s*['\"]admin_post_(?:nopriv_)?[^'\"]*(?:install|activate)[^'\"]*['\"]",
            r"register_rest_route\s*\([^)]*(?:install|activate|addon|plugin|theme)",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    # Install/activate sinks in a file that ALSO registers an unauthenticated entry
    # point (nopriv AJAX/admin_post, or REST permission_callback => __return_true).
    # Highest-priority class. CVE-2024-9234 (GutenKit), CVE-2024-9707 (Hunk Companion),
    # CVE-2025-1562 (FunnelKit unauth REST).
    "NOPRIV_PLUGIN_THEME_INSTALL": {
        "group": "group-b",
        "patterns": [
            r"\bactivate_plugin\s*\(",
            r"\bactivate_plugins\s*\(",
            r"\bswitch_theme\s*\(",
            r"new\s+\\?Plugin_Upgrader\b",
            r"new\s+\\?Theme_Upgrader\b",
            r"->install\s*\(",
            r"\bunzip_file\s*\(",
            r"do_plugin_install\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_|__return_true",
        "limit": 30,
    },
    # Install/activate sink + nonce verification present BUT no install/activate
    # capability check on the same line. Encodes the key insight: a nonce is NOT
    # authorization. CVE-2025-64374 (Motors: nonce, no cap, Subscriber-reachable
    # nonce), CVE-2025-1562 (FunnelKit: custom nonce-hash replaced the cap check).
    "PLUGIN_INSTALL_NONCE_WITHOUT_CAP": {
        "group": "group-b",
        "patterns": [
            r"\bactivate_plugin\s*\(",
            r"\bactivate_plugins\s*\(",
            r"\bswitch_theme\s*\(",
            r"new\s+\\?Plugin_Upgrader\b",
            r"new\s+\\?Theme_Upgrader\b",
            r"->install\s*\(",
            r"\bunzip_file\s*\(",
        ],
        "cross_file_filter": r"wp_verify_nonce|check_ajax_referer|check_admin_referer",
        "exclude_patterns": [
            r"current_user_can\s*\(\s*['\"](?:install_plugins|activate_plugins|install_themes|switch_themes|update_plugins|update_themes)['\"]",
        ],
        "limit": 30,
    },
    "WPDB_DIRECT_POST_TABLE_WRITES": {
        "group": "group-b",
        "patterns": [
            r"\$wpdb->update\s*\(\s*\$wpdb->(?:prefix\s*\.\s*['\"])?posts\b",
            r"\$wpdb->update\s*\(\s*['\"].*posts['\"]",
            r"\$wpdb->insert\s*\(\s*\$wpdb->(?:prefix\s*\.\s*['\"])?postmeta\b",
            r"\$wpdb->insert\s*\(\s*['\"].*postmeta['\"]",
            r"\$wpdb->update\s*\(\s*\$wpdb->(?:prefix\s*\.\s*['\"])?postmeta\b",
            r"\$wpdb->update\s*\(\s*['\"].*postmeta['\"]",
        ],
        "cross_file_filter": r"wp_ajax_|admin_post_|register_rest_route|add_action.*init|add_shortcode",
    },
    "WP_INSERT_POST_DATA_FILTER": {
        "group": "group-b",
        "patterns": [
            r"add_filter\s*\(\s*['\"]wp_insert_post_data['\"]",
            r"add_filter\s*\(\s*['\"]content_save_pre['\"]",
            r"add_filter\s*\(\s*['\"]title_save_pre['\"]",
            r"add_filter\s*\(\s*['\"]excerpt_save_pre['\"]",
        ],
        "limit": 30,
    },
    "FRONTEND_FORM_POST_UPDATE": {
        "group": "group-b",
        "patterns": [
            r"\$_(POST|GET|REQUEST)\s*\[\s*['\"](?:post_id|postid|post_ID|entry_id|page_id|content_id)['\"]",
        ],
        "cross_file_filter": r"wp_update_post\s*\(|wp_insert_post\s*\(",
    },
    "KSES_REMOVAL_CONTENT_WRITE": {
        "group": "group-b",
        "patterns": [
            r"kses_remove_filters\s*\(",
            r"remove_filter\s*\(\s*['\"]content_save_pre['\"]",
            r"remove_all_filters\s*\(\s*['\"]content_save_pre['\"]",
        ],
        "cross_file_filter": r"wp_insert_post\s*\(|wp_update_post\s*\(",
        "limit": 20,
    },
    "INIT_HOOK_STATE_CHANGES": {
        "group": "group-b",
        "patterns": [
            r"update_option\(",
            r"delete_option\(",
            r"wp_update_user\s*\(",
            r"wp_set_auth_cookie\s*\(",
            r"wp_insert_post\s*\(",
            r"wp_update_post\s*\(",
            r"wp_delete_post\s*\(",
            r"wp_delete_attachment\s*\(",
            r"wp_delete_comment\s*\(",
            r"wp_trash_comment\s*\(",
            r"wp_insert_comment\s*\(",
            r"wp_update_comment\s*\(",
            r"wp_delete_term\s*\(",
            r"wp_delete_user\s*\(",
            r"wp_set_object_terms\s*\(",
            r"set_post_thumbnail\s*\(",
            r"\$wpdb->(?:insert|update|delete|replace)\s*\(",
            r"wp_set_password\s*\(",
            r"update_user_meta\s*\(",
        ],
        "cross_file_filter": r"add_action\s*\(\s*['\"](?:init|wp_loaded|template_redirect|parse_request)['\"]",
    },
    # Raw superglobal reads in a file that also registers a handler on a
    # pre-authentication hook (init/wp_loaded/template_redirect/parse_request).
    # These hooks fire on every request before auth_redirect() — a request-
    # parameter isset()/equality check here is a ROUTING condition, not an
    # identity check. Mirrors ADMIN_INIT_SUPERGLOBAL_READS for the plain
    # `init`-family hooks, which had no equivalent broad lead before this.
    "INIT_HOOK_SUPERGLOBAL_READS": {
        "group": "group-ac",
        "patterns": [
            r"isset\s*\(\s*\$_GET\[",
            r"isset\s*\(\s*\$_POST\[",
            r"isset\s*\(\s*\$_REQUEST\[",
        ],
        "cross_file_filter": r"add_action\s*\(\s*['\"](?:init|wp_loaded|template_redirect|parse_request)['\"]",
        "limit": 40,
    },
    "SHORTCODE_PRIVILEGED_OPERATIONS": {
        "group": "group-b",
        "patterns": [
            r"wp_insert_post\s*\(",
            r"wp_update_post\s*\(",
            r"update_option\s*\(",
            r"wp_update_user\s*\(",
            r"wp_mail\s*\(",
            r"wp_remote_post\s*\(",
            r"wp_delete_post\s*\(",
            r"wp_delete_attachment\s*\(",
            r"wp_delete_comment\s*\(",
            r"wp_update_comment\s*\(",
            r"wp_delete_term\s*\(",
            r"wp_set_object_terms\s*\(",
            r"wp_delete_user\s*\(",
            r"\$wpdb->(?:insert|update|delete)\s*\(",
            r"wp_set_auth_cookie\s*\(",
        ],
        "cross_file_filter": r"add_shortcode\s*\(",
    },
    "OPTION_TRANSIENT_WRITES": {
        "group": "group-b",
        "patterns": [
            r"set_site_transient|set_transient"
        ],
    },
    "MASS_ASSIGNMENT": {
        "group": "group-b",
        "patterns": [
            r"array_merge.*\$_POST|array_merge.*\$_REQUEST",
            r"\$from_data = \$_POST|\$data = \$_POST|\$settings = \$_REQUEST",
        ],
    },
    "EXTRACT_INTO_OPTION_WRITE": {
        "group": "group-b",
        "patterns": [
            r"extract\s*\(",
        ],
        "cross_file_filter": r"update_option\(|add_option\(|update_post_meta\(|update_user_meta\(",
    },
    "OPTION_UPDATE_HOOKS": {
        "group": "group-b",
        "patterns": [
            r"add_action.*update_option_|add_action.*updated_option"
        ],
    },
    "CSRF_STATE_CHANGES": {
        "group": "group-ac",
        "patterns": [
            r"wp_redirect|wpdb->delete|wpdb->update|wpdb->insert|wp_delete_post|wp_delete_comment|wp_delete_term|wp_delete_user|wp_delete_attachment|delete_site_option|update_site_option|delete_option|update_option|wp_insert_post|wp_publish_post|wp_trash_post|wp_insert_comment|wp_update_comment|wp_new_comment|wp_trash_comment|wp_set_object_terms|wp_set_post_terms|set_post_thumbnail|delete_post_thumbnail"
        ],
        "exclude_patterns": [
            r"check_admin_referer|wp_verify_nonce|check_ajax_referer"
        ],
    },
    # CWE-266/862: custom AJAX router/dispatcher base classes that name a
    # getter method returning an opt-in allow-list of action names exempt
    # from (or requiring) nonce verification — e.g. getNoncedMethods(),
    # getFrontMethods(), getPublicMethods(). A plugin implementing this
    # architecture is worth checking for a default-deny current_user_can()
    # fallback covering actions NOT in the list; many such dispatchers only
    # gate the nonce this way and never require any capability by default.
    "AJAX_ROUTER_NONCE_ALLOWLIST_METHODS": {
        "group": "group-ac",
        "patterns": [
            r"function\s+get\w*(?:Not)?Nonced\w*Methods?\s*\(",
            r"function\s+get\w*(?:Front|Public|Unprotected|Allowed|Whitelisted)\w*Methods?\s*\(",
            r"in_array\s*\(\s*\$\w*action\w*\s*,\s*\$\w*(?:nonced?|whitelist|allowed|public|front)\w*\s*\)",
        ],
        "cross_file_filter": r"check_ajax_referer\(|wp_verify_nonce\(",
        "limit": 30,
    },
    # CWE-862/CWE-266: a handler assigns the result of a same-class self::/
    # static:: delegate call, or an instance method call on a helper/provider
    # object, to a variable — in a file that also verifies a nonce somewhere.
    # This is the "delegated-dispatch" shape: the handler never performs the
    # privileged action inline (an outbound API request, a DB introspection
    # query, a config toggle) — it hands off to a helper one call away, then
    # (typically) streams the result back via wp_send_json*(). A nonce proves
    # request intent, not the caller's privilege level; this is a coarse,
    # file-level lead — confirm manually that no current_user_can() (or an
    # equivalent capability wrapper) gates the delegate before reporting.
    # CVE-2025-54049 (Custom API for WP <= 4.2.2 — five wp_ajax_ handlers
    # checked only a nonce, letting Subscriber+ trigger admin-configured
    # external API calls, toggle API endpoints, and enumerate arbitrary DB
    # table columns via self::/instance delegate calls).
    "AJAX_HOOK_NONCE_ONLY_NO_CAPABILITY": {
        "group": "group-ac",
        "patterns": [
            r"\$\w+\s*=\s*self::\w+\s*\(",
            r"\$\w+\s*=\s*static::\w+\s*\(",
            r"\$\w+\s*=\s*\$\w+->\w+\s*\(",
        ],
        "cross_file_filter": r"check_ajax_referer\s*\(|wp_verify_nonce\s*\(",
        "exclude_patterns": [
            r"current_user_can\s*\(",
            r"\$wpdb\s*->\s*(?:get_results|get_row|get_var|get_col)\s*\(",
        ],
        "limit": 40,
    },
    # CWE-862/CWE-287: a file-download response (Content-Disposition:
    # attachment) in a file that also performs a nonce check — the download-
    # export sibling of AJAX_HOOK_NONCE_ONLY_NO_CAPABILITY above. A nonce alone
    # confirms CSRF origin, not the caller's authentication state; confirm no
    # current_user_can()/is_user_logged_in() gates the exporting function
    # before it is reachable pre-auth (directly on init/wp_loaded, or via a
    # custom do_action()-based dispatcher keyed off a request parameter and an
    # in_array() allow-list). See CVE-2019-17574 in VARIANT-PROVENANCE.md.
    "NONCE_ONLY_FILE_EXPORT_NO_CAPABILITY": {
        "group": "group-ac",
        "patterns": [
            r"Content-Disposition.*attachment",
        ],
        "cross_file_filter": r"wp_verify_nonce\s*\(|check_ajax_referer\s*\(|check_admin_referer\s*\(",
        "exclude_patterns": [
            r"current_user_can\s*\(",
            r"is_user_logged_in\s*\(",
        ],
        "limit": 30,
    },
    # CWE-862/CWE-330: a request-supplied value is compared against
    # md5()/sha1()/hash() of a fixed string literal used as a pseudo-nonce.
    # Because the hash input is a literal baked into the plugin's own source,
    # the resulting "token" is identical on every install and requires no
    # site-specific secret to compute — unlike a real nonce created with
    # wp_create_nonce()/verified with wp_verify_nonce(). See CVE-2024-6828
    # (redux-framework) in VARIANT-PROVENANCE.md.
    "HARDCODED_HASH_LITERAL_NONCE": {
        "group": "group-ac",
        "patterns": [
            r"\$_(?:REQUEST|GET|POST|COOKIE)\s*\[[^\]]+\].{0,80}={2,3}\s*(?:md5|sha1|hash)\s*\(\s*['\"]",
            r"(?:md5|sha1|hash)\s*\([^)]*['\"][^)]*\)\s*={2,3}\s*\$_(?:REQUEST|GET|POST|COOKIE)\s*\[",
        ],
        "exclude_patterns": [
            r"wp_verify_nonce|check_ajax_referer|check_admin_referer"
        ],
    },
    # CWE-862/CWE-330: a request-supplied value is checked only for
    # membership in a custom "issued tokens" store (isset()/array_key_exists()
    # against an array/property whose own name identifies it as a nonce/token
    # pool), with no check of which action/user the matched entry was
    # originally issued for. Unlike wp_verify_nonce(), a flat unscoped pool
    # accepts a token minted for any low-risk action to authorize an unrelated
    # sensitive one. See CVE-2024-22144 in VARIANT-PROVENANCE.md.
    "UNSCOPED_NONCE_STORE_LOOKUP": {
        "group": "group-ac",
        "patterns": [
            r"isset\s*\(\s*\$[^()]*?nonce[^()]*?\[\s*\$_(?:REQUEST|GET|POST|COOKIE)\s*\[",
            r"array_key_exists\s*\(\s*\$_(?:REQUEST|GET|POST|COOKIE)\s*\[[^\]]*\]\s*,\s*\$[^()]*?nonce",
        ],
        "case_insensitive": True,
        "limit": 30,
    },
    # CWE-352: a credential/token-style value read straight from $_GET (the
    # shape of an OAuth-style "connection callback" listener invoked on plain
    # page load) in a file that also persists data via update_option/etc.
    # elsewhere. Source-side complement to CSRF_STATE_CHANGES (which flags the
    # sink); this flags the unguarded read that feeds it.
    "GET_ACCESS_TOKEN_PARAM": {
        "group": "group-ac",
        "patterns": [
            r"\$_GET\s*\[\s*['\"][A-Za-z0-9_]*(access_token|oauth_token|auth_token|api_token|refresh_token)[A-Za-z0-9_]*['\"]\s*\]",
        ],
        "cross_file_filter": r"update_option\(|add_option\(|update_site_option\(|set_transient\(|update_user_meta\(|update_post_meta\(",
        "case_insensitive": True,
    },
    # CWE-266: a ternary discloses a secret-like value (auth/api key, token,
    # license/pairing key) in its "not yet connected" branch, gated only by a
    # single connection/pairing-state boolean call with no other check —
    # readable pre-authentication until that state flips true.
    "CONNECTION_STATE_GATED_SECRET_DISCLOSURE": {
        "group": "group-ac",
        "patterns": [
            r"(?:(?<!un)linked|paired|connect(?:ed)?|configur\w*|activat\w*|regist\w*|bound|setup|authoriz\w*|handshake)\w*\s*\([^()]*\)\s*\?\s*(?:''|\"\")\s*:\s*[^;,\n]{0,80}(?:auth_?key|api_?key|secret|license_?key|pairing_?key|pairing_?code|access_?token|auth_?token|secret_?key)",
            r"!\s*[\w:>\-]*(?:(?<!un)linked|paired|connect(?:ed)?|configur\w*|activat\w*|regist\w*|bound|setup|authoriz\w*|handshake)\w*\s*\([^()]*\)\s*\?\s*[^;,\n]{0,80}(?:auth_?key|api_?key|secret|license_?key|pairing_?key|pairing_?code|access_?token|auth_?token|secret_?key)[^;,\n]{0,40}:\s*(?:''|\"\")",
        ],
        "case_insensitive": True,
    },
    "ADMIN_INIT_SUPERGLOBAL_READS": {
        "group": "group-b",
        "patterns": [
            r"isset\s*\(\s*\$_GET\[",
            r"isset\s*\(\s*\$_POST\[",
            r"isset\s*\(\s*\$_REQUEST\[",
        ],
        "cross_file_filter": r"add_action.*admin_init",
        "limit": 40,
    },
    "ADMIN_INIT_STATE_CHANGES": {
        "group": "group-b",
        "patterns": [
            r"update_option\(",
            r"delete_option\(",
            r"wp_update_user\s*\(",
            r"wp_set_auth_cookie\s*\(",
            r"wp_update_post\s*\(",
            r"wp_delete_post\s*\(",
            r"wp_delete_attachment\s*\(",
            r"wp_delete_comment\s*\(",
            r"wp_update_comment\s*\(",
            r"wp_trash_comment\s*\(",
            r"wp_delete_term\s*\(",
            r"wp_delete_user\s*\(",
            r"wp_insert_post\s*\(",
            r"\$wpdb->(?:insert|update|delete)\s*\(",
        ],
        "cross_file_filter": r"add_action\s*\(\s*['\"]admin_init['\"]",
    },
    "SETTINGS_IMPORT_OPTION_WRITE": {
        "group": "group-b",
        "patterns": [
            r"json_decode\s*\(",
            r"simplexml_load_string\s*\(",
            r"simplexml_load_file\s*\(",
        ],
        "cross_file_filter": r"update_option\(|add_option\(",
        "line_filter": r"(?i)import|settings|config|backup|restore|migration|upload|file_get_contents|php://input|get_body",
        "limit": 30,
    },
    "FOREACH_POST_TO_OPTION_WRITE": {
        "group": "group-b",
        "patterns": [
            r"foreach\s*\(\s*\$_(POST|GET|REQUEST)",
            r"foreach\s*\(\s*\$(?:data|settings|options|params|fields|values|input)\s+as",
        ],
        "cross_file_filter": r"update_option\(|add_option\(|update_site_option\(",
        "limit": 30,
    },
    "CRITICAL_OPTION_VALUE_WRITE": {
        "group": "group-b",
        "patterns": [
            r"update_option\s*\(\s*['\"](?:users_can_register|default_role|siteurl|home|admin_email|active_plugins|template|stylesheet|wp_user_roles)['\"]",
        ],
        "exclude_patterns": [
            r"update_option\s*\(\s*['\"][^'\"]+['\"],\s*(?:0|1|'0'|'1'|true|false|null)\s*[,\)]",
        ],
        "limit": 20,
    },
    "DELETE_OPTION_ADD_OPTION_PAIR": {
        "group": "group-b",
        "patterns": [
            r"delete_option\s*\(",
        ],
        "cross_file_filter": r"add_option\(",
        "line_filter": r"\$",
        "limit": 30,
    },
    "ADMIN_INIT_USERINPUT_OPTION_WRITE": {
        "group": "group-b",
        "patterns": [
            r"update_option\s*\(.*\$_(POST|GET|REQUEST)",
            r"add_option\s*\(.*\$_(POST|GET|REQUEST)",
            r"delete_option\s*\(.*\$_(POST|GET|REQUEST)",
            # set_theme_mod persists into the 'theme_mods_<stylesheet>' option
            # the same way update_option does — a common sink in setup-wizard/
            # customizer-import flows that a plain update_option grep misses.
            r"set_theme_mod\s*\(.*\$_(POST|GET|REQUEST)",
        ],
        "cross_file_filter": r"add_action\s*\(\s*['\"]admin_init['\"]",
        "limit": 30,
    },
    # A $wpdb->query() executes a raw DROP TABLE / TRUNCATE TABLE, or an
    # unconditional DELETE FROM with no WHERE clause, against a table name
    # that is a loop/enumeration variable rather than a single hardcoded
    # identifier — a mass, cross-table destructive operation. Distinct from
    # DDL_TABLE_STATEMENT_RAW_VAR_INTERP (group-sqli), which flags SQL
    # injection via an attacker-tainted identifier; this section instead
    # flags the missing-authorization question — is there a
    # current_user_can()/nonce check anywhere before this runs? See
    # CVE-2020-7048 in VARIANT-PROVENANCE.md.
    "MASS_WPDB_TABLE_DROP_TRUNCATE": {
        "group": "group-ac",
        "patterns": [
            r"\$wpdb->query\s*\(\s*[\"'].*\b(?:DROP|TRUNCATE)\s+TABLE\b",
            r"\$wpdb->query\s*\(\s*[\"']\s*DELETE\s+FROM\s+\{?\$\w+\}?\s*[\"']\s*\)",
        ],
        "case_insensitive": True,
        "limit": 30,
    },
    "BULK_ACTION_HANDLERS": {
        "group": "group-b",
        "patterns": [
            r"add_filter\s*\(\s*['\"]handle_bulk_actions-",
            r"add_filter\s*\(\s*['\"]bulk_actions-",
        ],
    },
    "LOAD_SCREEN_HOOKS": {
        "group": "group-b",
        "patterns": [
            r"add_action\s*\(\s*['\"]load-edit\.php",
            r"add_action\s*\(\s*['\"]load-edit-comments\.php",
            r"add_action\s*\(\s*['\"]load-users\.php",
            r"add_action\s*\(\s*['\"]load-upload\.php",
            r"add_action\s*\(\s*['\"]load-\w+\.php",
        ],
    },
    "ADMIN_ACTION_HOOKS": {
        "group": "group-b",
        "patterns": [
            r"add_action\s*\(\s*['\"]admin_action_",
        ],
    },
    "USER_CONTROLLED_OPTION_KEY": {
        "group": "group-b",
        "patterns": [
            r"(?:update_option|add_option|delete_option)\s*\(\s*\$_(GET|POST|REQUEST)",
            # Bare-variable form: the key was assigned from request input a few
            # lines earlier (e.g. $opt_name = sanitize_text_field($_POST['opt_name']);
            # ... update_option($opt_name, ...);). Broader/leads-only — manual
            # triage confirms the assignment traces back to request input and
            # whether any allow-list (in_array/array_key_exists/isset) gates it.
            r"(?:update_option|add_option|delete_option)\s*\(\s*\$\w+\s*[,\)]",
        ],
    },
    "DEPENDENT_FIELD_CONTEXT_META_KEY": {
        "group": "group-ac",
        "patterns": [
            r"\[\s*['\"]meta_key['\"]\s*\]\s*=\s*\$\w+",
            r"get_(?:post|user)_meta\s*\(\s*\$\w+\s*,\s*\$\w+",
            r"\b(?:reset|current)\s*\(\s*\$(?:context|dependent_\w*|trigger_\w*|watched_\w*|listen\w*)\b",
        ],
    },
    # An ACF-ecosystem hook handler reads the raw '_acf_post_id' request field
    # directly (via acf_maybe_get_POST() or a raw $_POST/$_REQUEST access)
    # instead of the framework-validated acf_get_form_data('post_id'). ACF core
    # exposes '_acf_post_id' as a hidden field so acf/validate_save_post and
    # acf/save_post can resolve the save target (post_N | user_N | term_N |
    # option | ...); a plugin re-reading it raw can be redirected to an
    # arbitrary object (e.g. "user_1") regardless of what the form was
    # rendered for. CVE-2026-8809 (ACF Extended <= 0.9.2.5).
    "ACF_RAW_POST_ID_TRUST": {
        "group": "group-ac",
        "patterns": [
            r"acf_maybe_get_POST\s*\(\s*['\"]_acf_post_id['\"]",
            r"\$_(POST|REQUEST)\s*\[\s*['\"]_acf_post_id['\"]\s*\]",
        ],
    },
    # A foreach loop iterates over a multi-value selector field (list/target/
    # destination) taken from a form or AJAX submission, and the loop body
    # calls a subscribe/add-lead/sync-to-list style integration sink — a
    # shape common in email-marketing and CRM connector plugins. Lead
    # generation; confirm the loop item reaches the sink with no
    # in_array($item, $allowed) membership check against a server-side
    # configured allow-list.
    "FOREACH_SELECTOR_TO_CONNECTION_SINK_NO_ALLOWLIST": {
        "group": "group-ac",
        "patterns": [
            r"foreach\s*\(\s*\$\w*(?:list|target|destination|selector)\w*\s+as\s+\$\w+\s*\)",
        ],
        "cross_file_filter": r"(?i)\w*(?:subscribe|add_lead|add_contact|add_subscriber|add_member|to_connection|to_list|sync_contact)\w*\s*\(",
        "limit": 30,
    },
    # A nonce-only multi-item save loop extracts a resource index from a dynamic
    # $_POST/$_REQUEST field-name key; the index is then used to select which
    # underlying item/page/block the submitted value is written against, without
    # re-verifying the submitter is authorized for that SPECIFIC resource.
    "DYNAMIC_FIELD_INDEX_NO_PER_ITEM_AUTHZ": {
        "group": "group-ac",
        "patterns": [
            r"\(\s*int\s*\)\s*(?:str_replace|substr|preg_replace|str_ireplace)\s*\(",
            r"strpos\s*\(\s*\$\w+\s*,\s*['\"][\w\-]+['\"]\s*\)\s*===\s*0",
        ],
        "cross_file_filter": r"wp_verify_nonce|check_admin_referer",
        "limit": 40,
    },
    "USER_META_WRITES": {
        "group": "group-b",
        "patterns": [r"update_user_meta|delete_user_meta|add_user_meta"],
    },
    # A foreach loop iterates a request/JSON-body-derived array in key=>value
    # form and the file elsewhere writes user meta — the shape behind
    # unauthenticated self-registration/profile handlers that pass the loop
    # KEY straight into update_user_meta()/add_user_meta() as the meta_key
    # argument with no allow-list check on the key itself (CWE-266).
    # CVE-2024-2409 (MasterStudy LMS _register_user()).
    "FOREACH_KEY_TO_USER_META_WRITE": {
        "group": "group-ac",
        "patterns": [
            r"foreach\s*\(\s*\$_(POST|GET|REQUEST)[^)]*\sas\s+\$\w+\s*=>\s*\$\w+",
            r"foreach\s*\(\s*\$(?:data|settings|options|params|fields|values|input|payload|body|decoded)\w*(?:\[[^\]]+\])*\s+as\s+\$\w+\s*=>\s*\$\w+",
            # Profile/registration "change-set" naming variant — the loop
            # array holds request-derived field changes rather than the raw
            # request itself (e.g. $changes/$submitted/$updates built earlier
            # in the same handler from $_POST), and each key is gated only by
            # a denylist-style "is banned/blocked" check before the write, not
            # a positive allow-list (CWE-266/CWE-184). CVE-2023-3460
            # (Ultimate Member <= 2.6.6 update_profile()).
            r"foreach\s*\(\s*\$(?:changes|submitted|updates|updated_\w*|profile_data)\w*(?:\[[^\]]+\])*\s+as\s+\$\w+\s*=>\s*\$\w+",
            # Single-var (non-destructured) foreach over a request-derived
            # key/value-pair array (e.g. a REST "meta_data": [{key,value}, ...]
            # payload) where each item's own 'key' field — not the loop key
            # itself — becomes the meta key argument (CVE-2026-49111 class).
            r"foreach\s*\(\s*\$(?:request|data|payload|body|input|args)\w*(?:\[[^\]]+\])*\s+as\s+\$\w+\s*\)",
            # $user_meta / $profile_meta / $account_meta / $member_meta naming
            # variant — the loop array carries a "*_meta" name but is itself
            # request-derived (e.g. $request->get_param('user_meta')), which
            # none of the above naming heuristics recognize. CVE-2024-9636
            # (Post Grid and Gutenberg Blocks <= 2.3.3).
            r"foreach\s*\(\s*\$(?:user_meta|profile_meta|account_meta|member_meta)\w*(?:\[[^\]]+\])*\s+as\s+\$\w+\s*=>\s*\$\w+",
        ],
        "cross_file_filter": r"\w*update_user_meta\s*\(|\w*add_user_meta\s*\(|update_meta_data\s*\(|add_meta_data\s*\(",
        "limit": 30,
    },
    "SECURITY_GATE_FUNCTIONS": {
        "group": "group-b",
        "patterns": [
            r"decrypt\(|encrypt\(|hmac\(|hash_equals\(|openssl_\w+\(|authenticate\(|check_auth\(|verify_auth\(|validate_token\(|check_signature\(|verify_signature\(|verify_hash\("
        ],
    },
    "AUTH_INTERMEDIARIES": {
        "group": "group-b",
        "patterns": [
            r"api_key|api_token|auth_token|secret_key|license_key|verify_token"
        ],
        "line_filter": r"get_option|update_option|\$_|get_param|header|Authorization|\bdefine\(",
    },
    "TOKEN_AUTH_FLOWS": {
        "group": "group-b",
        "patterns": [
            r"get_user_meta.*token|update_user_meta.*token|get_option.*token|activation_key",
            r"wp_generate_password|wp_hash|md5\(|sha1\(|substr.*time|rand\(",
            r"wp_set_auth_cookie|wp_set_current_user|wp_signon",
        ],
    },
    "TOKEN_LOCALIZE_EXPOSURE": {
        "group": "group-b",
        "patterns": [
            r"wp_localize_script|wp_add_inline_script",
            # Catches the token/secret array-key line directly when it sits on a
            # different physical line than the wp_localize_script(...) call itself
            # (common multi-line data-array literal), which the sink-call pattern
            # above misses since matching is per-line.
            r"(?i)['\"](token|auth_?token|api_?key|secret)['\"]\s*=>",
        ],
        "line_filter": r"(?i)token|auth[Tt]oken|apiKey|api_key|secret",
    },
    # ===== GROUP C (Tier 5-6) =====
    "TIER5_HTML_RENDERERS": {
        "group": "group-c",
        "patterns": [
            r"WriteHTML|loadHTML|dompdf|mpdf|tcpdf|wkhtmlto|headless|puppeteer|phantomjs"
        ],
        "case_insensitive": True,
    },
    "TIER6_UNESCAPED_OUTPUT": {
        "group": "group-c",
        "patterns": [r"\becho\b|\bprint\b|\bprintf\b"],
        "exclude_patterns": [
            r"esc_html|esc_attr|wp_kses|esc_js|esc_url|wp_json_encode",
            # filter_var() with a string-sanitizing filter (strips tags /
            # entity-encodes special chars) is a real neutralizer when it
            # appears inline with the echo, same rationale as the escapers
            # above.
            r"filter_var\([^)]*FILTER_SANITIZE_(STRING|FULL_SPECIAL_CHARS)",
        ],
        "limit": 100,
    },
    "SCRIPT_BLOCK_ECHO": {
        "group": "group-c",
        "patterns": [r"<\?php\s+echo|<\?="],
    },
    "JS_CONTEXT_PHP_ECHO": {
        "group": "group-c",
        # Bare "echo $var;"/"<?= $var ?>" is included in addition to the
        # same-line "<?php echo $var" form to catch the common split-tag
        # style ("<?php" on its own line, "echo $var;" on the next) that the
        # same-line-only patterns miss.
        "patterns": [
            r"<\?php\s+echo\s+\$",
            r"<\?=\s*\$",
            r"^\s*echo\s+\$\w",
            # Wrong-escaper variant: an HTML sanitizer/stripper call (not a
            # bare variable) echoed directly in JS context — these functions
            # have no concept of JS-string/template-literal syntax and do
            # not neutralize a quote/backtick/${...} breakout (confirmed
            # vulnerable pattern: wp_kses() echoed inside an open JS
            # template literal).
            r"<\?php\s+echo\s+(?:wp_kses(?:_post|_data)?|sanitize_text_field|sanitize_textarea_field|wp_strip_all_tags|strip_tags)\s*\(",
            r"^\s*echo\s+(?:wp_kses(?:_post|_data)?|sanitize_text_field|sanitize_textarea_field|wp_strip_all_tags|strip_tags)\s*\(",
        ],
        # Inline event-handler attributes (onclick=, onerror=, etc.) are an
        # equally valid inline-JS context as a <script> block — a raw PHP
        # echo inside one, without esc_js()/wp_json_encode(), is the same
        # sink class (confirmed vulnerable pattern: GiveWP CVE-2026-14987).
        # case_insensitive: web-component/JSX-style custom elements (e.g.
        # SureCart's <sc-switch onClick="...">) use camelCase event-handler
        # attribute names, not lowercase onclick= — confirmed this filter
        # silently gated out both real CVE-2026-57314 sink files entirely
        # (onClick, capital C) before case_insensitive was added.
        "cross_file_filter": r"<script|onclick\s*=|onerror\s*=|onload\s*=|onmouseover\s*=|onfocus\s*=|onmouseout\s*=|onchange\s*=|onsubmit\s*=",
        "case_insensitive": True,
        "exclude_patterns": [r"esc_js\(|wp_json_encode\(|json_encode\(|esc_html\(|esc_attr\(|esc_url\("],
    },
    "ESC_URL_RAW_JS_CONTEXT_ECHO": {
        "group": "group-c",
        # echo esc_url_raw(...) inside a file that also carries an inline-JS
        # context (onclick=, onerror=, <script>, etc.) — esc_url_raw() is a
        # redirect/DB-storage sanitizer, never a display escaper; it does
        # not encode a JS-string-breaking quote at all, so echoing it into
        # any inline-JS sink is unsafe regardless of what else is nearby
        # (confirmed vulnerable pattern: SureCart CVE-2026-57314,
        # add_query_arg() with no base URL reflecting $_SERVER['REQUEST_URI']
        # into onclick="...('<?php echo esc_url_raw(...); ?>')" ).
        #
        # A standalone section rather than an extension of JS_CONTEXT_PHP_ECHO:
        # exclude_patterns there is line-level (whole physical line, not
        # match-position-aware), and SureCart's own vulnerable line packs a
        # SECOND, unrelated, correctly-escaped echo esc_attr(...) onto the
        # same line — which would silently suppress the very CVE line this
        # section exists to catch if it shared that exclude list. No
        # exclude_patterns here: esc_url_raw() is never a safe display
        # escaper in any position on the line, so nothing should suppress it.
        "patterns": [r"echo\s+esc_url_raw\("],
        "cross_file_filter": r"<script|onclick\s*=|onerror\s*=|onload\s*=|onmouseover\s*=|onfocus\s*=|onmouseout\s*=|onchange\s*=|onsubmit\s*=",
        "case_insensitive": True,
    },
    "ESC_URL_RAW_ATTR_CONTEXT_SPLICE": {
        "group": "group-c",
        # sanitize_url()/esc_url_raw() (sanitize_url() is an alias of
        # esc_url_raw() since WP 5.9) used in a file that also builds a
        # single-quoted href=/src= HTML attribute — both functions are
        # redirect/DB-storage sanitizers that skip the 'display'-context
        # step which HTML-entity-encodes a literal single quote, so
        # splicing their result into a single-quoted attribute lets a
        # stray ' terminate it and inject arbitrary attributes. Double-
        # quoted attributes are not exploitable this way (the shared
        # character-class filter strips " unconditionally regardless of
        # context).
        "patterns": [r"\b(?:sanitize_url|esc_url_raw)\s*\("],
        "cross_file_filter": r"href\s*=\\?'|src\s*=\\?'",
    },
    "PARSE_URL_FRAGMENT_UNESCAPED_REASSEMBLY": {
        "group": "group-c",
        # A URL split via wp_parse_url()/parse_url() has its 'fragment'
        # array key reassigned with a literal '#' prefix and no encoding
        # function — code reassembling a parsed URL commonly re-encodes
        # the query string correctly (parse_str()+urlencode_deep()/
        # build_query()) while treating the fragment as a bare structural
        # marker, missing that it is equally attacker-controllable text
        # needing its own encoding step before reaching an href/src sink.
        "patterns": [
            r"\[\s*['\"]fragment['\"]\s*\]\s*=\s*['\"]#['\"]\s*\.",
        ],
        "cross_file_filter": r"wp_parse_url\(|parse_url\(",
    },
    "PLAIN_CONCAT_EVENT_HANDLER_UNESCAPED": {
        "group": "group-c",
        # Plain-PHP-concatenation sibling of JS_CONTEXT_PHP_ECHO: no HTML
        # template, no <?php echo ?> — a bare variable or function-call
        # return value is spliced with `.` directly between the quote
        # delimiters of a JS string nested in a dynamically-built inline
        # event-handler attribute, with no esc_js()/wp_json_encode()/
        # json_encode() wrapping. sanitize_text_field()/esc_attr()/
        # esc_html()/esc_url()/esc_url_raw() do not neutralize a value in
        # this nested context (none strip/encode the quote that delimits
        # the JS string, or the encoding is undone by the browser's
        # attribute-value HTML-entity-decode before JS compilation), so
        # those calls are excluded from matching as the spliced value too
        # (confirmed vulnerable pattern: Booking Calendar CVE-2026-59558).
        "patterns": [
            r"(?<![$\w])on[a-zA-Z]+\s*=\s*\\?[\"][^\"]{0,300}?\\?['\"]\s*\.\s*"
            r"(?!esc_js\s*\(|wp_json_encode\s*\(|json_encode\s*\(|esc_attr\s*\(|esc_html\s*\(|esc_url\s*\(|esc_url_raw\s*\(|sanitize_text_field\s*\(|intval\s*\(|absint\s*\(|floatval\s*\()"
            r"(?:\$[A-Za-z_]\w*(?:->\w+|\[[^\]\n]{0,60}\]|\([^()\n]{0,120}\))*|[A-Za-z_][\w:]*\s*\([^()\n]{0,200}\))"
            r"\s*\.\s*\\?['\"][^\"]{0,300}?\\?[\"]",
        ],
        "case_insensitive": True,
    },
    "THE_AUTHOR_META_OUTPUT": {
        "group": "group-c",
        "patterns": [r"the_author_meta\("],
        "exclude_path_patterns": [r"vendor/", r"freemius/"],
    },
    "STORED_XSS_WRITES": {
        "group": "group-c",
        "patterns": [
            r"update_post_meta|add_post_meta|update_option|update_user_meta|wpdb->insert|wpdb->update|wpdb->query|wpdb->replace",
            # Mass-assignment into a 'meta_input' array element — the shape used by
            # self-registration/profile forms that loop over the whole request body
            # and write each field's raw value under a computed meta key, later
            # consumed by wp_insert_user()/wp_update_user()/wp_insert_post().
            r"\[\s*['\"]meta_input['\"]\s*\]\s*\[",
            # Selectively-sanitized sibling arguments in the same call: one
            # argument is wrapped in a sanitize_*() call while a sibling
            # argument in the SAME call is a raw request superglobal read.
            # Common in custom cache/store/setter methods with a (key, value)
            # signature — e.g. $cache->set(sanitize_text_field($_POST['q']),
            # $_POST['response']) — where the developer sanitized the lookup
            # key but forgot the persisted value (or vice versa). The actual
            # DB write may live inside that method's own body, one call away
            # from this line, so this is a co-location lead, not a confirmed
            # sink match.
            r"->\w+\(\s*sanitize_\w+\([^)]*\$_(?:GET|POST|REQUEST)\[[^\]]*\]\s*\)\s*,\s*\$_(?:GET|POST|REQUEST)\[",
            r"->\w+\(\s*\$_(?:GET|POST|REQUEST)\[[^\]]*\]\s*,\s*sanitize_\w+\([^)]*\$_(?:GET|POST|REQUEST)\[",
            # Constructor-hydrated persistence-record object: new $CLASS(['data' => ...])
            # followed by a parameterless persist call — the idiom used by lightweight
            # custom ORM/Entry/Model base classes that wrap $wpdb instead of calling it
            # directly. The internal write happens in a different file/class, so this
            # constructor call is the visible sink boundary for a line-based scanner.
            r"new\s+\w+\(\s*\[\s*['\"]data['\"]\s*=>",
        ],
    },
    "COMMENT_WRITE_KSES_BYPASS_SINKS": {
        "group": "group-c",
        "patterns": [
            r"wp_insert_comment\s*\(",
            r"wp_update_comment\s*\(",
        ],
    },
    "NONCE_RENDER_CONTEXT": {
        "group": "group-c",
        "patterns": [r"wp_localize_script|wp_add_inline_script"],
        "line_filter": r"(?i)nonce",
    },
    "SAVE_POST_HOOKS": {
        "group": "group-c",
        "patterns": [r"add_action.*save_post"],
    },
    "STORED_XSS_READS": {
        "group": "group-c",
        "patterns": [
            r"get_post_meta|get_option|get_user_meta|get_term_meta|get_the_author_meta"
        ],
        "exclude_patterns": [
            r"esc_html|esc_attr|esc_textarea|esc_url|intval|absint|wp_kses"
        ],
    },
    "POST_META_NO_SANITIZE_CALLBACK": {
        "group": "group-c",
        "patterns": [r"register_post_meta\("],
        "cross_file_filter": r"show_in_rest",
    },
    "SANITIZER_KEY_ALLOWLIST_BYPASS": {
        "group": "group-c",
        "patterns": [
            r"\$\w*(skip|exempt|bypass|excluded?)\w*(keys|fields|params|list)\w*\s*=\s*array\(",
            r"\$\w*(skip|exempt|bypass|excluded?)\w*(keys|fields|params|list)\w*\s*=\s*\[",
        ],
        "cross_file_filter": r"in_array\(",
    },
    "IS_STRING_ONLY_SANITIZER_ARRAY_BYPASS": {
        "group": "group-c",
        "patterns": [
            r"if\s*\(\s*is_string\s*\(\s*\$\w+\s*\)\s*\)",
        ],
        # Same-file proximity check: a foreach loop feeding an is_string() gate
        # that itself guards a sanitizer call, within roughly one loop body's
        # worth of text. Cannot detect the absent is_array() sibling branch —
        # a line-based scanner sees an identical gate line before and after the
        # fix — so every hit needs the elseif/is_array() check read manually.
        "cross_file_filter": r"foreach\s*\([\s\S]{0,150}?is_string\s*\([\s\S]{0,150}?(sanitize_text_field|sanitize_textarea_field|esc_html|esc_attr|wp_kses|strip_tags|htmlspecialchars|htmlentities)\s*\(",
        "limit": 40,
    },
    "IS_ARRAY_ONLY_SANITIZER_SCALAR_BYPASS": {
        "group": "group-c",
        "patterns": [
            r"if\s*\(\s*is_array\s*\(\s*\$\w+\s*\)",
        ],
        # Mirror image of IS_STRING_ONLY_SANITIZER_ARRAY_BYPASS: here the
        # ARRAY-shaped input is the one that gets sanitized (typically a
        # nested sub-key, e.g. a paired 'date'/'time' field), and the
        # unsanitized side is the accompanying else/scalar branch — a caller
        # who submits the field as a plain scalar instead of the expected
        # array bypasses the array-only sanitization. Same-file proximity
        # check only: a sanitizer call sits near the is_array() gate within
        # roughly one branch's worth of text. Cannot detect the absent
        # sanitizer in the else branch itself — a line-based scanner sees an
        # identical gate line before and after the fix — so every hit needs
        # the else branch read manually to confirm it doesn't independently
        # sanitize (e.g. via an is_scalar($X) ? sanitizer($X) : '' ternary).
        "cross_file_filter": r"is_array\s*\([\s\S]{0,300}?(sanitize_text_field|sanitize_textarea_field|esc_html|esc_attr|wp_kses|strip_tags|htmlspecialchars|htmlentities)\s*\(",
        "limit": 40,
    },
    "RECURSIVE_SANITIZER_UNSANITIZED_KEYS": {
        "group": "group-c",
        "case_insensitive": True,
        "patterns": [
            r"foreach\s*\(\s*\$\w+\s+as\s+\$\w+\s*=>\s*&?\$\w+\s*\)",
        ],
        # Same-file proximity check: a foreach loop destructuring both key and
        # value, feeding a sanitizer call (a named WP sanitizer, or a
        # same-named recursive self-call — custom recursive sanitizer helpers
        # commonly call themselves on the value) within roughly one loop
        # body's worth of text. Cannot detect whether the key is ALSO
        # sanitized elsewhere in the same loop before being used to
        # rebuild/index the returned array — a line-based scanner sees an
        # identical foreach/sanitizer pairing before and after the fix — so
        # every hit needs the key-sanitization line read manually.
        "cross_file_filter": r"foreach\s*\(\s*\$\w+\s+as\s+\$\w+\s*=>\s*&?\$\w+\s*\)[\s\S]{0,200}?([a-z0-9_]*saniti[sz]e[a-z0-9_]*\s*\(|wp_kses_post\(|wp_kses\(|esc_html\(|esc_attr\(|strip_tags\()",
        "limit": 40,
    },
    "META_BOX_REGISTRATIONS": {
        "group": "group-c",
        "patterns": [r"add_meta_box|add_meta_boxes"],
    },
    "POST_INSERT_UPDATE": {
        "group": "group-c",
        "patterns": [r"wp_insert_post|wp_update_post"],
    },
    "CUSTOM_VALUE_GETTERS": {
        "group": "group-c",
        "patterns": [
            r"->getValue\(\)|->renderValue\(\)|->render_value\(\)|->get_value\(\)"
        ],
    },
    "JOOMLA_STYLE_REQUEST_GETTER": {
        "group": "group-c",
        "patterns": [
            r"->getString\(|::getString\(|->getVar\(|::getVar\(",
        ],
    },
    "LIST_TABLE_COLUMNS": {
        "group": "group-c",
        "patterns": [
            r"manage_.*_columns|column_default",
            # Confirmed CVE fix shape: a column_* method's return/echo statement
            # carries a raw per-row array value straight out with no escaping —
            # the list-table rendering machinery echoes whatever this returns.
            r"(?:return|echo)\s+\$\w+\[[^\]]+\][^;]{0,60};",
        ],
        "exclude_patterns": [
            r"esc_html|esc_attr|wp_kses|htmlspecialchars|htmlentities|wp_strip_all_tags"
        ],
    },
    # Confirmed CVE fix shape variant of LIST_TABLE_COLUMNS: the per-row array
    # field is copied to a local variable one statement earlier, then that
    # variable alone (not an inline array index) is what the return/echo
    # carries unescaped — kept as its own section (rather than folded into
    # LIST_TABLE_COLUMNS) because the scanner matches one line at a time and
    # a bare "return $var;"/"echo $var;" is too generic to gate on a per-line
    # basis without the file-level cross_file_filter narrowing it to files
    # that actually look like a column/record value-getter.
    "COLUMN_VALUE_GETTER_BARE_RETURN": {
        "group": "group-c",
        "patterns": [
            r"(?:return|echo)\s+\$\w+\s*;",
        ],
        "cross_file_filter": r"class\s+\w*Column\w*\b|function\s+get_value\s*\(|function\s+get_column_value\s*\(|function\s+render_column\s*\(",
        "exclude_patterns": [
            r"esc_html|esc_attr|wp_kses|htmlspecialchars|htmlentities|wp_strip_all_tags"
        ],
        "limit": 40,
    },
    "KSES_ECHO_PATTERNS": {
        "group": "group-c",
        "patterns": [r"echo wp_kses|echo wp_kses_post"],
    },
    "TITLE_OUTPUT": {
        "group": "group-c",
        "patterns": [r"get_the_title|the_title|apply_filters.*'the_title'"],
    },
    # A WP core accessor with a boolean escape argument (default true) called
    # with escaping explicitly disabled, returning the raw request-derived
    # value for the caller to re-escape manually before any HTML/title output.
    "SEARCH_QUERY_ESCAPE_DISABLED": {
        "group": "group-c",
        "patterns": [r"get_search_query\s*\(\s*(?:false|0)\s*\)"],
        "exclude_patterns": [r"esc_html|esc_attr|wp_kses|htmlspecialchars|htmlentities"],
        "limit": 30,
    },
    "DATE_FORMAT_UNESCAPED": {
        "group": "group-c",
        "patterns": [r"get_the_modified_time\b|get_the_time\b"],
        "exclude_patterns": [r"esc_html|esc_attr|wp_kses"],
    },
    "SHORTCODE_IMPLODE_SEPARATOR": {
        "group": "group-c",
        "patterns": [r"implode\(\s*\$|join\(\s*\$"],
        "cross_file_filter": r"add_shortcode",
    },
    "CUSTOM_LIST_WALKER_CLASSES": {
        "group": "group-c",
        "patterns": [r"class\s+\S+\s+extends\s+Walker(_\w+)?\b"],
    },
    "BLOCK_ATTRIBUTE_OUTPUT": {
        "group": "group-c",
        # Block/shortcode attrs ($attributes[...]/$atts[...]) plus the same
        # shape for widget instance settings and module/form-field settings
        # arrays ($instance[...]/$field[...]) — a settings-array value used
        # unescaped on the same line (e.g. interpolated into an HTML-building
        # sprintf()/concat), regardless of which of these WP-idiomatic names
        # the array is bound to.
        "patterns": [r"\$attributes\[.*\]|\$atts\[.*\]|\$instance\[.*\]|\$field\[.*\]"],
        "exclude_patterns": [
            r"esc_html|esc_attr|wp_kses|intval|absint|esc_url"
        ],
    },
    "BLOCK_ATTRIBUTE_TAG_NAME_SINK": {
        "group": "group-c",
        "patterns": [
            r"<\s*<\?php\s+echo\s+esc_attr",
            r"<\s*<\?=\s*esc_attr",
            r"'</?'\s*\.\s*\$",
            r'"</?"\s*\.\s*\$',
            r"\$attributes\[.*[Tt]ag.*\]|\$attributes\[.*[Ee]lement.*\]|\$attributes\[.*[Hh]eading.*\]|\$attributes\[.*[Ww]rapper.*\]",
        ],
        "cross_file_filter": r"register_block_type|render_callback|\$attributes",
    },
    "TEMPLATE_UNESCAPED_META": {
        "group": "group-c",
        "patterns": [r"echo \$"],
        "glob_override": "src/views/**/*.php,templates/**/*.php,views/**/*.php,partials/**/*.php,blocks/**/*.php",
        "exclude_patterns": [
            r"esc_html|esc_attr|esc_url|esc_js|wp_kses|esc_textarea|wp_json_encode"
        ],
    },
    "JS_DATASET_READS": {
        "group": "group-c",
        "patterns": [r"dataset\.\w+"],
        "glob_override": "build/**/*.js,src/**/*.js,assets/frontend/**/*.js,frontend/**/*.js",
    },
    "ADD_QUERY_ARG_ECHO": {
        "group": "group-c",
        "patterns": [r"add_query_arg\("],
        "exclude_patterns": [r"esc_url\(|esc_url_raw\("],
    },
    "AJAX_ECHO_WP_DIE": {
        "group": "group-c",
        "patterns": [r"echo\b.*\bwp_die\b|echo\b.*\bdie\b|echo\b.*\bexit\b"],
        "cross_file_filter": r"wp_ajax_",
        "exclude_patterns": [r"wp_send_json|application/json|Content-Type"],
    },
    "SERVER_SELF_URI_OUTPUT": {
        "group": "group-c",
        "patterns": [
            r"\$_SERVER\['REQUEST_URI'\]|\$_SERVER\[\"REQUEST_URI\"\]",
            r"\$_SERVER\['PHP_SELF'\]|\$_SERVER\[\"PHP_SELF\"\]",
            r"\$_SERVER\['SCRIPT_NAME'\]|\$_SERVER\[\"SCRIPT_NAME\"\]",
        ],
        "exclude_patterns": [r"esc_url\(|esc_attr\(|esc_html\(|wp_unslash.*esc_|htmlspecialchars\("],
    },
    # A length-only check (strlen(...) == N) is a shape/format gate, not a
    # character-class allowlist or an output escape — HTML/JS-breaking bytes
    # of the correct length still pass. Flags candidate "looks validated but
    # isn't" request values for manual forward-tracing to their output sink.
    "LENGTH_ONLY_REQUEST_VALIDATION": {
        "group": "group-c",
        "patterns": [
            r"\w*strlen\(\s*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*\)\s*==\s*\d+",
        ],
    },
    "DO_SHORTCODE_USER_INPUT": {
        "group": "group-c",
        "patterns": [r"do_shortcode\(", r"apply_shortcodes\("],
        # $message/$value/$data/$string added (CVE-2025-69001, fluentform 6.1.11):
        # merge-tag/smart-tag templating helpers commonly assign their
        # interpolated-with-submitted-data result to one of these names right
        # before the do_shortcode() call, one hop past the request superglobal.
        # \$\w+\[['"]\w+['"]\] added (CVE-2026-11778, woo-multi-currency 2.2.14):
        # a foreach loop's item variable (any name, not just $ex) subscripted
        # with a string key ($item['field']) and interpolated straight into the
        # shortcode-expression string — the array itself was wc_clean()'d/
        # sanitize_text_field()'d one hop earlier (bracket syntax survives both),
        # so neither the request superglobal nor a generic holder name from the
        # list above appears on the do_shortcode() line itself.
        "line_filter": r"\$_GET|\$_POST|\$_REQUEST|\$content|\$input|\$body|\$text|\$html|\$message|\$value|\$data|\$string|\$\w+\[['\"]\w+['\"]\]",
    },
    # Second-order ASE: DB-stored content rendered via do_shortcode().
    # Exploitable when the write path is accessible to low-privilege users.
    "DO_SHORTCODE_DB_CONTENT": {
        "group": "group-c",
        "patterns": [
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*get_option\s*\(",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*get_post_meta\s*\(",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*get_user_meta\s*\(",
            r"(?:do_shortcode|apply_shortcodes)\s*\(\s*get_transient\s*\(",
        ],
    },
    "KSES_ALLOWED_EVENT_HANDLERS": {
        "group": "group-c",
        "patterns": [
            r"'onclick'|\"onclick\"|'onerror'|\"onerror\"|'onload'|\"onload\"|'onmouseover'|\"onmouseover\"|'onfocus'|\"onfocus\"|'onmouseout'|\"onmouseout\"|'onchange'|\"onchange\"|'onsubmit'|\"onsubmit\"|'onkeyup'|\"onkeyup\"|'onkeydown'|\"onkeydown\"",
        ],
        "cross_file_filter": r"wp_kses|allowed_html",
    },
    "INLINE_STYLE_META_SINK": {
        "group": "group-c",
        "patterns": [r"wp_add_inline_style\("],
        "exclude_patterns": [r"esc_attr\(|esc_html\(|sanitize_hex_color\(|safecss_filter_attr\("],
    },
    "COLOR_SETTING_UNSANITIZED_RETURN": {
        "group": "group-c",
        # A color-named property/array-key read with only a `?? $default`
        # null-coalesce guard — no hex-color/CSS-safe sanitizer on the line.
        # This is the source-side counterpart of INLINE_STYLE_META_SINK /
        # STYLE_TAG_RAW_CONCAT: a getter or DTO-hydration line that later
        # feeds an inline-CSS sink several call frames away, where the value
        # is a stored/request-derived "color" setting rather than a request
        # superglobal a normal taint rule would flag.
        "patterns": [
            r"->\w*[Cc]olou?r\b\s*\?\?",
            r"\[['\"]\w*[Cc]olou?r\w*['\"]\]\s*\?\?",
        ],
        "exclude_patterns": [
            r"sanitize_hex_color\(|sanitize_hex_color_no_hash\(|safecss_filter_attr\(|esc_attr\(|esc_html\(|wp_strip_all_tags\(|strip_tags\(|htmlspecialchars\(|htmlentities\(|intval\(|absint\("
        ],
    },
    "STYLE_TAG_RAW_CONCAT": {
        "group": "group-c",
        "patterns": [r"<style\b[\s\S]{0,150}?</style"],
        "exclude_patterns": [r"wp_strip_all_tags\(|strip_tags\(|esc_html\(|safecss_filter_attr\(|sanitize_hex_color\("],
    },
    "SCRIPT_TAG_RAW_CONCAT": {
        "group": "group-c",
        # Same-line raw variable concatenation between a literal <script> open
        # tag and </script> close tag — the browser executes everything up to
        # the first literal </script> as JavaScript, so an unescaped value
        # here (e.g. echo '<script>' . $var . '</script>';) is a direct sink
        # regardless of any HTML-attribute escaping elsewhere on the line.
        "patterns": [r"<script\b[\s\S]{0,150}?</script"],
        "exclude_patterns": [r"esc_js\(|esc_html\(|wp_json_encode\(|json_encode\(|htmlspecialchars\(|sanitize_text_field\("],
    },
    "WIDGET_RENDER_OUTPUT": {
        "group": "group-c",
        "patterns": [r"\$instance\["],
        "cross_file_filter": r"extends WP_Widget|function widget\(",
        "exclude_patterns": [r"esc_html|esc_attr|esc_url|esc_textarea|wp_kses|intval|absint"],
    },
    "ELEMENTOR_SETTINGS_ATTR_CONCAT": {
        "group": "group-c",
        "patterns": [r"\$settings\["],
        "cross_file_filter": r"extends.*Widget_Base|extends.*Base_Widget|register_controls",
        "exclude_patterns": [r"esc_attr\(|esc_html\(|esc_url\(|wp_kses|esc_js\(|intval|absint"],
        "line_filter": r"['\"].*\$settings\[|\$settings\[.*['\"]|'\s*\.\s*\$settings|\"\s*\.\s*\$settings|\$settings\[.*\]\s*\.",
    },
    "WC_BILLING_FIELD_READS": {
        "group": "group-c",
        "patterns": [
            r"->get_billing_",
            r"->get_shipping_",
            # Pre-formatted multi-field address block (already contains a line-break
            # tag) — a distinct prefix from the single-field getters above, so it
            # needs its own regex; developers often skip escaping it specifically
            # because naive esc_html() would also encode the inserted line breaks.
            r"->get_formatted_billing_address\(",
            r"->get_formatted_shipping_address\(",
        ],
        "exclude_patterns": [r"esc_html|esc_attr|wp_kses|sanitize_text_field"],
    },
    "CUSTOMER_MODEL_PROPERTY_UNESCAPED_RETURN": {
        # API-backed/"headless" commerce plugins (SureCart, EDD-style extensions)
        # expose customer/checkout data as magic-getter properties (->name,
        # ->email) rather than WC's get_billing_*() methods. A `return`
        # statement carrying one of these out of a WP_List_Table column_*
        # callback is a sink TIER6_UNESCAPED_OUTPUT misses entirely, since that
        # section only matches echo/print/printf, not return.
        # Confirmed TP: surecart 4.2.2 CVE-2026-57313 — InvoicesListTable.php
        # column_customer() returned $customer->name/->email unescaped.
        # esc_url()/esc_js() deliberately excluded from exclude_patterns below:
        # the canonical CVE line wraps a sibling $url argument in esc_url() on
        # the same line while leaving ->name/->email completely unescaped —
        # esc_url()/esc_js() protect a URL/JS-string context, not the text-node
        # name/email content, so their presence must not suppress this match
        # (same line-level-exclude imprecision the group-c methodology already
        # flags for TIER6_UNESCAPED_OUTPUT / SPRINTF_POSITIONAL_ARG_UNESCAPED).
        "group": "group-c",
        "patterns": [r"\breturn\b.*->(?:name|email)\b"],
        "line_filter": r"(?i)customer|checkout",
        "exclude_patterns": [
            r"esc_html|esc_attr|wp_kses|htmlspecialchars|htmlentities|sanitize_text_field|sanitize_email"
        ],
    },
    "WP_USER_PROFILE_FIELD_RAW_ACCESS": {
        "group": "group-c",
        "patterns": [
            # ->data->FIELD bypasses WP_User::__get()'s sanitize_user_field()
            # filtering entirely — the raw, unfiltered stdClass row.
            r"->data->(user_login|first_name|last_name|user_email|user_nicename|display_name|nickname)\b",
            # Magic-getter object access and plain-array shape for the same
            # account-owner-editable fields (first_name/last_name/nickname are
            # settable by any authenticated user via their own profile.php).
            r"->(first_name|last_name|user_nicename|nickname)\b",
            r"\[['\"](first_name|last_name|user_nicename|nickname)['\"]\]",
        ],
        # A bare substring check for "esc_html"/"esc_attr" anywhere on the line
        # false-negatives on the real CVE shape: esc_attr__('Username: ', ...)
        # escaping a hardcoded label elsewhere on the SAME line as the still-raw
        # field concatenation. Require the escaper's open-paren to lead directly
        # into the field-access chain instead.
        "exclude_patterns": [
            r"\\?(?:esc_html|esc_attr|wp_kses(?:_post)?|sanitize_text_field|htmlspecialchars|htmlentities|wp_strip_all_tags|sanitize_user)(?:__)?\(\s*\\?\$\w+(?:->data)?->(?:user_login|first_name|last_name|user_email|user_nicename|display_name|nickname)\b",
            r"\\?(?:esc_html|esc_attr|wp_kses(?:_post)?|sanitize_text_field|htmlspecialchars|htmlentities|wp_strip_all_tags|sanitize_user)(?:__)?\(\s*\\?\$\w+\[\s*['\"](?:first_name|last_name|user_nicename|nickname|display_name|user_login|user_email)['\"]\s*\]",
        ],
    },
    "WP_SPECIALCHARS_DECODE": {
        "group": "group-c",
        "patterns": [
            r"wp_specialchars_decode\(|htmlspecialchars_decode\(|html_entity_decode\(",
            # Higher-signal variant: a variable is entity-decoded back into
            # itself, the idiom used when a prior tag-stripping sanitizer's
            # output is unwound on the same line, reintroducing markup.
            r"\$(\w+)\s*=\s*html_entity_decode\(\s*\$\1\s*[,)]",
            # Higher-signal variant: a decode call flows straight into a
            # return/echo/print statement on the same line, with nothing
            # else on that line to escape the reconstructed markup.
            r"\b(?:return|echo|print)\b.*html_entity_decode\(",
        ],
        "exclude_path_patterns": [r"vendor/", r"freemius/"],
    },
    "JSON_UNESCAPED_SLASHES_ENCODE": {
        "group": "group-c",
        "patterns": [r"wp_json_encode|json_encode"],
        "line_filter": r"JSON_UNESCAPED_SLASHES",
    },
    "HTTP_HEADER_DB_WRITE": {
        "group": "group-c",
        "patterns": [
            r"\$_SERVER\['HTTP_REFERER'\]|\$_SERVER\[\"HTTP_REFERER\"\]",
            r"\$_SERVER\['HTTP_USER_AGENT'\]|\$_SERVER\[\"HTTP_USER_AGENT\"\]",
            r"\$_SERVER\['HTTP_X_FORWARDED_FOR'\]|\$_SERVER\[\"HTTP_X_FORWARDED_FOR\"\]",
            r"\$_SERVER\['HTTP_HOST'\]|\$_SERVER\[\"HTTP_HOST\"\]",
            r"\$_SERVER\['HTTP_ACCEPT_LANGUAGE'\]|\$_SERVER\[\"HTTP_ACCEPT_LANGUAGE\"\]",
        ],
        "cross_file_filter": r"update_option|update_post_meta|add_post_meta|update_user_meta|\$wpdb->insert|\$wpdb->update|\$wpdb->replace",
        "exclude_patterns": [r"esc_html\(|esc_attr\(|esc_url\(|sanitize_text_field\(|wp_kses\(|htmlspecialchars\(|strip_tags\(|wp_strip_all_tags\(|esc_url_raw\("],
        "limit": 40,
    },
    # A raw request superglobal is assigned directly into a key of a local
    # "args" array literal, in a file that also defines/calls a custom
    # logging/audit-trail insert function (bare or method, name matching the
    # cross_file_filter below). Activity-log/audit-trail/security-log
    # plugins commonly build an event-record array from raw $_POST/$_GET/
    # $_REQUEST data and hand the whole array to one custom log-insert entry
    # point instead of a direct $wpdb call; if that stored field is later
    # rendered in an admin log-viewer column without esc_html()/esc_attr(),
    # this is Stored XSS.
    "AUDIT_LOG_INSERT_UNSANITIZED_FIELD": {
        "group": "group-c",
        "patterns": [
            r"\$\w+\[['\"]?\w+['\"]?\]\s*=\s*\$_(?:POST|GET|REQUEST)\s*\[",
        ],
        "cross_file_filter": r"(?i)\b\w*(?:insert_log|log_event|add_log|log_action|log_activity|activity_log|audit_log|record_log|record_event|record_activity)\w*\s*\(",
        "exclude_patterns": [
            r"esc_html\(|esc_attr\(|sanitize_text_field\(|wp_kses\(|htmlspecialchars\(|htmlentities\(|strip_tags\(|wp_strip_all_tags\(|absint\(|intval\(|\(int\)|\(float\)|sanitize_key\(|sanitize_title\("
        ],
        "limit": 40,
    },
    "TRACKING_PARAM_UNSANITIZED_STORE": {
        "group": "group-c",
        "patterns": [
            r"\$_GET\[['\"](utm_source|utm_medium|utm_campaign|utm_term|utm_content|source|ref|referrer|campaign|affiliate)['\"]\]",
            r"\$_REQUEST\[['\"](utm_source|utm_medium|utm_campaign|utm_term|utm_content|source|ref|referrer|campaign|affiliate)['\"]\]",
            # Any two-argument "get URL parameter" call (static or instance,
            # any method name) whose second argument is a known marketing/
            # referral tracking key — e.g. Url::getParam($pageUrl, 'utm_source').
            r"(?:::|->)\w+\(\s*\$\w+\s*,\s*['\"](utm_source|utm_medium|utm_campaign|utm_term|utm_content|source|ref|referrer|campaign|affiliate)['\"]",
            # Attribution/landing-page/traffic-source value read straight from a
            # cookie or session var (fallback path of a request-vs-cookie
            # branch, commonly left unsanitized while the sibling $_REQUEST
            # branch is sanitized) — e.g. $_COOKIE['pys_landing_page'],
            # $_SESSION['TrafficSource'].
            r"\$_COOKIE\s*\[\s*['\"]\w*(?:landing[_]?page|traffic[_]?source|utm_source|utm_medium|utm_campaign)\w*['\"]\s*\]",
            r"\$_SESSION\s*\[\s*['\"]\w*(?:landing[_]?page|traffic[_]?source|utm_source|utm_medium|utm_campaign)\w*['\"]\s*\]",
        ],
        "exclude_patterns": [r"esc_html\(|esc_attr\(|esc_url\(|sanitize_text_field\(|wp_kses\(|htmlspecialchars\(|strip_tags\(|wp_strip_all_tags\(|esc_url_raw\(|sanitize_textarea_field\("],
        "case_insensitive": True,
        "limit": 40,
    },
    "WPDB_RESULT_UNESCAPED_OUTPUT": {
        "group": "group-c",
        "patterns": [
            r"echo\s+\$\w+->[\w]+",
            r"print\s+\$\w+->[\w]+",
            r"printf\s*\(.*\$\w+->[\w]+",
        ],
        "cross_file_filter": r"\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var",
        "exclude_patterns": [
            r"esc_html|esc_attr|esc_url|esc_textarea|wp_kses|intval|absint|esc_js|wp_json_encode|htmlspecialchars"
        ],
        "limit": 60,
    },
    "ADMIN_NOTICE_UNESCAPED_OUTPUT": {
        "group": "group-c",
        "patterns": [
            r"function\s+\w*admin.*notice",
            r"admin_notices.*function",
        ],
        "cross_file_filter": r"get_option|get_post_meta|get_user_meta|\$_GET|\$_POST|\$_REQUEST",
        "exclude_patterns": [r"esc_html|esc_attr|wp_kses|htmlspecialchars"],
        "limit": 30,
    },
    # Numbered/positional format specifiers (%1$s, %2$s, ...) are the WP
    # i18n-recommended form once a translatable string has 2+ placeholders
    # (translators may need to reorder them). Not filtered by an esc_*
    # exclude_patterns check: a call legitimately escaping one argument
    # (e.g. esc_url() for a %1$s link) can still leave a sibling %2$s
    # argument unescaped on the same line — manually verify each argument.
    "SPRINTF_POSITIONAL_ARG_UNESCAPED": {
        "group": "group-c",
        "patterns": [r"(?:sprintf|printf)\s*\(.*%\d+\$s"],
        "limit": 40,
    },
    "FILENAME_METADATA_OUTPUT": {
        "group": "group-c",
        "patterns": [
            r"\$_FILES\[.*\]\['name'\]|\$_FILES\[.*\]\[\"name\"\]",
            r"wp_get_attachment_metadata\(",
            r"get_attached_file\(",
        ],
        "cross_file_filter": r"echo|print|printf|sprintf",
        "exclude_patterns": [
            r"esc_html|esc_attr|wp_kses|htmlspecialchars|sanitize_file_name|sanitize_text_field"
        ],
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 40,
    },
    "UNSERIALIZED_ARRAY_FOREACH_ECHO": {
        "group": "group-c",
        # unserialize()/maybe_unserialize() of a stored value (e.g. a $wpdb row
        # column) in a file that also renders output — a common shape for
        # form-entry/log viewer admin screens that iterate the restored array
        # with foreach and echo an element without escaping.
        "patterns": [r"unserialize\(|maybe_unserialize\("],
        "cross_file_filter": r"echo|print|printf",
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 40,
    },
    "FOREACH_ITEM_FIELD_UNESCAPED_ECHO": {
        "group": "group-c",
        # A foreach loop's item variable is subscripted with a string key
        # ($item['field']) and echoed/printed directly on the same line — the
        # shape used by admin "view entry"/metabox templates that render a
        # stored record's fields (form submissions, log rows, imported data)
        # without escaping. Complements UNSERIALIZED_ARRAY_FOREACH_ECHO above:
        # that section requires a literal unserialize()/maybe_unserialize()
        # call in-file, which misses cases where the array-of-records is
        # instead handed in as a function/template parameter already fetched
        # elsewhere (e.g. via a model's get_post_meta()-backed getter).
        #
        # Second pattern: the loop iterates a field-schema array keyed by
        # field name, and the echoed value instead comes from a SEPARATE
        # sibling array indexed by that same loop key — commonly guarded by
        # an `isset($sibling[$key]) ? $sibling[$key] : $default` null-guard
        # ternary that checks presence but performs no escaping. Common to
        # form-builder entry/metabox renderers alongside the direct-field shape.
        #
        # Third pattern: the loop's KEY and VALUE are both bare (not
        # subscripted) and echoed together as a "label: value" pair — the
        # meta/data-inspector debug-dump idiom used by "view details" AJAX
        # panels and log viewers that print each stored field name next to
        # its raw value with no escaping on either.
        #
        # Fourth pattern: the iterated collection holds OBJECTS instead of
        # associative sub-arrays — the loop item's property is accessed via
        # `->` (`$field->value`) rather than array subscript, and echoed
        # directly. Object-shaped field records are the norm for
        # page-builder/form-builder "view submission" admin templates
        # (`foreach ($data->formData as $field) { echo $field->value; }`);
        # the cross_file_filter below also accepts the loop source itself
        # being a one-level property access (`$data->formData as $field`),
        # not only a bare variable.
        "patterns": [
            r"(?:echo|print)\b[^;]*\$\w+\s*\[\s*['\"]\w+['\"]\s*\]",
            r"(?:echo|print)\b[^;]*\bisset\s*\(\s*\$\w+\s*\[\s*\$\w+\s*\]\s*\)\s*\?\s*\$\w+\s*\[\s*\$\w+\s*\]\s*:",
            r"(?:echo|print)\b[^;]*\$\w+[^;]*\.\s*(?:'[^']*:[^']*'|\"[^\"]*:[^\"]*\")[^;]*\.\s*\$\w+[^;]*;",
            r"(?:echo|print)\b[^;]*\$\w+\s*->\s*\w+",
        ],
        "cross_file_filter": r"foreach\s*\(\s*\$\w+(?:->\w+)?\s+as\s+(?:\$\w+\s*=>\s*)?\$\w+\s*\)",
        "exclude_patterns": [
            r"esc_html|esc_attr|esc_html__|esc_attr__|esc_url|esc_url_raw|htmlspecialchars|htmlentities|wp_kses|wp_strip_all_tags|sanitize_text_field|absint|intval|wp_json_encode|json_encode|wp_send_json",
        ],
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 60,
    },
    "HYDRATED_RECORD_SELECTIVE_FIELD_ESCAPE": {
        "group": "group-c",
        # A record-formatting method (in a file that also bulk-rehydrates a
        # stored/log row via array_map('maybe_unserialize', ...) or a bare
        # unserialize()/maybe_unserialize() call) explicitly wraps ONE named
        # array key of that row in an escaping function before the row is
        # returned. Complements UNSERIALIZED_ARRAY_FOREACH_ECHO /
        # FOREACH_ITEM_FIELD_UNESCAPED_ECHO above (both echo-focused): this
        # section catches the REST/AJAX "return the formatted row" shape,
        # where selective per-field escaping (proving the author knew this
        # data needed escaping) commonly leaves a sibling free-text field
        # (subject/body/message/title/content/comment/note/description/text)
        # untouched — it silently keeps its raw hydrated value. Excludes
        # matches where the escaped field IS already one of those content-like
        # names, since that is the remediated shape, not the gap.
        #
        # Second pattern: the same selective-escape idiom on a row OBJECT
        # (`$row->field = esc_html($row->field);`) instead of an array key —
        # common where the row was just reassigned through an extensibility
        # filter hook (`$row = apply_filters($hook, $row);`, the standard
        # add-on-attaches-extra-properties idiom for log/report/entry
        # viewers) rather than an unserialize-style rehydration. Any OTHER
        # property the hook attached is not covered by the one hardcoded
        # esc_*() call. Triage: confirm the row collection is later bare-
        # echoed as JSON (echo json_encode(...)/wp_json_encode(...)) with no
        # esc_attr/esc_html wrapper — that is the render-time sink, invisible
        # to this line-based scanner.
        "patterns": [
            r"\[\s*['\"]\w+['\"]\s*\]\s*=\s*(?:htmlspecialchars|htmlentities|esc_html|esc_attr|esc_html__|esc_attr__|wp_kses|wp_kses_post|wp_strip_all_tags)\s*\(",
            r"\$(\w+)->(\w+)\s*=\s*(?:htmlspecialchars|htmlentities|esc_html|esc_attr|esc_html__|esc_attr__|wp_kses|wp_kses_post|wp_strip_all_tags)\s*\(\s*\$\1->\2\s*\)",
        ],
        "cross_file_filter": r"array_map\s*\(\s*['\"]maybe_unserialize['\"]|maybe_unserialize\s*\(|unserialize\s*\(|apply_filters\s*\(\s*['\"][^'\"]+['\"]\s*,\s*\$\w+\s*\)",
        "exclude_patterns": [
            r"\[\s*['\"](?:subject|body|message|title|content|comment|note|description|text)['\"]\s*\]\s*=\s*(?:htmlspecialchars|htmlentities|esc_html|esc_attr|esc_html__|esc_attr__|wp_kses|wp_kses_post|wp_strip_all_tags)\s*\(",
            r"->(?:subject|body|message|title|content|comment|note|description|text)\b\s*=\s*(?:htmlspecialchars|htmlentities|esc_html|esc_attr|esc_html__|esc_attr__|wp_kses|wp_kses_post|wp_strip_all_tags)\s*\(\s*\$\w+->(?:subject|body|message|title|content|comment|note|description|text)\b\s*\)",
        ],
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 40,
    },
    "KEYED_FIELD_VALUE_UNESCAPED_ARRAY_WRITE": {
        "group": "group-c",
        # A dynamically-keyed array write — `$ARR[$KEY] = $VALUE;` where BOTH
        # the index and the assigned value are bare variables, no function
        # call wrapping either side — in a file that ALSO calls a common
        # per-key usermeta/postmeta getter (get_user_meta/get_the_author_meta/
        # get_post_meta/get_metadata). This is the "schema-driven field
        # renderer" idiom: iterate a list of field names, fetch each field's
        # value via one of these getters, write it into a response/card array
        # under the same key with no escaping. The getter cross-file-filter
        # (rather than a bare foreach filter) keeps this section from matching
        # the extremely common "any dynamically-keyed cache/settings array
        # build" idiom that has nothing to do with usermeta/postmeta output.
        # A literal string-keyed write (`$arr['foo'] = $bar;`) or a write
        # already wrapped in an escaping call does not match; only the bare,
        # dynamically-keyed form does.
        "patterns": [
            r"\$\w+\[\s*\$\w+\s*\]\s*=\s*\$\w+\s*;",
        ],
        "cross_file_filter": r"(?:get_user_meta|get_the_author_meta|get_post_meta|get_metadata)\s*\(",
        "exclude_patterns": [
            r"esc_html|esc_attr|esc_html__|esc_attr__|esc_url|esc_url_raw|wp_kses|wp_kses_post|htmlspecialchars|htmlentities|sanitize_text_field|wp_strip_all_tags|absint|intval",
        ],
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 60,
    },
    "DYNAMIC_KEY_ESC_ATTR_ARRAY_WRITE": {
        "group": "group-c",
        # A dynamically-keyed array write using esc_attr() as the sanitizer —
        # the index is a variable (a generic per-item/per-key loop, e.g. a
        # REST/AJAX "update arbitrary meta key=>value map" handler), not a
        # literal string, so a literal-URL-key-name filter cannot apply here.
        # esc_attr() HTML-attribute-encodes but applies no protocol filtering;
        # if the loop has no per-key type branch and ANY of the dynamically
        # supplied keys is later rendered as an href/src attribute,
        # javascript: URIs survive storage untouched (CWE-79). Leads only —
        # manually confirm (a) no per-key type branch (e.g.
        # in_array($key, $url_keys, true)) guards this line, and (b) the
        # written array flows into a sink later rendered as a URL.
        "patterns": [
            r"\$\w+\[\s*\$\w+\s*\]\s*=\s*esc_attr\(",
        ],
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 60,
    },
    "JQUERY_DOM_INSERTION_SINKS": {
        "group": "group-c",
        "patterns": [
            r"\.html\s*\(",
            r"\.append\s*\(",
            r"\.prepend\s*\(",
            r"\.after\s*\(",
            r"\.before\s*\(",
            r"\.replaceWith\s*\(",
            # Plain vanilla-JS innerHTML assignment — same sink class as
            # jQuery .html(), catches admin "lookup"/"debug" tools that
            # fetch a REST/AJAX record and dump its fields via template
            # literals or string concat straight into the DOM.
            r"\.innerHTML\s*=",
        ],
        # PHP view/template globs added alongside the .js globs: these sinks
        # are equally common inline in a <script> block echoed directly by a
        # PHP admin view/template file, a shape a .js-only glob misses entirely.
        # Recursive "**/*.php" (not a single-level "*") on every PHP branch:
        # many plugins nest per-view templates a level or two deeper than the
        # named directory itself (e.g. "admin/views/<view>/tmpl/default.php",
        # a common Joomla-ported-to-WP admin MVC convention) — a single "*"
        # glob silently misses that whole class of files. "**/*.ext" matches
        # any depth including zero, via _glob_match's explicit path-segment
        # "**" handling, not stdlib fnmatch, so the top-level-file case (a
        # template directly inside the named directory) still matches too.
        "glob_override": "assets/**/*.js,admin/**/*.js,js/**/*.js,includes/**/*.js,src/**/*.js,admin/views/**/*.php,admin/partials/**/*.php,includes/views/**/*.php,views/**/*.php,partials/**/*.php,templates/**/*.php",
        "cross_file_filter": r"ajax|fetch|\.get\(|\.post\(|\$\.getJSON|wp\.ajax",
        "exclude_patterns": [r"\.text\(|DOMPurify|\.textContent|\.escapeHtml|\.sanitize"],
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"freemius/"],
        "limit": 40,
    },
    # React/Preact dangerouslySetInnerHTML assigned a raw expression rather
    # than a sanitizer call result — same DOM-XSS sink class as
    # JQUERY_DOM_INSERTION_SINKS above but a distinct AST shape (an
    # object-literal property, not a method call), common in built admin-UI
    # bundles that render stored records (form submissions, comments,
    # imported rows) as HTML.
    "DANGEROUSLY_SET_INNER_HTML_UNSANITIZED": {
        "group": "group-c",
        "patterns": [
            r"dangerouslySetInnerHTML\s*[:=]",
        ],
        "glob_override": "assets/**/*.js,admin/**/*.js,js/**/*.js,includes/**/*.js,src/**/*.js",
        "exclude_patterns": [r"DOMPurify|\.sanitize\(|\.purify\(|\.escapeHtml\(|sanitizeHtml\("],
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"freemius/"],
        "limit": 40,
    },
    # Select2 (and similarly-shaped autocomplete widgets) escape their rendered
    # option markup by default. A plugin-authored config that overrides
    # `escapeMarkup` to a no-op (identity return) — usually paired with a custom
    # `templateResult`/`formatResult` that string-concatenates AJAX response
    # fields into HTML — reintroduces raw HTML rendering of whatever the server
    # returned. The override itself is the signal: routine Select2 configs never
    # need to touch this option. Excludes the bundled select2 library sources
    # themselves (its own internal default-escaper definition, not a plugin's
    # override of it).
    "SELECT2_ESCAPE_MARKUP_OVERRIDE": {
        "group": "group-c",
        "patterns": [
            r"escapeMarkup\s*:\s*function\s*\(",
            r"escapeMarkup\s*:\s*\(?\s*\w*\s*\)?\s*=>",
        ],
        "glob_override": "assets/**/*.js,admin/**/*.js,js/**/*.js,includes/**/*.js,src/**/*.js",
        "cross_file_filter": r"templateResult|formatResult|templateSelection",
        "exclude_patterns": [r"DOMPurify|_\.escape\(|escapeHtml\(|he\.encode\(|htmlEncode\("],
        "exclude_path_patterns": [
            r"node_modules/", r"\.min\.js$", r"-min\.js$",
            r"select2/dist/", r"select2\.full", r"select2\.min", r"vendor/",
        ],
        "limit": 30,
    },
    # A quoted href=/src= HTML attribute is immediately followed by a `+`
    # concatenation operator — the raw-string-concat tag-builder shape (as
    # opposed to JQUERY_DOM_INSERTION_SINKS, which flags the DOM-insertion
    # call itself regardless of how the HTML argument was built). Deliberately
    # NOT excluding assets/**/jquery.*.js-style paths: bundled/forked slider
    # and lightbox libraries under assets/ are a common place for a plugin
    # vendor to add their own attribute-building glue code around a
    # third-party library, carrying the same risk as plugin-authored JS.
    "JS_HREF_SRC_ATTR_STRING_CONCAT": {
        "group": "group-c",
        "patterns": [
            r"(?:href|src)\s*=\s*\\?['\"]\s*\\?['\"]?\s*\+",
        ],
        "glob_override": "assets/**/*.js,admin/**/*.js,js/**/*.js,includes/**/*.js,src/**/*.js",
        "exclude_patterns": [
            r"encodeURIComponent\(|encodeURI\(|DOMPurify|escapeHtml|\.sanitize\("
        ],
        "exclude_path_patterns": [r"node_modules/", r"\.min\.js$", r"-min\.js$"],
        "limit": 40,
    },
    # CVE-2024-0903 (userfeedback-lite, CWE-79): a Vue render-function attrs
    # object bound an anchor's href directly to a stored record field (a
    # page-submission "link" value) with no URL-scheme validation; the
    # official fix wrapped the value in a javascript:-stripping helper before
    # assignment. Distinct AST shape from JS_HREF_SRC_ATTR_STRING_CONCAT
    # (raw string concatenation): this is a bare object-property/assignment/
    # setAttribute binding, which prevents quote-breakout but not a
    # javascript: URI executing when the rendered link is clicked. Requires
    # the char right after `href:`/`href=`/setAttribute('href', ...) to be an
    # identifier start (not a quote/backtick) so plain string/template
    # literals never match.
    "JS_HREF_ATTR_BINDING_NO_SCHEME_CHECK": {
        "group": "group-c",
        "patterns": [
            r"\bhref\s*[:=]\s*(?!['\"`])[A-Za-z_$]",
            r"setAttribute\(\s*['\"]href['\"]\s*,\s*(?!['\"`])[A-Za-z_$]",
        ],
        "glob_override": "assets/**/*.js,admin/**/*.js,js/**/*.js,includes/**/*.js,src/**/*.js",
        "exclude_patterns": [
            r"(?i)href\s*[:=]\s*(?:\w+\.)*(?:saniti[sz]e|escape|purify|clean|encodeuri|dompurify)\w*\(",
            r"(?i)setAttribute\(\s*['\"]href['\"]\s*,\s*(?:\w+\.)*(?:saniti[sz]e|escape|purify|clean|encodeuri|dompurify)\w*\(",
        ],
        "exclude_path_patterns": [r"node_modules/", r"vendor/", r"freemius/"],
        "limit": 40,
    },
    # The URL fragment (location.hash, or a window./document./self. alias) is
    # passed straight into a call as an argument — a hash/anchor "router"
    # idiom that is DOM-based XSS if the callee treats the value as a jQuery
    # selector, a JSON/base64-encoded settings blob, or otherwise uses it
    # unescaped in a DOM-affecting sink. The real-world fix for this class is
    # to validate the fragment against the DOM (querySelector/getElementById)
    # before forwarding it, or to compare it against a fixed literal — both
    # excluded below as the safe idiom.
    "LOCATION_HASH_UNVALIDATED_DISPATCH": {
        "group": "group-c",
        "patterns": [
            r"\(\s*(?:window\.|document\.|self\.)?location\.hash\b",
        ],
        "glob_override": "assets/**/*.js,admin/**/*.js,js/**/*.js,includes/**/*.js,src/**/*.js",
        "exclude_patterns": [
            r"location\.hash\s*={1,3}\s*['\"]",
            r"(?:querySelector|getElementById)\(\s*(?:window\.|document\.|self\.)?location\.hash\b",
        ],
        "exclude_path_patterns": [r"node_modules/", r"vendor/", r"freemius/", r"\.min\.js$", r"-min\.js$"],
        "limit": 40,
    },
    "REST_FIELD_CALLBACK_XSS": {
        "group": "group-c",
        "patterns": [r"register_rest_field\s*\("],
        "cross_file_filter": r"update_post_meta|update_user_meta|update_option|add_post_meta",
        "exclude_patterns": [r"sanitize_callback|sanitize_text_field|esc_html|wp_kses|intval|absint"],
        "limit": 30,
    },
    # RegExSS: preg_replace used to strip/modify HTML attributes on content.
    # Greedy regex quantifiers (.*?, .*, .+) match across attribute/element boundaries,
    # allowing attacker-crafted quote mixing to break out of matched context and promote
    # injected event handler attributes. CVE-2025-9512 (Schema & Structured Data).
    # Targets: preg_replace removing/rewriting attr="value" patterns in HTML.
    # Excludes: BBCode converters (\[), <script> tag removal, <tag> element removal,
    # smiley/emoticon converters, preg_replace_callback, /e modifier.
    "PREG_REPLACE_HTML_ATTR_STRIP": {
        "group": "group-c",
        "patterns": [
            r"preg_replace\s*\(\s*['\"].*\s\w+=\\?['\"].*(\.\*\??|\.\+\??|\[\^['\"][^\]]*\][*+?]).*['\"].*,",
        ],
        "exclude_patterns": [
            r"preg_replace.*\/e",
            r"preg_replace_callback",
            r"^\s*(\*|//|#|/\*)",
            r"\\\[",
            r"<script|<\\?/script|<style|<\\?/style|<link\s",
            r"<\\?/[\w-]+\s*>",
            r"smileys|smiley|emoticon|emoji|EMO_DIR",
            r"application/ld\+json|application\\?/ld",
        ],
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"freemius/", r"converters?/"],
        "limit": 60,
    },
    # CVE-2026-9148 (wpdiscuz, CWE-79): getCommentAuthor() interpolated the
    # stored comment_author_url ("Website" field) directly into a single-quoted
    # href attribute via PHP double-quoted string interpolation — a different
    # AST shape than dot-concatenation, so it doesn't overlap
    # STRING_CONCAT_URL_ATTR-style detection. Targets: href/src/action= followed
    # (optionally after a static scheme/path prefix literal such as "mailto:",
    # "tel:", "#", or a relative path — CVE-2026-5721, wpDataTables cell
    # formatter building a mailto: link from stored/imported contact data) by
    # a raw interpolated $variable (no escaping call can sit between the quote
    # and the $ in PHP interpolation syntax).
    #
    # CVE-2026-15395 (kali-forms, CWE-79) added the sibling dot-concatenation
    # shape: '<img ... src="' . $var . '" />', where a preg_match() format
    # gate (e.g. confirming a data:...;base64, prefix) ran immediately before
    # the concat — the gate gave false confidence and was mistaken for an
    # escaper. The attribute's opening quote is immediately followed by the
    # PHP string literal's own closing quote, then the concat operator into a
    # bare variable or a non-escaping function call (sanitize_text_field() is
    # not an attribute escaper and does not suppress this).
    "INTERPOLATED_HREF_ATTR_NO_ESC": {
        "group": "group-c",
        "patterns": [
            r"\b(?:href|src|action)\s*=\s*['\"][^'\"]*\{?\$[A-Za-z_][A-Za-z0-9_]*",
            r"\b(?:href|src|action)\s*=\s*['\"]\s*['\"]\s*\.\s*[$A-Za-z_]",
        ],
        "exclude_patterns": [
            r"esc_url\(|esc_url_raw\(|esc_attr\(|esc_html\(|wp_kses\(",
        ],
        "limit": 60,
    },
    # CVE-2026-57673 (optimole-wp, CWE-79): addcslashes($url, '/') is used
    # as an HTML-attribute escaper but only escapes '/' — it leaves '"',
    # '<', '>' unmodified. If the URL was previously decoded from stored
    # \uXXXX sequences via html_entity_decode(stripslashes()), those HTML
    # special chars survive the addcslashes call and can break out of img
    # src/href attributes when the result is used in str_replace() or
    # direct concatenation into an HTML tag string.
    "ADDCSLASHES_SLASH_ONLY_HTML_INJECT": {
        "group": "group-c",
        "patterns": [
            r"addcslashes\s*\(\s*\$\w+\s*,\s*['\"]\/['\"]\s*\)",
        ],
        "limit": 40,
    },
    # CVE-2024-1794 (forminator, CWE-79): a file is persisted via
    # move_uploaded_file() and gated only by wp_check_filetype() (filename/
    # extension vs. an allow-list) — wp_check_filetype_and_ext() (which also
    # sniffs the real content/magic bytes) never appears in the file. An
    # attacker can submit HTML/JS content under an allowed extension; a
    # browser opening the saved file directly may sniff and execute it.
    "UPLOAD_EXTENSION_ONLY_MIME_CHECK": {
        "group": "group-c",
        "patterns": [r"wp_check_filetype_and_ext\("],
        "invert": True,
        "cross_file_filter": r"(?s)(?=.*wp_check_filetype\()(?=.*move_uploaded_file\()",
        "exclude_path_patterns": [r"vendor/", r"freemius/", r"node_modules/"],
        "limit": 40,
    },
    # CVE-2026-57718 (unlimited-elements-for-elementor, CWE-79): a model
    # getter formats externally-sourced text for HTML display by piping it
    # through nl2br() alone — nl2br() only inserts <br /> before newlines,
    # it performs no HTML-entity encoding, so raw markup/script survives to
    # the rendered page. A line-based scanner cannot see whether a sanitizer
    # runs on a PRECEDING line for the same variable (the real vendor fix
    # shape here), so this is a lead only: every hit needs the enclosing
    # method read manually to confirm no wp_kses()/esc_html()-style call
    # runs on the value before or after the nl2br() call.
    "NL2BR_UNSANITIZED_TEXT": {
        "group": "group-c",
        "patterns": [r"nl2br\s*\("],
        "exclude_patterns": [
            r"esc_html\(|esc_attr\(|wp_kses\(|wp_kses_post\(|htmlspecialchars\(|htmlentities\(|sanitize_text_field\(|wp_strip_all_tags\("
        ],
        "exclude_path_patterns": [r"vendor/", r"vendor-prefixed/", r"node_modules/", r"freemius/"],
        "limit": 60,
    },
    "TEXTAREA_CONTENT_UNESCAPED_ECHO": {
        "group": "group-c",
        # Sink-specific: a value echoed as the TEXT CONTENT of an HTML
        # <textarea> with no escaping applied. The negative lookahead sits
        # right after the echo (not in exclude_patterns) because the same
        # line commonly ALSO contains an unrelated esc_attr()/esc_html() call
        # escaping a sibling attribute on the same <textarea> tag (e.g. its
        # own name="..."); a whole-line exclude_patterns check would
        # false-negative on the real, unescaped textarea body a few
        # characters later on that identical line.
        "patterns": [
            r"<textarea\b[\s\S]{0,300}?>\s*(?:<\?php\s+echo|<\?=)\s+(?!(?:esc_textarea|esc_html__|esc_html|esc_attr|htmlspecialchars|htmlentities|wp_kses_post|wp_kses|sanitize_text_field|wp_strip_all_tags)\s*\()"
        ],
        "exclude_path_patterns": [r"vendor/", r"vendor-prefixed/", r"node_modules/", r"freemius/"],
        "limit": 40,
    },
    # Lead only: a responsive-image "srcset" entry array is built by
    # concatenating a bare URL variable and a bare descriptor variable with a
    # literal separator, with neither side passed through an escaping
    # function on the same line. Confirm manually whether either variable is
    # sanitized/escaped earlier in the same function before the join.
    "SRCSET_DESCRIPTOR_CONCAT_UNESCAPED": {
        "group": "group-c",
        "patterns": [
            r"\$\w*src[-_]?set\w*\s*\[\s*\]\s*=\s*\$\w+\s*\.\s*(?:'[^']*'|\"[^\"]*\")\s*\.\s*\$\w+\s*;"
        ],
        "exclude_patterns": [r"esc_url\(|esc_url_raw\(|esc_attr\(|esc_html\("],
        "case_insensitive": True,
        "exclude_path_patterns": [r"vendor/", r"vendor-prefixed/", r"node_modules/", r"freemius/"],
        "limit": 40,
    },
    # A template/merge-tag substitution reassigns a text variable via
    # str_replace() where the replacement argument is an object property
    # (static or dynamically-named, e.g. a per-field "profile_N" loop),
    # with no escaping function wrapped around it on the same line.
    "MERGE_TAG_PROPERTY_STR_REPLACE_UNESCAPED": {
        "group": "group-c",
        "patterns": [
            r"\$\w+\s*\.?=\s*str_replace\([^;]*,\s*\$\w+->\$?\w+\s*,\s*\$\w+\s*\)",
        ],
        "exclude_patterns": [
            r"esc_html|esc_attr|sanitize_text_field|wp_kses|htmlspecialchars|htmlentities|wp_strip_all_tags",
        ],
        "limit": 60,
    },
    # Sibling of MERGE_TAG_PROPERTY_STR_REPLACE_UNESCAPED for a request
    # superglobal (not an object property) as the replacement source, e.g. a
    # dynamic-placeholder/personalization-tag engine substituting
    # {{GET:name}}/{{COOKIE:name}}-style tokens. sanitize_text_field() is
    # deliberately NOT in exclude_patterns here (unlike the sibling section):
    # it strips tags but not quotes, so it does not neutralize the value for
    # a <script> or unquoted/single-quoted HTML-attribute sink the engine's
    # own output may later reach — manually trace every downstream sink.
    "MERGE_TAG_SUPERGLOBAL_STR_REPLACE_UNESCAPED": {
        "group": "group-c",
        "patterns": [
            r"\$\w+\s*\.?=\s*str_replace\([^;]*,\s*(?:sanitize_text_field\s*\(\s*)?(?:wp_unslash\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]*\]",
        ],
        "exclude_patterns": [
            r"esc_html|esc_attr|esc_js|wp_kses|htmlspecialchars|htmlentities|wp_strip_all_tags",
        ],
        "limit": 60,
    },
    "MERGE_TAG_WP_KSES_SUPERGLOBAL_ASSIGN": {
        "group": "group-c",
        # Sibling of MERGE_TAG_SUPERGLOBAL_STR_REPLACE_UNESCAPED for
        # template/merge-tag engines that stage the resolved value in an
        # intermediate variable via wp_kses() rather than str_replace()-ing
        # it in place. wp_kses() is a tag-syntax filter, not an attribute-
        # safe encoder — it leaves quote/backslash characters untouched, so
        # this shape carries the same insufficiency the sibling section
        # flags, one hop earlier in the assignment chain.
        "patterns": [
            r"\$\w+\s*=\s*wp_kses\s*\(\s*(?:wp_unslash\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[",
        ],
        "exclude_patterns": [
            r"esc_html\s*\(\s*wp_kses|esc_attr\s*\(\s*wp_kses|esc_url\s*\(\s*wp_kses",
        ],
        "limit": 60,
    },
    "JSON_ENCODE_HTML_COMMENT_BREAKOUT": {
        "group": "group-c",
        "patterns": [
            r"<!--.*\.\s*(?:json_encode|wp_json_encode|implode)\s*\(.*-->",
        ],
        "exclude_patterns": [
            r"esc_html\(",
        ],
        "cross_file_filter": r"json_encode\(|wp_json_encode\(",
    },
    # ===== GROUP D1 (Tier 8-10: SSRF, Email, Info Disclosure) =====
    "TIER8_SSRF": {
        "group": "group-d1",
        "patterns": [
            r"wp_remote_get\(|wp_remote_post\(|curl_exec\(|download_url\("
        ],
        "exclude_patterns": [r"wp_safe_remote"],
    },
    "RAW_CURL": {
        "group": "group-d1",
        "patterns": [r"curl_init|curl_exec|curl_setopt"],
        "exclude_path_patterns": [r"vendor", r"freemius"],
    },
    "DOM_XML_PARSING": {
        "group": "group-d1",
        "patterns": [r"loadHTML|loadXML|simplexml_load_string", r"getAttribute\("],
    },
    "SSRF_SAFE_REMOTE_USER_INPUT": {
        "group": "group-d1",
        "patterns": [
            r"wp_safe_remote_get\(|wp_safe_remote_post\(|wp_safe_remote_request\(|wp_safe_remote_head\(",
        ],
        "cross_file_filter": r"wp_ajax_|wp_ajax_nopriv_|register_rest_route|admin_post_|wc_ajax_",
    },
    "SSRF_FETCH_FEED": {
        "group": "group-d1",
        "patterns": [r"fetch_feed\("],
        "cross_file_filter": r"wp_ajax_|wp_ajax_nopriv_|register_rest_route|admin_post_|\$_GET|\$_POST|\$_REQUEST|get_option|get_post_meta",
    },
    "SSRF_IMAGE_SIDELOAD": {
        "group": "group-d1",
        "patterns": [r"media_sideload_image\(|wp_remote_fopen\("],
    },
    "SSRF_GETIMAGESIZE": {
        "group": "group-d1",
        "patterns": [r"(?<!->)getimagesize\s*\(\s*\$"],
        "exclude_patterns": [r"getimagesize\s*\(\s*\$\w*(?:file|path|image|abspath|tmp|local|dir|name|attach)"],
        "cross_file_filter": r"wp_ajax_|register_rest_route|admin_post_|\$_GET|\$_POST|\$_REQUEST",
    },
    "SSRF_GET_HEADERS": {
        "group": "group-d1",
        "patterns": [r"get_headers\s*\(\s*\$"],
    },
    "SSRF_STREAM_SOCKET": {
        "group": "group-d1",
        "patterns": [r"stream_socket_client\s*\(", r"stream_context_create\s*\("],
        "cross_file_filter": r"\$_GET|\$_POST|\$_REQUEST|get_option|get_param",
        "exclude_path_patterns": [r"vendor", r"freemius"],
    },
    "SSRF_WEBHOOK_URL_STORE": {
        "group": "group-d1",
        "patterns": [
            r"update_option\s*\(.*(?:webhook|callback|endpoint|notify|hook).*url",
            r"update_post_meta\s*\(.*(?:webhook|callback|endpoint|notify|hook).*url",
        ],
        "case_insensitive": True,
    },
    "SSRF_CRON_HTTP_FETCH": {
        "group": "group-d1",
        "patterns": [
            r"wp_remote_get\s*\(\s*\$|wp_remote_post\s*\(\s*\$|wp_safe_remote_get\s*\(\s*\$|wp_safe_remote_post\s*\(\s*\$",
        ],
        "cross_file_filter": r"wp_schedule_event|wp_schedule_single_event|wp_cron|add_action.*cron",
        "exclude_path_patterns": [r"vendor", r"freemius"],
        "limit": 30,
    },
    "SSRF_SANITIZE_URL_NO_HOST_CHECK": {
        "group": "group-d1",
        "patterns": [r"sanitize_url\s*\(\s*\$"],
        "cross_file_filter": r"\$_GET|\$_POST|\$_REQUEST|get_param\(",
        "exclude_path_patterns": [r"vendor", r"freemius"],
    },
    "EMAIL_HEADER_LINE_BUILD": {
        "group": "group-d1",
        "patterns": [r"[\"'](?:From|Reply-To|Cc|Bcc):\s"],
        "case_insensitive": True,
    },
    # ===== GROUP D2 (Tier 11-12: IDOR, Race Conditions) =====
    "TIER11_IDOR": {
        "group": "group-d2",
        "patterns": [
            r"\$_GET\[.*[Ii][Dd]|\$_POST\[.*[Ii][Dd]|\$_REQUEST\[.*[Ii][Dd]",
            r"filter_input\b.*['\"][Ii][Dd]['\"]",
            r"wc_get_order.*query_vars",
        ],
    },
    "WC_ORDER_RECEIVED_QUERY_VAR": {
        "group": "group-ac",
        "patterns": [
            r"query_vars\[.*['\"]order.(received|pay)['\"]",
            r"get_query_var\s*\(\s*['\"]order.(received|pay)",
        ],
    },
    "WP_POST_REPARENTING": {
        "group": "group-d2",
        "patterns": [r"wp_update_post.*post_parent"],
    },
    "IDOR_OWNERSHIP_CHECKS": {
        "group": "group-d2",
        "patterns": [
            r"host_id.*current_user|user_id.*current_user|author_id.*current_user|owner_id.*current_user",
            # Reversed token order: get_current_user_id() called first, the
            # id-like comparison target read second — e.g.
            # `get_current_user_id() !== absint($atts['user_id'])`. The
            # original patterns above require the id token before
            # "current_user" and miss this shape entirely (CWE-639) — see
            # CVE-2026-13450 in VARIANT-PROVENANCE.md.
            r"current_user.*(?:host_id|user_id|author_id|owner_id)",
            # Custom (non-WP-native) auth pipelines resolve the caller's
            # identity into an object on $this rather than get_current_user_id()
            # (e.g. `$this->staff`, `$this->member`, `$this->vendor`) — the
            # ownership comparator is then `$this-><obj>->getId()` against a
            # record's owner field, in either token order. The patterns above
            # are WP-native-only and miss this shape entirely; confirmed miss
            # on a per-record ownership check in bookly-responsive-appointment
            # -booking-tool 27.9 (`$staff_id != $this->staff->getId()`).
            r"\$this->\w+->getId\(\)\s*(?:!=|!==|==|===)",
            r"(?:!=|!==|==|===)\s*\$this->\w+->getId\(\)",
        ],
    },
    "REST_IDOR_USER_ID": {
        "group": "group-d2",
        "patterns": [r"get_param.*user_id|user_id.*get_param"],
    },
    "REST_IDOR_RESOURCE_ID": {
        "group": "group-d2",
        "patterns": [r"->get_param.*'id'"],
    },
    "REST_BODY_PARAM_POST_ID": {
        "group": "group-d2",
        "patterns": [r"get_json_params\(\)|get_body_params\(\)"],
        "cross_file_filter": r"register_rest_route",
    },
    "REST_WEBHOOK_BODY": {
        "group": "group-d1",
        "patterns": [r"->get_body\(\)"],
        "cross_file_filter": r"register_rest_route",
    },
    "ILLUSORY_OWNERSHIP": {
        "group": "group-d2",
        "patterns": [
            r"current_user_id.*\$_POST|\$_POST.*current_user_id|current_user_id.*\$_GET"
        ],
    },
    # CWE-639: an authorization gate calls a capability/role method on a target
    # object (usually resolved via a request-controlled id) instead of checking
    # the current caller, combined with an inequality against the current user
    # id — e.g. `! $target->can_X() && get_current_user_id() !== $user_id`. This
    # only denies when the TARGET lacks the capability, so any caller passes
    # whenever the target happens to have it (auth decided by the wrong subject).
    "CAPABILITY_CHECK_ON_TARGET_OBJECT": {
        "group": "group-ac",
        "patterns": [
            r"!\s*\$\w+->(can|is|has)_\w*\([^)]*\)\s*&&\s*(get_current_user_id|wp_get_current_user)\(\)\s*(!==|!=)\s*\$\w+"
        ],
    },
    # CWE-639: current_user_can() invoked with the literal 'read' capability
    # string (or a post-type object's exposed ->cap->read property) plus a
    # second (object-id) argument. 'read' is WordPress's coarse, role-level
    # primitive capability — get_post_type_capabilities() (wp-includes/post.php)
    # hard-codes cap->read to the literal 'read' string whenever map_meta_cap
    # is true, so it is never registered as a real per-object meta capability.
    # Every default role from Subscriber upward holds 'read', and the object-id
    # argument is silently ignored, making the check unconditionally true
    # regardless of the object's author/status. The correct per-object
    # capability is the meta cap 'read_post'. See CVE-2026-65463 in
    # VARIANT-PROVENANCE.md.
    "READ_PRIMITIVE_CAP_OBJECT_GATE": {
        "group": "group-ac",
        "patterns": [
            r"current_user_can\s*\(\s*['\"]read['\"]\s*,",
            r"current_user_can\s*\(\s*\$\w+(?:->\w+)*->cap->read\s*,",
        ],
    },
    "IDOR_ACCOUNT_TAKEOVER_SINKS": {
        "group": "group-d2",
        "patterns": [
            r"wp_update_user\s*\(",
            r"wp_set_password\s*\(",
            r"wp_set_auth_cookie\s*\(",
        ],
    },
    "IDOR_LOOKUP_BY_UNIQUE_FIELD_THEN_WRITE": {
        "group": "group-ac",
        "patterns": [
            r"findOneBy\s*\(\s*\[\s*['\"](email|username|user_email|user_login)['\"]",
            r"get_user_by\s*\(\s*['\"](email|login)['\"]",
            r"WHERE\s+(user_)?email\s*=|WHERE\s+user_login\s*=",
            r"(update_user_meta|add_user_meta)\s*\(\s*\$\w+->\w+->ID",
            # Role write directly on a variable resolved by the lookup above
            # (any variable name, any arrow depth) — the shape of a stale
            # privileged-role snapshot restored onto an arbitrary user object
            # resolved via get_user_by()/findOneBy() with only an array-
            # membership check, no requester-identity/ownership verification
            # (CWE-266). CVE-2025-24648 (admin-site-enhancements 7.6.2.1).
            r"\$\w+->(add_role|set_role)\s*\(",
        ],
    },
    # CWE-639: a resource-scoping foreign key (course/group/team/org/etc. id)
    # used for an authorization decision is read from request input FIRST,
    # with the value that would normally be derived from the actual content
    # being accessed used only as a fallback when the parameter is absent —
    # see CVE-2026-57694 in VARIANT-PROVENANCE.md.
    "REQUEST_PARAM_OWNER_KEY_FALLBACK": {
        "group": "group-ac",
        "patterns": [
            r"\$\w*(?:course|group|team|org|project|tenant|workspace|community|board|class|cohort|plan|membership)_?id\w*\s*=\s*(?:\$_GET\[|\$_REQUEST\[|Input::get\(|filter_input\s*\(\s*INPUT_GET)",
        ],
    },
    # CWE-862: a "mark complete" / progress-tracking write call receives an
    # id-like variable directly — a lead for handlers that never verify the
    # caller is a member/owner/enrolled in that id's real parent resource
    # before writing completion state (self-triaged finding, not CVE-backed —
    # see the mark_lesson_complete entry in VARIANT-PROVENANCE.md).
    "PROGRESS_COMPLETION_WRITE_ID_ARG": {
        "group": "group-ac",
        "patterns": [
            r"(?:mark_\w*_complete|complete_\w*|update_progress|record_progress|mark_\w*_done|set_\w*_complete)\s*\(\s*\$\w*id\w*\s*[,)]",
        ],
    },
    # CWE-862/639: a getter/lookup call takes a nested "child" resource id
    # (question/item/line-item/field/answer/comment id) with no accompanying
    # call verifying it belongs to a scoping parent id also read from the
    # request — see CVE-2026-13765 in VARIANT-PROVENANCE.md.
    "CHILD_ID_GETTER_NO_PARENT_CONTAINMENT": {
        "group": "group-ac",
        "patterns": [
            r"\w*get_\w+\s*\(\s*\$\w*(?:question|item|child|line_item|field|answer|comment|slide)_id\b",
        ],
        # "permission_callback" also matches REST route arrays defined in a
        # child controller whose actual register_rest_route() call lives in
        # a shared abstract base class (a common WP plugin OOP pattern).
        "cross_file_filter": r"wp_ajax_|register_rest_route|admin_post_|permission_callback",
    },
    "IDOR_POST_META_WRITES": {
        "group": "group-d2",
        "patterns": [
            r"update_post_meta\s*\(\s*\$",
            r"delete_post_meta\s*\(\s*\$",
            r"add_post_meta\s*\(\s*\$",
        ],
    },
    "IDOR_POST_DELETE": {
        "group": "group-d2",
        "patterns": [
            r"wp_delete_post\s*\(\s*\$",
            r"wp_delete_attachment\s*\(\s*\$",
        ],
    },
    "IDOR_WC_ORDER_ACCESS": {
        "group": "group-d2",
        "patterns": [
            r"wc_get_order\s*\(\s*\$",
        ],
        "cross_file_filter": r"wp_ajax_|admin_post_|register_rest_route|wc_ajax_|rest_api_init|webhook|ipn|callback",
    },
    "IDOR_POST_READ_NO_AUTH": {
        "group": "group-d2",
        "patterns": [
            r"get_post\s*\(\s*\$",
            # get_post()'s ID argument wrapped in an int-cast helper before the
            # bare variable — intval()/absint()/(int) sanitize the TYPE but not
            # the caller's authorization, so this is the same missing-per-resource-
            # auth sink as the bare-variable form above. Confirmed real-world shape:
            # get_post( intval( $_POST['id'] ) ) with no current_user_can() gate.
            r"get_post\s*\(\s*(?:intval|absint)\s*\(",
            r"get_post\s*\(\s*\(int\)",
            r"get_post_field\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_|register_rest_route|admin_post_|add_shortcode",
    },
    "IDOR_SHORTCODE_ATTRIBUTE_ID": {
        "group": "group-d2",
        "patterns": [
            r"\$atts\[.*[Ii][Dd]",
        ],
        "cross_file_filter": r"add_shortcode",
    },
    "IDOR_ATTACHMENT_FILE_ACCESS": {
        "group": "group-d2",
        "patterns": [
            r"get_attached_file\s*\(\s*\$",
            r"wp_get_attachment_url\s*\(\s*\$",
            r"wp_get_attachment_image_src\s*\(\s*\$",
        ],
        "cross_file_filter": r"wp_ajax_|register_rest_route|admin_post_",
    },
    "WP_QUERY_DRAFT_STATUS_AJAX": {
        "group": "group-d2",
        "patterns": [
            r"'post_status'\s*=>\s*\[.*(?:draft|pending|future|trash|any)",
            r"['\"]post_status['\"]\s*=>\s*['\"](?:draft|pending|future|trash|any)",
            r"'post_status'\s*=>\s*array\s*\([^)]*(?:draft|pending|future|trash|any)",
            r"\['post_status'\]\s*=\s*['\"](?:draft|pending|future|trash|any)['\"]",
        ],
        "cross_file_filter": r"wp_ajax_|register_rest_route|add_shortcode",
        "case_insensitive": True,
    },
    "WP_PARSE_ARGS_WRONG_ORDER": {
        "group": "group-d2",
        "patterns": [r"=\s*wp_parse_args\("],
    },
    # CWE-470/CWE-862: a class name is used to dynamically instantiate an
    # object (`new $var(...)` or a `$var::method(...)` factory call) in a
    # file that also handles raw request input or builds a ReflectionClass
    # from a variable — the shape behind CVE-2026-12238 (wp-google-maps):
    # `$class::createInstance()` ran before the code verified, via
    # Reflection, that $class was an expected type, so an attacker-chosen
    # WPGMZA-namespaced class got instantiated (and its constructor's
    # side-effecting DB write executed) before the later type-mismatch
    # rejection fired. Purely textual — does not verify the class name is
    # actually request-derived or that the type check (if any) runs after
    # the instantiation; both require reading the surrounding function.
    "DYNAMIC_CLASS_FROM_REQUEST": {
        "group": "group-ac",
        "patterns": [
            r"new\s+\$\w+\s*\(",
            r"\$\w+::\$?\w+\s*\(",
        ],
        # cross_file_filter originally required a literal superglobal/get_param
        # token in the same file — misses plugins that funnel all request access
        # through a wrapper method (e.g. `self::parameter()`, `$this->param()`)
        # with the superglobal read living in a different, shared base-class
        # file. Broadened to also match generic wrapper-method name substrings
        # regardless of call-site prefix (self::/->/bare) — confirmed miss on a
        # `new $class()` dynamic-class-instantiation sink gated only by this
        # filter (audit evidence: bookly-responsive-appointment-booking-tool
        # 27.9, `self::parameter()` wrapper, no raw superglobal token anywhere
        # in the containing file).
        "cross_file_filter": r"ReflectionClass\s*\(|\$_REQUEST|\$_POST|\$_GET|->get_param\s*\(|->record\s*\[|->data\s*\[|->params\s*\[|\bparameter\s*\(|\bparam\s*\(|\brequest\s*\(|\binput\s*\(",
    },
    # ----- Auth Bypass / Broken Access Control: state-machine & account-state leads -----
    # CWE-841 (workflow/state-machine -> auth bypass): handler branches on a client-supplied
    # step/stage indicator gating a privileged auth sink — candidate for missing
    # server-side prerequisite-state check. Analyzed in Group E.
    "WORKFLOW_STEP_AUTH_SINK": {
        "group": "group-e",
        "patterns": [
            r"\$_(GET|POST|REQUEST)\s*\[\s*['\"](step|stage|phase|wizard|current_step|next_step|sub_?step|screen)['\"]",
            r"(get_query_var|->get_param)\s*\(\s*['\"](step|stage|phase|wizard)['\"]",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    # CWE-840 (idempotency/one-time-action): single-use flag written — verify it is
    # checked BEFORE being set (re-use/replay) and gates a real account/auth state change.
    # Analyzed in Group E (cross-ref Group B if it re-triggers a privileged grant).
    "ONETIME_AUTH_FLAG_REPLAY": {
        "group": "group-e",
        "patterns": [
            r"update_(post|user)_meta\s*\([^;]*['\"][a-z0-9_]*(used|redeemed|claimed|verified|completed|confirmed|activated|consumed|processed)[a-z0-9_]*['\"]",
            r"update_option\s*\([^;]*['\"][a-z0-9_]*(used|redeemed|claimed|verified|completed|confirmed|activated)[a-z0-9_]*['\"]",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    # CWE-639 (user-controlled key -> privilege escalation): a state-bearing account field
    # assigned directly from request, or a state field read from request. Analyzed in Group B.
    "ACCOUNT_STATE_FIELD_FROM_INPUT": {
        "group": "group-b",
        "patterns": [
            r"['\"](status|state|plan|tier|level|stage|membership|subscription|account_type|user_type|approved|enabled|active)['\"]\s*=>\s*\$_(GET|POST|REQUEST)",
            r"\$_(GET|POST|REQUEST)\s*\[\s*['\"](plan|tier|level|membership|subscription|account_type|user_type)['\"]\s*\]",
            r"update_(?:post|user)_meta\s*\(\s*\$\w+\s*,\s*['\"][a-z0-9_]*(?:enable[_-]?selling|is[_-]?vendor|vendor[_-]?status|vendor[_-]?enabled|seller[_-]?status)[a-z0-9_]*['\"]",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    # CWE-862 (missing authorization): a REST/AJAX handler accepts a full
    # outbound-email template (subject + body) as literal keys read straight
    # from the request itself, rather than from server-stored (admin) config.
    "EMAIL_TEMPLATE_FROM_REQUEST": {
        "group": "group-ac",
        "patterns": [
            r"\[\s*['\"](?:email|mail)_?(?:subject|body|template)['\"]\s*\]",
        ],
        "case_insensitive": True,
        "cross_file_filter": r"wp_mail\(|mail\(",
    },
    # CWE-862 (missing authorization): a verification/authentication-gate
    # function short-circuits to an unconditional pass when a configurable
    # auth-factor toggle (password-auth, 2FA, signature requirement, etc.) is
    # reported disabled, with no fallback secret/token comparison in that
    # branch. Codified from CVE-2026-27366 (mainwp-child <= 6.1.1):
    # is_verified_register() returned true whenever password auth was
    # disabled, with no fallback Unique Security ID check.
    "DISABLED_AUTH_FACTOR_UNCONDITIONAL_TRUE": {
        "group": "group-ac",
        "patterns": [
            r"if\s*\(\s*!\s*(?:\$\w+\s*->\s*)?\w*(?:is_enabled|enable|disab|require|is_active)\w*\s*\(",
            r"if\s*\(\s*empty\s*\(\s*(?:\$\w+\s*->\s*)?\w*(?:is_enabled|enable|disab|require|is_active)\w*\s*\(",
        ],
        "cross_file_filter": r"hash_equals\(|wp_check_password\(|password_verify\(|hash_hmac\(|wp_set_auth_cookie\(|wp_set_current_user\(",
        "exclude_patterns": [r"enable_debug|enable_cache|enable_log|enable_gzip|enable_compression|enable_minify"],
        "case_insensitive": True,
        "limit": 40,
    },
    # CWE-863 (incorrect authorization / type confusion): an object-type
    # allow-list restriction is enforced only inside an is_array() guard —
    # `is_array($RESTRICT) && ... && !in_array($ACTUAL, $RESTRICT)` — with no
    # companion branch for when $RESTRICT is a scalar. Codified from
    # CVE-2025-14736 (acf-frontend-form-element <= 3.28.29): a form's
    # "allowed post types" restriction, when set to a scalar (a single type,
    # or the plugin's own internal admin_form post type), silently bypassed
    # the containment check entirely, letting a request-derived object id
    # ($_GET/$_POST/$_REQUEST) resolve to ANY object regardless of the
    # configured type restriction.
    "TYPE_RESTRICTION_ARRAY_ONLY_BYPASS": {
        "group": "group-ac",
        "patterns": [
            r"is_array\(\s*\$[\w\[\]'\"]+\s*\)\s*&&[^;{}]*!\s*in_array\(",
        ],
        "limit": 40,
    },
    "TIME_BASED_EXPORT_FILENAME": {
        "group": "group-d1",
        # gmdate()/date() are equally guessable as time() when concatenated into a
        # filename (day+hour-granularity strings, not a random component) — added
        # alongside time() rather than replacing it.
        "patterns": [r"\btime\(\)", r"\bgmdate\s*\(", r"\bdate\s*\("],
        # "upload|attachment" widen the filter beyond true export/backup
        # terminology — a user-uploaded-file MIRROR copied to a second public
        # directory under a predictable name is the same disclosure shape as a
        # predictable export filename, just triggered by a form submission
        # instead of an admin-initiated export action.
        "cross_file_filter": r"csv|fputcsv|export|backup|upload|attachment",
        "line_filter": r"file|path|name|csv|export|backup",
    },
    # ===== GROUP D1 — Information Disclosure (Tier 10) =====
    "LOCALIZE_SCRIPT_SENSITIVE_DATA": {
        "group": "group-d1",
        "patterns": [
            r"wp_localize_script\(|wp_add_inline_script\(",
            # Raw inline-<script> echo of a JSON-encoded config array is the same
            # sink class as wp_localize_script()/wp_add_inline_script() — a value
            # ends up embedded in page-source-visible JS either way (confirmed
            # pattern: CWE-200 site-wide API/auth-token leak via a broad, often
            # under-gated hook such as admin_head/wp_head/wp_enqueue_scripts).
            r"echo\s+(?:json_encode|wp_json_encode)\s*\(",
        ],
        "cross_file_filter": r"(?i)api_key|apiKey|secret_key|private_key|client_secret|stripe|openai|recaptcha_secret|jwt|bearer|auth_token|site_token",
        "exclude_patterns": [r"nonce"],
    },
    "SETTINGS_SECRET_TO_HTML_ATTR": {
        "group": "group-d1",
        "patterns": [r"data-[\w-]+\s*=\s*[\"'].*esc_attr\s*\("],
        "cross_file_filter": r"(?i)access_token|api_key|secret_key|private_key|client_secret|auth_token",
        "line_filter": r"(?i)json_encode|settings|config",
        "exclude_patterns": [r"nonce"],
        "case_insensitive": True,
        "limit": 30,
    },
    "API_RESPONSE_PAGINATION_TOKEN": {
        "group": "group-d1",
        "patterns": [
            r"=\s*\$\w+(?:\[[^\]]*\]|->\s*\w+)*\s*->\s*paging\b",
            r"=\s*\$\w+(?:\[[^\]]*\]|->\s*\w+)*\s*\[\s*['\"]paging['\"]\s*\]",
        ],
        "limit": 30,
    },
    "LOG_FILE_PUBLIC_WRITE": {
        "group": "group-d1",
        "patterns": [
            r"file_put_contents\s*\(.*(?:log|\.txt|debug|error)",
            r"fopen\s*\(.*(?:log|\.txt|debug|error).*['\"](?:w|a)",
            r"fwrite\s*\(.*\$(?:log|file|handle|fp)",
        ],
        "cross_file_filter": r"(?i)wp_upload_dir|wp-content|uploads|plugin_dir_path|WP_CONTENT_DIR",
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"vendor_prefixed/"],
    },
    "USER_OBJECT_RESPONSE_EXPOSURE": {
        "group": "group-d1",
        "patterns": [
            r"\(array\)\s*\$(?:user|current_user|wp_user)",
            r"->data->user_pass|->user_pass(?!\w)",
            r"json_encode.*get_userdata|json_encode.*get_user_by|json_encode.*wp_get_current_user",
        ],
        "cross_file_filter": r"wp_ajax_|register_rest_route|wp_send_json|WP_REST_Response|rest_ensure_response",
        "exclude_patterns": [r"unset.*user_pass", r"wp_check_password", r"wp_set_password", r"single_user_pass", r"user_password", r"confirm_user"],
    },
    # CWE-200: an "*_id"-keyed value is pulled straight from the request (a raw
    # superglobal index or a framework array-accessor such as Arr::get()) and
    # cast via intval()/absint(), in a file that also emits a JSON response
    # (wp_send_json()-family) — the standard shape of a public AJAX/REST-style
    # data responder. Codified from a real-world fix: an AJAX handler resolved
    # a client-supplied ID straight into a settings/data getter with no
    # get_post()/get_post_status() existence-and-status check first, letting
    # an unauthenticated caller read settings/row data for draft, private, or
    # trashed objects by substituting an arbitrary ID. File-level lead only —
    # manual review must confirm the getter's return value reaches the JSON
    # response and that no get_post()/get_post_status()/current_user_can()
    # guard runs before it (see the companion Semgrep rule for the precise,
    # function-scoped version of this check).
    "REQUEST_ID_TO_JSON_RESPONSE_NO_STATUS_CHECK": {
        "group": "group-d1",
        "patterns": [
            r"intval\s*\(\s*Arr::get\(\s*\$\w+,\s*['\"]\w*_id['\"]",
            r"absint\s*\(\s*Arr::get\(\s*\$\w+,\s*['\"]\w*_id['\"]",
            r"intval\s*\(\s*\$_(?:REQUEST|POST|GET)\[\s*['\"]\w*_id['\"]\s*\]",
            r"absint\s*\(\s*\$_(?:REQUEST|POST|GET)\[\s*['\"]\w*_id['\"]\s*\]",
        ],
        "cross_file_filter": r"wp_send_json\s*\(|wp_send_json_success\s*\(",
    },
    "REST_PREPARE_FIELD_FILTERS": {
        "group": "group-d1",
        "patterns": [r"add_filter\s*\(\s*['\"]rest_prepare_"],
    },
    "EXPORT_FILE_PREDICTABLE_PATH": {
        "group": "group-d1",
        "patterns": [
            r"wp_upload_dir\s*\(\)",
            r"wp_get_upload_dir\s*\(\)",
        ],
        # "tmp|temp|cache|download" widen the filter beyond true export/backup
        # terminology — a temporary/cache/download-buffer file written with a
        # static filename directly under wp_upload_dir()'s basedir is the same
        # predictable-shared-path disclosure shape and used the same naming
        # convention that the narrower export/backup-only filter missed.
        # "upload|attachment" further widen it to user-uploaded-file MIRROR
        # copies (a form-plugin add-on persisting a second copy of a submitted
        # file attachment under wp_upload_dir() for admin review) — same
        # disclosure shape, unauthenticated-submission-triggered instead of
        # admin-export-triggered.
        "cross_file_filter": r"csv|fputcsv|export|backup|dump|\.sql|\.zip|imagepng|imagejpeg|imagegif|qrcode|qr_code|tmp|temp|cache|download|upload|attachment",
    },
    # CWE-862/CWE-269: a "form validator"-style helper ($obj->validateForm(),
    # ->isValid(), ->processForm(), ->validateRequest(), etc.) is commonly
    # mistaken for a security check. It confirms submitted fields match a
    # cached form definition; it carries neither wp_verify_nonce()'s CSRF
    # guarantee nor current_user_can()'s authorization guarantee. Surfaces
    # candidate gate call sites for the auditor to check whether
    # current_user_can() is present anywhere in the enclosing function.
    # Codified from CVE-2025-15403 (custom-registration-form-builder-with-
    # submission-manager / RegistrationMagic <= 6.0.7.1): admin_menu() wrote
    # an attacker-controlled per-role menu-accessibility array (later
    # consumed by add_cap()) gated only by
    # $this->mv_handler->validateForm('options_admin_menu'), with no
    # current_user_can() anywhere in the function.
    "FORM_VALIDATOR_SOLE_GATE_CANDIDATE": {
        "group": "group-ac",
        "patterns": [
            r"->\s*(?:validateForm|validate_form|validateRequest|validate_request|isValidForm|is_valid_form|isValidRequest|is_valid_request|processForm|process_form|formIsValid|form_is_valid|checkForm|check_form)\s*\(",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    # Post content/excerpt flowed into public head/meta markup (og:/twitter:
    # tags, JSON-LD, meta description) without a post_password_required()
    # guard in the same line's context — see CVE-2023-5845 in
    # VARIANT-PROVENANCE.md.
    "META_TAG_CONTENT_NO_PASSWORD_CHECK": {
        "group": "group-ac",
        "patterns": [
            r"(?:og:description|og:title|twitter:description|twitter:title|itemprop=[\"']description|application/ld\+json)[^;]{0,200}(?:get_the_excerpt|get_the_content|->\s*post_content|->\s*post_excerpt)\s*\(?",
            r"(?:get_the_excerpt|get_the_content|->\s*post_content|->\s*post_excerpt)\s*\([^;]{0,200}(?:og:description|og:title|twitter:description|twitter:title)",
            r"(?:og:description|og:title|twitter:description|twitter:title)[^;]{0,200}->\s*[a-zA-Z_]*(?:excerpt|description)[a-zA-Z_]*\s*\(",
        ],
        "case_insensitive": True,
        "limit": 40,
    },
    # A case-SENSITIVE route-prefix check (strpos/substr/strncmp against
    # $request->get_route()) gating a same-file parameter strip/hardening
    # call (unset($request[...])). WordPress's own REST dispatcher matches
    # routes case-insensitively, so this class of gate silently fails open
    # on an alternate-case route while WP still routes the request to the
    # same controller. Codified from CVE-2026-65508
    # (simply-schedule-appointments <= 1.6.12.10): a rest_pre_dispatch
    # handler stripped the internal-only append_where_sql parameter only
    # when strpos($request->get_route(), '/ssa/') !== 0, letting
    # /SSA/v1/... requests through with append_where_sql intact, which
    # was concatenated unescaped into a SQL WHERE clause.
    "REST_DISPATCH_CASE_SENSITIVE_ROUTE_GATE": {
        "group": "group-ac",
        "patterns": [
            r"\b(?:strpos|substr|strncmp)\s*\(\s*\$\w+\s*->\s*get_route\s*\(\s*\)",
        ],
        "cross_file_filter": r"unset\s*\(\s*\$\w+\[",
        "case_insensitive": True,
        "limit": 40,
    },
    "PHPINFO_SERVER_INFO": {
        "group": "group-d1",
        "patterns": [
            r"\bphpinfo\s*\(",
            r"\bphp_uname\s*\(",
            r"\bget_loaded_extensions\s*\(",
            r"\bphp_sapi_name\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_|register_rest_route|admin_post_|admin_init",
    },
    "ERROR_HANDLER_PATH_EXPOSURE": {
        "group": "group-d1",
        "patterns": [
            r"wp_die\s*\(\s*\$",
            r"wp_send_json_error\s*\(\s*\$",
            r"trigger_error\s*\(",
            r"getMessage\s*\(\)",
            r"->last_error",
        ],
        "cross_file_filter": r"wp_ajax_|register_rest_route|admin_post_",
        "exclude_patterns": [r"error_log", r"wp_die\s*\(\s*['\"]", r"wp_send_json_error\s*\(\s*['\"]", r"gettext|__\("],
    },
    "NOPRIV_DATA_RESPONSE": {
        "group": "group-d1",
        "patterns": [
            r"get_users\s*\(|get_user_by\s*\(|get_userdata\s*\(",
            r"get_option\s*\(",
            r"\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var",
        ],
        "cross_file_filter": r"wp_ajax_nopriv_|admin_post_nopriv_",
    },
    "REST_RETURN_TRUE_DATA_RESPONSE": {
        "group": "group-d1",
        "patterns": [
            r"get_users\s*\(|get_user_by\s*\(|get_userdata\s*\(",
            r"get_option\s*\(",
            r"\$wpdb->get_results|\$wpdb->get_row|\$wpdb->get_var",
            r"get_user_meta\s*\(|get_post_meta\s*\(",
            r"->user_email|->user_login|->display_name",
        ],
        "cross_file_filter": r"__return_true.*permission_callback|permission_callback.*__return_true",
        "exclude_patterns": [r"current_user_can", r"manage_options"],
    },
    "LOG_FILE_SESSION_TOKEN_WRITE": {
        "group": "group-d1",
        "patterns": [
            r"file_put_contents\s*\(",
            r"fwrite\s*\(",
            r"error_log\s*\(.*,\s*3\s*,",
        ],
        "cross_file_filter": r"(?i)cookie|session|token|auth|bearer|authorization|wp_get_session_token|wp_get_all_sessions",
        "line_filter": r"(?i)cookie|session|token|auth|header|bearer|\$_SERVER\[.HTTP_",
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"vendor_prefixed/"],
        "limit": 30,
    },
    "NONCE_FRONTEND_DISCLOSURE": {
        "group": "group-d1",
        "patterns": [
            r"wp_create_nonce\s*\(",
        ],
        "cross_file_filter": r"wp_enqueue_scripts|wp_footer|wp_head|wp_print_scripts|the_content|wp_localize_script|wp_add_inline_script",
        "exclude_patterns": [r"wp_create_nonce\s*\(\s*['\"]wp_rest['\"]"],
        "limit": 30,
    },
    "REST_SENSITIVE_CPT_EXPOSURE": {
        "group": "group-d1",
        "patterns": [
            r"register_post_type\s*\(",
        ],
        "cross_file_filter": r"show_in_rest.*true|'show_in_rest'\s*=>\s*true",
        "line_filter": r"(?i)order|appointment|booking|payment|subscription|invoice|transaction|customer|lead|ticket|submission|application|credential|secret|private|internal",
        "limit": 30,
    },
    "REST_META_FIELD_EXPOSURE": {
        "group": "group-d1",
        "patterns": [
            r"register_meta\s*\(|register_rest_field\s*\(",
        ],
        "cross_file_filter": r"show_in_rest.*true|'show_in_rest'\s*=>\s*true|auth_callback",
        "line_filter": r"(?i)api_key|secret|token|password|ssn|credit_card|billing|phone|email|address|ip_address|session",
        "exclude_patterns": [r"auth_callback.*manage_options|auth_callback.*current_user_can"],
        "limit": 30,
    },
    "AJAX_AUTH_ONLY_DATA_RESPONSE": {
        "group": "group-d1",
        "patterns": [
            r"get_option\s*\(.*(?:api_key|secret|license|token|password|smtp|stripe|paypal|credentials)",
            r"\$wpdb->get_results.*(?:user|email|order|payment|transaction|customer)",
            r"get_users\s*\(|get_user_by\s*\(|get_userdata\s*\(",
        ],
        "cross_file_filter": r"wp_ajax_(?!nopriv_)\w+",
        "exclude_patterns": [r"current_user_can\s*\(\s*['\"](?:manage_options|administrator|edit_others_posts|manage_woocommerce)", r"wp_ajax_nopriv_"],
        "exclude_path_patterns": [r"vendor/", r"node_modules/"],
        "limit": 30,
    },
    "PLUGIN_DIR_SENSITIVE_FILE_WRITE": {
        "group": "group-d1",
        "patterns": [
            r"file_put_contents\s*\(",
            r"fopen\s*\(.*['\"](?:w|a)",
            r"fwrite\s*\(",
        ],
        "cross_file_filter": r"plugin_dir_path|WP_PLUGIN_DIR|WP_CONTENT_DIR|ABSPATH|plugins_url",
        "line_filter": r"(?i)\.sql|\.log|\.bak|\.json|\.csv|\.xml|\.zip|config|dump|backup|export|debug",
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"vendor_prefixed/"],
        "exclude_patterns": [r"sys_get_temp_dir|/tmp/|tempnam"],
        "limit": 30,
    },
    # DB_PASSWORD (or another credential constant) referenced in a file that also
    # performs a raw file write — a common backup/migration idiom that bundles DB
    # credentials into a portable file; flag for manual check that the payload is
    # encrypted before it touches disk.
    "DB_CREDENTIALS_UNENCRYPTED_FILE_WRITE": {
        "group": "group-d1",
        "patterns": [
            r"\bDB_PASSWORD\b",
        ],
        "cross_file_filter": r"file_put_contents\s*\(|->put_contents\s*\(|fwrite\s*\(",
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"vendor_prefixed/"],
        "limit": 30,
    },
    "WPDB_PREFIX_RESPONSE_EXPOSURE": {
        "group": "group-d1",
        "patterns": [
            r"\$wpdb->prefix(?!\s*\.)",
            r"\$table_prefix(?!\s*\.)",
        ],
        "cross_file_filter": r"wp_send_json|WP_REST_Response|rest_ensure_response|wp_die|echo.*json_encode",
        "exclude_patterns": [r"\$wpdb->prefix\s*\.\s*['\"]", r"->prepare\(", r"->get_results\(", r"->query\("],
        "limit": 20,
    },
    # CWE-22 (path traversal via insufficient directory access restriction):
    # PHP code programmatically writes a `.htaccess` file into a directory
    # that stores generated artifacts (backup archives, DB dumps, logs,
    # export output), but the written content only sets `Options -Indexes`
    # (disables directory listing) with no `Deny from all` / `Require all
    # denied` directive — the directory is still directly web-requestable
    # file-by-file. Codified from CVE-2026-52703 (fastdup <= 2.7.2):
    # includes/Admin/Helper/Helper.php init_archive_directory() wrote
    # `Options -Indexes` as the entire `.htaccess` payload for the archive
    # directory holding full-site backup ZIPs; 2.7.3 rewrote the payload to
    # add `Require all denied` (Apache 2.4) / `Deny from all` (2.2) and added
    # ensure_htaccess() to actively repair a pre-existing weak file.
    # cross_file_filter is file-wide (not same-line) because the path
    # assignment, the content-literal assignment, and the write call are
    # normally three separate statements.
    "HTACCESS_WEAK_DENY_DIRECTIVE": {
        "group": "group-d1",
        "patterns": [
            r"file_put_contents\s*\(",
            r"fopen\s*\(.*['\"](?:w|a)",
            r"fwrite\s*\(",
        ],
        "cross_file_filter": r"(?is)(?=.*\.htaccess)(?=.*options\s*-indexes)(?!.*(?:deny\s+from\s+all|require\s+all\s+denied))",
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"vendor_prefixed/"],
        "limit": 30,
    },
    # CWE-200/CWE-552: mkdir()/wp_mkdir_p() creates a new subdirectory
    # beneath wp_upload_dir() to hold user-submitted or generated file
    # content, but the file contains no companion write of an index.html or
    # .htaccess guard anywhere. Complements HTACCESS_WEAK_DENY_DIRECTIVE
    # (an existing-but-weak .htaccess payload) by surfacing the opposite
    # gap: total absence of any protective file next to the
    # directory-creation call, leaving the folder directly listable/
    # web-fetchable. Manual check: confirm the enclosing function has no
    # fopen(...)/file_put_contents(...) call writing '.htaccess' or
    # 'index.html' into the same directory.
    "UPLOAD_MKDIR_NO_INDEX_PROTECTION": {
        "group": "group-d1",
        "patterns": [
            r"\bmkdir\s*\(",
            r"\bwp_mkdir_p\s*\(",
        ],
        "cross_file_filter": r"(?i)wp_upload_dir\s*\(\)",
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"vendor_prefixed/"],
        "limit": 30,
    },
    "POSTS_RESULTS_FILTER_HOOK": {
        "group": "group-d1",
        "patterns": [
            r"add_filter\s*\(\s*['\"](?:posts_results|the_posts)['\"]",
        ],
        "limit": 30,
    },
    "JSON_PATH_DYNAMIC_KEY_LOOKUP": {
        "group": "group-d1",
        "patterns": [
            r"JSON_EXTRACT\s*\(|JSON_UNQUOTE\s*\(",
        ],
        "cross_file_filter": r"\$wpdb->prepare\s*\(",
        "limit": 30,
    },
    # ===== GROUP E — Authentication Bypass (CWE-287/288) =====
    "SOCIAL_LOGIN_AUTH_COOKIE_FLOW": {
        "group": "group-e",
        "patterns": [
            r"get_user_by\s*\(\s*['\"]email['\"]",
            r"get_users\s*\(",
            r"email_exists\s*\(",
        ],
        # Session/cookie sinks (classic OAuth-bypass shape) OR an
        # account/order-ownership-binding sink (same unverified-email-match
        # defect, broader sink class — see vuln-audit E.1 item 7).
        "cross_file_filter": r"wp_set_auth_cookie|wp_set_current_user|wp_signon|set_user_id|set_customer_id|set_owner_id",
        "limit": 40,
    },
    # A WooCommerce/order-object PII getter (billing email/phone — a
    # non-secret, externally-knowable customer identifier) is compared
    # directly with ==/===/!=/!== to decide resource access, distinct from
    # SOCIAL_LOGIN_AUTH_COOKIE_FLOW's get_user_by()/email_exists() lookup
    # shape above (this sink is the order object's own accessor, not a WP
    # user lookup). Manual check: is this comparison one of several OR'd
    # branches alongside a genuine secret check (hash_equals()/order key),
    # and does it independently grant the same access?
    "ORDER_PII_FIELD_ACCESS_COMPARISON": {
        "group": "group-ab",
        "patterns": [
            r"===?\s*\(?\s*\$?\w+(?:->|::)get_billing_(?:email|phone)\s*\(",
            r"\$?\w+(?:->|::)get_billing_(?:email|phone)\s*\(\s*\)\s*\)?\s*===?",
        ],
        "limit": 30,
    },
    "LOOSE_COMPARISON_AUTH_TOKEN": {
        "group": "group-e",
        "patterns": [
            r"\$\w*(?:token|secret|password|auth_key|api_key|secret_key|reset_key|login_key|session_key|access_key|nonce|hmac|signature|license)\b\s*==\s*",
            r"\s*==\s*\$\w*(?:token|secret|password|auth_key|api_key|secret_key|reset_key|login_key|session_key|access_key|nonce|hmac|signature|license)\b",
            # Same class, but the "*key"-style variable is written in camelCase
            # rather than snake_case (e.g. userKey, sessionKey) — matched
            # case-insensitively via a scoped inline flag so the untouched
            # patterns above stay case-sensitive (avoids sweeping in unrelated
            # camelCase identifiers like an OAuth "accessToken" status check).
            r"\$\w*(?i:user_?key)\b\s*(?:==|!=)\s*",
            r"\s*(?:==|!=)\s*\$\w*(?i:user_?key)\b",
        ],
        "exclude_patterns": [r"===", r"!=="],
        "limit": 40,
    },
    "EMPTY_SECRET_COMPARISON": {
        "group": "group-e",
        "patterns": [
            r"get_option\s*\(.*(?:secret|api_key|auth_key|access_key|token|license_key|password|salt|signing|hmac).*\)",
            # HMAC key fetched via a live method/static/function call inlined directly into
            # hash_hmac() — the same empty-secret-forgery risk one hop behind a getter/facade
            # rather than a direct get_option() read in the same call.
            r"hash_hmac\s*\(.*\b[a-zA-Z_]\w*\s*\(\s*\)\s*\)\s*;?\s*$",
            # Same empty-by-default risk when the secret is read from per-record
            # metadata (post/user/comment meta) instead of a site-wide option.
            r"(?:get_post_meta|get_user_meta|get_comment_meta)\s*\([^)]*(?:secret|api_key|auth_key|access_key|token|license_key|password|salt|signing)[^)]*\)",
            # Same risk via a stored object's own get_meta() accessor (e.g. an
            # order/subscription verification key) rather than a procedural getter.
            r"->get_meta\s*\(\s*['\"][^'\"]*(?:secret|api_key|auth_key|access_key|token|license_key|password|salt|signing)[^'\"]*['\"]",
            # Same empty-by-default risk for a one-time verification code/passcode/
            # magic-link token stored under a per-record or transient key rather
            # than a generic-named secret — the getter returns '' when no code has
            # been generated yet for that identifier, and a loose comparison lets
            # an empty/omitted submitted value match it.
            r"(?:get_post_meta|get_user_meta|get_comment_meta|get_transient|get_option)\s*\([^)]*(?:otp|verification_?code|one_?time_?(?:code|pass)|passcode|pin_?code|magic_?(?:link|token))[^)]*\)",
        ],
        "cross_file_filter": r"hash_equals|hash_hmac|===|==|wp_verify_nonce|check_signature|verify",
        # "password" substring also matches WordPress's post-visibility password
        # concept (post_password, has_password) and plugin copy/import/duplicate
        # toggles referencing it (copypassword) — not an authentication secret.
        "exclude_patterns": [r"update_option|add_option|delete_option|date_format|generate_password|copy_?password|post_password|has_password|password_protected|password_required|get_option\s*\(\s*['\"][^'\"]*(?:path|url|endpoint|version|prefix|format|date|display|setting|notice|install|count|flag|status|mode|style|layout|enable|disable|page_id)[^'\"]*['\"]", r"wp_salt\s*\(|\b(?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)\b"],
        "limit": 40,
    },
    "WP_AUTHENTICATE_APP_PASSWORD_UNCHECKED": {
        "group": "group-e",
        "patterns": [
            r"wp_authenticate_application_password\s*\(",
            r"wp_authenticate\s*\(",
        ],
        "exclude_patterns": [r"is_wp_error\s*\("],
        "limit": 30,
    },
    # A custom login-validation function's own credential-verification call
    # (wp_authenticate()/wp_check_password()/wp_signon()/
    # wp_authenticate_application_password()) is gated behind a boolean
    # parameter defaulting to true — callers that omit/falsify it skip
    # password verification entirely. CVE-2025-67953 (booking-activities
    # <= 1.16.44, unauthenticated account takeover).
    "OPTIONAL_AUTH_FLAG_SKIPS_PASSWORD_CHECK": {
        "group": "group-ab",
        "patterns": [
            r"function\s+\w+\s*\([^)]*\$(?:require|verify|check|need|should|force|skip|do)_?(?:auth|password|creden|login)\w*\s*=\s*true",
        ],
        "cross_file_filter": r"wp_authenticate\s*\(|wp_check_password\s*\(|wp_signon\s*\(|wp_authenticate_application_password\s*\(",
        "limit": 30,
    },
    # A REST/webhook permission_callback gates its signature/HMAC
    # verification behind `if (empty($header))` / `if (! empty($header))`
    # on a value read from the request. An attacker who simply omits that
    # header skips verification entirely and reaches the function's
    # unconditional `return true;` fallthrough instead of a default-deny
    # (CWE-287/862 — "verify only if present" is equivalent to no
    # authentication for a caller who omits the credential).
    "WEBHOOK_PERMISSION_OPTIONAL_HEADER_DEFAULT_ALLOW": {
        "group": "group-ab",
        "patterns": [
            r"if\s*\(\s*!?\s*empty\s*\(\s*\$\w+\s*\)\s*\)\s*\{",
        ],
        "cross_file_filter": r"(?s)(?=.*->get_header\s*\()(?=.*\b(?:hash_hmac|hash_equals)\s*\()(?=.*\breturn\s+true\s*;)",
        "limit": 30,
    },
    "PREDICTABLE_AUTH_TOKEN_GENERATION": {
        "group": "group-e",
        "patterns": [
            r"md5\s*\(\s*\$\w*(?:user_id|user|uid|id)\b",
            r"md5\s*\(\s*(?:get_current_user_id\(\)|time\(\)|date\()",
            r"sha1\s*\(\s*\$\w*(?:user_id|user|uid|id)\b",
            r"substr\s*\(\s*md5\s*\(",
            r"substr\s*\(\s*sha1\s*\(",
            r"mt_srand\s*\(.*?(?:microtime|time|date)\s*\(",
        ],
        "cross_file_filter": r"wp_set_auth_cookie|wp_set_current_user|auto.?login|magic.?link|login_url|verify.*token|check.*token",
        "limit": 30,
    },
    # CWE-287 (improper authentication): password_verify() checks a plaintext
    # against a "hash" argument taken directly from request-controlled input
    # instead of a value the server previously stored. Because password_hash()
    # embeds its own random salt, an attacker can self-mint a valid hash for
    # any known/guessable plaintext offline and submit it as the cookie/
    # parameter value, defeating the check regardless of the plaintext's
    # entropy.
    "PASSWORD_VERIFY_REQUEST_CONTROLLED_HASH": {
        "group": "group-ab",
        "patterns": [
            r"password_verify\s*\([^;]*,\s*(?:\w+\s*\(\s*)*\$_(?:COOKIE|GET|POST|REQUEST)\b",
        ],
        "limit": 30,
    },
    # CWE-287/347: wp_check_password() contains a legacy branch
    # (strlen($hash)<=32 -> hash_equals($hash, md5($password))) that runs
    # before any bcrypt/phpass verification. Flags every call site for
    # manual argument-provenance triage (mirrors the audit-time "grep every
    # wp_check_password( call site" coverage check) plus the narrower
    # direct-superglobal-as-hash-argument shape.
    "WP_CHECK_PASSWORD_REQUEST_CONTROLLED_HASH": {
        "group": "group-ab",
        "patterns": [
            r"\\?wp_check_password\s*\(",
        ],
        "limit": 40,
    },
    "COOKIE_TO_AUTH_FUNCTION": {
        "group": "group-e",
        "patterns": [
            r"\$_COOKIE\[.*\].*wp_set_current_user|\$_COOKIE\[.*\].*wp_set_auth_cookie",
            r"wp_set_current_user\s*\(.*\$_COOKIE|wp_set_auth_cookie\s*\(.*\$_COOKIE",
            r"(?:!empty|isset)\s*\(\s*\$_COOKIE\[['\"][^'\"]*(?:skip|bypass|unlock|maintenance|access)",
            # CVE-2024-28000 class: the cookie-derived value is assigned to a
            # local variable first, and that bare variable is passed to
            # wp_set_current_user() several lines later (split assign-then-
            # call shape) — the same-line regexes above require both tokens
            # on one line and miss this shape.
            r"wp_set_current_user\s*\(\s*\$\w+\s*\)\s*;",
            # Same split assign-then-call shape as above, for wp_set_auth_cookie()
            # specifically — the bare identifier variable may carry extra trailing
            # args (true/is_ssl()) that the plain single-arg regex above doesn't cover.
            r"wp_set_auth_cookie\s*\(\s*\$\w+\s*(?:,[^;]*)?\)\s*;",
            # Cookie value (direct or via an intermediate variable, matched
            # via cross_file_filter) compared with ==/=== to a hardcoded
            # auth/session status-word literal — a fixed constant baked into
            # the plugin's own source rather than a per-install secret or a
            # signed/hashed token, so the expected value never varies.
            r"\$_COOKIE\[[^\]]+\]\s*={2,3}\s*['\"](?:authenticated|verified|valid|granted|unlocked|active|confirmed|logged.?in)['\"]",
            r"['\"](?:authenticated|verified|valid|granted|unlocked|active|confirmed|logged.?in)['\"]\s*={2,3}\s*\$_COOKIE\[",
            r"['\"](?:authenticated|verified|valid|granted|unlocked|active|confirmed|logged.?in)['\"]\s*={2,3}\s*\$\w+\b",
            r"\$\w+\s*={2,3}\s*['\"](?:authenticated|verified|valid|granted|unlocked|active|confirmed|logged.?in)['\"]",
        ],
        "cross_file_filter": r"\$_COOKIE",
        "limit": 20,
    },
    "JWT_DECODE_NO_VERIFY": {
        "group": "group-e",
        "patterns": [
            r"JWT::decode\s*\(",
            r"Firebase\\JWT|firebase.*jwt",
            r"base64_decode\s*\(.*explode\s*\(\s*['\"]\\.['\"]",
            r"json_decode\s*\(\s*base64_decode",
            # Non-JWT custom bearer token: a client-supplied token is base64-decoded
            # into a variable that is later regex-parsed for an embedded identifier
            # (CVE-2026-4880 class) — same insufficient-verification defect as a
            # manually-parsed JWT, without the dot-delimited/json_decode() structure.
            r"=\s*@?base64_decode\s*\(\s*\$\w*(?i:token)\w*\s*\)",
        ],
        "cross_file_filter": r"wp_set_auth_cookie|wp_set_current_user|wp_signon|user_id|get_user_by|authenticate",
        "limit": 30,
    },
    "STRPOS_DOMAIN_VALIDATION": {
        "group": "group-e",
        "patterns": [
            r"strpos\s*\(.*(?:domain|host|origin|referer|remote_addr|ip_address|server_name)",
            r"str_contains\s*\(.*(?:domain|host|origin|referer|remote_addr|ip_address|server_name)",
        ],
        "line_filter": r"(?i)valid|check|verify|allow|trust|whitelist|permit|auth",
        "limit": 30,
    },
    "STRPOS_USERNAME_ALLOWLIST_MEMBERSHIP": {
        "group": "group-ab",
        "patterns": [
            r"strpos\s*\(.*user_login",
            r"str_contains\s*\(.*user_login",
            r"strpos\s*\(.*->(?:user_email|user_nicename|display_name)\b",
        ],
        "limit": 30,
    },
    "PASSWORD_RESET_FLOW": {
        "group": "group-ab",
        "patterns": [
            r"get_password_reset_key\s*\(",
            r"check_password_reset_key\s*\(",
            r"reset_password\s*\(",
            r"retrieve_password\s*\(",
            # CVE-2026-8206 class: the account is resolved by a request-
            # controlled non-email identifier (login/id/slug) — a
            # co-occurring signal for the recipient-ownership variant.
            r"get_user_by\s*\(\s*['\"](login|id|slug)['\"]",
            # CVE-2025-14975 class: a plugin hooks WP core's random_password
            # filter (used by wp_generate_password(), which
            # get_password_reset_key() itself calls) — trusting request data
            # here poisons every reset key generated process-wide.
            r"add_filter\s*\(\s*['\"]random_password['\"]",
        ],
        "limit": 30,
    },
    # CWE-287: an authentication/verification-code check compares two values
    # BOTH read directly from request superglobals in the same condition —
    # the "expected" side was never independently re-fetched from
    # server-side storage — a tautological comparison an attacker can
    # satisfy by supplying matching values for both sides. Co-occurrence
    # with a login-completing sink elsewhere in the file narrows the lead to
    # the exploitable shape; manual review confirms neither operand is a
    # fresh server-side lookup.
    "OTP_COMPARISON_BOTH_SIDES_REQUEST_CONTROLLED": {
        "group": "group-ab",
        "patterns": [
            r"(?:\w+\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*={2,3}\s*(?:\w+\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\[",
        ],
        "cross_file_filter": r"wp_set_auth_cookie|wp_set_current_user|wp_signon",
        "limit": 30,
    },
    "RECOVERY_CODE_VALIDATION_BRANCH_MISMATCH": {
        "group": "group-ab",
        "patterns": [
            # CVE-2025-31095 class: a custom recovery/verification/OTP-code
            # validator call exists in the file (name containing
            # verification/recovery/otp/reset + code + valid/verify/check).
            # Co-occurring with a custom credential-change sink (see
            # cross_file_filter below) is a candidate for the "validator
            # call lives only in the sibling branch of an if/else, so
            # supplying code + new-value together in one request bypasses
            # it" class. Grep here is a coarse file-level co-occurrence
            # lead only — manual review must confirm the validator call is
            # NOT unconditionally reachable before the credential-change
            # sink (i.e. that it isn't hoisted above the branch, per the
            # real fix shape).
            r"(?i)\w*(?:verification|recovery|otp|reset)_?code\w*_(?:is_)?valid\w*\s*\(",
            r"(?i)(?:is_|validate_|verify_)\w*(?:verification|recovery|otp|reset)_?code\w*\s*\(",
        ],
        "cross_file_filter": r"(?i)\w*(?:change|set|reset|update)_(?:password|credential)\w*\s*\(",
        "limit": 20,
    },
    # CWE-200/287: a one-time verification code (OTP/passcode/2FA code) is
    # placed under a like-named array key that is also passed to a JSON-
    # response sink (wp_send_json()-family) in the same file — either the
    # code-holding variable is echoed back verbatim, or the code-generating
    # call is made inline as the key's value. The out-of-band channel the
    # code is supposed to require (SMS/email) is bypassed entirely because
    # the code is readable directly from the HTTP response. File-level lead
    # only — manual review must confirm the emitted value is the actual
    # generated secret (not a masked/hashed transform or an unrelated
    # reference code) and that a JSON-response sink is reachable from the
    # same code path.
    "OTP_VALUE_IN_JSON_RESPONSE": {
        "group": "group-ab",
        "patterns": [
            r"(?i)['\"]\w*(?:otp|passcode|verification_?code|auth_?code|security_?code)\w*['\"]\s*=>\s*\$\w*(?:otp|passcode|verification_?code|auth_?code|security_?code)\w*\b",
            r"(?i)['\"]\w*(?:otp|passcode|verification_?code|auth_?code|security_?code)\w*['\"]\s*=>\s*\w*(?:otp|sms|totp|passcode)\w*(?:gen|send|create|make)\w*\s*\(",
        ],
        "cross_file_filter": r"wp_send_json(?:_success|_error)?\s*\(",
        "limit": 30,
    },
    "AUTOLOGIN_MAGIC_LINK": {
        "group": "group-e",
        "patterns": [
            r"(?i)auto.?login|magic.?link|one.?time.?login|passwordless|login.?token|login.?key|login.?link|instant.?login",
        ],
        "cross_file_filter": r"wp_set_auth_cookie|wp_set_current_user|wp_signon",
        "limit": 30,
    },
    # CWE-287 (improper authentication): a third-party identity-verification
    # response (an OTP/social-login provider) is gated only on the presence of
    # its own token/identity field, never compared against the request-
    # controlled identifier used to resolve which account is logged in.
    "THIRD_PARTY_VERIFIED_IDENTITY_UNCHECKED_LOGIN": {
        "group": "group-ab",
        "patterns": [
            r"isset\s*\(\s*\$\w+\s*->\s*(?:idToken|phoneNumber|localId|id_token|access_token)\s*\)",
            # A local OTP/token-named validator function definition — a lead for the
            # "reads its own prior-challenge state back from $_SESSION but never
            # hash_equals()-binds it to the caller-supplied identifier" variant.
            r"function\s+(?!(?:send|generate|create|issue)_)\w*(?:otp|token|verif|2fa|mfa)\w*\s*\(",
            # A plural, meta-value-style user lookup assigned to a variable — a
            # lead for the "get_users() resolves an account from a request-
            # controlled identifier with no in-function code/OTP check before
            # the session grant" variant.
            r"\$\w+\s*=\s*get_users\s*\(\s*(?:\$\w+|array\s*\()",
            # CVE-2026-15014 class: the identity-binding check that should tie
            # a generic "verified" session flag to the specific identifier
            # just verified is itself wrapped in `!empty($_SESSION[...]) &&`,
            # so when that companion session value is unset (e.g. a
            # DIFFERENT, unrelated flow set the shared boolean flag) the
            # mismatch check is silently skipped instead of failing closed —
            # an existence-gated guard that only sometimes runs is
            # equivalent to no guard at all for the identifier binding.
            r"!\s*empty\s*\(\s*\$_SESSION\[[^\]]+\]\s*\)\s*&&[^;{]*(?:strpos|substr|===?|!==?)\b",
        ],
        "cross_file_filter": r"(?s)(?=.*get_user(?:s|_by)\s*\()(?=.*(?:wp_set_auth_cookie|wp_set_current_user)\s*\()",
        "limit": 30,
    },
    # CWE-287/347: openssl_verify() (and any "verify"-style wrapper method on a
    # signature/DSig object that directly forwards its return value) returns a
    # tri-state int — 1 valid, 0 invalid, -1 processing error — and -1 is
    # truthy in PHP, so a plain `if (!$result)` check silently accepts a
    # verification ERROR as a successful signature match. Only a strict
    # comparison against 1 is safe; manually confirm the matched call site
    # never performs that strict check before reporting.
    "OPENSSL_VERIFY_LOOSE_CHECK": {
        "group": "group-ab",
        "patterns": [
            r"if\s*\(\s*!\s*openssl_verify\s*\(",
            r"if\s*\(\s*!\s*\$\w*(?i:sig)\w*\s*->\s*verify\s*\(",
        ],
        "limit": 30,
    },
    # CWE-287/294: a file both verifies a request signature (openssl_verify()
    # or an HMAC via hash_hmac()) and grants an authenticated session
    # (wp_set_current_user()/wp_set_auth_cookie()), with no add_option() call
    # anywhere in the file. add_option() is the standard WP idiom for an
    # atomic "set only if not already present" check; its absence means a
    # cryptographically valid signed request has no single-use/replay guard
    # and can be resubmitted indefinitely to re-authenticate as the resolved
    # account. Lead only — confirm the signature payload actually includes a
    # nonce/timestamp and that no get_transient()/set_transient() pair (a
    # non-atomic but partial mitigation) already covers it before reporting.
    "SIGNATURE_AUTH_NO_REPLAY_GUARD": {
        "group": "group-ab",
        "patterns": [
            r"add_option\s*\(",
        ],
        "invert": True,
        "cross_file_filter": r"(?s)(?=.*\b(?:openssl_verify|hash_hmac)\s*\()(?=.*\b(?:wp_set_current_user|wp_set_auth_cookie)\s*\()",
        "exclude_path_patterns": [r"vendor/", r"node_modules/"],
        "limit": 30,
    },
    # CWE-287/640: a request dispatcher routes to a password/credential-reset
    # handler on a bare $_REQUEST/$_POST/$_GET literal-equality match, with no
    # $_SESSION reference anywhere in the same gating condition — the
    # OTP/recovery-code verification step and the mutating dispatch are
    # decoupled, so the verification step can be skipped entirely. The routed
    # literal must combine a mutation verb with a password/credential noun
    # (mirrors a plain "validate/verify the code" routing key, which is a
    # legitimate no-prior-check step, not the mutating one). Same-line
    # exclude on $_SESSION filters the fixed shape, where the real fix adds a
    # session-state check into the same condition.
    "PASSWORD_RESET_DISPATCH_NO_SESSION_CHECK": {
        "group": "group-ab",
        "patterns": [
            r"\$_(?:REQUEST|POST|GET)\s*\[[^\]]+\]\s*\)*\s*===?\s*['\"](?=[\w-]*(?:reset|change|update|set))(?=[\w-]*(?:pass|pwd|password|credential))[\w-]*['\"]",
        ],
        "exclude_patterns": [
            r"\$_SESSION",
        ],
        "limit": 30,
    },
    # A manually constructed WP_REST_Request that is never dispatched through
    # rest_do_request()/$server->dispatch() bypasses the route's own
    # registered permission_callback entirely — the request object is
    # consumed by a direct controller method call instead of WordPress's own
    # REST routing/permission-enforcement layer. Leads-only: legitimate
    # internal dispatch via rest_do_request()/dispatch() also matches this
    # construction pattern and must be excluded manually.
    "MANUAL_REST_REQUEST_CONSTRUCTION": {
        "group": "group-ab",
        "patterns": [
            r"new\s+\\?WP_REST_Request\s*\(",
        ],
        "exclude_path_patterns": [r"vendor/", r"node_modules/", r"vendor_prefixed/", r"tests?/"],
        "limit": 30,
    },
}

# Per-pattern exclude for CAPABILITY_HANDLER_CROSSREF pattern index 1
_CAPABILITY_CROSSREF_PAT1_EXCLUDE = re.compile(
    r"manage_options|edit_others|upload_files|unfiltered_html"
)
assert "current_user_can" in SECTIONS["CAPABILITY_HANDLER_CROSSREF"]["patterns"][1], \
    "CAPABILITY_HANDLER_CROSSREF pattern order changed — update pat_idx == 1 logic in run_section()"

# Bucket key -> output filename, from the shared registry (surface + foundation meta
# buckets, then one file per impact group).
GROUP_FILE_MAP = group_registry.grep_file_map()

# Ordered section lists per group (controls output order)
GROUP_SECTION_ORDER = {
    "surface": [
        "STANDALONE_PHP", "AJAX_HOOKS", "WC_AJAX_HOOKS", "ADMIN_HOOKS",
        "INIT_HOOKS", "PAGEBUILDER_HOOKS", "REST_ENDPOINTS", "SHORTCODES",
        "DO_SHORTCODE_CONTENT_FILTER",
        "OUTBOUND_HTTP", "REDIRECTS", "EMAIL", "INPUT_SUPERGLOBALS",
        "INPUT_STREAMS", "DB_READS", "CRYPTO_OPS", "REST_FIELD_REGISTRATIONS",
        "REST_NONCE_EXPOSURE", "CSV_EXPORT_SURFACE", "WP_CLI_COMMANDS",
        "NON_AJAX_DISPATCHERS", "RAW_ACTION_PARAM_DISPATCH", "SQL_FILTER_HOOKS", "BLOCK_TYPES",
        "JSON_ENCODE_SURFACE", "JSON_WRAPPER_METHOD_ECHO", "ADMIN_LIST_TABLES", "WP_USER_QUERY",
        "ADMIN_GET_DISPATCHERS", "ROLE_CAPABILITY_MAPPING", "ROLE_ARRAY_MEMBERSHIP_CHECK",
        "WC_STORE_API_ENDPOINTS", "BROKEN_AUTH_LOGIC",
        "NOPRIV_WP_QUERY_POST_STATUS", "NOPRIV_CUSTOM_TABLE_POST_STATUS",
        "WPQUERY_PERM_READABLE", "SHORTCODE_WP_QUERY_POST_STATUS",
        "CAPABILITY_HANDLER_CROSSREF", "NOPRIV_AJAX_SQL_CROSSREF",
        "REST_SQL_CROSSREF", "REST_ARRAY_MERGE_INJECTION", "TAXONOMY_WRITES",
        "SLIM_FASTROUTE_ROUTER",
        "POI_BUNDLED_LIBRARIES",
        "COMPOSER_DEPENDENCY_FILES",
    ],
    # Foundation phase: auth / reachability / custom-sink FACTS, aggregated from
    # existing sections. These sections ALSO remain in their original group files —
    # the writer keys results by section NAME, so one section may appear in several
    # group output files. Built once, read by the Foundation sub-agent before the
    # impact groups so every group inherits the auth floor + custom-wrapper map.
    "foundation": [
        # Reachability / entry points
        "STANDALONE_PHP", "AJAX_HOOKS", "WC_AJAX_HOOKS", "ADMIN_HOOKS",
        "INIT_HOOKS", "PAGEBUILDER_HOOKS", "REST_ENDPOINTS", "SHORTCODES",
        "REST_FIELD_REGISTRATIONS", "REST_NONCE_EXPOSURE",
        "NON_AJAX_DISPATCHERS", "RAW_ACTION_PARAM_DISPATCH", "ADMIN_GET_DISPATCHERS", "SLIM_FASTROUTE_ROUTER",
        "WC_STORE_API_ENDPOINTS",
        # Roles / capabilities / auth logic
        "ROLE_CAPABILITY_MAPPING", "ROLE_ARRAY_MEMBERSHIP_CHECK", "BROKEN_AUTH_LOGIC",
        "CAPABILITY_HANDLER_CROSSREF", "TIER4_CAPABILITY_CHECKS", "CPT_PAGE_CAPABILITY_TYPE",
        # Auth gates / token flows / custom wrappers (sink-inventory seed)
        "SECURITY_GATE_FUNCTIONS", "AUTH_INTERMEDIARIES",
        "TOKEN_AUTH_FLOWS", "TOKEN_LOCALIZE_EXPOSURE",
        "CUSTOM_UNSERIALIZE_WRAPPERS", "CUSTOM_TEMPLATE_LOADER_FUNCTIONS",
    ],
    "group-a": [
        "TIER1_CODE_EXEC", "TIER1_DESERIALIZATION", "DYNAMIC_HOOK_NAME_EXECUTION", "EXTRACT_VARIABLE_CLOBBER", "TIER1_COMMAND_EXEC",
        "TIER1_TEMPLATE_ENGINES", "TWIG_LOADER_TAINTED_FIELD_VALUE", "TIER1_FILE_WRITE", "WEBSERVER_DIRECTIVE_HEADER_CONCAT",
        "TIER2_FILE_READ",
        "TIER2_FILE_DELETE", "URL_PATH_DERIVED_CACHE_DELETE", "FILE_EXISTS_BEFORE_DELETE",
        "WP_FILESYSTEM_DELETE", "STRPOS_PATH_PREFIX_CONTAINMENT", "REALPATH_REASSIGN_NO_CONTAINMENT",
        "DELETE_HANDLER_REGISTRATION", "REQUEST_METHOD_DELETE_DISPATCH",
        "FILE_DELETE_USER_INPUT_DIRECT", "BATCH_FILE_DELETE",
        "FILE_WRITE_USER_INPUT_DIRECT",
        "RECURSIVE_DIRECTORY_DELETE",
        "TIER2_CONTENT_DELETE", "CONTENT_DELETE_HANDLER_REGISTRATION",
        "CONTENT_DELETE_USER_INPUT_DIRECT",
        "FILE_DOWNLOAD_ENDPOINTS", "FILE_READ_STREAM_FUNCTIONS",
        "DOWNLOAD_HANDLER_REGISTRATION", "WP_FILESYSTEM_READ",
        "PATH_CONCAT_LTRIM_JOIN", "MAIL_ATTACHMENT_BASEDIR_CONCAT",
        "READFILE_USER_INPUT_DIRECT", "REQUEST_PARAM_FILENAME_CONCAT_NO_CAST",
        "REQUEST_ARRAY_FILE_LIST_LOOP",
        "UPLOAD_TEST_TYPE_FALSE", "FILES_ARRAY_INDEX_ZERO_ONLY_VALIDATION",
        "STRPOS_ARITHMETIC_EXTENSION_CHECK", "MIME_ALLOWLIST_LOOP_EXTENSION_UNBOUND",
        "REQUEST_CONTROLLED_UPLOAD_ALLOWLIST", "PHP_EXTENSION_DENYLIST_ARRAY",
        "EXIF_IMAGETYPE_WEAK_UPLOAD_GATE", "WP_FILESYSTEM_COPY_NO_FILETYPE_CHECK",
        "ORIGINAL_FILENAME_KEY_NO_FILETYPE_CHECK", "FILENAME_VALIDATOR_NO_EXTENSION_CHECK",
        "DATA_URI_DECODE_RAW_FILE_WRITE",
        "FILETYPE_CHECK_NO_HALT_BEFORE_PERSIST", "ZIP_HANDLING",
        "PHAR_WRAPPER", "PHP_STREAM_WRAPPERS",
        "FILE_PUT_CONTENTS_USER_PATH",
        "INCLUDE_REQUIRE_USER_INPUT", "TEMPLATE_LOADING_USER_INPUT",
        "INCLUDE_CONCAT_VARIABLE", "CLASS_FACTORY_ROUTER_PARAM", "DYNAMIC_CLASS_FROM_REQUEST", "SHORTCODE_ATTR_TEMPLATE_INCLUDE",
        "WP_TEMPLATE_PARAM_NAMES", "TEMPLATE_SELECTOR_WEAK_SANITIZER",
        "DB_STORED_PATH_TO_INCLUDE", "AJAX_TEMPLATE_PARAM_INCLUDE",
        "NESTED_ARRAY_INPUT_TO_INCLUDE", "FILE_EXISTS_BEFORE_INCLUDE",
        "FILE_EXISTS_NEGATED_GUARD_CONCAT",
        "DYNAMIC_FILE_EXTENSION_INCLUDE", "CUSTOM_TEMPLATE_LOADER_FUNCTIONS",
        "WP_KSES_ON_FILE_PATH",
        "BASE64_TO_UNSERIALIZE",
        "RECURSIVE_UNSERIALIZE_REPLACE", "POI_MAGIC_METHODS",
        "SHORTCODE_ATTR_UNSERIALIZE", "COOKIE_DESERIALIZATION",
        "CUSTOM_META_TABLE_UNSERIALIZE", "TOKEN_META_WRITE_NO_SERIALIZE",
        "JSON_DECODE_TO_CODE_EXEC", "PLUGIN_ACTIVATION_CALLS",
        "ATTACHMENT_METADATA_UNLINK", "REGISTER_SETTING_NO_SANITIZE",
        "EXTRACT_SUPERGLOBALS",
        "VARIABLE_FUNCTION_CALLS", "CALLABLE_VARIABLE_CHAINED_INVOCATION",
        "PREFIXED_DYNAMIC_FUNCTION_NAME", "CALLBACK_ACCEPTING_FUNCTIONS",
        "REGEX_CAPTURE_CALLBACK_HANDLERS", "UNESCAPED_SECRET_REGEX_GATE",
        "DO_SHORTCODE_RCE", "COMMENT_TEXT_DO_SHORTCODE",
        "STRIPSLASHES_SUPERGLOBAL_MISSING_STRIP_SHORTCODES",
        "SHORTCODE_TOGGLE_DEFAULT_ENABLED",
        "SHORTCODE_CALLBACK_OB_BUFFER_MISSING_STRIP_SHORTCODES",
        "SHORTCODE_CONSTRUCTION_INJECTION", "REST_RETURN_TRUE_CODE_EXEC",
        "REST_RETURN_TRUE_PLUGIN_INSTALL", "PLACEHOLDER_CODE_EXEC",
        "UPLOAD_DESTINATION_FROM_USER", "CUSTOM_UPLOAD_WRAPPER_RAW_FILENAME",
        "IMPORT_HANDLER_UNSERIALIZE",
        "CUSTOM_UNSERIALIZE_WRAPPERS",
        "UPLOAD_MIMES_FILTER", "FILETYPE_AND_EXT_FILTER_OVERRIDE",
        "DIRECT_FILES_SUPERGLOBAL_UPLOAD", "REST_FILE_PARAMS",
        "SIDELOAD_HANDLERS", "UPLOAD_PREFILTER_HOOKS",
        "WP_UPLOAD_BITS_USER_FILENAME", "FORM_RECORD_RAW_VALUE_ACCESS",
        "CUSTOM_PATH_SEGMENT_COLLAPSE",
    ],
    # Auth Bypass (CWE-287/288). Runs EARLY — right after Foundation. Includes the
    # token-auth exposure sections (auth-primitive leaks feed the auth-bypass analysis).
    "group-ab": [
        "WORKFLOW_STEP_AUTH_SINK", "ONETIME_AUTH_FLAG_REPLAY",
        "SOCIAL_LOGIN_AUTH_COOKIE_FLOW",
        "ORDER_PII_FIELD_ACCESS_COMPARISON",
        "LOOSE_COMPARISON_AUTH_TOKEN",
        "EMPTY_SECRET_COMPARISON",
        "WP_AUTHENTICATE_APP_PASSWORD_UNCHECKED",
        "OPTIONAL_AUTH_FLAG_SKIPS_PASSWORD_CHECK",
        "WEBHOOK_PERMISSION_OPTIONAL_HEADER_DEFAULT_ALLOW",
        "PREDICTABLE_AUTH_TOKEN_GENERATION",
        "PASSWORD_VERIFY_REQUEST_CONTROLLED_HASH",
        "WP_CHECK_PASSWORD_REQUEST_CONTROLLED_HASH",
        "COOKIE_TO_AUTH_FUNCTION",
        "JWT_DECODE_NO_VERIFY",
        "STRPOS_DOMAIN_VALIDATION",
        "STRPOS_USERNAME_ALLOWLIST_MEMBERSHIP",
        "PASSWORD_RESET_FLOW",
        "OTP_COMPARISON_BOTH_SIDES_REQUEST_CONTROLLED",
        "RECOVERY_CODE_VALIDATION_BRANCH_MISMATCH",
        "OTP_VALUE_IN_JSON_RESPONSE",
        "AUTOLOGIN_MAGIC_LINK",
        "THIRD_PARTY_VERIFIED_IDENTITY_UNCHECKED_LOGIN",
        "OPENSSL_VERIFY_LOOSE_CHECK",
        "SIGNATURE_AUTH_NO_REPLAY_GUARD",
        "PASSWORD_RESET_DISPATCH_NO_SESSION_CHECK",
        "MANUAL_REST_REQUEST_CONSTRUCTION",
        # Token-auth exposure (auth-primitive leaks that feed auth-bypass analysis)
        "TOKEN_AUTH_FLOWS", "TOKEN_LOCALIZE_EXPOSURE",
    ],
    # Access Control — missing-auth + IDOR + CSRF + options/content/account-state
    # writes + plugin-install. Runs right after Auth-Bypass; fills auth-model.md
    # Verdict/CIA columns for the impact groups that follow.
    "group-ac": [
        "ACCOUNT_STATE_FIELD_FROM_INPUT",
        "EMAIL_TEMPLATE_FROM_REQUEST",
        "DISABLED_AUTH_FACTOR_UNCONDITIONAL_TRUE",
        "TYPE_RESTRICTION_ARRAY_ONLY_BYPASS",
        "TIER4_CAPABILITY_CHECKS",
        "CPT_CUSTOM_CAPABILITIES", "CPT_PAGE_CAPABILITY_TYPE", "REST_POST_TYPE_PARAM", "TEMPLATE_REDIRECT_LOGIN_GATE", "REST_PERMISSION_CHECK_HAS_CAP",
        "REST_LOGIN_ONLY_PERMISSION", "REST_NONCE_ONLY_PERMISSION", "REST_REFLECTION_PERMISSION_WIRING",
        "REST_PERMISSION_CHECK_NAMED_ALWAYS_TRUE",
        # Option/setting sentinel-gated `return true;` with no visible
        # login/capability check (CWE-862/287) — see CVE-2025-68015 in
        # VARIANT-PROVENANCE.md.
        "REST_PERMISSION_OPTION_SENTINEL_RETURN_TRUE",
        "REST_ITEMS_PERM_ON_WRITE_ROUTE", "REST_ITEM_PERMISSION_NO_CONTEXT_CHECK",
        "REST_PERMISSION_TYPE_DISCRIMINATOR_NULL_DEFAULT",
        "TIER4_OPTION_WRITES",
        "NOPRIV_OPTION_WRITES", "NOPRIV_USER_WRITES", "ROLE_KEY_ASSIGNED_FROM_REQUEST_LOOP",
        "ROLE_KEY_CONDITIONAL_OVERRIDE_ONLY",
        "ROLE_REGISTRATION_ADMIN_CAP_PARITY", "REST_USER_CREATION_ROLE_ELEVATION",
        "DYNAMIC_HOOK_GATE_ROLE_WRITE",
        "PREMODERATION_ONLY_GATE_ROLE_WRITE",
        "NOPRIV_CONTENT_DELETES",
        "NOPRIV_CONTENT_WRITES", "NOPRIV_COMMENT_WRITES", "NOPRIV_COMMENT_READS",
        "NOPRIV_TERM_WRITES", "NOPRIV_THUMBNAIL_WRITES",
        "NOPRIV_SELF_ATTESTED_CAPABILITY",
        "AJAX_AUTHENTICATED_FILE_WRITE_SIGNAL",
        # Plugin/theme install & activation (Missing Authorization -> RCE)
        "PLUGIN_THEME_INSTALL_SINKS", "MANUAL_PLUGIN_THEME_INSTALL",
        "INSTALL_ACTIVATE_HANDLER_REGISTRATION", "NOPRIV_PLUGIN_THEME_INSTALL",
        "PLUGIN_INSTALL_NONCE_WITHOUT_CAP",
        "WPDB_DIRECT_POST_TABLE_WRITES",
        "WP_INSERT_POST_DATA_FILTER",
        "FRONTEND_FORM_POST_UPDATE", "KSES_REMOVAL_CONTENT_WRITE",
        "INIT_HOOK_STATE_CHANGES", "INIT_HOOK_SUPERGLOBAL_READS", "SHORTCODE_PRIVILEGED_OPERATIONS",
        "OPTION_TRANSIENT_WRITES",
        "MASS_ASSIGNMENT", "EXTRACT_INTO_OPTION_WRITE",
        "OPTION_UPDATE_HOOKS", "CSRF_STATE_CHANGES", "HARDCODED_HASH_LITERAL_NONCE", "UNSCOPED_NONCE_STORE_LOOKUP", "GET_ACCESS_TOKEN_PARAM",
        "CONNECTION_STATE_GATED_SECRET_DISCLOSURE",
        "ADMIN_INIT_SUPERGLOBAL_READS", "ADMIN_INIT_STATE_CHANGES",
        "SETTINGS_IMPORT_OPTION_WRITE", "FOREACH_POST_TO_OPTION_WRITE",
        "CRITICAL_OPTION_VALUE_WRITE", "DELETE_OPTION_ADD_OPTION_PAIR",
        "ADMIN_INIT_USERINPUT_OPTION_WRITE",
        "BULK_ACTION_HANDLERS",
        "LOAD_SCREEN_HOOKS", "ADMIN_ACTION_HOOKS",
        "DASHBOARD_WIDGET_REGISTRATION",
        "USER_CONTROLLED_OPTION_KEY", "USER_META_WRITES",
        "FOREACH_KEY_TO_USER_META_WRITE",
        "DEPENDENT_FIELD_CONTEXT_META_KEY", "ACF_RAW_POST_ID_TRUST", "DYNAMIC_FIELD_INDEX_NO_PER_ITEM_AUTHZ",
        "FOREACH_SELECTOR_TO_CONNECTION_SINK_NO_ALLOWLIST",
        "SECURITY_GATE_FUNCTIONS", "AUTH_INTERMEDIARIES",
        # IDOR (Tier 11)
        "TIER11_IDOR", "WC_ORDER_RECEIVED_QUERY_VAR",
        "WP_POST_REPARENTING", "IDOR_OWNERSHIP_CHECKS", "REST_IDOR_USER_ID",
        "REST_IDOR_RESOURCE_ID", "REST_BODY_PARAM_POST_ID",
        "ILLUSORY_OWNERSHIP", "CAPABILITY_CHECK_ON_TARGET_OBJECT",
        "READ_PRIMITIVE_CAP_OBJECT_GATE",
        "IDOR_ACCOUNT_TAKEOVER_SINKS", "IDOR_POST_META_WRITES",
        "IDOR_POST_DELETE", "IDOR_WC_ORDER_ACCESS",
        "IDOR_POST_READ_NO_AUTH", "IDOR_SHORTCODE_ATTRIBUTE_ID",
        "IDOR_ATTACHMENT_FILE_ACCESS", "IDOR_LOOKUP_BY_UNIQUE_FIELD_THEN_WRITE",
        # Request-param resource-scoping key takes precedence over the
        # content-derived owner id in an authorization check (CWE-639) — see
        # CVE-2026-57694 in VARIANT-PROVENANCE.md.
        "REQUEST_PARAM_OWNER_KEY_FALLBACK",
        # "Mark complete" / progress-write call receiving an id-like arg with
        # no owning-parent membership check (CWE-862) — self-triaged, see the
        # mark_lesson_complete entry in VARIANT-PROVENANCE.md.
        "PROGRESS_COMPLETION_WRITE_ID_ARG",
        # Nested child-resource id passed to a getter with no parent-
        # containment check (CWE-862/639) — see CVE-2026-13765 in
        # VARIANT-PROVENANCE.md.
        "CHILD_ID_GETTER_NO_PARENT_CONTAINMENT",
        # Adversarial draft-status / parse_args access-control patterns, relocated
        # here when Group adv was collapsed into AC + Chain.
        "WP_QUERY_DRAFT_STATUS_AJAX", "WP_PARSE_ARGS_WRONG_ORDER",
        # Unsafe reflection / dynamic class instantiation from request input
        # (CWE-470/CWE-862) — see CVE-2026-12238 in VARIANT-PROVENANCE.md.
        "DYNAMIC_CLASS_FROM_REQUEST",
        # Custom AJAX router/dispatcher opt-in nonce-allowlist pattern
        # (CWE-266/862) — see CVE-2026-48879 in VARIANT-PROVENANCE.md.
        "AJAX_ROUTER_NONCE_ALLOWLIST_METHODS",
        # wp_ajax_ hook (no nopriv counterpart) + nonce-only guard, no
        # same-line capability check (CWE-266/862) — see CVE-2025-54049 in
        # VARIANT-PROVENANCE.md.
        "AJAX_HOOK_NONCE_ONLY_NO_CAPABILITY",
        # Form-validator helper mistaken for an auth check (CWE-862/269) —
        # see CVE-2025-15403 in VARIANT-PROVENANCE.md.
        "FORM_VALIDATOR_SOLE_GATE_CANDIDATE",
        # Nonce-only-gated file-export/download response (CWE-862/287) —
        # see CVE-2019-17574 in VARIANT-PROVENANCE.md.
        "NONCE_ONLY_FILE_EXPORT_NO_CAPABILITY",
        # Post content/excerpt in public meta tags without post_password_required()
        # (CWE-200/862) — see CVE-2023-5845 in VARIANT-PROVENANCE.md.
        "META_TAG_CONTENT_NO_PASSWORD_CHECK",
        # Case-sensitive route-prefix gate (strpos/substr/strncmp against
        # $request->get_route()) guarding a same-file parameter strip —
        # WP's dispatcher matches routes case-insensitively (CWE-178/89) —
        # see CVE-2026-65508 in VARIANT-PROVENANCE.md.
        "REST_DISPATCH_CASE_SENSITIVE_ROUTE_GATE",
        # Mass DROP TABLE/TRUNCATE TABLE/table-wide DELETE FROM with no
        # authorization check nearby (CWE-862/284) — see CVE-2020-7048 in
        # VARIANT-PROVENANCE.md.
        "MASS_WPDB_TABLE_DROP_TRUNCATE",
        # Literal '__return_true' permission_callback on a third-party
        # integration route (CWE-862/200) — see CVE-2026-15827 in
        # VARIANT-PROVENANCE.md.
        "REST_RETURN_TRUE_INTEGRATION_PROXY",
        # get_user_meta()/get_post_meta() called without the third $single
        # argument (returns an array), then strictly compared (===/!==)
        # against a scalar — the comparison is always constant, which can
        # collapse one branch of a nonce-or-token authorization gate down to
        # the weaker remaining condition (CWE-697/862) — see CVE-2026-13332
        # in VARIANT-PROVENANCE.md.
        "META_GETTER_UNSINGLE_STRICT_COMPARE",
    ],
    # SQL injection (Tier 3) — direct/interpolated sinks plus wrapper/aliased sinks,
    # prepare()-format-string injection, and custom query-builder sinks
    # (see docs/sqli-research-2026.md).
    "group-sqli": [
        "TIER3_SQL", "ORDERBY_PARAMETER_HANDLING", "WP_QUERY_VAR_SQL",
        "WP_UNSLASH_SQL_CONTEXT", "ESC_LIKE_USAGE", "ADVANCED_SEARCH_PATHS",
        "WPDB_LOOP_SQL_BUILD",
        "COOKIE_SQL_INPUT", "SHORTCODE_ATTR_SQL", "ESC_ATTR_SQL_CONTEXT",
        "ESC_URL_RAW_SQL_CONTEXT", "SPRINTF_SQL_BUILD", "CONCAT_ASSIGN_SQL_BUILD",
        "WP_UNSLASH_BEFORE_SQL", "FILTER_INPUT_SQL_CONTEXT",
        "WPDB_WRAPPER_SQL", "PREPARE_USER_INPUT_FORMAT_STRING",
        "SQL_QUERY_BUILDER_METHODS", "SELF_REASSIGN_STR_REPLACE_SQL_BUILD",
        "DYNAMIC_WHERE_KEY_CONCAT", "RAW_WHERE_ARRAY_KEY_PASSTHROUGH", "RAW_QUERY_KEY_SQL",
        "ORDERBY_ALLOWLIST_KEY_VALUE_CONFUSION", "RULES_COLLECTION_VS_LOOP_ITEM_ISSET",
        "PREPARE_UNQUOTED_IN_CLAUSE_PLACEHOLDER",
        "WPDB_IN_CLAUSE_DOUBLE_QUOTE_WRAP", "RAW_SQL_CLAUSE_QUOTED_VAR",
        "UNQUOTED_BARE_VARIABLE_SQL_FRAGMENT_INTERP",
        "FOREACH_REQUEST_KEY_WPDB_WRITE", "QUOTED_VALUE_CONCAT_SQL_BUILD",
        "UNQUOTED_INTERPOLATED_ARRAY_KEY_SQL", "DDL_TABLE_STATEMENT_RAW_VAR_INTERP",
        "SERVER_HEADER_RAW_SQL_CONCAT",
        "REST_VALIDATE_CALLBACK_EMPTY_PARAMS", "REQUEST_FIELDS_RAW_SELECT_COLUMN_LIST",
        "SQL_KEYWORD_BLOCKLIST_REGEX_ARRAY", "NUMERIC_TERNARY_UNESCAPED_QUOTE_WRAP",
        "SPRINTF_IN_CLAUSE_FORMAT_STRING", "SQL_DUMP_ROW_PROPERTY_INTERPOLATION",
        "REQUEST_ARRAY_IMPLODE_UNCAST_IN_CLAUSE", "EXPLODE_CSV_UNCAST_TAX_QUERY_TERMS",
    ],
    "group-c": [
        "TIER5_HTML_RENDERERS", "TIER6_UNESCAPED_OUTPUT", "SCRIPT_BLOCK_ECHO", "JS_CONTEXT_PHP_ECHO",
        "ESC_URL_RAW_JS_CONTEXT_ECHO", "PLAIN_CONCAT_EVENT_HANDLER_UNESCAPED",
        "THE_AUTHOR_META_OUTPUT", "STORED_XSS_WRITES", "COMMENT_WRITE_KSES_BYPASS_SINKS", "NONCE_RENDER_CONTEXT",
        "SAVE_POST_HOOKS", "STORED_XSS_READS",
        "POST_META_NO_SANITIZE_CALLBACK", "SANITIZER_KEY_ALLOWLIST_BYPASS",
        "IS_STRING_ONLY_SANITIZER_ARRAY_BYPASS", "IS_ARRAY_ONLY_SANITIZER_SCALAR_BYPASS",
        "RECURSIVE_SANITIZER_UNSANITIZED_KEYS",
        "META_BOX_REGISTRATIONS",
        "POST_INSERT_UPDATE", "CUSTOM_VALUE_GETTERS", "JOOMLA_STYLE_REQUEST_GETTER", "LIST_TABLE_COLUMNS",
        "COLUMN_VALUE_GETTER_BARE_RETURN",
        "KSES_ECHO_PATTERNS", "TITLE_OUTPUT", "SEARCH_QUERY_ESCAPE_DISABLED", "DATE_FORMAT_UNESCAPED",
        "SHORTCODE_IMPLODE_SEPARATOR", "CUSTOM_LIST_WALKER_CLASSES", "BLOCK_ATTRIBUTE_OUTPUT",
        "BLOCK_ATTRIBUTE_TAG_NAME_SINK", "TEMPLATE_UNESCAPED_META",
        "JS_DATASET_READS",
        "ADD_QUERY_ARG_ECHO", "AJAX_ECHO_WP_DIE", "SERVER_SELF_URI_OUTPUT",
        "LENGTH_ONLY_REQUEST_VALIDATION",
        "DO_SHORTCODE_USER_INPUT", "DO_SHORTCODE_DB_CONTENT",
        "KSES_ALLOWED_EVENT_HANDLERS",
        "INLINE_STYLE_META_SINK", "COLOR_SETTING_UNSANITIZED_RETURN", "STYLE_TAG_RAW_CONCAT", "SCRIPT_TAG_RAW_CONCAT", "WIDGET_RENDER_OUTPUT",
        "WC_BILLING_FIELD_READS", "CUSTOMER_MODEL_PROPERTY_UNESCAPED_RETURN",
        "WP_USER_PROFILE_FIELD_RAW_ACCESS", "ELEMENTOR_SETTINGS_ATTR_CONCAT",
        "WP_SPECIALCHARS_DECODE", "JSON_UNESCAPED_SLASHES_ENCODE",
        "HTTP_HEADER_DB_WRITE", "AUDIT_LOG_INSERT_UNSANITIZED_FIELD", "TRACKING_PARAM_UNSANITIZED_STORE", "WPDB_RESULT_UNESCAPED_OUTPUT",
        "ADMIN_NOTICE_UNESCAPED_OUTPUT", "SPRINTF_POSITIONAL_ARG_UNESCAPED", "FILENAME_METADATA_OUTPUT",
        "KEYED_FIELD_VALUE_UNESCAPED_ARRAY_WRITE",
        "DYNAMIC_KEY_ESC_ATTR_ARRAY_WRITE",
        "JQUERY_DOM_INSERTION_SINKS",
        "DANGEROUSLY_SET_INNER_HTML_UNSANITIZED",
        "SELECT2_ESCAPE_MARKUP_OVERRIDE",
        "JS_HREF_SRC_ATTR_STRING_CONCAT",
        "JS_HREF_ATTR_BINDING_NO_SCHEME_CHECK",
        "LOCATION_HASH_UNVALIDATED_DISPATCH",
        "REST_FIELD_CALLBACK_XSS",
        "PREG_REPLACE_HTML_ATTR_STRIP",
        "INTERPOLATED_HREF_ATTR_NO_ESC",
        "ADDCSLASHES_SLASH_ONLY_HTML_INJECT",
        "UNSERIALIZED_ARRAY_FOREACH_ECHO",
        "FOREACH_ITEM_FIELD_UNESCAPED_ECHO",
        "HYDRATED_RECORD_SELECTIVE_FIELD_ESCAPE",
        "UPLOAD_EXTENSION_ONLY_MIME_CHECK",
        "NL2BR_UNSANITIZED_TEXT",
        "TEXTAREA_CONTENT_UNESCAPED_ECHO",
        "SRCSET_DESCRIPTOR_CONCAT_UNESCAPED",
        "MERGE_TAG_PROPERTY_STR_REPLACE_UNESCAPED",
        "MERGE_TAG_SUPERGLOBAL_STR_REPLACE_UNESCAPED",
        "MERGE_TAG_WP_KSES_SUPERGLOBAL_ASSIGN",
        "JSON_ENCODE_HTML_COMMENT_BREAKOUT",
        "ESC_URL_RAW_ATTR_CONTEXT_SPLICE",
        "PARSE_URL_FRAGMENT_UNESCAPED_REASSEMBLY",
    ],
    "group-d1": [
        "TIER8_SSRF", "RAW_CURL", "DOM_XML_PARSING",
        "SSRF_SAFE_REMOTE_USER_INPUT", "SSRF_FETCH_FEED",
        "SSRF_IMAGE_SIDELOAD", "SSRF_GETIMAGESIZE", "SSRF_GET_HEADERS",
        "SSRF_STREAM_SOCKET", "SSRF_WEBHOOK_URL_STORE", "SSRF_CRON_HTTP_FETCH",
        "SSRF_SANITIZE_URL_NO_HOST_CHECK",
        "EMAIL_HEADER_LINE_BUILD",
        "REST_WEBHOOK_BODY",
        "TIME_BASED_EXPORT_FILENAME",
        "LOCALIZE_SCRIPT_SENSITIVE_DATA", "SETTINGS_SECRET_TO_HTML_ATTR",
        "API_RESPONSE_PAGINATION_TOKEN", "LOG_FILE_PUBLIC_WRITE",
        "USER_OBJECT_RESPONSE_EXPOSURE", "REQUEST_ID_TO_JSON_RESPONSE_NO_STATUS_CHECK",
        "REST_PREPARE_FIELD_FILTERS", "EXPORT_FILE_PREDICTABLE_PATH",
        "PHPINFO_SERVER_INFO", "ERROR_HANDLER_PATH_EXPOSURE",
        "NOPRIV_DATA_RESPONSE",
        "REST_RETURN_TRUE_DATA_RESPONSE",
        "LOG_FILE_SESSION_TOKEN_WRITE",
        "NONCE_FRONTEND_DISCLOSURE",
        "REST_SENSITIVE_CPT_EXPOSURE", "REST_META_FIELD_EXPOSURE",
        "AJAX_AUTH_ONLY_DATA_RESPONSE",
        "PLUGIN_DIR_SENSITIVE_FILE_WRITE",
        "DB_CREDENTIALS_UNENCRYPTED_FILE_WRITE",
        "HTACCESS_WEAK_DENY_DIRECTIVE",
        "UPLOAD_MKDIR_NO_INDEX_PROTECTION",
        "WPDB_PREFIX_RESPONSE_EXPOSURE",
        "POSTS_RESULTS_FILTER_HOOK",
        "JSON_PATH_DYNAMIC_KEY_LOOKUP",
    ],
    # Group adv collapsed (0 lifetime TP): its two sections moved to
    # group-ac above; race/"Beyond the Checklist" reasoning folded into the Chain pass.
}

# Drift guard: the section-order buckets must be exactly the registry's bucket set.
assert set(GROUP_SECTION_ORDER) == set(GROUP_FILE_MAP), (
    "GROUP_SECTION_ORDER buckets do not match group_registry.grep_file_map(): "
    f"{set(GROUP_SECTION_ORDER) ^ set(GROUP_FILE_MAP)}"
)


def _glob_match(path: str, pattern: str) -> bool:
    """True recursive-glob match for a '/'-joined relpath against a pattern
    that may contain a standalone '**' path segment (matches zero or more
    entire path segments) plus ordinary '*'/'?' wildcards WITHIN a segment.

    Deliberately NOT stdlib fnmatch: fnmatch has no concept of path segments,
    so a bare '*' already spans '/' and a pattern like 'dir/**/*.ext' or
    '**/composer.json' silently fails to match a file directly inside dir/
    (or at the root) — there is no intermediate segment for '**' to consume.
    Confirmed empirically: fnmatch("js/ctf-scripts.js", "js/**/*.js") is
    False, and every glob_override in this file using the 'dir/**/*.ext'
    idiom was affected, silently disabling top-level-file matching for the
    directories it named.
    """
    path_parts = path.split("/")
    pat_parts = pattern.split("/")

    def match(pi: int, gi: int) -> bool:
        if gi == len(pat_parts):
            return pi == len(path_parts)
        seg = pat_parts[gi]
        if seg == "**":
            for k in range(pi, len(path_parts) + 1):
                if match(k, gi + 1):
                    return True
            return False
        if pi == len(path_parts):
            return False
        if not fnmatch(path_parts[pi], seg):
            return False
        return match(pi + 1, gi + 1)

    return match(0, 0)


# ---------------------------------------------------------------------------
# File cache
# ---------------------------------------------------------------------------

class FileCache:
    """Reads and caches all target files. Handles encoding gracefully."""

    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir).resolve()
        # relpath -> list of lines (strings)
        self.php_files: dict[str, list[str]] = {}
        # relpath -> raw content string (for cross-file filter full-text search)
        self.php_contents: dict[str, str] = {}
        # Non-PHP files found via glob_override — lazily populated
        self._extra_files: dict[str, list[str]] = {}
        self._extra_contents: dict[str, str] = {}
        self._glob_cache: dict[str, dict[str, list[str]]] = {}
        self._load_php_files()

    def _is_excluded_dir(self, rel: str) -> bool:
        parts = Path(rel).parts
        for part in parts:
            if part in EXCLUDED_DIRS:
                return True
        return False

    def _read_file(self, full_path: Path) -> str | None:
        """Read file with encoding fallback. Returns None for binary/unreadable."""
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            try:
                with open(full_path, "r", encoding="latin-1") as f:
                    return f.read()
            except Exception:
                return None
        except Exception:
            return None

    def _load_php_files(self):
        """Walk target_dir for all .php files, excluding vendor/node_modules.

        vendor/ is not pruned wholesale: plugins increasingly ship first-party
        "shared-core" code as an internal Composer package under
        vendor/<own-vendor-namespace>/ (same publisher, not a third-party
        dependency). A subdirectory directly under vendor/ is kept when its
        name matches the plugin's own slug (this project's plugins/<slug>/
        <version>/ layout gives us the slug as target_dir's parent dirname) —
        every other vendor/<pkg>/ subtree (genuine third-party deps) stays
        excluded, same as before.
        """
        plugin_slug = _normalize_slug(self.target_dir.parent.name)
        for root, dirs, files in os.walk(self.target_dir):
            rel_parts = Path(root).relative_to(self.target_dir).parts
            if rel_parts and rel_parts[-1] == "vendor":
                # Inside a vendor/ dir: keep only the plugin's own-namespace
                # subpackage (if any) so os.walk descends into it; prune
                # every other vendor/<pkg>/ subtree (genuine third-party deps).
                dirs[:] = [
                    d
                    for d in dirs
                    if d not in ALWAYS_EXCLUDED_DIRS
                    and _normalize_slug(d) == plugin_slug
                ]
            else:
                # Let 'vendor' itself through here (only node_modules/freemius
                # pruned) so os.walk can descend into it — the branch above
                # decides what survives one level down.
                dirs[:] = [d for d in dirs if d not in ALWAYS_EXCLUDED_DIRS]
            for fname in files:
                if not fname.lower().endswith(".php"):
                    continue
                full = Path(root) / fname
                rel = str(full.relative_to(self.target_dir)).replace("\\", "/")
                content = self._read_file(full)
                if content is None:
                    continue
                self.php_contents[rel] = content
                self.php_files[rel] = content.splitlines()

    def get_glob_files(self, glob_patterns: str) -> dict[str, list[str]]:
        """Return {relpath: lines} for files matching comma-separated glob patterns.
        Does NOT exclude vendor/node_modules (glob_override is intentional)."""
        if glob_patterns in self._glob_cache:
            return self._glob_cache[glob_patterns]

        patterns = [p.strip() for p in glob_patterns.split(",") if p.strip()]
        result: dict[str, list[str]] = {}
        for root, dirs, files in os.walk(self.target_dir):
            for fname in files:
                full = Path(root) / fname
                rel = str(full.relative_to(self.target_dir)).replace("\\", "/")
                if any(_glob_match(rel, pat) for pat in patterns):
                    if rel in self.php_contents:
                        result[rel] = self.php_files[rel]
                    elif rel not in self._extra_contents:
                        content = self._read_file(full)
                        if content is not None:
                            self._extra_contents[rel] = content
                            lines = content.splitlines()
                            self._extra_files[rel] = lines
                            result[rel] = lines
                    else:
                        result[rel] = self._extra_files[rel]
        self._glob_cache[glob_patterns] = result
        return result


# ---------------------------------------------------------------------------
# Semgrep coordinate loader
# ---------------------------------------------------------------------------

def load_semgrep_coords(filepath: str | None) -> set[str]:
    """Load semgrep coordinates file. Each line: relative/path.php:LINE"""
    if not filepath:
        return set()
    coords = set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    # Normalize: forward slashes, lowercase
                    normalized = line.replace("\\", "/")
                    coords.add(normalized)
    except FileNotFoundError:
        print(f"WARNING: Semgrep coords file not found: {filepath}", file=sys.stderr)
    except Exception as e:
        print(f"WARNING: Error reading semgrep coords: {e}", file=sys.stderr)
    return coords


# ---------------------------------------------------------------------------
# Scanner engine
# ---------------------------------------------------------------------------

def truncate_line(line: str, max_len: int = LINE_TRUNCATE) -> str:
    """Truncate line content, adding ellipsis if needed."""
    stripped = line.strip()
    if len(stripped) > max_len:
        return stripped[:max_len] + "…"
    return stripped


def format_hit(relpath: str, lineno: int, line: str, semgrep_coords: set[str]) -> str:
    """Format a single match line for output."""
    content = truncate_line(line)
    coord = f"{relpath}:{lineno}"
    tag = " [SEMGREP]" if coord in semgrep_coords else ""
    return f"- {relpath}:{lineno}: {content}{tag}"


def matches_any(text: str, compiled_patterns: list[re.Pattern]) -> bool:
    for pat in compiled_patterns:
        if pat.search(text):
            return True
    return False


_LOOKAROUND_FLAG_GROUP = re.compile(r"^\(\?[a-zA-Z]+\)")


def is_pure_lookaround_pattern(pattern_src: str) -> bool:
    """True if pattern_src consists ONLY of a leading inline-flag group
    (e.g. (?s), (?is)) followed by one or more top-level lookaround
    assertions (?=...), (?!...), (?<=...), (?<!...) — i.e. it consumes no
    characters anywhere.

    Such patterns are used as multi-condition AND/NOT-file-content filters
    (e.g. "file mentions A and B but not C"). Evaluated via .search() on a
    large non-matching file, they are pathologically slow: a failed lookahead
    at position 0 implies failure at every later position too (the lookahead
    only tests suffixes of the string), yet re.search() doesn't know that and
    re-attempts the whole O(n) lookahead scan at every one of the n starting
    positions, making the whole thing O(n^2). Since match-at-0 and search()
    are provably equivalent for this exact pattern shape, callers can safely
    use .match() instead of .search() for patterns this function flags,
    turning O(n^2) into O(n) with no change in which files qualify.
    """
    s = pattern_src
    m = _LOOKAROUND_FLAG_GROUP.match(s)
    if m:
        s = s[m.end():]
    i, n = 0, len(s)
    if n == 0:
        return False
    while i < n:
        if not (s.startswith("(?=", i) or s.startswith("(?!", i)
                or s.startswith("(?<=", i) or s.startswith("(?<!", i)):
            return False
        depth = 0
        j = i
        in_class = False
        while j < n:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if in_class:
                if c == "]":
                    in_class = False
            else:
                if c == "[":
                    in_class = True
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
            j += 1
        else:
            return False  # unbalanced parens
        i = j
    return True


def run_section(
    section_name: str,
    config: dict,
    cache: FileCache,
    semgrep_coords: set[str],
) -> list[str]:
    """Run a single section and return formatted result lines."""
    limit = config.get("limit", DEFAULT_LIMIT)
    is_inverted = config.get("invert", False)
    case_flag = re.IGNORECASE if config.get("case_insensitive", False) else 0
    glob_override = config.get("glob_override")
    cross_file_filter = config.get("cross_file_filter")
    exclude_path_patterns = config.get("exclude_path_patterns", [])
    line_filter_src = config.get("line_filter")

    # Compile main patterns
    patterns_src = config["patterns"]
    compiled_patterns = []
    for p in patterns_src:
        try:
            compiled_patterns.append(re.compile(p, case_flag))
        except re.error as e:
            print(f"  WARNING: bad regex in {section_name}: {p} -> {e}", file=sys.stderr)

    # Compile exclude patterns (line-level)
    exclude_compiled = []
    for ep in config.get("exclude_patterns", []):
        try:
            exclude_compiled.append(re.compile(ep, case_flag))
        except re.error:
            pass

    # Compile exclude path patterns
    exclude_path_compiled = []
    for epp in exclude_path_patterns:
        try:
            exclude_path_compiled.append(re.compile(epp))
        except re.error:
            pass

    # Compile line filter
    line_filter_re = None
    if line_filter_src:
        try:
            line_filter_re = re.compile(line_filter_src)
        except re.error:
            pass

    # Determine file set
    if glob_override:
        files_dict = cache.get_glob_files(glob_override)
    else:
        files_dict = cache.php_files

    # Cross-file filtering: identify qualifying files first
    if cross_file_filter:
        try:
            cff_re = re.compile(cross_file_filter, case_flag)
        except re.error:
            cff_re = None

        if cff_re:
            # Patterns that are pure lookaround conjunctions (e.g.
            # "(?s)(?=.*A)(?=.*B)") consume no characters, so a failed
            # lookahead at position 0 (A/B not found anywhere) also fails at
            # every later position — re.match() at position 0 is therefore
            # exactly equivalent to re.search() for these, but O(n) instead
            # of the O(n^2) re.search() incurs by re-running the whole
            # lookahead scan at each of the n starting positions. This
            # matters even after line-length capping: a file can have many
            # lines each under the per-line cap yet total several hundred KB
            # (e.g. large generated data/icon-map PHP files), which is
            # already enough to make the O(n^2) path take minutes.
            cff_is_pure_lookaround = is_pure_lookaround_pattern(cross_file_filter)
            qualifying = set()
            # Always check against PHP files for cross-file filter
            for rel, content in cache.php_contents.items():
                safe_content = (
                    content
                    if len(content) <= MAX_MATCH_LINE_LENGTH * 50
                    else "\n".join(
                        (l if len(l) <= MAX_MATCH_LINE_LENGTH else l[:MAX_MATCH_LINE_LENGTH])
                        for l in cache.php_files.get(rel, content.splitlines())
                    )
                )
                cff_hit = (
                    cff_re.match(safe_content)
                    if cff_is_pure_lookaround
                    else cff_re.search(safe_content)
                )
                if cff_hit:
                    qualifying.add(rel)
            # Restrict files_dict to qualifying files only
            files_dict = {k: v for k, v in files_dict.items() if k in qualifying}

    # Path exclusion filtering
    if exclude_path_compiled:
        files_dict = {
            k: v for k, v in files_dict.items()
            if not any(ep.search(k) for ep in exclude_path_compiled)
        }

    results: list[str] = []
    overflow = 0

    if is_inverted:
        # Report files NOT matching any pattern
        for relpath in sorted(files_dict.keys()):
            lines = files_dict[relpath]
            full_text = "\n".join(
                (l if len(l) <= MAX_MATCH_LINE_LENGTH else l[:MAX_MATCH_LINE_LENGTH])
                for l in lines
            )
            if not matches_any(full_text, compiled_patterns):
                if len(results) < limit:
                    results.append(f"- {relpath}")
                else:
                    overflow += 1
    else:
        # Normal matching: scan every line
        # Special handling for CAPABILITY_HANDLER_CROSSREF pattern index 1
        is_cap_crossref = section_name == "CAPABILITY_HANDLER_CROSSREF"

        for relpath in sorted(files_dict.keys()):
            lines = files_dict[relpath]
            for lineno_0, line in enumerate(lines):
                lineno = lineno_0 + 1

                if len(line) > MAX_MATCH_LINE_LENGTH:
                    continue

                matched = False
                for pat_idx, pat in enumerate(compiled_patterns):
                    if pat.search(line):
                        # CAPABILITY_HANDLER_CROSSREF: pattern index 1
                        # (current_user_can) has per-pattern exclusion
                        if is_cap_crossref and pat_idx == 1:
                            if _CAPABILITY_CROSSREF_PAT1_EXCLUDE.search(line):
                                continue
                        matched = True
                        break

                if not matched:
                    continue

                # Apply line-level excludes
                if exclude_compiled and matches_any(line, exclude_compiled):
                    continue

                # Apply line filter (line must ALSO match this)
                if line_filter_re and not line_filter_re.search(line):
                    continue

                if len(results) < limit:
                    results.append(format_hit(relpath, lineno, line, semgrep_coords))
                else:
                    overflow += 1

    if overflow > 0:
        results.append(f"[+{overflow} more — run manually if needed]")

    return results


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

def write_output_files(
    output_dir: str,
    all_results: dict[str, list[str]],
) -> dict[str, tuple[int, int]]:
    """Write the per-group output files. Returns {filename: (section_count, hit_count)}."""
    os.makedirs(output_dir, exist_ok=True)
    stats: dict[str, tuple[int, int]] = {}

    for group_key, filename in GROUP_FILE_MAP.items():
        section_order = GROUP_SECTION_ORDER.get(group_key, [])
        sections_written = 0
        total_hits = 0
        lines: list[str] = []

        for section_name in section_order:
            hits = all_results.get(section_name, [])
            if not hits:
                continue
            sections_written += 1
            # Count actual result lines (not the overflow indicator)
            hit_count = sum(1 for h in hits if not h.startswith("[+"))
            total_hits += hit_count
            lines.append(f"## [{section_name}]")
            lines.extend(hits)
            lines.append("")  # blank line after section

        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        stats[filename] = (sections_written, total_hits)

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="WordPress plugin vulnerability grep scanner"
    )
    parser.add_argument("target_dir", help="Plugin source directory to scan")
    parser.add_argument("output_dir", help="Directory to write results files")
    parser.add_argument(
        "--semgrep-coords",
        default=None,
        help="File with semgrep coordinates (one path:line per line)",
    )
    parser.add_argument(
        "--xss-limit",
        type=int,
        default=None,
        help="Override TIER6_UNESCAPED_OUTPUT hit limit (default: 100)",
    )
    args = parser.parse_args()

    target_dir = os.path.abspath(args.target_dir)
    output_dir = os.path.abspath(args.output_dir)

    if args.xss_limit is not None:
        SECTIONS["TIER6_UNESCAPED_OUTPUT"]["limit"] = args.xss_limit

    if not os.path.isdir(target_dir):
        print(f"ERROR: Target directory does not exist: {target_dir}", file=sys.stderr)
        sys.exit(1)

    # Load semgrep coords
    semgrep_coords = load_semgrep_coords(args.semgrep_coords)

    # Build file cache
    print(f"Scanning: {target_dir}")
    cache = FileCache(target_dir)
    print(f"Cached {len(cache.php_files)} PHP files")
    if semgrep_coords:
        print(f"Loaded {len(semgrep_coords)} semgrep coordinates")

    # Validate GROUP_SECTION_ORDER references
    for _gk, _snames in GROUP_SECTION_ORDER.items():
        for _sn in _snames:
            if _sn not in SECTIONS:
                print(f"ERROR: GROUP_SECTION_ORDER['{_gk}'] references "
                      f"non-existent section '{_sn}'", file=sys.stderr)
                sys.exit(1)

    # Run all sections (each unique section computed once, even when referenced by
    # multiple groups — e.g. the foundation group re-lists surface/group-a/group-ac sections)
    all_results: dict[str, list[str]] = {}
    computed: set[str] = set()
    total_sections_with_results = 0
    total_matches = 0

    for group_key in GROUP_SECTION_ORDER:
        for section_name in GROUP_SECTION_ORDER[group_key]:
            if section_name in computed:
                continue
            computed.add(section_name)
            config = SECTIONS[section_name]
            hits = run_section(section_name, config, cache, semgrep_coords)
            if hits:
                all_results[section_name] = hits
                total_sections_with_results += 1
                hit_count = sum(1 for h in hits if not h.startswith("[+"))
                total_matches += hit_count
                overflow_line = [h for h in hits if h.startswith("[+")]
                overflow_note = f" {overflow_line[0]}" if overflow_line else ""
                print(f"  [{section_name}] {hit_count} hits{overflow_note}")

    # Write output
    stats = write_output_files(output_dir, all_results)

    # Summary
    print()
    print("GREP_SCAN_COMPLETE")
    print(f"Files written to: {output_dir}")
    for filename in GROUP_FILE_MAP.values():
        sec_count, hit_count = stats.get(filename, (0, 0))
        print(f"  {filename}: {sec_count} sections, {hit_count} total hits")
    print(f"Total: {total_sections_with_results} sections with results | {total_matches} total matches")
    print("END_GREP_SCAN_COMPLETE")


if __name__ == "__main__":
    main()
