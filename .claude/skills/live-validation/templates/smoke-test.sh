#!/bin/bash
# smoke-test.sh — Pre-PoC endpoint verification
#
# Usage:
#   bash /tmp/smoke-test.sh <role> <password> <endpoint_type> <action_or_route> [nonce_key] [nonce_page] [extra_params]
#
# Arguments:
#   role          - WordPress username (e.g. contributor, subscriber, author)
#   password      - Password for that user
#   endpoint_type - "ajax" or "rest"
#   action_or_route - For ajax: the action param value. For rest: the full route (e.g. /wp-json/ns/v1/route)
#   nonce_key     - (optional) JS key name to grep for nonce (e.g. nonce_ajaxrequest, my_plugin_nonce)
#   nonce_page    - (optional) Admin page path to fetch nonce from (e.g. /wp-admin/post-new.php)
#   extra_params  - (optional) Additional POST params as key=val&key=val
#
# Examples:
#   bash /tmp/smoke-test.sh contributor contributor123 ajax shortpixel_ajaxRequest nonce_ajaxrequest /wp-admin/post-new.php "screen_action=ai/requestalt&type=media&id=9"
#   bash /tmp/smoke-test.sh subscriber subscriber123 rest /wp-json/plugin/v1/data
#   bash /tmp/smoke-test.sh "" "" ajax my_nopriv_action

set -euo pipefail

ROLE="${1:-}"
PASS="${2:-}"
ETYPE="${3:?endpoint_type required: ajax or rest}"
ACTION="${4:?action_or_route required}"
NONCE_KEY="${5:-}"
NONCE_PAGE="${6:-}"
EXTRA="${7:-}"

CK="/tmp/smoke_ck_$$.txt"
BASE="http://127.0.0.1"

echo "=== Smoke Test ==="
echo "  Role:     ${ROLE:-unauthenticated}"
echo "  Type:     $ETYPE"
echo "  Action:   $ACTION"

# ── Login (skip for unauthenticated) ────────────────────────────────────────
if [ -n "$ROLE" ] && [ -n "$PASS" ]; then
    curl -s -c "$CK" "$BASE/wp-login.php" > /dev/null
    curl -s -b "$CK" -c "$CK" -X POST "$BASE/wp-login.php" \
        -d "log=$ROLE&pwd=$PASS&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
        -L -o /dev/null
    if grep -q "wordpress_logged_in" "$CK" 2>/dev/null; then
        echo "  Login:    OK"
    else
        echo "  Login:    FAILED"
        rm -f "$CK"
        exit 1
    fi
else
    echo "  Login:    skipped (unauthenticated)"
    touch "$CK"
fi

# ── Nonce acquisition ───────────────────────────────────────────────────────
NONCE=""
if [ -n "$NONCE_KEY" ] && [ -n "$NONCE_PAGE" ]; then
    PAGE_HTML=$(curl -s -b "$CK" "$BASE$NONCE_PAGE")
    NONCE=$(echo "$PAGE_HTML" | grep -oP "${NONCE_KEY}[\"']?\s*[:=]\s*[\"']([a-f0-9]+)" | head -1 | grep -oP '[a-f0-9]{6,}$')
    if [ -n "$NONCE" ]; then
        echo "  Nonce:    $NONCE (from $NONCE_PAGE)"
    else
        echo "  Nonce:    NOT FOUND on $NONCE_PAGE for key '$NONCE_KEY'"
        echo "            (page returned $(echo "$PAGE_HTML" | wc -c) bytes)"
    fi
fi

# ── Fire the request ────────────────────────────────────────────────────────
echo ""
if [ "$ETYPE" = "ajax" ]; then
    POST_DATA="action=$ACTION"
    [ -n "$NONCE" ] && POST_DATA="$POST_DATA&nonce=$NONCE"
    [ -n "$EXTRA" ] && POST_DATA="$POST_DATA&$EXTRA"
    echo "  POST $BASE/wp-admin/admin-ajax.php"
    echo "  Data: $POST_DATA"
    RESP=$(curl -s -b "$CK" -X POST "$BASE/wp-admin/admin-ajax.php" \
        -d "$POST_DATA" -w '\n__HTTP_CODE__:%{http_code}')
elif [ "$ETYPE" = "rest" ]; then
    URL="$BASE$ACTION"
    [ -n "$EXTRA" ] && URL="$URL?$EXTRA"
    HEADERS=""
    [ -n "$NONCE" ] && HEADERS="-H X-WP-Nonce:$NONCE"
    echo "  GET $URL"
    RESP=$(curl -s -b "$CK" $HEADERS "$URL" -w '\n__HTTP_CODE__:%{http_code}')
else
    echo "  ERROR: endpoint_type must be 'ajax' or 'rest'"
    rm -f "$CK"
    exit 1
fi

HTTP_CODE=$(echo "$RESP" | grep '__HTTP_CODE__' | cut -d: -f2)
BODY=$(echo "$RESP" | grep -v '__HTTP_CODE__')

echo ""
echo "  HTTP:     $HTTP_CODE"
echo "  Response: $(echo "$BODY" | head -c 500)"

# ── Interpret ───────────────────────────────────────────────────────────────
echo ""
if [ "$HTTP_CODE" = "200" ]; then
    if echo "$BODY" | grep -q '"0"\|^0$'; then
        echo "  VERDICT:  NONCE FAILED (response is 0 — action not registered or nonce invalid)"
    elif echo "$BODY" | grep -q '^-1$'; then
        echo "  VERDICT:  AUTH FAILED (response is -1)"
    elif echo "$BODY" | grep -qi 'not allowed\|unauthorized.*error.*-7'; then
        echo "  VERDICT:  AUTH REJECTED (handler has capability check)"
    elif [ ${#BODY} -lt 3 ]; then
        echo "  VERDICT:  EMPTY RESPONSE (handler reached but returned nothing)"
    else
        echo "  VERDICT:  ENDPOINT REACHABLE (200 + non-empty response)"
    fi
elif [ "$HTTP_CODE" = "403" ]; then
    echo "  VERDICT:  AUTH BLOCKED (403)"
elif [ "$HTTP_CODE" = "404" ]; then
    echo "  VERDICT:  NOT FOUND (endpoint not registered)"
elif [ "$HTTP_CODE" = "500" ]; then
    echo "  VERDICT:  SERVER ERROR (check debug.log)"
else
    echo "  VERDICT:  UNEXPECTED ($HTTP_CODE)"
fi

rm -f "$CK"
