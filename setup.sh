#!/bin/sh

WP_PATH=/var/www/html

wpcli() {
  wp --allow-root --path="$WP_PATH" "$@"
}

# ── 1. Wait for WordPress files ──────────────────────────────────────────────
echo "[setup] Waiting for wp-config.php..."
i=0
while [ ! -f "$WP_PATH/wp-config.php" ]; do
  i=$((i+1))
  [ $i -gt 60 ] && echo "[setup] ERROR: wp-config.php never appeared" && exit 1
  sleep 3
done

# ── 2. Wait for database ─────────────────────────────────────────────────────
echo "[setup] Waiting for database..."
i=0
while ! php -r "
\$c = new mysqli(
  getenv('WORDPRESS_DB_HOST'),
  getenv('WORDPRESS_DB_USER'),
  getenv('WORDPRESS_DB_PASSWORD'),
  getenv('WORDPRESS_DB_NAME')
);
exit(\$c->connect_error ? 1 : 0);
" 2>/dev/null; do
  i=$((i+1))
  [ $i -gt 40 ] && echo "[setup] ERROR: database never became reachable" && exit 1
  sleep 3
done

# ── 3. Install WordPress core ────────────────────────────────────────────────
if wpcli core is-installed > /dev/null 2>&1; then
  echo "[setup] WordPress already installed."
else
  echo "[setup] Installing WordPress..."
  wpcli core install \
    --url="http://localhost:8000" \
    --title="WP Auditor" \
    --admin_user="admin" \
    --admin_password="admin123" \
    --admin_email="admin@example.com" \
    --skip-email
fi

# ── 3b. Enable pretty permalinks ─────────────────────────────────────────────
echo "[setup] Enabling pretty permalinks..."
wpcli rewrite structure '/%postname%/' --hard
wpcli rewrite flush --hard

# ── 4. Create role users ─────────────────────────────────────────────────────
echo "[setup] Provisioning users..."
for role in administrator editor author contributor subscriber; do
  pass="${role}123"
  if wpcli user get "$role" --field=ID > /dev/null 2>&1; then
    wpcli user update "$role" --user_pass="$pass" --role="$role" --skip-email > /dev/null 2>&1
    echo "[setup]   updated  $role"
  else
    wpcli user create "$role" "${role}@example.com" \
      --role="$role" \
      --user_pass="$pass" \
      --display_name="$role"
    echo "[setup]   created  $role / $pass"
  fi
done

# ── 5. Install & activate plugins ────────────────────────────────────────────
if [ -n "$PLUGIN_SLUG" ]; then
  echo "$PLUGIN_SLUG" | tr ',' '\n' | while read -r slug; do
    slug=$(echo "$slug" | tr -d ' ')
    [ -z "$slug" ] && continue
    if [ -d "$WP_PATH/wp-content/plugins/$slug" ]; then
      echo "[setup] Plugin dir exists (pre-copied): $slug — activating only"
      wpcli plugin activate "$slug" || echo "[setup]   WARNING: activation failed for $slug"
    else
      echo "[setup] Installing plugin: $slug"
      wpcli plugin install "$slug" --activate --force
    fi
  done
fi

# ── 6. Enable debug logging ──────────────────────────────────────────────────
echo "[setup] Configuring debug logging..."
touch "$WP_PATH/wp-content/debug.log"
chmod 666 "$WP_PATH/wp-content/debug.log"

# ── 7. Verify plugin installation ───────────────────────────────────────────
if [ -n "$PLUGIN_SLUG" ]; then
  echo "[setup] Verifying plugins..."
  echo "$PLUGIN_SLUG" | tr ',' '\n' | while read -r slug; do
    slug=$(echo "$slug" | tr -d ' ')
    [ -z "$slug" ] && continue
    if wpcli plugin is-installed "$slug" 2>/dev/null; then
      STATUS=$(wpcli plugin get "$slug" --field=status 2>/dev/null)
      echo "[setup]   $slug: $STATUS"
    else
      echo "[setup]   WARNING: $slug NOT INSTALLED"
    fi
  done
fi

# ── 8. Post-activation health check ─────────────────────────────────────────
echo "[setup] Checking debug.log for activation errors..."
if [ -f "$WP_PATH/wp-content/debug.log" ] && [ -s "$WP_PATH/wp-content/debug.log" ]; then
  ERRORS=$(grep -ci 'fatal\|error' "$WP_PATH/wp-content/debug.log" 2>/dev/null | grep -v Xdebug || echo 0)
  if [ "$ERRORS" -gt 0 ]; then
    echo "[setup]   *** $ERRORS error(s) in debug.log:"
    grep -i 'fatal\|error' "$WP_PATH/wp-content/debug.log" | grep -v Xdebug | tail -5
  else
    echo "[setup]   debug.log: clean"
  fi
else
  echo "[setup]   debug.log: empty (good)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "[setup] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[setup]  WordPress  http://localhost:8000"
echo "[setup]  WP Admin   http://localhost:8000/wp-admin"
echo "[setup]  Adminer    http://localhost:8080"
echo "[setup]  Mailpit    http://localhost:8025  (captured outbound email)"
echo "[setup] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[setup]  admin            / admin123"
for role in administrator editor author contributor subscriber; do
  printf "[setup]  %-16s / %s123\n" "$role" "$role"
done
if [ -n "$PLUGIN_SLUG" ]; then
  echo "$PLUGIN_SLUG" | tr ',' '\n' | while read -r slug; do
    slug=$(echo "$slug" | tr -d ' ')
    [ -n "$slug" ] && printf "[setup]  plugin: %-20s (active)\n" "$slug"
  done
fi
echo "[setup] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
