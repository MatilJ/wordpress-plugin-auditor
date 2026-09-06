# WordPress Core Reference Versions

This directory holds local copies of WordPress core source, used as ground truth by the
`vuln-audit` skill (e.g. to check exactly what `sanitize_text_field()` or `esc_url()` does before
calling something a false positive). It's gitignored — everything except this file — because it's
~60-70MB per version. You populate it yourself; there's no download script for it, just the
manual steps below.

## Adding a version

1. Download from `https://wordpress.org/wordpress-X.Y.Z.zip`
2. Extract, then copy `wp-includes/` and `wp-admin/includes/` (rename the latter to
   `wp-admin-includes/`, to avoid `wp-admin`-vs-`wp-includes` path confusion during audits) into
   `wp-core/X.Y/`
3. Add a row to the table below
4. Optionally regenerate `wp-core-reference.md` at the project root if a function's behavior
   changed between versions you care about

## Available

| Version | Source | Date Added |
|---|---|---|
| _(none yet — add your first version above)_ | | |

## Contents per version

Each version directory should contain:
- `wp-includes/` — core functions (formatting, kses, pluggable, wpdb, user, post, REST, etc.)
- `wp-admin-includes/` — admin functions (renamed from `wp-admin/includes/`)

## Usage

Default: the `vuln-audit` skill uses whatever's the newest version you have. Override: if an
audited plugin's `Tested up to:` targets a different major version **and** a function's behavior
actually changed between versions, point it at that version instead.
