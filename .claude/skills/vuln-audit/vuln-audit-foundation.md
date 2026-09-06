# Vuln-Audit Foundation — Auth Model & Custom-Sink Facts (runs first)

> Authorized Wordfence bug-bounty research (see `AUTHORIZATION.md`). Loaded alongside core
> `SKILL.md`. This phase runs ONCE, after the grep/Semgrep stages and BEFORE any impact group.
> Its outputs (`auth-model.md`, `foundation.md`) are read by every later group so the auth floor,
> reachability, and custom-sink map are established once instead of re-derived per group.

## Role — FACTS, not verdicts

Unlike the Stage 1 context builder (deliberately neutral, no security framing), you ARE a
security analyst: you establish the authorization and sink **facts** the impact groups need.
But you **stop at facts**. You do NOT confirm vulnerabilities, assign CVSS, or write to
`findings.md`. You record what gates exist (or are absent), who can reach each handler, and
which plugin functions wrap dangerous calls. The impact groups turn these facts into verdicts.

**Quality guards (mandatory — a weak foundation must never weaken the audit):**
- Record gate presence/absence **as observed in source**. When unsure, write `UNVERIFIED` —
  never guess "secure"/"vulnerable" (those are verdicts the impact groups assign).
- Your auth-model is an **index, not a substitute for reading code**. Every later group re-reads
  the handler body before confirming — a gate may live in a called method, a base class, or a
  conditional your grep view missed. State this expectation in the file header.
- The custom-sink inventory is a **head start on the greppable wrappers, not a completeness
  claim.** The per-group SINK-discovery protocol (core SKILL.md "Custom sink discovery") stays
  active as a backstop; groups append newly discovered wrappers to `leads-forward.md`.
- Leads are **observations, not scope verdicts.** Do not assert in a lead note whether a
  disclosed resource is in-scope or exempt from an OOS category (e.g. non-public post/page/CPT
  content) — state the technical gap only; applying the Scope Gate (core SKILL.md item 8) is the
  confirming impact group's job, not Foundation's.

## Inputs

- `AUDIT_DIR/audit-context.md` — read the **Entry Point Map** + **Structural Summary** first
  (compact), then deeper sections as needed.
- `AUDIT_DIR/grep/foundation-results.md` — the aggregated auth / reachability / custom-sink grep
  sections. This is your primary working set.
- `AUDIT_DIR/grep/surface-results.md` — for deeper attack-surface detail when a foundation hit
  needs its surrounding context.
- Do NOT read Semgrep group files — auth/surface facts are architectural, not Semgrep findings;
  Semgrep auth leads are triaged by the Access-Control / Auth-Bypass groups as verdicts.

## Phase F1 — Reachability & entry-point facts

For every entry point, record the route → handler and the WordPress auth floor it inherits
(→ core "WordPress Route → Hook → Auth Quick Reference"). Use foundation-results sections
`STANDALONE_PHP`, `AJAX_HOOKS`, `WC_AJAX_HOOKS`, `ADMIN_HOOKS`, `INIT_HOOKS`,
`PAGEBUILDER_HOOKS`, `REST_ENDPOINTS`, `SHORTCODES`, `NON_AJAX_DISPATCHERS`,
`ADMIN_GET_DISPATCHERS`, `SLIM_FASTROUTE_ROUTER`, `WC_STORE_API_ENDPOINTS`.

- `wp_ajax_nopriv_` / `admin_post_nopriv_` / `__return_true` REST / `init`/`wp_loaded`/
  `template_redirect` / `wp-cron` → **PR:N floor** (unauthenticated-reachable). Flag these first.
- `wp_ajax_` / `admin_init` / `admin_post_` → **PR:L floor** (any logged-in user).
- `STANDALONE_PHP` (files that self-bootstrap WordPress via a raw `require`/`include` of
  `wp-load.php`/`wp-blog-header.php`, reachable directly at their own file path instead of
  through a hook) → outside the auth system entirely regardless of which WP functions the file
  calls afterward; record as a distinct reachability fact. A file with NO WordPress reference at
  all (true zero-integration standalone script) is not grep-covered — identify these by manual
  read.
- `WC_STORE_API_ENDPOINTS` (`woocommerce_store_api_register_update_callback()`,
  `register_endpoint_data()`) extend the WooCommerce Blocks Cart/Checkout Store API — reachable
  at whatever auth level the Store API's own cart/checkout routes allow (guest-accessible by
  default; carts are anonymous-session-scoped). Record the callback as **PR:N floor** unless the
  Store API route itself requires login. The `$cart`/`$request` object passed to the callback is
  scoped to the caller's own session — a callback that only reads/writes that object is
  self-scoped by design; it becomes an IDOR candidate only if it additionally resolves a
  DIFFERENT customer's order/data from a request-supplied ID (apply Tier 11 IDOR analysis then).
- Internal routers (Slim/FastRoute) inside a nopriv callback → enumerate every registered route;
  each is an independent reachability fact (record the route table, not just the dispatcher).
- **Custom non-WordPress authentication pipeline** — a plugin-defined request-dispatch mechanism
  (cryptographic signature verification, a bespoke API-key/HMAC scheme) that entirely replaces
  `current_user_can()`/nonce-based auth for a class of entry points, distinct from `STANDALONE_PHP`'s
  "outside WP entirely" case since these run inside a loaded WordPress but bypass its capability
  system. Record every entry point gated ONLY by this mechanism as its own reachability category,
  separate from PR:N/PR:L. Note whether the credential (signing key, shared secret, API token) is
  ever distributed to any customer/end-user tier, or exists solely on the vendor's own
  infrastructure — the standard Contributor/Subscriber/Unauthenticated taxonomy does not cleanly
  describe a vendor-infrastructure-only credential requirement, and this determination is often the
  deciding factor in whether findings reachable only through this pipeline are submittable. Flag it
  explicitly for the Chain pass's auth-floor scope assessment (→ SKILL_CHAIN Phase 2C Step 1) — do
  not silently default to "Unauthenticated" without this note.

## Phase F2 — Custom role / capability architecture map

**Run before the auth-model tables.** Use `ROLE_CAPABILITY_MAPPING`. Build the four-column map:

| Role name | Capabilities granted | How role is obtained | Handlers gated by these caps |
|---|---|---|---|

1. For every `add_cap()`/`add_role()` hit, record capabilities granted below Editor level.
2. For every AJAX/REST handler, record the capability in `current_user_can()`.
3. Mark Contributor-or-lower-accessible handlers `[LOW-PRIV-ACCESSIBLE]`.
4. **Self-obtainable roles:** trace `set_role()`/`add_role()`/`wp_insert_user()` to entry points.
   If reachable via a nopriv hook or public registration → record `SELF-OBTAINABLE` (a capability
   behind such a role is functionally open). This is a FACT; the impact group judges the impact.
5. **Bespoke role-array checks (`ROLE_ARRAY_MEMBERSHIP_CHECK`):** a gate comparing `$user->roles`
   (or equivalent) against literal strings via `array_intersect()`/`in_array()` is NOT
   `current_user_can()` — verify each compared string is an actual default WP/WC role slug
   (`administrator`, `editor`, `author`, `contributor`, `subscriber`, `shop_manager`, `customer`),
   not a capability name that merely resembles one (e.g. `manage_woocommerce` is a capability
   granted to `administrator`+`shop_manager`, never a role slug itself). Record the handler's
   TRUE effective auth floor from the roles that actually match — a compared string matching no
   real role silently narrows (or, in principle, widens) the gate relative to what its
   apparent, capability-shaped name implies.

6. **Additive per-role access-tier options (distinct from `$user->roles`/capabilities):** Some
   plugins layer their own permission-tier system on top of native WP roles — a
   `get_option('plugin_<role>_access')`-style per-WP-role toggle (not a capability, not
   `$user->roles` membership) checked by a custom `has_access()`/`can_access()`-style wrapper.
   For each such wrapper found: (1) record the DEFAULT state for every native WP role (often
   deny-by-default below Editor/Admin); (2) trace the grant/upgrade path — if changing another
   role's tier itself requires the HIGHEST tier (no self-service escalation), every handler
   gated SOLELY by this tier model is bounty-ineligible under the "admin-granted access" scope
   exclusion (global CLAUDE.md) regardless of the underlying code defect's severity. Record this
   as a Foundation fact (in the Handler Auth Summary's Auth Gate column, e.g. `tier:<role>` with
   a one-line default/grant-path note under Leads for Impact Groups) so every later group applies
   the determination once instead of re-deriving it independently per group.
7. **CPT `capability_type` meta-cap remapping (independent of a custom `capabilities` array):**
   `register_post_type()`'s `capability_type` parameter (default `'post'`) combined with
   `map_meta_cap => true` (WP Core's default) changes which PRIMITIVE capability
   `current_user_can('edit_post'/'edit_posts', ...)` resolves to for that post type — even with
   NO `capabilities` array override present. `capability_type => 'page'` resolves the
   `edit_post`/`edit_posts` meta-caps to the `edit_page`/`edit_pages` primitives; only Editor and
   Administrator hold `edit_pages`/`edit_others_pages` by default — Contributor and Author do
   not, despite the capability string in handler source reading as the generic `'edit_post'`
   (which normally implies Contributor+ for the default `'post'` type). Record the RESOLVED
   floor for every CPT a handler gates against, not the capability string's apparent (default-
   type) meaning. Use GREP_RESULTS `CPT_PAGE_CAPABILITY_TYPE` (fires on any non-default
   `capability_type`) to locate the registration call, then read it directly to confirm the
   resolved primitive before recording a handler's auth floor in the Handler Auth Summary.

## Phase F3 — Nonce availability map

→ See core CANON:nonce-verification (do not restate the rule; apply it). For every nonce action
string used by a handler, trace ALL `wp_create_nonce()`/`wp_nonce_field()`/`wp_localize_script()`
emission sites and record the **lowest-privilege page/hook that emits it** = the auth floor for
that nonce. Use `REST_NONCE_EXPOSURE` (nonce-vendor endpoints) and `TIER4_CAPABILITY_CHECKS`.
Record per action string: emission sites, lowest emission capability, and whether any
public/Subscriber/Contributor-reachable surface emits it. Record facts only — "emitted on a
public page" not "nonce theater" (the latter is the AC group's verdict).

When the emission site lives inside a class/feature that is itself conditionally instantiated
or hooked based on a custom role check — a role-array-membership test (`array_intersect($roles,
$user->roles)`), a role-name string comparison, or any bespoke gate other than
`current_user_can()` — trace that gate's default value as a separate fact before recording the
nonce's floor from the emission hook's native visibility (e.g. `is_admin_bar_showing()`
defaulting to Subscriber+). A plugin can layer its own narrower role restriction on top of a
WordPress Core feature's broader default visibility, so the hook context alone does not
establish reachability; record both facts (Core hook floor AND the plugin's own gate default)
so the confirming impact group can determine which one actually controls.

## Phase F4 — Write `AUDIT_DIR/auth-model.md` (FACTS)

Fill the facts; leave the verdict columns for the Access-Control group.

```markdown
## Auth Model — [plugin-slug] [version]
Built by the Foundation phase. FACTS only — `CIA Impact` and `Verdict` are filled by the
Access-Control group. Impact groups: re-read the handler body before confirming; a gate may
live in a called method/base class/conditional not visible here.

### Custom Roles
| Role | Capabilities | Self-registerable | Registration path |
|------|-------------|-------------------|-------------------|

### Nonce Availability
| Action String | Lowest Emission Capability | Public/Low-priv reachable? | Emission Site(s) |
|---------------|----------------------------|----------------------------|------------------|

### Handler Auth Summary
| Handler | Type | Auth Gate (cap / none / UNVERIFIED) | Nonce (action / none) | CIA Impact | Verdict |
|---------|------|-------------------------------------|------------------------|------------|---------|
<!-- Foundation fills Handler..Nonce. Leave CIA Impact and Verdict as "—" (AC group fills). -->

### Leads for Impact Groups
- [Suspicious reachable patterns not yet confirmed — relevant group noted]
```

## Phase F5 — Write `AUDIT_DIR/foundation.md` (custom-sink / wrapper inventory)

Plugin-defined functions that wrap a dangerous call behave as sinks for every caller. Inventory
them ONCE here so every group (including the earliest) inherits the map. Use foundation-results
sections `SECURITY_GATE_FUNCTIONS`, `AUTH_INTERMEDIARIES`, `TOKEN_AUTH_FLOWS`,
`TOKEN_LOCALIZE_EXPOSURE`, `CUSTOM_UNSERIALIZE_WRAPPERS`, `CUSTOM_TEMPLATE_LOADER_FUNCTIONS`,
plus any wrapper you spot while mapping the surface.

For each candidate wrapper: read the function body; classify the wrapped call and whether the
protection is present, absent, or conditional; grep all callers
(`Grep(pattern: "function_name\\(", path: SOURCE_DIR)`).

```markdown
## Foundation — Custom Sink / Wrapper Inventory — [plugin-slug] [version]
Head start on greppable wrappers — NOT a completeness claim. Groups still run per-group SINK
discovery and add newly found wrappers to the SINK LEDGER in leads-forward.md.

### Custom Sinks / Wrappers
| Function @ file:line | Type (sqli/xss/file-op/rce/ssrf/auth) | Wraps | Protection (present/absent/conditional) | Callers (N) |
|----------------------|---------------------------------------|-------|------------------------------------------|-------------|

### Auth / Token Intermediaries
| Function @ file:line | Returns on failure | Failure halts execution? | Notes |
|----------------------|--------------------|--------------------------|-------|

### Custom Data-Access Layer (if any)
- [ORM/model save()/update()/delete() methods that enforce or omit auth — note which]
```

Also seed each confirmed custom sink into the **SINK LEDGER** of `AUDIT_DIR/leads-forward.md`
(core SKILL.md §5/§6 ledger format), one deduped row per `fn@file:line` with `Consumed-by`
left `(none)` — impact groups fill `Consumed-by` as they evaluate each sink, and the Chain
pass sweeps any still-`(none)` at the end.

## Output & continuation

1. Write `AUDIT_DIR/auth-model.md` (Phase F4) and `AUDIT_DIR/foundation.md` (Phase F5).
2. Initialise `AUDIT_DIR/leads-forward.md` as the cross-group ledger (core SKILL.md §5): write the
   `## SINK LEDGER` table header and the `## LEADS` header, then seed the SINK LEDGER rows from
   the inventory (`Consumed-by = (none)`).
3. Write `AUDIT_DIR/checkpoint-foundation.md`: entry-point/auth-floor counts, custom-role notes,
   custom-sink count, and any high-priority reachable leads for the impact groups.
4. Do NOT write to `findings.md` — Foundation confirms nothing.

Return: `[FOUNDATION] Complete. Auth model + sink inventory written. Roles: N, nopriv entry points: M, custom sinks: K.`
