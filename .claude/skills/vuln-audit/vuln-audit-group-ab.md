# Vuln-Audit Group AB — Authentication Bypass (CWE-287/288)

> Authorized Wordfence bug-bounty research (see `AUTHORIZATION.md`). Loaded alongside core `SKILL.md`. Runs EARLY — in the access-control band right after Foundation, before the impact groups. Read checkpoint-foundation.md, auth-model.md (format: Custom Roles table, Nonce Availability table, Handler Auth Summary table — written by the Foundation phase; Verdict/CIA columns still blank at this point), foundation.md, and leads-forward.md before starting.

**Authentication Bypass ≠ Missing Authorization.** Missing Authorization (CWE-862, Group AC) = endpoint reachable without capability check. Authentication Bypass (CWE-287/288, this group) = endpoint validates credentials but the validation logic is flawed, allowing an attacker to pass as a legitimate user. Auth bypass typically CVSS 9.8 (PR:N/UI:N) when admin impersonation is achievable.

Use GREP_RESULTS sections from `AUDIT_DIR/grep/group-ab-results.md`: `SOCIAL_LOGIN_AUTH_COOKIE_FLOW`, `ORDER_PII_FIELD_ACCESS_COMPARISON`, `LOOSE_COMPARISON_AUTH_TOKEN`, `EMPTY_SECRET_COMPARISON`, `WP_AUTHENTICATE_APP_PASSWORD_UNCHECKED`, `PREDICTABLE_AUTH_TOKEN_GENERATION`, `COOKIE_TO_AUTH_FUNCTION`, `JWT_DECODE_NO_VERIFY`, `STRPOS_DOMAIN_VALIDATION`, `STRPOS_USERNAME_ALLOWLIST_MEMBERSHIP`, `PASSWORD_RESET_FLOW`, `AUTOLOGIN_MAGIC_LINK`, `WORKFLOW_STEP_AUTH_SINK`, `ONETIME_AUTH_FLAG_REPLAY`, and the token sections `TOKEN_AUTH_FLOWS`, `TOKEN_LOCALIZE_EXPOSURE` (moved into this group). Also re-examine `SECURITY_GATE_FUNCTIONS`, `AUTH_INTERMEDIARIES` from the Foundation grep results (foundation-results.md) for auth bypass leads the Foundation flagged.

## E.1 — OAuth/Social Login Callback Analysis

Use `SOCIAL_LOGIN_AUTH_COOKIE_FLOW`. For each hit where `get_user_by('email', ...)`, `get_users()`, or `email_exists()` appears in a file also containing `wp_set_auth_cookie()`/`wp_set_current_user()`:

1. Read the full callback function. Identify: (a) where the email address originates; (b) what verification proves the email belongs to the OAuth requester.
2. **Confirmed bypass when:** email comes from a POST/GET parameter, an unverified OAuth `id_token` claim, or a social provider callback where the plugin does NOT verify the `access_token`/`id_token` against the provider's token info endpoint or JWKS before using the email. The pattern: attacker sends `email=victim@example.com` → plugin calls `get_user_by('email', 'victim@example.com')` → `wp_set_auth_cookie($user->ID)` → attacker authenticated as victim.
3. **Empty parameter variant:** When social login parameter is empty, `get_users(['meta_value' => ''])` or `get_user_by('email', '')` may return the first user with a matching (empty) meta record — typically admin. `/?jupiterx-google-social-login=` (empty) returned admin.
4. **Token-to-email binding:** Even when a valid OAuth token exists, if the plugin does not verify that the token's `email` claim matches the `$_POST['email']` sent by the attacker → bypass. Valid attacker token + victim email = session as victim.
5. **Mechanical rule:** `get_user_by('email', $email)` → `wp_set_auth_cookie($user->ID)` where `$email` is not cryptographically bound to a verified OAuth token → CONFIRMED. CVSS 9.8.
6. **FP indicators:** Plugin verifies the access_token via `wp_remote_get()` to the provider's userinfo endpoint AND compares the returned email with the claimed email before setting the auth cookie; Firebase JWT decode with key validation; OAuth state parameter validated via `wp_verify_nonce()`.
7. **Same class, broader sink:** the unverified-email-match defect is not limited to `wp_set_auth_cookie()`/`wp_set_current_user()` — the same email-matched user ID, trusted with no ownership proof, feeding a `set_user_id()`/`set_customer_id()`/`set_owner_id()`-style account/order-binding call (or a `->user_id`/`->customer_id` property write) is CWE-287/CWE-862 at whatever CIA impact the resulting write carries, even with no session impersonation (e.g. an order marked paid/completed, an enrollment, a subscription activation against an arbitrary victim account). Verify no `is_user_logged_in()`-gated branch instead binds the REQUESTER's own ID before confirming (Semgrep `claude.php.wordpress.access-control.unverified-email-lookup-account-binding`, heuristic — not a confirmation).
8. **Non-secret PII field as an OR'd fallback branch:** a check OR'ing `hash_equals()`/`key_is_valid()` with a sibling branch granting the same access via equality against a non-secret field (billing email/phone) on the same object is CWE-287/CWE-639 — confirm any downstream ownership re-check isn't itself skipped for the anonymous path this reaches. Use GREP_RESULTS `ORDER_PII_FIELD_ACCESS_COMPARISON` / Semgrep `claude.php.wordpress.access-control.email-match-order-ownership-bypass`.

## E.2 — Loose Comparison on Auth Tokens (Type Juggling)

Use `LOOSE_COMPARISON_AUTH_TOKEN`. For each `==` or `!=` comparison involving a token/key/secret/hash variable:

1. Determine both operands. If either can be `null`, `false`, `0`, `""`, or `true` → type juggling bypass.
2. **`json_decode()` + `==`:** `json_decode('true')` returns boolean `true`. In PHP, `true == "any_nonzero_string"` → `true`. If the plugin compares a JSON-decoded request body field against a stored secret using `==`, sending `true` as the JSON value bypasses any string comparison.
3. **Absent value + `==`:** `get_transient('token')` returns `false` when absent. `$_GET['token']` is `null` when absent. `null == false` → `true`. If both a stored token and a user-supplied token can be absent simultaneously, the comparison passes.
4. **Mechanical rule:** `==`/`!=` comparison where one operand is a token/key/secret stored server-side and the other is user-supplied = audit signal. If `==` is used AND either operand can be a PHP falsy value → CONFIRMED. CVSS 9.8 if the comparison gates admin-level access.
5. **FP indicators:** `===` used; `hash_equals()` used (timing-safe strict comparison); `empty()` guard before comparison; comparison result not used as auth gate.
   - One operand is the bare `null` literal (`if ($secret !== null)`-style presence/config check) — this proves nothing about a second attacker-controlled value and is not the null==false/0/"" type-juggling risk this rule targets, which requires BOTH operands to be independently attacker-influenceable.
   - The variable's NAME matches the token/secret regex only by coincidence of a broader identifier (e.g. a `$token`/`$secret_key` OBJECT whose `->get_environment()`/`->get_type()` METHOD result is what's actually compared) — verify the compared VALUE is the secret material itself, not an unrelated classification/state string read off a same-named object.

## E.3 — Empty/Unconfigured Secret Comparison

Use `EMPTY_SECRET_COMPARISON`. For each `get_option()` reading a secret/key/token used in an auth comparison:

1. Determine the plugin's activation/setup flow. Does the option have a default value? Is the option populated during plugin activation, or only after manual configuration?
2. **Confirmed bypass when:** (a) option defaults to empty string (`''`); (b) user-supplied token is compared against this option; (c) no `empty()` guard rejects empty stored secret before comparison; (d) sending an empty token value matches `'' === ''` or `'' == ''`. Empty `secret_key` option → empty Authorization header passed.
3. **HMAC with empty key:** When the secret is used as a key for `hash_hmac()` and the key is empty, the HMAC is computed with an empty key — attacker can replicate this computation locally and forge valid signatures. Empty `api_key` → `hash_hmac('sha256', $data, '')` → computable. The secret is not always a direct `get_option()` in the same call — a getter/facade method (`$this->getSigningSecret()`) one or more hops removed from the actual option read has the identical risk; `EMPTY_SECRET_COMPARISON` also flags `hash_hmac()` calls whose key argument is any inlined method/static/function call (not `wp_salt()`/an `AUTH_KEY`-family constant), since inlining the getter — rather than capturing it into a variable first — is what makes a pre-use emptiness check structurally absent. Semgrep lead `claude.php.wordpress.access-control.hmac-key-inline-getter-missing-empty-check` (heuristic, NOT a confirmation).
4. **Mechanical rule:** `get_option('*secret*')` or `get_option('*key*')` compared without prior `if (empty($secret)) { return WP_Error; }` → investigate. If the plugin has no mandatory setup wizard forcing secret configuration → CONFIRMED.

## E.4 — wp_authenticate_application_password() Return Not Checked

Use `WP_AUTHENTICATE_APP_PASSWORD_UNCHECKED`. For each call:

1. `wp_authenticate_application_password()` returns: `WP_User` on success, `WP_Error` on invalid password/user, `$input_user` (which may be `null`) when application passwords are disabled or the feature is not in use (verified in WP 7.0 source, user.php:372-384).
2. **Confirmed bypass when:** (a) return value compared with `==` instead of strict type check; (b) `is_wp_error()` check absent; (c) `null` return not handled — plugin proceeds to grant access on null. Null return treated as non-false → `wp_set_current_user()` called with the username.
3. **Mechanical rule:** `wp_authenticate_application_password()` or `wp_authenticate()` call without subsequent `is_wp_error($result)` AND without `$result instanceof WP_User` strict check → CONFIRMED. CVSS 9.8 when attacker can send Basic Auth header with any admin username and invalid password.
4. **FP indicators:** `is_wp_error($result)` checked and error handled (return/wp_die); `$result instanceof WP_User` verified; function used only as a filter callback on `authenticate` hook (WP Core manages the chain).

## E.5 — Predictable Auto-Login Token Generation

Use `PREDICTABLE_AUTH_TOKEN_GENERATION`. For each hit:

1. Identify the token generation algorithm. Classify entropy:
   - **Deterministic (CVSS 9.8):** `md5($user_id)`, `sha1($user_id)`, `md5($user_id . CONSTANT)` where CONSTANT is in the source tree — attacker computes for any user_id. E.g. `substr(md5($user_id), 0, 10)` — admin token always `c4ca4238a0`.
   - **Time-seeded (CVSS 8.1-9.8):** `md5(time())`, `sha1(date('Y-m-d'))` — attacker brute-forces narrow window.
   - **Adequate (FP):** `wp_generate_password(32, false)`, `random_bytes()`, `openssl_random_pseudo_bytes()`, `wp_hash()` with AUTH_SALT.
2. **Token as sole auth gate:** Read the token validation code. If the token is the ONLY check before `wp_set_auth_cookie()`/`wp_set_current_user()` (no additional nonce, session binding, or IP restriction) → exploitable.
3. **Mechanical rule:** `md5($user_id)` or `sha1($user_id)` in a file containing auth cookie/session functions → CONFIRMED. `substr(md5(...), 0, N)` reduces keyspace further.
4. **FP indicators:** Token generated with `wp_generate_password()`, `random_bytes()`, `openssl_random_pseudo_bytes()`, or `wp_hash()` with non-source-code salt; token stored in user_meta with TTL enforcement and single-use deletion after validation.

## E.6 — Cookie-to-Auth-Function Pipeline (and Cookie-to-Security-Gate, generally)

Use `COOKIE_TO_AUTH_FUNCTION`. For each hit:

1. Cookies are fully client-controlled. ANY flow from `$_COOKIE` to `wp_set_current_user()` / `wp_set_auth_cookie()` without cryptographic verification is an authentication bypass.
2. **Confirmed bypass when:** cookie value is used as user_id or is the sole lookup key for user resolution without HMAC/signature verification. Attacker sets cookie to admin user_id → authenticated as admin. E.g. `$_COOKIE['original_user_id']` → `wp_set_current_user()` + `wp_set_auth_cookie()` with no auth/nonce/cap check.
3. **Mechanical rule:** `$_COOKIE[...]` → `wp_set_current_user($cookie_val)` or `wp_set_auth_cookie($cookie_val)` without `hash_equals(hash_hmac(...), ...)` verification → CONFIRMED. CVSS 9.8.
4. **FP indicators:** Cookie value is an HMAC-signed token validated via `hash_equals(hash_hmac(...), $cookie_value)` before use; cookie value is passed through `wp_validate_auth_cookie()` (WordPress core auth flow); cookie stores a session key that is matched against a server-side record via DB lookup.
5. **Same class, broader sink:** the underlying defect — a raw client-controlled cookie trusted without cryptographic verification — is not limited to `wp_set_current_user()`/`wp_set_auth_cookie()`. A cookie whose mere presence (`isset()`/`!empty()`, no comparison at all) or a loose-equality comparison directly flips ANY security/visibility/access-control decision variable (a maintenance-mode display gate, a paywall/lock bypass, a feature-restriction toggle) is the same vulnerability class at CWE-287/CWE-565, even when the sink is a plugin-internal boolean rather than a WordPress user session. Trace the flag to its use: if it feeds a bypass branch with no independent server-side check, treat it as CONFIRMED at whatever CIA impact the bypassed gate carries (may be lower than 9.8 when no admin/user-session impersonation results).

## E.7 — JWT Without Signature Verification

Use `JWT_DECODE_NO_VERIFY`. For each hit:

1. **Firebase JWT library:** `JWT::decode($jwt, $key, $algorithms)` — verify `$key` is not empty, null, or a hardcoded literal. Verify `$algorithms` array is specified (missing = no algorithm enforcement). E.g. JWT processed without signature verification.
2. **Manual JWT parsing:** `explode('.', $jwt)` followed by `base64_decode($parts[1])` extracts payload without signature check. If the decoded payload's `user_id`/`sub`/`email` claim flows to an auth function → CONFIRMED bypass.
3. **Empty key variant:** `JWT::decode($jwt, new Key(get_option('jwt_secret'), 'HS256'))` where `jwt_secret` option is empty/unconfigured. HS256 with empty key = attacker computes valid signatures for any payload.
4. **Mechanical rule:** JWT payload extraction without signature verification in the same function → CONFIRMED. CVSS 9.8. Empty key + JWT::decode() without empty() guard → CONFIRMED.
5. **FP indicators:** `JWT::decode()` called with a non-empty, non-hardcoded key from `wp-config.php` constants (AUTH_KEY, AUTH_SALT); signature verification via `openssl_verify()` or `hash_hmac()` + `hash_equals()` before payload extraction.

## E.8 — strpos() for Domain/Origin/Identity Allowlist Validation

Use `STRPOS_DOMAIN_VALIDATION` and `STRPOS_USERNAME_ALLOWLIST_MEMBERSHIP`. For each hit:

1. `strpos($input, 'trusted.com') !== false` matches `evil-trusted.com` and `trusted.com.evil.com`. Identical defect, different domain: `strpos($allowlist, $user->user_login) !== false` against a free-text username/email allowlist treats any user whose identity is a SUBSTRING of a listed entry as a member too (e.g. `alice` collides with whitelisted `alice_marketing`) — CWE-697 root cause, CWE-863 result.
2. **Confirmed bypass when:** the strpos()/str_contains() result gates an auth decision: IP/domain allowlist, origin check, webhook source validation, or a username/email allowlist deciding capability level.
3. **Correct validation:** exact match (`===`), suffix match with leading dot, or `parse_url()` for hosts; `in_array($user->user_login, explode(',', $allowlist), true)` for an identity allowlist — never `strpos()`.
4. **FP indicators:** strpos() used for logging/display/search-filtering, not auth-gating; exact/`in_array(..., true)` match used elsewhere in the same function; default/unconfigured allowlist is empty (`strpos('', $needle)` returns `false`, not itself exploitable) and a logged-out request still fails a downstream `current_user_can()` check.

## E.9 — Password Reset Flow Analysis

Use `PASSWORD_RESET_FLOW`. For each hit:

1. Map the complete WordPress password reset flow: `get_password_reset_key($user)` generates key → email delivery → `check_password_reset_key($key, $login)` validates → `reset_password($user, $new_pass)` sets new password.
2. **Confirmed bypass when:** (a) `reset_password()` called without prior `check_password_reset_key()` in the same flow; (b) `check_password_reset_key()` return value not checked with `is_wp_error()`; (c) reset key compared with `==` instead of `===`; (d) user from `$_POST['user_id']` instead of from the validated reset key's associated user.
3. **Custom reset implementations:** Plugins implementing their own password reset (not using WP Core functions) — verify: token has adequate entropy (≥32 chars, `wp_generate_password()` or `random_bytes()`), TTL enforcement (≤24h), single-use deletion after use, user binding (token tied to specific user_id in DB).
4. **FP indicators:** WP Core `check_password_reset_key()` called and `is_wp_error()` properly handled; token stored in user_meta with activation_key matching WP Core's hashed format.

## E.10 — Multi-Step Auth Flow Gap Analysis

Covers authentication flows where a critical step is missing or does not halt execution.

1. **Missing return/exit after auth error.** `check_login_and_get_user()` verified `user_id` and `login_nonce` in a 2FA REST flow — when `login_nonce` invalid, the function logged the error but did NOT return/exit → execution fell through to `wp_set_auth_cookie()` with the `user_id`. **Mechanical rule:** In any auth verification function, if an error/failure branch logs or records the failure but does not `return`, `exit`, `die`, or `wp_die()` → execution continues to the success path. Read every error branch for explicit halting.
2. **2FA skip via direct endpoint.** If a plugin implements 2FA, identify the endpoint that completes authentication after 2FA verification. Does a separate endpoint (e.g., REST API route, AJAX handler) call `wp_set_auth_cookie()` based on a session token or user_id without re-verifying the 2FA step? If `user_id` is passed as a parameter and accepted without verifying 2FA completion → bypass.
3. **Multi-step form wizards.** Registration or account creation flows split across multiple steps. If the final step (email verification, admin approval) can be skipped by sending the completion request directly → auth bypass.
4. **Mechanical rule:** For every code path that calls `wp_set_auth_cookie()` or `wp_set_current_user()`, trace backwards: does EVERY branch that reaches this call pass through a complete credential verification chain? If any branch reaches the auth function with only partial verification → CONFIRMED.

## E.11 — Workflow-Step / Sequential-State Auth Bypass & One-Time-Flag Replay

State-machine and idempotency flaws that reach a privileged auth/identity sink — CWE-841 (Sequential State Bypass) and CWE-840 (idempotency replay). Previously filed under "Business Logic"; they are **authentication bypass** when the sink is `wp_set_auth_cookie`/`wp_set_current_user`/`wp_set_password`/`wp_update_user`/`wp_insert_user` or an account activate/verify write. Use `WORKFLOW_STEP_AUTH_SINK` and `ONETIME_AUTH_FLAG_REPLAY` grep results; Semgrep lead `claude.php.wordpress.access-control.request-step-gates-auth-bypass` (heuristic, NOT a confirmation).

1. **Workflow-step bypass (CWE-841).** Multi-step flows (registration, email/OTP verification, onboarding, password reset, multi-page wizards) where a later-step handler trusts a client-supplied step/stage/status indicator and acts WITHOUT re-reading server-side state to confirm prior steps completed. For each handler branching on `$_REQUEST['step'|'stage'|'phase'|…]`, check whether the privileged auth action in that branch is gated by a server-side state read (`get_user_meta`/`get_transient`/`get_option`/`get_post_meta`, or a direct `$wpdb` state query) proving the prerequisite — its absence is the bug. Canonical shape: an OTP/code-login handler that compares submitted vs stored value WITHOUT first verifying an OTP was generated and is pending, so an empty/absent stored value matches an empty submission → unauthenticated takeover. The empty/loose-comparison facet is E.2/E.3; the missing-prerequisite-state facet is here. Cross-reference E.10 (missing return/exit; 2FA-skip).
2. **One-time-action / idempotency replay (CWE-840).** A token/claim/verification meant to be single-use is replayable because the `used`/`redeemed`/`verified`/`completed`/`activated` flag is set non-atomically (check-then-set across separate queries — see the Chain pass, Tier 12) or is never checked before the privileged action. For each single-use flag write, verify a guard reads the SAME flag BEFORE the action in the same path. In scope here when replay produces an auth/account state change (re-activate/re-verify an account); if it re-triggers a non-auth privileged grant, cross-reference Group AC; pure quota/coupon/vote replay is OOS. WP mechanics: `update_*_meta`/`update_option` upsert with no atomicity; `get_transient` returns `false` when absent/expired.
3. **Mechanical rule:** a privileged auth sink reachable inside a request-step/stage branch (or after a replayable one-time flag) with no server-side prerequisite-state read and no capability/nonce gate → CONFIRMED auth bypass. Determine the auth floor from reachability; CVSS up to 9.8 when admin impersonation/takeover is achievable.

## E.12 — Multi-Channel Dispatch Bypass

Some plugins route requests through more than one independent dispatch mechanism for logically the same set of privileged operations — e.g., a direct AJAX-style action dispatcher (`ctrl_action=ajax&ajax_action=X`) alongside a separate non-AJAX page-render dispatcher, each its own code path with its own gate. Use `RAW_ACTION_PARAM_DISPATCH`, `SLIM_FASTROUTE_ROUTER`, and `AJAX_HOOKS` surface results to enumerate a plugin's dispatch code paths manually.

1. **Enumerate every dispatch mechanism**, not just the one an obvious gate protects — a check on ONE channel (e.g. page-render) does not apply to a sibling channel (e.g. AJAX/REST/webhook) reaching the same handlers directly.
2. **Mechanical rule:** for any privileged operation reachable through 2+ distinct dispatch entry points, trace the gate independently for EACH — do not assume a gate on one channel is inherited by the others.
3. **Devastating variant:** the gated channel's own rendered output (e.g. a credential-entry page shown to unauthenticated visitors) may embed the tokens/nonces the ungated channel requires — verify what it discloses before concluding the ungated channel is unreachable without the gate's secret.
4. **FP indicator:** every dispatch channel independently re-derives and checks the same authorization/state condition before reaching privileged handlers.
5. **REST-dispatch-bypass sub-variant:** a manually constructed `WP_REST_Request` handed directly to a controller method (not `rest_do_request()`/`$server->dispatch()`) never enters WP's REST routing layer, so the route's own `permission_callback` never runs. Use `MANUAL_REST_REQUEST_CONSTRUCTION` grep results / Semgrep `manual-rest-request-direct-controller-call` (leads-only) — confirm the function is reachable without the route's normal permission check before confirming.

## E.13 — Token Verification Omits a Generation-Time Binding Component

A custom anti-replay/CSRF-style token scheme may compute a binding component (requester IP, User-Agent, session ID) at generation time as part of the token's derivation, but the verification function may re-check only the raw stored token value and never re-derive or re-compare that binding component against the CURRENT request.

1. **Mechanical rule:** read the verification function's full body, not just the fact that a comparison exists — if generation computes `token = f(secret, fingerprint)` but verification only checks `stored_token == submitted_token` without recomputing `fingerprint` from the current request, the token is replayable from any origin regardless of comparison strictness (`===` vs `==`).
2. A token scheme advertised or documented as bound to the requester (e.g. via an embedded fingerprint) that is actually replayable degrades to a bare bearer token — treat it as providing zero requester-binding for CVSS purposes.
3. **FP indicator:** the verification function re-derives the SAME binding component from the current request (current IP/UA/session) and compares it, not merely the shared-secret portion.

## E.14 — Third-Party Credential-Exchange Argument Injection (Non-WP-User OAuth/PKCE)

Distinct from E.1: E.1 covers OAuth flows that authenticate a WordPress USER. This subsection covers plugins implementing an OAuth/PKCE-style handshake to connect the SITE ITSELF to an external SaaS account (payment gateway, CRM, marketing platform) — the sink is a STORED API credential (`access_token`/API key written via `update_option()` or similar), not a WP auth cookie.

1. For each outbound request the plugin makes to complete such a handshake (identify via `OUTBOUND_HTTP`/`TOKEN_AUTH_FLOWS` grep results in files also implementing a "connect account"/"integration"/"onboarding" feature), read the URL-construction line. Identify every request-supplied value — sourced from a public callback/webhook endpoint reachable by anyone, not just the site owner — interpolated into that URL.
2. **Confirmed bypass when:** the value is NOT `urlencode()`/`rawurlencode()`'d before interpolation AND the URL carries a fixed query segment the plugin appends after the tainted value. Raw `?`/`=`/`&` bytes then inject an earlier-parsed query parameter that the destination's query parsing resolves in place of the plugin's intended one — substituting a security-relevant value (typically a PKCE `code_verifier`/state).
3. **Mechanical rule:** request-supplied value → interpolated into an outbound URL without `urlencode()`/`rawurlencode()` → URL also carries a plugin-appended query parameter after the tainted segment → CONFIRMED. Exploit shape: the attacker completes the SAME handshake with their OWN external account to get a valid identifier/verifier pair, supplies the crafted value to the victim site's public callback, and the destination validates the attacker's credentials and returns them — the plugin stores them as the victim site's.
4. **FP indicators:** the interpolated value is passed through `urlencode()`/`rawurlencode()`, or restricted to digits only (`preg_replace('/\D/', '', ...)`/`(int)`) before interpolation; the outbound URL has no fixed query-string segment after the tainted value (so an injected `&key=value` pair has nothing to override); the destination endpoint is not itself security-relevant (e.g. a read-only status poll, not a credential exchange).

## E.15 — Signed-Payload Scope Exclusion (Target-Identity Parameter Outside the Signed Content)

Distinct from E.13 (a binding component that WAS generated but omitted at verification): here the
parameter deciding WHO/WHAT the privileged action affects (username, user ID, account, recipient,
target resource) was NEVER in the signed content at generation OR verification — it's read from a
separate, unsigned channel (a GET/POST field beside the signature) and trusted once the signature
verifies (which proves only that *some* operation was authorized, not that it targets THIS resource).

1. **Mechanical rule:** read the exact bytes passed to the verify call (`hash_hmac()`,
   `openssl_verify()`, `Crypt_RSA::verify()`, etc.) and enumerate every parameter the code reads/acts
   on AFTER verification (target user, account ID, redirect used for more than display). If ANY such
   parameter is absent from the signed content, a holder of ONE valid signature can resubmit it with
   that parameter changed to a more privileged target (e.g. omitting `username` for an admin-fallback) — CONFIRMED.
2. **Common shape:** an "automatic login"/"magic link"/"impersonation token" handler that signs a nonce
   + redirect URL but resolves the target account from a separate, unsigned `username`/`user_id` GET
   parameter, defaulting to the highest-privileged account when empty.
3. **FP indicator:** the signed message string includes the target identity/resource parameter itself
   (verify by reading the exact concatenation/serialization passed to the verify call, not just that a
   param with that name exists in the request).

## E.16 — wp_check_password() Misused as a Bearer-Token Check

Use `WP_CHECK_PASSWORD_REQUEST_CONTROLLED_HASH` grep results (flags every `wp_check_password(`/`\wp_check_password(` call site) and Semgrep lead `claude.php.wordpress.access-control.wp-check-password-request-controlled-hash-arg` (heuristic, NOT a confirmation).

1. `wp_check_password($password, $hash, $user_id = '')` falls back to `hash_equals($hash, md5($password))` whenever `strlen($hash) <= 32` — a legacy branch that runs BEFORE any bcrypt/phpass verification, regardless of the site's real hashing mechanism.
2. **Mechanical rule:** for every call site, identify what the 2nd argument (`$hash`) is — directly or one hop through a parameter/local variable. If it is request-controlled (`$_GET`/`$_POST`/`$_COOKIE`/`$_REQUEST`, or a value assigned from one), AND the 1st argument (`$password`) has no secret component (a fixed string, `site_url()`/`home_url()`, `$_SERVER['HTTP_HOST']`, or anything else the attacker already knows or can compute) → CONFIRMED. The attacker submits `md5($password)` (≤32 hex chars) as the hash argument and passes the check with zero knowledge of any real credential (CWE-287/CWE-347).
3. **FP indicator:** the 1st argument embeds a genuine secret the attacker does not know (a stored password, a random per-user token) — forging a matching short hash then requires already knowing that secret.

## E.17 — Self-Minted, Self-Disclosed Verification Token (Nonce-Vendor Pattern)

Related to E.14 (same "connect the site to an external account" exploit shape) but a distinct mechanical defect: E.14 is about an unencoded value injected into an outbound URL; this is about the site's OWN inbound verification step trusting a token the ATTACKER generated and observed themselves, with no cryptographic proof it was ever meant for them specifically. Use Semgrep `claude.php.wordpress.access-control.self-minted-option-token-credential-sink` (heuristic — flags the shape, does not confirm reachability or the write-side trace).

1. **Mechanical rule:** a value is minted (`wp_create_nonce()`, `wp_generate_password()`, `uniqid()`, etc.) and persisted to `get_option()`/`get_site_option()` by a function reachable at or below the target auth floor, and that SAME stored value is disclosed back to the requester (echoed in a response body, embedded in a redirect `Location` URL, or otherwise readable without extra privilege) by that same reachable code path. A SEPARATE function later compares a request-supplied value against the stored option (`===`/`==`, NOT `wp_verify_nonce()`) as its sole gate before a credential-linkage sink (account-connect/login/authorize call, or a token-shaped `update_option()`/`update_site_option()` write). Trace the option name across BOTH the write (mint+disclose) and read (compare+consume) sides — they are commonly in different functions/files.
2. **Why this is exploitable despite the comparison being `===` (strict) and the token being cryptographically strong:** the token's entropy is irrelevant when the attacker is the one who generated it and immediately reads it back — `wp_create_nonce()`'s output is only unpredictable to a party who did NOT just trigger its generation. This is a distinct root cause from E.2/E.3's type-juggling/empty-secret bypasses (comparison correctness is not the defect here) and from E.13 (no binding component was ever supposed to exist — the token itself IS the entire "proof," and proving only "I recently observed the mint" is not proof of caller identity).
3. **FP indicator — contrast with a genuinely safe stored-token gate:** a token compared the same way (`get_option()`/`get_site_option()` + `===`) is NOT this bug when it is (a) generated with strong entropy AND (b) never reflected/echoed back to the requester on ANY reachable code path — i.e. the value that would let an attacker pass the check is never disclosed to them by the plugin itself. Grep every read/echo/redirect site of the option name before dismissing; a token satisfying only (a) without (b) is still the vulnerable pattern.

## CHECKPOINT: Write checkpoint-group-ab.md

After completing all subsections, write `AUDIT_DIR/checkpoint-group-ab.md`:

```markdown
# Checkpoint — Group AB (Auth Bypass) — [plugin] [version]

## Findings Confirmed
[List findings with CVSS, CWE, file:line, auth analysis — or "None" if clean]

## E.1–E.15 Analysis Summary
[One paragraph per subsection: what was examined, key code paths, why safe or vulnerable]

## Authentication Bypass Surface Summary
| Feature | Auth Method | Comparison Type | Empty-Guard | Token Entropy | Verdict |
|---------|------------|-----------------|-------------|---------------|---------|

## Leads for Chain Analysis
[Any partial findings, cross-group opportunities, or chains to verify]
```

Update `AUDIT_DIR/leads-forward.md` per the core ledger protocol (SKILL.md §5/§6): append any LEADS for later groups and the Chain pass (tag each `Relevant-to`), and for every custom sink you evaluated add/refresh its **SINK LEDGER** row with `AB` in `Consumed-by` (dedup by `fn@file:line`) — leave `(none)` only for a sink deferred to a later group or the Chain pass.

### Auth Model Addendum (Group AB)

If Authentication Bypass analysis found auth-relevant facts NOT already in auth-model.md (new token/secret comparison patterns, auth-flow gaps that change the Handler Auth Summary, cookie-to-auth pipelines, or structural facts), append an addendum to `AUDIT_DIR/auth-model.md`:

```markdown
---

## Addendum — Group AB (<ISO timestamp>)

### New Nonce Availability
| Action String | Min Capability | Public? | Source Page/Hook | Discovery Context |

### New Handler Auth Observations
| Handler | Type | Auth Gate | Nonce | CIA Impact | Discovery Context |

### Capability/Role Discoveries
- ...

### Auth-Relevant Structural Facts
- ...
```

Omit sub-sections with no new observations. Omit the entire addendum if no auth-relevant discoveries were made. Do NOT modify the Foundation phase's original tables or earlier addenda — only append below them.

## Group AB — FP Verification Rules

These rules supplement the universal FP rules in the shared core SKILL.md.

38. **OAuth callback with server-side token verification** — When a social login callback includes `wp_remote_get()` or `wp_remote_post()` to the OAuth provider's userinfo/token-info endpoint, AND the returned email is compared against the claimed email before `wp_set_auth_cookie()`, this is a proper verification chain. Confirm the comparison is strict (`===`) and the response is checked for errors before trusting the email claim.

39. **wp_authenticate() as a filter callback** — `wp_authenticate()` registered via `add_filter('authenticate', ...)` returns WP_User or WP_Error as part of the WordPress authentication filter chain. WP Core manages error handling upstream in `wp_signon()`. The plugin callback does not need its own `is_wp_error()` check — only standalone calls to `wp_authenticate()` outside the filter chain require it.

40. **wp_validate_auth_cookie() as session verification** — Cookie values passed through `wp_validate_auth_cookie()` before use in auth functions are safe — this is the standard WordPress session verification mechanism. Only flag cookie-to-auth flows that bypass this function.

41. **strpos() in non-auth context** — `strpos($domain, 'keyword')` used for logging, analytics categorization, or display routing (not gating authentication or authorization) is not a security finding. Confirm the strpos() result is used in a conditional that gates access before reporting.
   - Even when the result DOES gate a conditional, confirm who can influence the compared value — if only a same-or-higher-privileged write path can set it, a loose substring match provides no additional escalation.

42. **HMAC-signed auto-login tokens** — Auto-login/magic-link tokens generated with `hash_hmac('sha256', $data, AUTH_SALT)` or similar site-specific secret are not predictable even if `$data` contains the user_id. Only flag tokens where the entire value is computable from public information without knowledge of a server-side secret.

43. **`WORKFLOW_STEP_AUTH_SINK` / `request-step-gates-auth-bypass`** — A request step/stage value that only selects which view/template to render (no state change) is FP. Require the branch to reach a privileged auth sink with no server-side prerequisite-state read; server-side state may be verified via a direct `$wpdb` query rather than `get_*_meta`/`get_transient` — confirm no such check exists before reporting.

44. **Self-registration + auto-login is not impersonation** — `wp_set_current_user()`/`wp_set_auth_cookie()` called with the return value of `wp_insert_user()`/`wp_create_user()` in the SAME request is the standard "register then auto-login" pattern, not a bypass, even without email verification, since Core's own duplicate-email/username rejection prevents account takeover. Only flag when the ID passed to the auth sink can instead resolve to a PRE-EXISTING account (a user-supplied ID, or a lookup by attacker-chosen email/username).

45. **`wp_check_password()` with a genuine stored hash never hits the MD5 fallback** — When the 2nd argument (`$hash`) always originates from `wp_hash_password()`/`password_hash()` output (bcrypt/phpass, always well over 32 characters), `strlen($hash) <= 32` can never be true regardless of how the 1st argument is sourced. Confirm by tracing where the stored value was written, not just its variable name.

46. **Existence-gated mismatch check is not a binding check** — a reject-on-mismatch comparison wrapped in `!empty()`/`isset()` on the session-stored side only rejects when that value happens to be set, defeating the check. Confirm EVERY branch setting the paired "verified" flag also unconditionally sets the companion identity value — one branch setting the flag alone makes it identifier-unbound.

47. **Missing `empty($secret)` guard is not exploitable when the OTHER (claim/input) operand already has its own prior `!empty()` guard on the same code path.** An empty-by-default stored secret can never satisfy `===`/`==` against a guaranteed non-empty claim value — verify which operand the enclosing condition actually guards before flagging a bare `EMPTY_SECRET_COMPARISON` hit (Semgrep `empty-secret-comparison-auth-bypass` encodes this exclusion for the `$OBJ->get_meta()` shape).

48. **`md5()`/`sha1()` of a user ID used only as a cache/rate-limit transient key is not a predictable-token finding.** When the hash's sole consumer in the enclosing function is `get_transient()`/`set_transient()` (or an object-cache equivalent) as the KEY argument — never compared via `===`/`hash_equals()` as an auth/session credential — predictability carries no authentication-bypass impact even though the shape mechanically matches E.5's `md5($user_id)` trigger (Semgrep `predictable-auth-token-md5-user-id` encodes this exclusion).

49. **`hash_equals()` on a resolved object's own key is a complete identity-binding check when the object was fetched BY that same request-supplied ID.** Verifying `hash_equals($resolved->get_key(), $submitted_key)` immediately after resolving `$resolved` via the identical ID the key is checked against binds the ID and key as a matched pair — no separate fingerprint/nonce is needed, unlike the missing-binding-component gap in E.13. Confirm the fetch and the compare share the same ID variable before treating this shape as a gap.
