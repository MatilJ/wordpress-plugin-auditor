# WordPress Plugin Auditor

An experiment in whether an AI agent can find real, exploitable vulnerabilities in WordPress
plugins. Not just flag patterns, but confirm them against live code. It is built end to end with
Claude Code and has three parts: a native regex/dataflow scanner, a custom Semgrep corpus, and a
multi-agent audit pipeline that reads plugin source the way a careful human researcher would. It
understands the architecture first, hunts for vulnerabilities second, and writes nothing down until
it has been checked against the source and exploited on a local install.

The project is wired for coordinated disclosure through the
[Wordfence Intelligence Bug Bounty Program](https://www.wordfence.com/threat-intel/bug-bounty-program/).
Findings go to the vendor privately, and nothing is published here until the CVE is public (see
[`case-studies/`](./case-studies/)). None of the pipeline logic is Wordfence-specific. The program's
rules live in one file you own, so you can rewrite it for whatever coordinated-disclosure program you
work with.

> **Honest scope.** This is bounty-oriented research, not a neutral security scanner. The pipeline is
> tuned to Wordfence's in-scope vulnerability classes and privilege levels, and it deliberately sets
> aside finding types that program does not reward (Contributor and Author level bugs, for example,
> which went out of scope in 2026). Those are still real vulnerabilities in the code. The tool just
> does not queue them for submission. To retarget it, rewrite the one policy file it reads,
> `templates/global-CLAUDE.md.example`.

> **Please use this responsibly.** Do not clone this, point it at wordpress.org in bulk, and start
> firing reports at Wordfence. The program is already dealing with a flood of low-quality,
> AI-generated submissions, and reviewers spend real time rejecting them. This tool only produces
> something worth submitting when a human verifies every finding against the source and proves it
> works in the live sandbox first. Skip that step and you waste the reviewers' time and burn your own
> standing; programs restrict and ban accounts for repeat false positives. Treat every finding as a
> lead until you have confirmed it yourself.

## Track record

A few numbers, so you know this is not a pile of prompts that has never found anything real. These
are all-time counts from my own records.

| Outcome | Count |
|---|---|
| Public CVEs (assigned by Wordfence as CNA) | **3** (see [`case-studies/`](./case-studies/)) |
| Findings that paid a bounty | 1 |
| Submitted, returned as duplicates (real bug, someone else reported it first) | 15 |
| Submitted, rejected | 11 |
| Live-validated leads across the full history | 200+ |

The three public CVEs are written up in [`case-studies/`](./case-studies/), with the real disclosure
report and a working PoC for each:
[CVE-2026-14433](https://www.cve.org/CVERecord?id=CVE-2026-14433) (unauthenticated Stored XSS in
Online Booking & Scheduling Calendar by vcita),
[CVE-2026-13454](https://www.cve.org/CVERecord?id=CVE-2026-13454) (SQL injection in MotoPress
Appointment Booking), and [CVE-2026-15066](https://www.cve.org/CVERecord?id=CVE-2026-15066) (Stored
XSS in Loco Translate).

About that 200+ figure. It is the all-time count of leads that passed live validation, meaning each
one was actually exploited against a local, disposable WordPress install rather than just
pattern-matched. It spans every privilege level the pipeline tests, including Contributor and Author
findings that were later dropped from my tracking registry once Wordfence took those roles out of
scope in 2026. It is not a count of Wordfence submissions, and it is not a count of bugs a second
human independently re-verified. Read it as evidence that the pipeline reliably finds real bugs, not
as a bounty tally. A handful of other findings are still with Wordfence awaiting a decision; those
plugins are not named and are not counted as CVEs here until the record is public.

## Why this exists

Auditing WordPress plugins for security bugs by hand does not scale. There are tens of thousands of
them. Pointing an LLM at a plugin and asking it to "find bugs" does not work well either; it
pattern-matches to whatever vulnerability classes it already expects and hallucinates the rest of the
way there. What worked, in my experience, was less about prompting and more about process.

**Build context before hunting.** A dedicated phase reads the plugin's architecture (hooks, entry
points, custom sinks, the auth model) before any vulnerability hunting starts, so later analysis is
not guessing at code it has never seen.

**Split the search space, not the model's attention.** Vulnerability analysis runs as separate
passes: auth bypass, access control, RCE and file operations, SQLi, XSS, SSRF and info disclosure,
then a final cross-tier chaining pass. Each pass is a fresh sub-agent with its own bounded context
and its own methodology file, so no single pass has to hold the whole plugin and every vulnerability
class in its head at once.

**Static tools generate leads, never verdicts.** A native grep scanner (400+ pattern sections) and
the custom Semgrep corpus in `semgrep_rules/`, both grown from real confirmed CVEs, run first and
hand every pass a pre-filtered list of coordinates to look at. Every hit still gets checked by hand
against the actual source before it is written down as a finding, because most static-analysis hits
are false positives and the pipeline treats them that way by default.

**The corpus gets better after every audit.** Confirmed findings and dismissed false positives both
feed a cross-audit pattern database. Two tuning skills use it to prune rules that never catch anything
real and to add coverage for whatever the methodology missed. Every change is evidence-gated rather
than a guess.

## How it works

```
  wp-plugin-downlauditor.py ──► plugins/<slug>/<version>/        (your local plugin corpus)
        │                              │
        │ (Semgrep pre-scan)           │
        ▼                              ▼
  semgrep_rules/ ──────────►  grep_scan.py + extract_semgrep_coords.py
   (custom corpus)                     │
                                        ▼
                         Full Audit Pipeline (Claude Code skill)
                    Foundation → AB → AC → A → SQLi → C → D1 → Chain
                                        │
                                        ▼
                         audit/<slug>/<version>/findings.md
                                        │
                          ┌─────────────┼─────────────┐
                          ▼             ▼              ▼
                    vuln-report   poc-generator   registry-updater
                   (disclosure)      (PoC)         (vuln-registry.md)
                                        │
                                        ▼
                            live-validation (Docker WordPress)
                                confirms it before you submit
```

Two scripts, `daily_targets.py` fed by `wf_variants.py` and `audit_targets.py`, turn your local
plugin database and the Wordfence disclosure feed into a ranked daily worklist (`targets.md`). Once
you are past initial setup, `docs/daily-workflow.md` walks through the day-to-day loop.

## Quickstart

If you already have Python, Docker, and the Semgrep CLI installed:

```bash
git clone <this-repo-url> wordpress-plugin-auditor
cd wordpress-plugin-auditor
pip install -r requirements.txt
semgrep login                                    # free account, unlocks the full ruleset
cp templates/global-CLAUDE.md.example ~/.claude/CLAUDE.md   # your researcher policy; go edit it
cp .env.example .env                              # optional: Wordfence API key, for variant leads
docker compose up -d                              # optional; the live-validation skill brings this up itself
```

Open Claude Code from this repo's directory and the skills show up on their own. They live in
`.claude/skills/`, with no separate install step. The tracked `.claude/settings.json` ships only the
project's hooks and no pre-approved permission allowlist, so Claude Code prompts you to approve tool
actions the first time each one runs. Approvals you add land in the gitignored
`.claude/settings.local.json`, which stays on your machine. Get a plugin on disk (see [Building your
plugin database](#building-your-plugin-database) below) and say:

```
Audit <plugin-slug> with Full Audit Pipeline
```

Everything else below is the detail behind that quickstart.

## Prerequisites

- **Python 3.10+**, `pip install -r requirements.txt` (pulls in `requests`, `tqdm`, and
  `python-dateutil`; everything else used is stdlib).
- **[Semgrep CLI](https://semgrep.dev/)**, logged in via `semgrep login`. The free tier is enough.
  Most of the custom rules in `semgrep_rules/` run without an account, but the corpus also includes
  join-mode rules (`mode: join`) that Semgrep only executes when you are logged in, so log in to get
  the full corpus running. Logging in also unlocks Semgrep's own registry rules on top, if you want
  those too.
- **Docker Desktop** (or Docker Engine plus Compose), for the local WordPress instance that
  `live-validation` uses to confirm a finding before you write it up.
- **[Claude Code](https://claude.com/product/claude-code)**. The skills use its
  `${CLAUDE_PROJECT_DIR}` and `${CLAUDE_SKILL_DIR}` path substitutions and its Skill/Agent tooling,
  so this genuinely needs Claude Code, not just any LLM with file access.
- Optional: a free Wordfence Intelligence API key if you want variant-analysis leads (chasing fresh
  disclosures against plugins you already track). The pipeline works fine without one; you just lose
  that lead source.

I have built and run this on Windows with PowerShell. It should work fine on macOS and Linux, since
the Python is plain stdlib and the Docker setup is a standard Compose file. A few of the exact shell
commands quoted inside the skills (mainly `live-validation`) are PowerShell-flavored, so expect to
adjust quoting if you are on bash or zsh.

## Setup walkthrough

### 1. Clone and install dependencies

```bash
git clone <this-repo-url> wordpress-plugin-auditor
cd wordpress-plugin-auditor
pip install -r requirements.txt
semgrep login
```

### 2. Set your researcher policy

The skills do not hardcode scope, eligibility, or severity rules. They read all of that from your
**global** Claude Code instructions at `~/.claude/CLAUDE.md`, which applies across every project on
your machine, not just this one. That is on purpose. Your bounty-program rules and researcher tier
are yours, and they should not get overwritten every time you pull an update to this repo.

```bash
cp templates/global-CLAUDE.md.example ~/.claude/CLAUDE.md    # merge it in if you already have one
```

The template ships with Wordfence's current, public bug bounty ruleset, so if that is your program
you can use it close to as-is and just set your researcher tier. On a different program, rewrite the
scope and OOS sections to match its actual public policy, and do the same for `AUTHORIZATION.md`.

### 3. Building your plugin database

There is no bundled plugin corpus and no bundled install-count database. You build both yourself,
locally, with `wp-plugin-downlauditor.py`, which pulls from the public WordPress.org plugin API:

```bash
# Download everything with 50,000+ active installs, updated in the last 24 months,
# and audit it with this repo's Semgrep corpus while you're at it:
python wp-plugin-downlauditor.py -m both --db databases/50k.db \
    --active-installs-min 50000 --config ./semgrep_rules
```

Run it a few more times with different `--active-installs-min` floors and you end up with
install-tiered databases (`databases/25.db`, `databases/500.db`, `databases/50k.db`, and so on).
`lookup_installs.py` and the install-count hook search every `.db` under `databases/` and use
whichever has the highest match. `databases/` is gitignored; it is yours.

One plugin at a time, on demand:

```bash
python wp-plugin-downlauditor.py --plugin <slug> -m both --config ./semgrep_rules
```

### 4. Optional: a Wordfence API key, for variant leads

Free key, from wordfence.com, your account, Integrations. Then either:

```bash
cp .env.example .env    # edit .env, set WORDFENCE_API_KEY=...
```

or just export `WORDFENCE_API_KEY` yourself. Without a key, `daily_targets.py` still works; you just
do not get variant leads from fresh disclosures.

### 5. Local WordPress environment, for live validation

You usually do not start this by hand. When you run the `live-validation` skill, it starts Docker
Desktop if it is not already running, tears down any old stack, brings the environment up fresh, and
copies in and activates the plugin being audited (plus any dependency plugins) before it runs the
PoC. That is the intended path, and it is how a finding gets proven to work before it becomes a
disclosure report.

The environment itself is WordPress, MariaDB, [Mailpit](https://mailpit.axllent.org/) (which catches
any outbound email so nothing actually leaves the sandbox), and Adminer at `localhost:8080`.
`setup.sh` provisions an admin account plus one user per role (administrator, editor, author,
contributor, subscriber), each with a `<role>123` password. These are throwaway local credentials
that nobody else can reach.

If you just want to poke at the environment by hand, you can bring it up yourself:

```bash
docker compose up -d
```

To install a specific plugin at boot, set `PLUGIN_SLUG` first (the `setup` service reads it):

```bash
PLUGIN_SLUG=<slug> docker compose up -d
```

### 6. Your first audit

Once you have at least one plugin downloaded (step 3), open Claude Code from this repo's root and say:

```
Audit <plugin-slug> with Full Audit Pipeline
```

If the slug is in one of your `databases/*.db` files, the install-count hook fills in
`[INSTALL-COUNT]` automatically. Output goes to `audit/<slug>/<version>/`, and `findings.md` is the
one worth watching.

## Daily/weekly workflow

Once setup is done, the loop is simple. `daily_targets.py` ranks what is worth auditing today across
three angles: fresh releases of plugins you have already audited, fresh Wordfence disclosures on
plugins you track, and never-touched high-install plugins. You run the pipeline against the top of
that list, and confirmed findings feed a pattern database that a weekly ritual uses to decide what is
worth one of your limited submission slots and which Semgrep rules have stopped earning their keep.
`docs/daily-workflow.md` has the full walkthrough with real command examples. It links out to
`docs/edge-workflow.md` and `docs/accumulator-playbook.md` for the two halves in more depth, and
`docs/detection-backfill.md` covers the separate loop for hardening the rule corpus itself.

## Directory layout

`CLAUDE.md` has the full annotated tree. In short: `plugins/` and `audit/` are your own working state
(gitignored, you populate them); `semgrep_rules/` and `.claude/skills/` are the framework itself;
`databases/` is your local plugin and install-count corpus from step 3 above; and `wp-core/` is a
WordPress-core reference tree you build per `wp-core/VERSIONS.md`.

## Confidentiality & responsible disclosure

This produces disclosure reports, not public write-ups. Findings go only to the program you are
working with, and only once you can verify the code reference yourself in the real source tree. Do
not trust an unverified claim, whether it came from Semgrep, from grep, or from the model's own
reasoning. Nothing gets disclosed publicly before the program finishes coordinated disclosure and any
CVE is public. `AUTHORIZATION.md` and your `~/.claude/CLAUDE.md` cover the full discipline this is
built around.

## Adapting to a different bug bounty program

Everything program-specific lives in two files, and both are meant to be forked:

- `~/.claude/CLAUDE.md` (from `templates/global-CLAUDE.md.example`): scope, in-scope and
  out-of-scope vuln classes, install thresholds, severity model, confidence bar.
- `AUTHORIZATION.md`: the authorization basis and disclosure discipline you are operating under.

The skills read their policy from those two files instead of hardcoding Wordfence's rules, so
rewriting them to match a different program's public policy (Patchstack, HackerOne, a private VDP) is
enough on its own. No skill code needs to change.

> **Policy is a point-in-time snapshot.** The bundled Wordfence scope and eligibility policy in
> `templates/global-CLAUDE.md.example` and the payout values in `bounty_calculator_config.json` were
> copied from the program's public pages when this repo was written, and they are **not** kept in sync
> automatically. The calculator config came from
> `https://www.wordfence.com/api/threat-intel/bounty-calculator-config`, which is public. Bounty
> programs change their rules, thresholds, and rates, so verify against the program's own current
> pages before you rely on any number here for a scope or reward decision.

## Known limitations

- Verified on Windows and PowerShell only. macOS and Linux should work, but I have not run it there,
  so expect to adapt a handful of PowerShell-flavored commands, mostly in `live-validation`.
- Only one bounty program's policy is fully worked out. Everything else needs you to fork the two
  policy files above rather than flip a config switch.
- The Semgrep corpus and grep patterns are a living body of work, not a finished product. They grow
  from confirmed findings and dismissed false positives, so a fresh clone starts with whatever
  general coverage already exists and gets sharper the more you use it (via `tune-semgrep` and
  `tune-vuln-audit` after each audit, and `/codify-variant` after each confirmed disclosure).

## Credits

The download-and-audit approach in `wp-plugin-downlauditor.py` was inspired by
[prjblk/wordpress-audit-automation](https://github.com/prjblk/wordpress-audit-automation), and the
community forks by [0xb120](https://github.com/0xb120/wp-plugin-downlauditor) and
[m3ssap0](https://github.com/m3ssap0/wordpress-audit-automation), which got there first on the idea
of bulk-downloading WordPress.org plugins via the official API and auditing them with Semgrep. None of
those projects carry an explicit license, so what is here is an independent rewrite of the same idea,
with a different architecture and no shared code, rather than a redistribution of theirs. Full credit
to them for the concept.

Vulnerability data for variant analysis comes from the
[Wordfence Intelligence](https://www.wordfence.com/threat-intel/) feed. Plugin metadata comes from the
public [WordPress.org Plugins API](https://developer.wordpress.org/reference/functions/plugins_api/).

## License

MIT. See `LICENSE`.
