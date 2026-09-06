# Security Policy

## What this project is

`wordpress-plugin-auditor` is a research framework for **authorized, coordinated-disclosure**
security testing of WordPress plugins and themes. It downloads third-party plugin source, runs
static analysis over it, and drives an AI-assisted manual audit whose findings are meant to be
reported **privately** to a bug bounty program (Wordfence by default) and disclosed publicly only
after the program completes its process and any CVE is public.

Nothing in this repository is itself an exploit against a live third-party site, and it is not a
tool for opportunistic or unauthorized testing.

## Acceptable use

- Test only against **software you are authorized to test** and only in a **local environment**
  (the bundled Docker stack, or your own lab). Do not point the dynamic-validation tooling at
  production sites you do not own or operate.
- Follow the disclosure discipline described in `AUTHORIZATION.md` and your
  `~/.claude/CLAUDE.md`: private reporting first, no public disclosure until the vendor/program has
  finished coordinated disclosure.
- When you confirm a vulnerability in a third-party plugin, report it to the relevant bug bounty
  program or vendor — **not** as a public issue on this repository.

## Reporting a vulnerability in *this framework's own code*

If you find a security issue in the framework itself (for example, a way the tooling could be made
to write outside its intended directories, execute unintended commands, or leak local secrets),
please report it privately rather than opening a public issue:

- Open a **GitHub private security advisory** ("Report a vulnerability" under the repository's
  Security tab), or
- Contact the maintainer through the address associated with the repository owner.

Please include a description, affected files, and a minimal reproduction. We aim to acknowledge
reports within a reasonable time and will coordinate a fix and disclosure timeline with you.

## Out of scope for *this* repository's security reports

- Vulnerabilities in the third-party WordPress plugins/themes you audit with the tool — those go to
  the plugin's vendor or the bug bounty program, per the disclosure process above.
- Findings that depend on running the tool against targets or environments you are not authorized
  to test.
