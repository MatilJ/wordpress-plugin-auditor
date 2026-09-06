# Variant Provenance

Maps rule/section extensions back to the disclosed CVE that seeded them.
This trail lives here, not in rule YAML (`references` stay CWE/OWASP-only).

Format: `<rule-id or section>  ⇐  <CVE>  CWE-<n>  (<slug> <affected>→<patched>, <date>)`

Free-text engineering notes can follow an entry — e.g. why a rule was extended,
false positives found and how they were suppressed, or Semgrep engine
limitations discovered along the way (taint-tracking gaps, array-taint
imprecision, etc.). Empirically verify each addition before logging it: the
rule should fire on the pre-patch line and stay silent on the patched one.

This file ships empty in the public repo — it's a personal, append-only log
that accumulates as *you* confirm variants and run `/codify-variant`. Nothing
is lost by starting fresh: every entry is generated from your own research,
not carried over from anyone else's.

---
