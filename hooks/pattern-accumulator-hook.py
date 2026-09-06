import json
import os
import re
import subprocess
import sys
from pathlib import Path


def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        print(json.dumps({}))
        return

    prompt = data.get("prompt", "")
    if not re.search(r"tune[_-](?:semgrep|vuln[_-]audit)", prompt, re.IGNORECASE):
        print(json.dumps({}))
        return

    script_dir = Path(__file__).resolve().parent.parent
    accumulator = script_dir / "pattern_accumulator.py"
    audit_dir = script_dir / "audit"

    slug_m = re.search(r"tune[_-](?:semgrep|vuln[_-]audit)\s+([\w-]+)", prompt, re.IGNORECASE)
    target_dir = None

    if slug_m:
        slug = slug_m.group(1)
        slug_path = audit_dir / slug
        if slug_path.exists():
            versions = sorted(slug_path.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            for v in versions:
                if (v / "findings.md").exists():
                    target_dir = v
                    break

    if not target_dir:
        findings_files = sorted(audit_dir.rglob("findings.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        if findings_files:
            target_dir = findings_files[0].parent

    if not target_dir:
        print(json.dumps({}))
        return

    try:
        result = subprocess.run(
            [sys.executable, str(accumulator), "ingest", str(target_dir)],
            capture_output=True, text=True, timeout=10,
            cwd=str(script_dir),
        )
        output = result.stdout.strip()
        msg = f"[PATTERN-DB] {output}" if output else "[PATTERN-DB] Ingestion completed (no output)"
    except Exception as e:
        msg = f"[PATTERN-DB] Ingestion failed: {e}"

    print(json.dumps({"systemMessage": msg}))


if __name__ == "__main__":
    main()
