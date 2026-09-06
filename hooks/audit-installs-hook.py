import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lookup_installs import lookup


def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        print(json.dumps({}))
        return

    prompt = data.get("prompt", "")
    match = re.search(r"(?i)audit\s+([\w-]+)\s+with\s+full\s+audit\s+pipeline", prompt)
    if not match:
        print(json.dumps({}))
        return

    slug = match.group(1)
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_dir = os.path.join(script_dir, "databases")

    result = lookup(slug, db_dir)
    if not result:
        msg = (
            f"[INSTALL-COUNT] Plugin '{slug}' was NOT found in any local database. "
            f"Query the WordPress.org API to get the correct install count before writing audit headers."
        )
    else:
        installs = f"{result['active_installs']:,}"
        msg = (
            f"[INSTALL-COUNT] Plugin '{slug}' has {installs} active installs "
            f"(source: {result['source_db']}, last_updated: {result['last_updated']}). "
            f"Use this exact number in audit-context.md ('Active installs:') and "
            f"findings.md ('Plugin installs:'). Do NOT guess or use any other number."
        )

    print(json.dumps({"systemMessage": msg}))


if __name__ == "__main__":
    main()
