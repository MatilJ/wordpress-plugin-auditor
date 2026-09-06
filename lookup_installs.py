import sqlite3
import glob
import os
import sys
import json


def lookup(slug, db_dir="databases"):
    best = None
    for db_path in glob.glob(os.path.join(db_dir, "*.db")):
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(
                "SELECT active_installs, version, last_updated FROM Plugins WHERE slug = ?",
                (slug,),
            )
            for row in cur.fetchall():
                installs, version, last_updated = row
                if best is None or installs > best["active_installs"]:
                    best = {
                        "slug": slug,
                        "active_installs": installs,
                        "version": version,
                        "last_updated": last_updated,
                        "source_db": os.path.basename(db_path),
                    }
            conn.close()
        except sqlite3.Error:
            continue
    return best


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python lookup_installs.py <plugin-slug>", file=sys.stderr)
        sys.exit(1)

    slug = sys.argv[1]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_dir = os.path.join(script_dir, "databases")

    result = lookup(slug, db_dir)
    if result:
        print(json.dumps(result))
    else:
        print(json.dumps({"error": f"Slug '{slug}' not found in any database"}))
        sys.exit(1)
