"""
Live-validation lock manager.

Provides atomic lock acquisition for the shared Docker WordPress
environment used by live-validation across parallel Claude Code sessions.

Usage:
    python lock_manager.py acquire <plugin-slug>
    python lock_manager.py release <session-id>
    python lock_manager.py heartbeat <session-id>
    python lock_manager.py wait <plugin-slug> [--timeout 1800] [--interval 90]
    python lock_manager.py status
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone

LOCK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live-validation.lock")
STALE_HEARTBEAT_SECONDS = 600  # 10 minutes
STALE_CONTAINER_CHECK_SECONDS = 180  # only check containers if heartbeat > 3 min old


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _read_lock():
    try:
        with open(LOCK_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _find_claude_pid():
    """Walk the process tree upward from this Python process to find claude.exe."""
    try:
        pid = os.getpid()
        for _ in range(5):
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$p = Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\";"
                 f" $parent = Get-Process -Id $p.ParentProcessId -ErrorAction SilentlyContinue;"
                 f" Write-Output \"$($p.ParentProcessId)|$($parent.ProcessName)\""],
                capture_output=True, text=True, timeout=10
            )
            parts = result.stdout.strip().split("|")
            if len(parts) == 2:
                parent_pid, parent_name = int(parts[0]), parts[1].lower()
                if "claude" in parent_name:
                    return parent_pid
                pid = parent_pid
            else:
                break
    except (ValueError, subprocess.TimeoutExpired, OSError):
        pass
    return os.getpid()


def _is_claude_alive(pid):
    """Check if PID is a live claude-related process."""
    if not pid:
        return False
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"],
            capture_output=True, text=True, timeout=10
        )
        name = result.stdout.strip().lower()
        return "claude" in name
    except (subprocess.TimeoutExpired, OSError):
        return True  # assume alive if we can't check


def _docker_containers_running():
    """Check if any project Docker containers are running."""
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--status", "running", "-q"],
            capture_output=True, text=True, timeout=15,
            cwd=os.path.dirname(LOCK_PATH)
        )
        return bool(result.stdout.strip())
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False  # can't check = assume not running


def _heartbeat_age(lock_data):
    """Seconds since last heartbeat."""
    try:
        hb = datetime.fromisoformat(lock_data["heartbeat"])
        return (datetime.now(timezone.utc) - hb).total_seconds()
    except (KeyError, ValueError, TypeError):
        return float("inf")


def _is_stale(lock_data):
    """Determine if lock is stale. Requires 2 of 3 signals."""
    if not lock_data:
        return True

    age = _heartbeat_age(lock_data)
    signals = 0

    heartbeat_stale = age > STALE_HEARTBEAT_SECONDS
    if heartbeat_stale:
        signals += 1

    pid_dead = not _is_claude_alive(lock_data.get("claude_pid"))
    if pid_dead:
        signals += 1

    if signals >= 2:
        return True

    # Only check containers if heartbeat is somewhat old (avoids false positive during startup)
    if age > STALE_CONTAINER_CHECK_SECONDS:
        no_containers = not _docker_containers_running()
        if no_containers:
            signals += 1

    return signals >= 2


def _break_stale_lock():
    """Rename stale lock for forensic review."""
    stale_name = os.path.join(
        os.path.dirname(LOCK_PATH),
        f"live-validation.lock.stale.{int(time.time())}"
    )
    try:
        os.rename(LOCK_PATH, stale_name)
    except OSError:
        # Another process already broke it, or file gone
        try:
            os.remove(LOCK_PATH)
        except OSError:
            pass


def _try_create_lock(plugin_slug, session_id):
    """Atomic lock creation. Returns True if acquired."""
    lock_data = {
        "plugin": plugin_slug,
        "started": _now_iso(),
        "session_id": session_id,
        "heartbeat": _now_iso(),
        "claude_pid": _find_claude_pid(),
    }
    try:
        fd = os.open(LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(lock_data, f, indent=2)
        except Exception:
            # If write fails, clean up the empty lock file
            try:
                os.remove(LOCK_PATH)
            except OSError:
                pass
            raise
        return True
    except FileExistsError:
        return False


def cmd_acquire(plugin_slug):
    session_id = secrets.token_hex(4)

    if _try_create_lock(plugin_slug, session_id):
        print(json.dumps({"status": "acquired", "session_id": session_id}))
        return 0

    lock_data = _read_lock()
    if lock_data and _is_stale(lock_data):
        _break_stale_lock()
        if _try_create_lock(plugin_slug, session_id):
            print(json.dumps({"status": "acquired", "session_id": session_id, "broke_stale": True}))
            return 0

    holder = lock_data.get("plugin", "unknown") if lock_data else "unknown"
    print(json.dumps({"status": "busy", "holder": holder}))
    return 1


def cmd_release(session_id):
    lock_data = _read_lock()
    if not lock_data:
        print(json.dumps({"status": "not_found"}))
        return 1
    if lock_data.get("session_id") != session_id:
        print(json.dumps({"status": "not_owner", "owner": lock_data.get("session_id")}))
        return 1
    try:
        os.remove(LOCK_PATH)
        print(json.dumps({"status": "released"}))
        return 0
    except OSError as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        return 1


def cmd_heartbeat(session_id):
    lock_data = _read_lock()
    if not lock_data:
        print(json.dumps({"status": "lock_lost", "reason": "file_missing"}))
        return 1
    if lock_data.get("session_id") != session_id:
        print(json.dumps({"status": "lock_lost", "reason": "owner_changed",
                          "current_owner": lock_data.get("session_id")}))
        return 1

    lock_data["heartbeat"] = _now_iso()
    try:
        with open(LOCK_PATH, "w", encoding="utf-8") as f:
            json.dump(lock_data, f, indent=2)
        print(json.dumps({"status": "alive", "heartbeat": lock_data["heartbeat"]}))
        return 0
    except OSError as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        return 1


def cmd_wait(plugin_slug, timeout=1800, interval=90):
    session_id = secrets.token_hex(4)
    deadline = time.time() + timeout

    while time.time() < deadline:
        if _try_create_lock(plugin_slug, session_id):
            print(json.dumps({"status": "acquired", "session_id": session_id}))
            return 0

        lock_data = _read_lock()
        if lock_data and _is_stale(lock_data):
            _break_stale_lock()
            if _try_create_lock(plugin_slug, session_id):
                print(json.dumps({"status": "acquired", "session_id": session_id, "broke_stale": True}))
                return 0

        holder = lock_data.get("plugin", "unknown") if lock_data else "unknown"
        elapsed = timeout - (deadline - time.time())
        print(json.dumps({
            "status": "waiting",
            "holder": holder,
            "elapsed_minutes": round(elapsed / 60, 1),
            "remaining_minutes": round((deadline - time.time()) / 60, 1),
        }))
        sys.stdout.flush()
        time.sleep(interval)

    print(json.dumps({"status": "timeout"}))
    return 1


def cmd_status():
    if not os.path.exists(LOCK_PATH):
        print(json.dumps({"locked": False}))
        return 0

    lock_data = _read_lock()
    if not lock_data:
        print(json.dumps({"locked": True, "corrupt": True}))
        return 0

    lock_data["locked"] = True
    lock_data["stale"] = _is_stale(lock_data)
    lock_data["heartbeat_age_seconds"] = round(_heartbeat_age(lock_data), 1)
    lock_data["holder_alive"] = _is_claude_alive(lock_data.get("claude_pid"))
    print(json.dumps(lock_data, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Live-validation lock manager")
    sub = parser.add_subparsers(dest="command")

    p_acquire = sub.add_parser("acquire")
    p_acquire.add_argument("plugin_slug")

    p_release = sub.add_parser("release")
    p_release.add_argument("session_id")

    p_heartbeat = sub.add_parser("heartbeat")
    p_heartbeat.add_argument("session_id")

    p_wait = sub.add_parser("wait")
    p_wait.add_argument("plugin_slug")
    p_wait.add_argument("--timeout", type=int, default=3600)
    p_wait.add_argument("--interval", type=int, default=90)

    sub.add_parser("status")

    args = parser.parse_args()

    if args.command == "acquire":
        sys.exit(cmd_acquire(args.plugin_slug))
    elif args.command == "release":
        sys.exit(cmd_release(args.session_id))
    elif args.command == "heartbeat":
        sys.exit(cmd_heartbeat(args.session_id))
    elif args.command == "wait":
        sys.exit(cmd_wait(args.plugin_slug, args.timeout, args.interval))
    elif args.command == "status":
        sys.exit(cmd_status())
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
