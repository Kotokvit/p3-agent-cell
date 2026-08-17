#!/usr/bin/env python3
"""
P3 Bridge v5 — AI-side bridge with security module.

Sends commands to PC via GitHub repo relay, reads results.
Full security: HMAC signing, encryption, token sanitization.

Usage:
  export P3_GITHUB_TOKEN=<classic_pat>
  export P3_SECRET=<shared_secret>

  python3 p3_bridge.py cmd "ls -la"        # One-shot command
  python3 p3_bridge.py status              # System status
  python3 p3_bridge.py repl                # Interactive REPL
"""

import urllib.request
import urllib.error
import json
import time
import sys
import os
import re
import base64
import argparse
import uuid
import signal
import readline
import atexit
from datetime import datetime, timezone
from pathlib import Path

# Import security module
sys.path.insert(0, str(Path(__file__).parent))
from p3_security import (
    ChannelEncryption,
    generate_hmac,
    get_crypto,
)

# ──────────────────────────── Config ────────────────────────────

GITHUB_API = "https://api.github.com"
REPO_OWNER = os.environ.get("P3_REPO_OWNER", "Kotokvit")
REPO_NAME = os.environ.get("P3_REPO_NAME", "p3-agent-cell")
RELAY_PATH = os.environ.get("P3_RELAY_PATH", "relay")
ENGINE_DIR = os.environ.get("P3_ENGINE_DIR", "/home/vitalij/Стільниця/P3_Engine_repo")

TOKEN = os.environ.get("P3_GITHUB_TOKEN", "")
P3_SECRET = os.environ.get("P3_SECRET", "")

HISTORY_FILE = os.path.expanduser("~/.p3_bridge_history")

# ──────────────────────────── Sanitize ────────────────────────────

def sanitize(text):
    """Strip ALL GitHub token patterns from text."""
    if not text:
        return text
    for pat in [
        r'ghp_[A-Za-z0-9]{36}',
        r'github_pat_[A-Za-z0-9_]{82}',
        r'gho_[A-Za-z0-9]{36}',
        r'ghr_[A-Za-z0-9]{36}',
        r'ghu_[A-Za-z0-9]{36}',
        r'ghi_[A-Za-z0-9]{36}',
    ]:
        text = re.sub(pat, '***TOKEN***', text)
    text = re.sub(
        r'(https?://)(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})(@)',
        r'\1***TOKEN***\3', text
    )
    return text

# ──────────────────────────── GitHub API ────────────────────────────

_sha_cache = {}

def github_api(method, path, data=None, retries=3):
    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    }
    url = f"{GITHUB_API}{path}"
    body = json.dumps(data).encode() if data else None

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            resp = urllib.request.urlopen(req, timeout=20)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403 and attempt < retries - 1:
                reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                if reset:
                    wait_time = min(reset - int(time.time()) + 1, 30)
                    print(f"  ⏳ Rate limited, waiting {wait_time}s...", file=sys.stderr)
                    time.sleep(wait_time)
                else:
                    time.sleep(2 ** attempt)
                continue
            if e.code in (409, 422) and attempt < retries - 1:
                time.sleep(1)
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise
    return None

def repo_get(path):
    try:
        data = github_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}")
        content = base64.b64decode(data["content"]).decode("utf-8")
        _sha_cache[path] = data["sha"]
        return content, data["sha"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None
        raise

def repo_put(path, content_str, message="update", sha=None, retries=3):
    content_b64 = base64.b64encode(content_str.encode("utf-8")).decode("ascii")
    data = {"message": message, "content": content_b64}
    if sha:
        data["sha"] = sha

    for attempt in range(retries):
        try:
            result = github_api("PUT", f"/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}", data)
            if result and "content" in result:
                _sha_cache[path] = result["content"].get("sha", "")
            return result
        except urllib.error.HTTPError as e:
            if e.code in (409, 422):
                _, new_sha = repo_get(path)
                if new_sha:
                    data["sha"] = new_sha
                    if attempt < retries - 1:
                        continue
                raise
            raise
    return None

# ──────────────────────────── Relay Commands ────────────────────────────

def send_command(cmd, cwd=None, timeout=120):
    """Send a command through the GitHub repo relay with HMAC signing."""
    cmd_id = str(uuid.uuid4())[:8]
    if not cwd:
        cwd = ENGINE_DIR
    safe_cmd = sanitize(cmd)
    ts = time.time()

    cmd_data = {
        "id": cmd_id,
        "cmd": safe_cmd,
        "cwd": cwd,
        "timeout": timeout,
        "ts": ts,
    }

    # Sign with HMAC if secret is set
    if P3_SECRET:
        cmd_data["hmac"] = generate_hmac(cmd_id, safe_cmd, ts)
        cmd_data["encrypted"] = False

    content = json.dumps(cmd_data, ensure_ascii=False, indent=2)

    # Encrypt if secret is set
    crypto = get_crypto()
    if crypto.enabled:
        content = crypto.encrypt(content)
        cmd_data["encrypted"] = True

    path = f"{RELAY_PATH}/cmd.json"
    sha = _sha_cache.get(path)
    if not sha:
        _, sha = repo_get(path)
    result = repo_put(path, content, message=f"cmd: {cmd_id}", sha=sha)
    return cmd_id

def read_result(expected_id=None, max_wait=120, poll_interval=4):
    """Poll result.json until we get the expected result."""
    path = f"{RELAY_PATH}/result.json"
    crypto = get_crypto()
    start = time.time()

    while time.time() - start < max_wait:
        try:
            content, sha = repo_get(path)
            if content:
                # Try decryption
                try:
                    content = crypto.decrypt(content)
                except Exception:
                    pass

                result = json.loads(content)
                if expected_id is None or result.get("id") == expected_id:
                    return result
        except Exception:
            pass
        time.sleep(poll_interval)
        sys.stdout.write(".")
        sys.stdout.flush()
    return None

# ──────────────────────────── High-level Commands ────────────────────────────

def do_cmd(cmd, cwd=None, timeout=120, wait=120, verbose=True):
    """Execute a command on the remote PC."""
    cmd_id = send_command(cmd, cwd, timeout)
    if verbose:
        ts = datetime.now().strftime("%H:%M:%S")
        enc = "🔒" if P3_SECRET else "  "
        print(f"[{ts}] {enc}→ Repo [{cmd_id}]: {cmd[:80]}")

    result = read_result(cmd_id, max_wait=wait)
    if not result:
        if verbose:
            print(f"\n  ✗ Timeout after {wait}s")
        return None

    if verbose:
        rc = result.get("returncode", "?")
        elapsed = result.get("elapsed", "?")
        print(f"\n--- RESULT (rc={rc}, {elapsed}s) ---")
        if result.get("stdout"):
            print(result["stdout"][:8000])
        if result.get("stderr"):
            print(f"STDERR: {result['stderr'][:3000]}", file=sys.stderr)
    return result

def do_status():
    """Get system status from the remote PC."""
    return do_cmd(
        'echo "=== SYSTEM ===" && uname -a && '
        'echo "=== CPU ===" && nproc && '
        'echo "=== RAM ===" && free -h | head -2 && '
        'echo "=== GPU ===" && nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader 2>/dev/null || echo "no-gpu" && '
        'echo "=== DISK ===" && df -h / | tail -1 && '
        'echo "=== DOCKER ===" && sudo docker ps --format "{{.Names}}: {{.Status}}" 2>/dev/null || echo "no-docker"',
        timeout=15, wait=30
    )

# ──────────────────────────── REPL ────────────────────────────

def setup_history():
    try:
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t\n;")
        try:
            readline.read_history_file(HISTORY_FILE)
        except FileNotFoundError:
            pass
        atexit.register(readline.write_history_file, HISTORY_FILE)
    except Exception:
        pass

REPL_COMMANDS = {
    "status": "System status",
    "help": "Show help",
    "quit": "Exit",
}

def repl_completer(text, state):
    options = [c for c in REPL_COMMANDS if c.startswith(text)]
    if state < len(options):
        return options[state]
    return None

def run_repl():
    setup_history()
    readline.set_completer(repl_completer)

    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║       P³ Bridge v5 — AI Side + Security              ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  Relay:   GitHub {REPO_OWNER}/{REPO_NAME}{' ' * 16}║")
    print(f"║  Encrypt: {'YES 🔒' if P3_SECRET else 'NO':<42}║")
    print(f"║  HMAC:    {'YES' if P3_SECRET else 'NO':<42}║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Commands:                                           ║")
    print("║    status     — System status                       ║")
    print("║    <cmd>      — Execute on PC                       ║")
    print("║    help       — Show help                           ║")
    print("║    quit       — Exit                                ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    while True:
        try:
            line = input("p³> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not line:
            continue
        if line in ("quit", "exit", "q"):
            print("Bye!")
            break
        elif line == "help":
            print("\nCommands: status, <shell-cmd>, help, quit\n")
            continue
        elif line == "status":
            do_status()
            continue

        do_cmd(line)

# ──────────────────────────── Main ────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="P3 Bridge v5 — AI Side with Security"
    )
    sub = parser.add_subparsers(dest="action")
    sub.add_parser("repl")
    cmd_p = sub.add_parser("cmd")
    cmd_p.add_argument("command")
    cmd_p.add_argument("--cwd", default=None)
    cmd_p.add_argument("--timeout", type=int, default=120)
    cmd_p.add_argument("--wait", type=int, default=120)
    sub.add_parser("status")
    args = parser.parse_args()

    if not TOKEN:
        print("ERROR: Set P3_GITHUB_TOKEN environment variable", file=sys.stderr)
        sys.exit(1)

    if args.action == "repl":
        run_repl()
    elif args.action == "cmd":
        result = do_cmd(args.command, args.cwd, args.timeout, args.wait)
        sys.exit(0 if result and result.get("returncode") == 0 else 1)
    elif args.action == "status":
        do_status()
    else:
        run_repl()

if __name__ == "__main__":
    main()
