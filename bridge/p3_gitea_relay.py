#!/usr/bin/env python3
"""
P3 Bridge — Gitea Relay Backend (UNLIMITED, NO RATE LIMITS!)

Gitea is a self-hosted GitHub clone. It has ZERO API rate limits.
This module uses Gitea as the relay backend instead of GitHub,
giving unlimited command throughput.

Architecture:
  AI Sandbox → Gitea API (UNLIMITED) → PC Client → exec → result → Gitea API → AI

Usage:
  export P3_GITEA_URL=http://your-pc:3000    # or tunnel URL
  export P3_GITEA_TOKEN=<gitea-api-token>
  export P3_GITEA_REPO=p3admin/p3-relay

  python3 p3_gitea_relay.py cmd "ls -la"
  python3 p3_gitea_relay.py status
  python3 p3_gitea_relay.py repl

Requirements:
  - Gitea running on PC (or accessible via tunnel)
  - Gitea API token with repo write access
  - p3admin/p3-relay repo created in Gitea

Setup Gitea:
  1. docker run -d --name=gitea -p 3000:3000 gitea/gitea:latest
  2. Open http://localhost:3000, create admin account
  3. Create repo: p3admin/p3-relay
  4. Generate API token in Settings → Applications
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
from datetime import datetime
from pathlib import Path

# ──────────────────────────── Config ────────────────────────────

GITEA_URL = os.environ.get("P3_GITEA_URL", "http://localhost:3000")
GITEA_TOKEN = os.environ.get("P3_GITEA_TOKEN", "")
GITEA_REPO = os.environ.get("P3_GITEA_REPO", "p3admin/p3-relay")
RELAY_PATH = os.environ.get("P3_RELAY_PATH", "relay")

# Fallback: GitHub relay (for when Gitea is unreachable)
GITHUB_TOKEN = os.environ.get("P3_GITHUB_TOKEN", "")
GITHUB_REPO_OWNER = os.environ.get("P3_REPO_OWNER", "Kotokvit")
GITHUB_REPO_NAME = os.environ.get("P3_REPO_NAME", "p3-agent-cell")

HISTORY_FILE = os.path.expanduser("~/.p3_bridge_history")

# ──────────────────────────── Sanitize ────────────────────────────

def sanitize(text):
    if not text:
        return text
    for pat in [
        r'ghp_[A-Za-z0-9]{36}',
        r'github_pat_[A-Za-z0-9_]{82}',
    ]:
        text = re.sub(pat, '***TOKEN***', text)
    return text

# ──────────────────────────── Gitea API ────────────────────────────

class GiteaRelay:
    """Gitea-based relay — UNLIMITED API calls, no rate limits!"""

    def __init__(self, url, token, repo, relay_path="relay"):
        self.url = url.rstrip("/")
        self.token = token
        self.repo = repo  # "owner/repo"
        self.relay_path = relay_path
        self.sha_cache = {}

    def _api(self, method, path, data=None, retries=3):
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        url = f"{self.url}/api/v1/repos/{self.repo}/contents/{path}"
        body = json.dumps(data).encode() if data else None

        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method=method)
                resp = urllib.request.urlopen(req, timeout=10)
                return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if e.code in (409, 422) and attempt < retries - 1:
                    time.sleep(0.5)
                    continue
                if e.code == 404:
                    return None
                raise
            except Exception:
                if attempt < retries - 1:
                    time.sleep(1)
                    continue
                raise
        return None

    def get_file(self, path):
        try:
            data = self._api("GET", path)
            if data and "content" in data:
                content = base64.b64decode(data["content"]).decode("utf-8")
                self.sha_cache[path] = data.get("sha", "")
                return content, data.get("sha", "")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, None
            raise
        return None, None

    def put_file(self, path, content_str, message="update", sha=None):
        content_b64 = base64.b64encode(content_str.encode("utf-8")).decode("ascii")
        data = {"message": message, "content": content_b64}
        if sha:
            data["sha"] = sha

        for attempt in range(3):
            try:
                result = self._api("PUT", path, data)
                if result and "sha" in result:
                    self.sha_cache[path] = result["sha"]
                return result
            except urllib.error.HTTPError as e:
                if e.code in (409, 422):
                    _, new_sha = self.get_file(path)
                    if new_sha:
                        data["sha"] = new_sha
                        continue
                raise
        return None

    def send_command(self, cmd, cwd=None, timeout=120):
        cmd_id = str(uuid.uuid4())[:8]
        cmd_data = {
            "id": cmd_id,
            "cmd": sanitize(cmd),
            "cwd": cwd or "",
            "timeout": timeout,
            "ts": time.time(),
            "source": "gitea",
        }
        content = json.dumps(cmd_data, ensure_ascii=False, indent=2)
        path = f"{self.relay_path}/cmd.json"
        sha = self.sha_cache.get(path)
        if not sha:
            _, sha = self.get_file(path)
        self.put_file(path, content, message=f"cmd: {cmd_id}", sha=sha)
        return cmd_id

    def read_result(self, expected_id=None, max_wait=120, poll_interval=2):
        """Poll Gitea for result. With Gitea, we can poll every 2s (no rate limit!)"""
        path = f"{self.relay_path}/result.json"
        start = time.time()
        while time.time() - start < max_wait:
            try:
                content, sha = self.get_file(path)
                if content:
                    result = json.loads(content)
                    if expected_id is None or result.get("id") == expected_id:
                        return result
            except Exception:
                pass
            time.sleep(poll_interval)
            sys.stdout.write(".")
            sys.stdout.flush()
        return None

    def test_connection(self):
        """Test Gitea connectivity."""
        try:
            url = f"{self.url}/api/v1/version"
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=5)
            version = json.loads(resp.read().decode())
            return True, version
        except Exception as e:
            return False, str(e)


# ──────────────────────────── GitHub Fallback ────────────────────────────

class GitHubFallback:
    """Fallback to GitHub repo relay (5000 req/hr limit)."""

    def __init__(self, token, owner, repo, relay_path="relay"):
        self.token = token
        self.owner = owner
        self.repo = repo
        self.relay_path = relay_path
        self.sha_cache = {}
        self.api = "https://api.github.com"

    def _api(self, method, path, data=None, retries=3):
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }
        url = f"{self.api}{path}"
        body = json.dumps(data).encode() if data else None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method=method)
                resp = urllib.request.urlopen(req, timeout=20)
                return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if e.code in (409, 422) and attempt < retries - 1:
                    time.sleep(1)
                    continue
                if e.code == 404:
                    return None
                raise
            except Exception:
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                raise
        return None

    def get_file(self, path):
        try:
            data = self._api("GET", f"/repos/{self.owner}/{self.repo}/contents/{path}")
            if data and "content" in data:
                content = base64.b64decode(data["content"]).decode("utf-8")
                self.sha_cache[path] = data["sha"]
                return content, data["sha"]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, None
            raise
        return None, None

    def put_file(self, path, content_str, message="update", sha=None):
        content_b64 = base64.b64encode(content_str.encode("utf-8")).decode("ascii")
        data = {"message": message, "content": content_b64}
        if sha:
            data["sha"] = sha
        for attempt in range(3):
            try:
                result = self._api("PUT", f"/repos/{self.owner}/{self.repo}/contents/{path}", data)
                if result and "content" in result:
                    self.sha_cache[path] = result["content"].get("sha", "")
                return result
            except urllib.error.HTTPError as e:
                if e.code in (409, 422):
                    _, new_sha = self.get_file(path)
                    if new_sha:
                        data["sha"] = new_sha
                        continue
                raise
        return None

    def send_command(self, cmd, cwd=None, timeout=120):
        cmd_id = str(uuid.uuid4())[:8]
        cmd_data = {
            "id": cmd_id, "cmd": sanitize(cmd),
            "cwd": cwd or "", "timeout": timeout,
            "ts": time.time(), "source": "github",
        }
        content = json.dumps(cmd_data, ensure_ascii=False, indent=2)
        path = f"{self.relay_path}/cmd.json"
        sha = self.sha_cache.get(path)
        if not sha:
            _, sha = self.get_file(path)
        self.put_file(path, content, message=f"cmd: {cmd_id}", sha=sha)
        return cmd_id

    def read_result(self, expected_id=None, max_wait=120, poll_interval=4):
        path = f"{self.relay_path}/result.json"
        start = time.time()
        while time.time() - start < max_wait:
            try:
                content, sha = self.get_file(path)
                if content:
                    result = json.loads(content)
                    if expected_id is None or result.get("id") == expected_id:
                        return result
            except Exception:
                pass
            time.sleep(poll_interval)
            sys.stdout.write(".")
            sys.stdout.flush()
        return None


# ──────────────────────────── Unified Bridge ────────────────────────────

class UnifiedBridge:
    """Auto-selects best relay: Gitea (unlimited) → GitHub (fallback)."""

    def __init__(self):
        self.gitea = None
        self.github = None
        self.active = None
        self.active_name = "none"

        # Try Gitea first
        if GITEA_URL and GITEA_TOKEN:
            self.gitea = GiteaRelay(GITEA_URL, GITEA_TOKEN, GITEA_REPO, RELAY_PATH)
            ok, info = self.gitea.test_connection()
            if ok:
                self.active = self.gitea
                self.active_name = f"Gitea ({info.get('version','?')})"
            else:
                print(f"  ⚠ Gitea unreachable: {info}", file=sys.stderr)

        # Fallback to GitHub
        if not self.active and GITHUB_TOKEN:
            self.github = GitHubFallback(
                GITHUB_TOKEN, GITHUB_REPO_OWNER, GITHUB_REPO_NAME, RELAY_PATH
            )
            self.active = self.github
            self.active_name = "GitHub (5000/hr)"

    def cmd(self, command, cwd=None, timeout=120, wait=120, verbose=True):
        if not self.active:
            print("ERROR: No relay available. Set P3_GITEA_URL+TOKEN or P3_GITHUB_TOKEN", file=sys.stderr)
            return None

        cmd_id = self.active.send_command(command, cwd, timeout)
        if verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            # Gitea can poll faster
            poll = 2 if isinstance(self.active, GiteaRelay) else 4
            print(f"[{ts}] → {self.active_name} [{cmd_id}]: {command[:80]}")

        poll = 2 if isinstance(self.active, GiteaRelay) else 4
        result = self.active.read_result(cmd_id, max_wait=wait, poll_interval=poll)

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

    def status(self):
        return self.cmd(
            'echo "=== SYSTEM ===" && uname -a && '
            'echo "=== CPU ===" && nproc && '
            'echo "=== RAM ===" && free -h | head -2 && '
            'echo "=== DISK ===" && df -h / | tail -1',
            timeout=15, wait=30
        )


# ──────────────────────────── REPL ────────────────────────────

def run_repl(bridge):
    try:
        readline.parse_and_bind("tab: complete")
        try:
            readline.read_history_file(HISTORY_FILE)
        except FileNotFoundError:
            pass
        atexit.register(readline.write_history_file, HISTORY_FILE)
    except Exception:
        pass

    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║       P³ Bridge — Unified (Gitea + GitHub)           ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  Active:  {bridge.active_name:<42}║")
    if bridge.gitea:
        print(f"║  Gitea:   {GITEA_URL} ({GITEA_REPO})")
    if bridge.github:
        print(f"║  GitHub:  {GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Gitea = UNLIMITED (no rate limits!)                 ║")
    print("║  GitHub = 5000 req/hr (fallback)                     ║")
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
        elif line == "status":
            bridge.status()
            continue
        bridge.cmd(line)

# ──────────────────────────── Main ────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="P3 Bridge — Unified (Gitea + GitHub)")
    sub = parser.add_subparsers(dest="action")
    sub.add_parser("repl")
    cmd_p = sub.add_parser("cmd")
    cmd_p.add_argument("command")
    cmd_p.add_argument("--cwd", default=None)
    cmd_p.add_argument("--timeout", type=int, default=120)
    cmd_p.add_argument("--wait", type=int, default=120)
    sub.add_parser("status")
    args = parser.parse_args()

    bridge = UnifiedBridge()

    if args.action == "repl":
        run_repl(bridge)
    elif args.action == "cmd":
        result = bridge.cmd(args.command, args.cwd, args.timeout, args.wait)
        sys.exit(0 if result and result.get("returncode") == 0 else 1)
    elif args.action == "status":
        bridge.status()
    else:
        run_repl(bridge)

if __name__ == "__main__":
    main()
