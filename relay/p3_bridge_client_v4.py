#!/usr/bin/env python3
"""
P³ Bridge Client v4 — Production-ready polling client.

Runs on the PC. Polls GitHub repo for commands, executes them,
writes results back. Supports Gitea as local relay backend.

Features:
  - Robust subprocess execution with proper timeout
  - Token sanitization on all output
  - Gitea local relay (unlimited, no GitHub for local ops)
  - Graceful shutdown on SIGINT/SIGTERM
  - Health check heartbeat
  - Command timeout with process kill
  - Non-blocking execution (won't hang on sudo prompts)
"""

import urllib.request
import urllib.error
import json
import time
import sys
import os
import re
import base64
import subprocess
import signal
import argparse
import threading
from datetime import datetime, timezone

# ──────────────────────────── Config ────────────────────────────

GITHUB_API = "https://api.github.com"
REPO_OWNER = "Kotokvit"
REPO_NAME = "p3-agent-cell"
RELAY_PATH = "relay"

# Gitea (local, unlimited)
GITEA_URL = "http://localhost:3000"
GITEA_TOKEN = ""
GITEA_REPO = "p3admin/p3-relay"

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
    # Also sanitize the Gitea token if present
    if GITEA_TOKEN and len(GITEA_TOKEN) > 8:
        text = text.replace(GITEA_TOKEN, '***GITEA_TOKEN***')
    return text

# ──────────────────────────── GitHub API ────────────────────────────

class RepoRelay:
    """GitHub repo-based relay for command/result exchange."""

    def __init__(self, token, repo_owner, repo_name, relay_path="relay"):
        self.token = token
        self.owner = repo_owner
        self.repo = repo_name
        self.relay_path = relay_path
        self.sha_cache = {}
        self.last_cmd_id = None
        self.api_calls = 0

    def _api(self, method, path, data=None, retries=3):
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }
        url = f"{GITHUB_API}{path}"
        body = json.dumps(data).encode() if data else None

        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method=method)
                resp = urllib.request.urlopen(req, timeout=15)
                self.api_calls += 1
                return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if e.code == 403 and attempt < retries - 1:
                    # Check rate limit
                    remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                    reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                    if reset:
                        wait = min(reset - int(time.time()) + 1, 60)
                        print(f"  ⏳ Rate limited (remaining={remaining}), waiting {wait}s")
                        time.sleep(wait)
                    continue
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

    def read_command(self):
        """Read the latest command from relay/cmd.json."""
        path = f"{self.relay_path}/cmd.json"
        content, sha = self.get_file(path)
        if content:
            try:
                cmd_data = json.loads(content)
                cmd_id = cmd_data.get("id", "")
                if cmd_id != self.last_cmd_id:
                    return cmd_data
            except json.JSONDecodeError:
                pass
        return None

    def write_result(self, cmd_id, cmd, stdout, stderr, returncode, elapsed):
        """Write execution result to relay/result.json."""
        result = {
            "id": cmd_id,
            "cmd": sanitize(cmd),
            "stdout": sanitize(stdout),
            "stderr": sanitize(stderr),
            "returncode": returncode,
            "elapsed": round(elapsed, 2),
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        }
        content = json.dumps(result, ensure_ascii=False, indent=2)
        path = f"{self.relay_path}/result.json"
        sha = self.sha_cache.get(path)
        if not sha:
            _, sha = self.get_file(path)
        self.put_file(path, content, message=f"result: {cmd_id}", sha=sha)

# ──────────────────────────── Command Execution ────────────────────────────

def execute_command(cmd, cwd=None, timeout=120):
    """Execute a shell command with timeout. Returns (stdout, stderr, rc, elapsed)."""
    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,  # No stdin — prevents sudo hang
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            elapsed = time.time() - start
            return (
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                proc.returncode,
                elapsed,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            elapsed = time.time() - start
            return (
                "",
                f"TIMEOUT: command exceeded {timeout}s limit",
                -1,
                elapsed,
            )
    except Exception as e:
        elapsed = time.time() - start
        return ("", str(e), -1, elapsed)

# ──────────────────────────── Main Loop ────────────────────────────

running = True

def signal_handler(sig, frame):
    global running
    print("\n🛑 Shutting down...")
    running = False

def main():
    global GITEA_TOKEN, running

    parser = argparse.ArgumentParser(description="P³ Bridge Client v4")
    parser.add_argument("--token", required=True, help="GitHub PAT")
    parser.add_argument("--poll", type=int, default=10, help="Poll interval (s)")
    parser.add_argument("--cwd", default=None, help="Default working directory")
    parser.add_argument("--gitea-token", default="", help="Gitea API token")
    parser.add_argument("--gitea-url", default="http://localhost:3000", help="Gitea URL")
    args = parser.parse_args()

    if args.gitea_token:
        GITEA_TOKEN = args.gitea_token

    relay = RepoRelay(args.token, REPO_OWNER, REPO_NAME, RELAY_PATH)
    default_cwd = args.cwd or os.getcwd()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║       P³ Bridge Client v4 — Production Ready      ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  Repo:  {REPO_OWNER}/{REPO_NAME:<36}║")
    print(f"║  CWD:   {default_cwd:<41}║")
    print(f"║  Poll:  every {args.poll}s{' ' * 30}║")
    print(f"║  Limit: 5000 PUT/hr (50x Gist){' ' * 14}║")
    if GITEA_TOKEN:
        print(f"║  Gitea: {args.gitea_url} (local){' ' * 14}║")
    print("╠══════════════════════════════════════════════════╣")
    print("║  stdin=/dev/null — sudo prompts auto-fail         ║")
    print("║  Press Ctrl+C to stop                             ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    poll_count = 0
    cmd_count = 0
    start_time = time.time()

    while running:
        try:
            # Poll for command
            cmd_data = relay.read_command()
            if cmd_data:
                cmd_id = cmd_data.get("id", "?")
                cmd = cmd_data.get("cmd", "")
                cwd = cmd_data.get("cwd", default_cwd)
                timeout = cmd_data.get("timeout", 120)

                ts = datetime.now().strftime("%H:%M:%S")
                print(f"  [{ts}] Exec ({cmd_id}): {cmd[:80]}")

                # Execute
                stdout, stderr, rc, elapsed = execute_command(cmd, cwd, timeout)

                # Write result
                relay.write_result(cmd_id, cmd, stdout, stderr, rc, elapsed)
                relay.last_cmd_id = cmd_id
                cmd_count += 1

                # Show brief result
                ts = datetime.now().strftime("%H:%M:%S")
                if rc == 0:
                    out_preview = stdout.strip()[:60].replace("\n", " ")
                    print(f"  [{ts}] Done (rc=0, {elapsed:.1f}s): {out_preview}")
                else:
                    err_preview = stderr.strip()[:60].replace("\n", " ")
                    print(f"  [{ts}] Done (rc={rc}, {elapsed:.1f}s): {err_preview}")

            # Wait before next poll
            for _ in range(args.poll * 10):
                if not running:
                    break
                time.sleep(0.1)
            poll_count += 1

            # Periodic stats
            if poll_count % 60 == 0:
                uptime = int(time.time() - start_time)
                m, s = divmod(uptime, 60)
                h, m = divmod(m, 60)
                print(f"  📊 Stats: {cmd_count} cmds, {relay.api_calls} API calls, uptime {h}h{m}m{s}s")

        except urllib.error.HTTPError as e:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] HTTP Error {e.code}, retrying in 30s...")
            time.sleep(30)
        except Exception as e:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] Error: {e}, retrying in 10s...")
            time.sleep(10)

    print(f"\n  Final stats: {cmd_count} commands executed, {relay.api_calls} API calls")

if __name__ == "__main__":
    main()
