#!/usr/bin/env python3
"""
P3 Bridge Client v5 — Dual Backend (GitHub + Gitea)

PC-side client with:
  - GitHub relay (5000 req/hr, for AI sandbox access)
  - Gitea relay (UNLIMITED, for local/direct operations)
  - Security module (validation, rate limiting, audit)
  - Auto-selects best backend per command

Usage:
  python3 p3_client.py --token <GITHUB_PAT> --gitea-token <GITEA_TOKEN> [options]
"""

import urllib.request
import urllib.error
import json
import time
import sys
import os
import base64
import signal
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Import security
sys.path.insert(0, str(Path(__file__).parent))
try:
    from p3_security import full_validate_and_execute, get_validator, get_limiter, get_audit, get_crypto
    HAS_SECURITY = True
except ImportError:
    HAS_SECURITY = False

# ──────────────────────────── Config ────────────────────────────

GITHUB_API = "https://api.github.com"
REPO_OWNER = os.environ.get("P3_REPO_OWNER", "Kotokvit")
REPO_NAME = os.environ.get("P3_REPO_NAME", "p3-agent-cell")
RELAY_PATH = os.environ.get("P3_RELAY_PATH", "relay")

GITEA_URL = os.environ.get("P3_GITEA_URL", "http://localhost:3000")
GITEA_REPO = os.environ.get("P3_GITEA_REPO", "p3admin/p3-relay")

ENGINE_DIR = os.environ.get("P3_ENGINE_DIR", str(Path.home()))

# ──────────────────────────── Repo Relay Base ────────────────────────────

class RepoRelay:
    """Generic repo-based relay (works with both GitHub and Gitea APIs)."""

    def __init__(self, token, api_base, repo_path, relay_path="relay", is_gitea=False):
        self.token = token
        self.api_base = api_base
        self.repo_path = repo_path  # "owner/repo"
        self.relay_path = relay_path
        self.is_gitea = is_gitea
        self.sha_cache = {}
        self.last_cmd_id = None
        self.api_calls = 0
        self.name = "Gitea" if is_gitea else "GitHub"

    def _api(self, method, url, data=None, retries=3):
        headers = {
            "Authorization": f"token {self.token}",
            "Content-Type": "application/json",
        }
        if not self.is_gitea:
            headers["Accept"] = "application/vnd.github.v3+json"
        else:
            headers["Accept"] = "application/json"

        body = json.dumps(data).encode() if data else None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method=method)
                timeout = 10 if self.is_gitea else 15
                resp = urllib.request.urlopen(req, timeout=timeout)
                self.api_calls += 1
                return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if e.code == 403 and not self.is_gitea and attempt < retries - 1:
                    reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                    if reset:
                        wait = min(reset - int(time.time()) + 1, 60)
                        print(f"  ⏳ {self.name} rate limited, waiting {wait}s")
                        time.sleep(wait)
                    continue
                if e.code in (409, 422) and attempt < retries - 1:
                    time.sleep(0.5 if self.is_gitea else 1)
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

    def _contents_url(self, path):
        if self.is_gitea:
            return f"{self.api_base}/api/v1/repos/{self.repo_path}/contents/{path}"
        return f"{self.api_base}/repos/{self.repo_path}/contents/{path}"

    def get_file(self, path):
        try:
            data = self._api("GET", self._contents_url(path))
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
                result = self._api("PUT", self._contents_url(path), data)
                if result:
                    new_sha = result.get("sha", "")
                    if not new_sha and "content" in result:
                        new_sha = result["content"].get("sha", "")
                    if new_sha:
                        self.sha_cache[path] = new_sha
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
        result = {
            "id": cmd_id,
            "cmd_preview": cmd[:30] + "..." if len(cmd) > 30 else cmd,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "elapsed": round(elapsed, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        content = json.dumps(result, ensure_ascii=False, indent=2)
        path = f"{self.relay_path}/result.json"
        sha = self.sha_cache.get(path)
        if not sha:
            _, sha = self.get_file(path)
        self.put_file(path, content, message=f"result: {cmd_id}", sha=sha)

# ──────────────────────────── Main Loop ────────────────────────────

running = True

def signal_handler(sig, frame):
    global running
    print("\n  🛑 Shutting down...")
    running = False

def main():
    global running

    parser = argparse.ArgumentParser(description="P3 Bridge Client v5 — Dual Backend")
    parser.add_argument("--token", required=True, help="GitHub PAT (repo+gist scope)")
    parser.add_argument("--gitea-token", default="", help="Gitea API token")
    parser.add_argument("--gitea-url", default=GITEA_URL, help="Gitea URL")
    parser.add_argument("--poll", type=int, default=10, help="GitHub poll interval (s)")
    parser.add_argument("--gitea-poll", type=int, default=3, help="Gitea poll interval (s, faster!)")
    parser.add_argument("--cwd", default=None, help="Default working directory")
    parser.add_argument("--security", default="blacklist", choices=["blacklist", "whitelist"])
    args = parser.parse_args()

    if args.gitea_token:
        os.environ["P3_GITEA_TOKEN"] = args.gitea_token
    os.environ["P3_SECURITY_MODE"] = args.security

    # Set up relays
    github_relay = RepoRelay(
        args.token, GITHUB_API, f"{REPO_OWNER}/{REPO_NAME}",
        RELAY_PATH, is_gitea=False
    )

    gitea_relay = None
    if args.gitea_token:
        gitea_relay = RepoRelay(
            args.gitea_token, args.gitea_url, GITEA_REPO,
            RELAY_PATH, is_gitea=True
        )
        # Test Gitea connection
        try:
            url = f"{args.gitea_url}/api/v1/version"
            resp = urllib.request.urlopen(url, timeout=5)
            ver = json.loads(resp.read().decode())
            gitea_ok = True
            gitea_ver = ver.get("version", "?")
        except Exception:
            gitea_ok = False
            gitea_ver = "?"

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    default_cwd = args.cwd or ENGINE_DIR

    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║    P³ Bridge Client v5 — Dual Backend + Security     ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  GitHub:  {REPO_OWNER}/{REPO_NAME} (5000/hr){' ' * 12}║")
    print(f"║  Poll:    every {args.poll}s{' ' * 32}║")
    if gitea_relay and gitea_ok:
        print(f"║  Gitea:   {args.gitea_url} ({GITEA_REPO}){' ' * 4}║")
        print(f"║  G.Poll:  every {args.gitea_poll}s (UNLIMITED!){' ' * 8}║")
    else:
        print(f"║  Gitea:   {'NOT AVAILABLE' if not args.gitea_token else 'UNREACHABLE'}{' ' * 34}║")
    print(f"║  CWD:     {default_cwd[:41]}{' ' * (41 - min(len(default_cwd), 41))}║")
    print(f"║  Security: {args.security:<40}║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  stdin=/dev/null — sudo prompts auto-fail            ║")
    print("║  Press Ctrl+C to stop                                ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    poll_count = 0
    cmd_count = 0
    start_time = time.time()

    while running:
        try:
            # Poll BOTH relays (Gitea first — it's unlimited)
            for relay, poll_interval in [(gitea_relay, args.gitea_poll), (github_relay, args.poll)]:
                if relay is None:
                    continue

                cmd_data = relay.read_command()
                if cmd_data:
                    cmd_id = cmd_data.get("id", "?")
                    cmd = cmd_data.get("cmd", "")
                    cwd = cmd_data.get("cwd", default_cwd)
                    timeout = cmd_data.get("timeout", 120)

                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"  [{ts}] {relay.name} ({cmd_id}): {cmd[:60]}")

                    # Execute with security
                    if HAS_SECURITY:
                        stdout, stderr, rc, elapsed = full_validate_and_execute(
                            cmd, cmd_id, cwd=cwd, timeout=timeout
                        )
                    else:
                        import subprocess
                        start = time.time()
                        try:
                            proc = subprocess.Popen(cmd, shell=True, cwd=cwd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL)
                            stdout, stderr = proc.communicate(timeout=timeout)
                            elapsed = time.time() - start
                            stdout = stdout.decode("utf-8", errors="replace")
                            stderr = stderr.decode("utf-8", errors="replace")
                            rc = proc.returncode
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                            elapsed = time.time() - start
                            stdout, stderr, rc = "", f"TIMEOUT ({timeout}s)", -1
                        except Exception as e:
                            elapsed = time.time() - start
                            stdout, stderr, rc = "", str(e), -1

                    # Write result back to SAME relay
                    relay.write_result(cmd_id, cmd, stdout, stderr, rc, elapsed)
                    relay.last_cmd_id = cmd_id
                    cmd_count += 1

                    ts = datetime.now().strftime("%H:%M:%S")
                    if rc == 0:
                        preview = stdout.strip()[:60].replace("\n", " ")
                        print(f"  [{ts}] Done (rc=0, {elapsed:.1f}s): {preview}")
                    elif rc == -2:
                        print(f"  [{ts}] REJECTED: {stderr[:50]}")
                    else:
                        preview = stderr.strip()[:60].replace("\n", " ")
                        print(f"  [{ts}] Done (rc={rc}, {elapsed:.1f}s): {preview}")

            # Wait (use shorter interval if Gitea is available)
            wait = args.gitea_poll if (gitea_relay and gitea_ok) else args.poll
            for _ in range(wait * 10):
                if not running:
                    break
                time.sleep(0.1)
            poll_count += 1

            if poll_count % 120 == 0:
                uptime = int(time.time() - start_time)
                m, s = divmod(uptime, 60)
                h, m = divmod(m, 60)
                gh_calls = github_relay.api_calls
                gi_calls = gitea_relay.api_calls if gitea_relay else 0
                print(f"  📊 {cmd_count} cmds, GH:{gh_calls} GI:{gi_calls} API calls, uptime {h}h{m}m{s}s")

        except urllib.error.HTTPError as e:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] HTTP Error {e.code}, retrying in 30s...")
            time.sleep(30)
        except Exception as e:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] Error: {e}, retrying in 10s...")
            time.sleep(10)

    gh_calls = github_relay.api_calls
    gi_calls = gitea_relay.api_calls if gitea_relay else 0
    print(f"\n  Final: {cmd_count} commands, GH:{gh_calls} GI:{gi_calls} API calls")

if __name__ == "__main__":
    main()
