#!/usr/bin/env python3
"""
P3 Bridge Client v5 — Production client with security module.

Runs on the PC. Polls GitHub repo for commands, validates them,
executes in sandbox, writes results back. Full audit trail.

Usage:
  python3 p3_client.py --token <GITHUB_PAT> [options]

Environment:
  P3_SECRET         Shared secret for HMAC + optional encryption
  P3_SECURITY_MODE  "blacklist" (default) or "whitelist"
  P3_RATE_LIMIT     Max commands per minute (default: 30)
  P3_SANDBOX_DIR    If set, execute commands in Docker sandbox
  P3_AUDIT_DIR      Audit log directory (default: /var/log/p3-bridge)
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

# Import security module (same directory)
sys.path.insert(0, str(Path(__file__).parent))
from p3_security import (
    CommandValidator,
    RateLimiter,
    AuditLogger,
    ChannelEncryption,
    generate_hmac,
    verify_hmac,
    full_validate_and_execute,
    get_validator,
    get_limiter,
    get_audit,
    get_crypto,
)

# ──────────────────────────── Config ────────────────────────────

GITHUB_API = "https://api.github.com"
REPO_OWNER = os.environ.get("P3_REPO_OWNER", "Kotokvit")
REPO_NAME = os.environ.get("P3_REPO_NAME", "p3-agent-cell")
RELAY_PATH = os.environ.get("P3_RELAY_PATH", "relay")

ENGINE_DIR = os.environ.get("P3_ENGINE_DIR", str(Path.home() / "Стільниця" / "P3_Engine_repo"))

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
                    reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                    remaining = resp.headers.get("X-RateLimit-Remaining", "?")
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
            # Try decryption
            crypto = get_crypto()
            try:
                content = crypto.decrypt(content)
            except Exception:
                pass  # Not encrypted, use as-is

            try:
                cmd_data = json.loads(content)
                cmd_id = cmd_data.get("id", "")

                # Verify HMAC if present
                if cmd_data.get("hmac") and os.environ.get("P3_SECRET"):
                    if not verify_hmac(
                        cmd_id, cmd_data["cmd"], cmd_data["ts"], cmd_data["hmac"]
                    ):
                        print(f"  ⚠️  HMAC verification FAILED for {cmd_id}")
                        return None

                if cmd_id != self.last_cmd_id:
                    return cmd_data
            except json.JSONDecodeError:
                pass
        return None

    def write_result(self, cmd_id, cmd, stdout, stderr, returncode, elapsed):
        """Write execution result to relay/result.json."""
        result = {
            "id": cmd_id,
            "cmd_hash": cmd[:20] + "..." if len(cmd) > 20 else cmd,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "elapsed": round(elapsed, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        content = json.dumps(result, ensure_ascii=False, indent=2)

        # Try encryption
        crypto = get_crypto()
        if crypto.enabled:
            content = crypto.encrypt(content)

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

    parser = argparse.ArgumentParser(
        description="P3 Bridge Client v5 — Production with Security"
    )
    parser.add_argument("--token", required=True, help="GitHub PAT (repo+gist scope)")
    parser.add_argument("--poll", type=int, default=10, help="Poll interval (s)")
    parser.add_argument("--cwd", default=None, help="Default working directory")
    parser.add_argument("--security", default="blacklist",
                        choices=["blacklist", "whitelist"],
                        help="Security mode")
    parser.add_argument("--rate-limit", type=int, default=30,
                        help="Max commands per minute")
    args = parser.parse_args()

    # Set env for security module
    os.environ["P3_SECURITY_MODE"] = args.security
    os.environ["P3_RATE_LIMIT"] = str(args.rate_limit)

    relay = RepoRelay(args.token, REPO_OWNER, REPO_NAME, RELAY_PATH)
    default_cwd = args.cwd or ENGINE_DIR

    # Initialize security components
    validator = get_validator()
    limiter = get_limiter()
    audit = get_audit()
    crypto = get_crypto()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║      P³ Bridge Client v5 — Production + Security     ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  Repo:     {REPO_OWNER}/{REPO_NAME:<35}║")
    print(f"║  CWD:      {default_cwd:<40}║")
    print(f"║  Poll:     every {args.poll}s{' ' * 30}║")
    print(f"║  Security: {args.security:<41}║")
    print(f"║  Rate:     {args.rate_limit} cmds/min{' ' * 29}║")
    print(f"║  Encrypt:  {'YES' if crypto.enabled else 'NO':<41}║")
    print(f"║  Audit:    {AUDIT_DIR:<41}║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  stdin=/dev/null — sudo prompts auto-fail            ║")
    print("║  Blocked: rm -rf /, dd, fork bombs, reverse shells   ║")
    print("║  Press Ctrl+C to stop                                ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    poll_count = 0
    cmd_count = 0
    rejected_count = 0
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
                print(f"  [{ts}] Command ({cmd_id}): {cmd[:60]}")

                # Full security pipeline: validate → rate limit → execute → audit
                stdout, stderr, rc, elapsed = full_validate_and_execute(
                    cmd, cmd_id, cwd=cwd, timeout=timeout
                )

                # Track stats
                if rc == -2:
                    rejected_count += 1
                elif rc == -3:
                    rejected_count += 1
                else:
                    cmd_count += 1

                # Write result
                relay.write_result(cmd_id, cmd, stdout, stderr, rc, elapsed)
                relay.last_cmd_id = cmd_id

                # Show brief result
                ts = datetime.now().strftime("%H:%M:%S")
                if rc == -2:
                    print(f"  [{ts}] REJECTED: {stderr[:50]}")
                elif rc == -3:
                    print(f"  [{ts}] RATE LIMITED: {stderr[:50]}")
                elif rc == 0:
                    preview = stdout.strip()[:60].replace("\n", " ")
                    print(f"  [{ts}] Done (rc=0, {elapsed:.1f}s): {preview}")
                else:
                    preview = stderr.strip()[:60].replace("\n", " ")
                    print(f"  [{ts}] Done (rc={rc}, {elapsed:.1f}s): {preview}")

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
                stats = audit.get_stats(1)  # Last hour
                print(f"  📊 Stats: {cmd_count} cmds, {rejected_count} rejected, "
                      f"{relay.api_calls} API calls, uptime {h}h{m}m{s}s")

        except urllib.error.HTTPError as e:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] HTTP Error {e.code}, retrying in 30s...")
            time.sleep(30)
        except Exception as e:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] Error: {e}, retrying in 10s...")
            time.sleep(10)

    # Final stats
    stats = audit.get_stats(24)
    print(f"\n  Final: {cmd_count} executed, {rejected_count} rejected, "
          f"{relay.api_calls} API calls")
    print(f"  Audit: {stats['total_commands']} logged in 24h, "
          f"error rate {stats['error_rate']:.1%}")

if __name__ == "__main__":
    main()
