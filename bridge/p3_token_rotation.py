#!/usr/bin/env python3
"""
P3 Bridge — Token Rotation Manager

Inspired by Asati's zCode Account Manager, but for GitHub PATs.
Rotate multiple GitHub tokens to multiply your effective rate limit.

Math: 1 token = 5000 req/hr → N tokens = N × 5000 req/hr

Usage:
  # Register tokens
  python3 p3_token_rotation.py add ghp_TOKEN1 --name "personal"
  python3 p3_token_rotation.py add ghp_TOKEN2 --name "bot-account"
  python3 p3_token_rotation.py add ghp_TOKEN3 --name "ci-account"

  # List tokens
  python3 p3_token_rotation.py list

  # Get next available token (round-robin)
  python3 p3_token_rotation.py next

  # Show rate limit status for all tokens
  python3 p3_token_rotation.py status

Config stored in: ~/.p3/tokens.json (chmod 600)
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
import argparse
from pathlib import Path
from datetime import datetime

CONFIG_DIR = Path.home() / ".p3"
TOKENS_FILE = CONFIG_DIR / "tokens.json"
GITHUB_API = "https://api.github.com"

# ──────────────────────────── Config ────────────────────────────

def load_tokens():
    if not TOKENS_FILE.exists():
        return []
    with open(TOKENS_FILE) as f:
        return json.load(f)

def save_tokens(tokens):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=2, ensure_ascii=False)
    # chmod 600 — only owner can read (contains tokens!)
    TOKENS_FILE.chmod(0o600)

def mask_token(token):
    """Show first 4 and last 4 chars, mask the rest."""
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}{'*' * (len(token) - 8)}{token[-4:]}"

# ──────────────────────────── Token Operations ────────────────────────────

def add_token(token, name="", notes=""):
    tokens = load_tokens()

    # Validate token
    username = validate_token(token)
    if not username:
        print(f"  ✗ Token validation failed (HTTP error or invalid token)")
        return False

    # Check for duplicates
    for t in tokens:
        if t["token"] == token:
            print(f"  ✗ Token already exists: {mask_token(token)}")
            return False

    entry = {
        "token": token,
        "name": name or f"token-{len(tokens) + 1}",
        "username": username,
        "notes": notes,
        "added": datetime.now().isoformat(),
        "last_used": None,
        "use_count": 0,
        "enabled": True,
    }
    tokens.append(entry)
    save_tokens(tokens)
    print(f"  ✓ Added: {entry['name']} (@{username}, {mask_token(token)})")
    return True

def validate_token(token):
    """Validate GitHub PAT and return username."""
    try:
        req = urllib.request.Request(
            f"{GITHUB_API}/user",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        return data.get("login")
    except Exception:
        return None

def check_rate_limit(token):
    """Get current rate limit status for a token."""
    try:
        req = urllib.request.Request(
            f"{GITHUB_API}/rate_limit",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        core = data.get("resources", {}).get("core", {})
        return {
            "limit": core.get("limit", 0),
            "remaining": core.get("remaining", 0),
            "reset": core.get("reset", 0),
            "used": core.get("limit", 0) - core.get("remaining", 0),
            "percent_used": round(
                (core.get("limit", 0) - core.get("remaining", 0)) / max(core.get("limit", 1), 1) * 100, 1
            ),
        }
    except Exception as e:
        return {"error": str(e)}

def list_tokens():
    tokens = load_tokens()
    if not tokens:
        print("  No tokens registered. Use 'add' command.")
        return

    print(f"\n  {'#':<3} {'Name':<15} {'User':<15} {'Token':<20} {'Enabled':<8} {'Uses':<6}")
    print(f"  {'─' * 70}")
    for i, t in enumerate(tokens):
        enabled = "✓" if t.get("enabled", True) else "✗"
        print(f"  {i+1:<3} {t.get('name',''):<15} @{t.get('username',''):<14} {mask_token(t['token']):<20} {enabled:<8} {t.get('use_count',0):<6}")
    print(f"\n  Total: {len(tokens)} tokens, effective limit: {len([t for t in tokens if t.get('enabled',True)]) * 5000} req/hr")

def show_status():
    tokens = load_tokens()
    if not tokens:
        print("  No tokens registered.")
        return

    print(f"\n  {'Name':<15} {'User':<15} {'Remaining':<12} {'Limit':<8} {'Used':<8} {'Reset':<20}")
    print(f"  {'─' * 80}")

    total_remaining = 0
    total_limit = 0

    for t in tokens:
        if not t.get("enabled", True):
            continue
        rl = check_rate_limit(t["token"])
        if "error" in rl:
            print(f"  {t.get('name',''):<15} @{t.get('username',''):<14} ERROR: {rl['error'][:30]}")
            continue

        reset_time = datetime.fromtimestamp(rl.get("reset", 0)).strftime("%H:%M:%S")
        bar = "█" * int(rl["percent_used"] / 5) + "░" * (20 - int(rl["percent_used"] / 5))
        print(f"  {t.get('name',''):<15} @{t.get('username',''):<14} {rl['remaining']:<12} {rl['limit']:<8} {rl['used']:<8} {reset_time}")

        total_remaining += rl.get("remaining", 0)
        total_limit += rl.get("limit", 0)

    print(f"\n  Total: {total_remaining} / {total_limit} requests remaining")

def get_next_token():
    """Get next available token with most remaining requests (round-robin + smart)."""
    tokens = load_tokens()
    enabled = [t for t in tokens if t.get("enabled", True)]
    if not enabled:
        return None

    # Find token with most remaining requests
    best = None
    best_remaining = -1

    for t in enabled:
        rl = check_rate_limit(t["token"])
        remaining = rl.get("remaining", 0)
        if remaining > best_remaining:
            best_remaining = remaining
            best = t

    if best and best_remaining > 0:
        # Update use stats
        best["last_used"] = datetime.now().isoformat()
        best["use_count"] = best.get("use_count", 0) + 1
        save_tokens(tokens)
        return best["token"]

    # All tokens exhausted — return least recently used
    enabled.sort(key=lambda t: t.get("last_used", "0000"))
    return enabled[0]["token"]

def remove_token(index):
    tokens = load_tokens()
    if index < 1 or index > len(tokens):
        print(f"  ✗ Invalid index: {index}")
        return
    removed = tokens.pop(index - 1)
    save_tokens(tokens)
    print(f"  ✓ Removed: {removed.get('name','')} ({mask_token(removed['token'])})")

def toggle_token(index):
    tokens = load_tokens()
    if index < 1 or index > len(tokens):
        print(f"  ✗ Invalid index: {index}")
        return
    tokens[index - 1]["enabled"] = not tokens[index - 1].get("enabled", True)
    status = "enabled" if tokens[index - 1]["enabled"] else "disabled"
    save_tokens(tokens)
    print(f"  ✓ {tokens[index-1].get('name','')} {status}")

# ──────────────────────────── Main ────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="P3 Token Rotation Manager")
    sub = parser.add_subparsers(dest="action")

    # Add
    add_p = sub.add_parser("add", help="Add a GitHub PAT")
    add_p.add_argument("token", help="GitHub PAT")
    add_p.add_argument("--name", default="", help="Friendly name")
    add_p.add_argument("--notes", default="", help="Notes")

    # Remove
    rm_p = sub.add_parser("remove", help="Remove token by index")
    rm_p.add_argument("index", type=int, help="Token index (from 'list')")

    # Toggle
    tog_p = sub.add_parser("toggle", help="Enable/disable token")
    tog_p.add_argument("index", type=int, help="Token index")

    # Next
    sub.add_parser("next", help="Get next available token")

    # List
    sub.add_parser("list", help="List all tokens")

    # Status
    sub.add_parser("status", help="Rate limit status for all tokens")

    args = parser.parse_args()

    if args.action == "add":
        add_token(args.token, args.name, args.notes)
    elif args.action == "remove":
        remove_token(args.index)
    elif args.action == "toggle":
        toggle_token(args.index)
    elif args.action == "next":
        token = get_next_token()
        if token:
            print(token)
        else:
            print("No tokens available", file=sys.stderr)
            sys.exit(1)
    elif args.action == "list":
        list_tokens()
    elif args.action == "status":
        show_status()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
