# P³ Bridge — Remote Command Bridge

> AI Sandbox ←→ GitHub Repo Relay ←→ Your PC

Execute commands on your PC from any AI agent. Zero open ports. Zero VPN. Just GitHub.

## How It Works

```
┌─────────────┐     cmd.json      ┌──────────────┐    poll     ┌───────────┐
│  AI Agent   │ ──────────────▶  │  GitHub Repo  │ ◀───────── │  Your PC  │
│  (Sandbox)  │                   │  relay/       │            │  (Client)  │
│             │  ◀──────────────  │               │ ────────▶ │             │
└─────────────┘    result.json    └──────────────┘   write     └───────────┘
```

1. **AI side** writes `relay/cmd.json` to the GitHub repo (via API)
2. **PC client** polls the repo every 10 seconds, reads `cmd.json`
3. **PC client** executes the command, writes `relay/result.json` back
4. **AI side** polls `result.json`, gets the output

**No inbound ports. No SSH. No VPN.** GitHub is the only intermediary.

## Quick Start (5 minutes)

### Prerequisites

- Python 3.8+ on both machines
- GitHub account
- GitHub Classic PAT with `repo` + `gist` scopes

### Step 1: Create GitHub PAT

Go to [GitHub Settings → Tokens → Personal access tokens → Tokens (classic)](https://github.com/settings/tokens)

Create a new token with scopes:
- ✅ `repo` (full control of private repositories)
- ✅ `gist` (create gists)

Save the token — you'll need it on both sides.

### Step 2: Set Up the Repo

If you're using the default repo (`Kotokvit/p3-agent-cell`), it already exists.
For a new repo:

```bash
# Create repo via API
curl -s -H "Authorization: token YOUR_PAT" \
  -d '{"name":"p3-agent-cell","auto_init":true}' \
  "https://api.github.com/user/repos"

# Create relay directory
curl -s -H "Authorization: token YOUR_PAT" \
  -d '{"message":"init relay","content":"'$(echo -n "{}" | base64)'"}' \
  "https://api.github.com/repos/YOUR_USERNAME/p3-agent-cell/contents/relay/.init"
```

### Step 3: PC Side — Install & Run

```bash
# Clone the repo
git clone https://github.com/Kotokvit/p3-agent-cell.git
cd p3-agent-cell

# Option A: Automated setup (recommended)
chmod +x setup/install_pc.sh
./setup/install_pc.sh --token ghp_YOUR_TOKEN_HERE

# Option B: Manual setup
pip install cryptography  # optional, for channel encryption
python3 bridge/p3_client.py --token ghp_YOUR_TOKEN_HERE

# Option C: Systemd service (auto-start on boot)
./setup/install_pc.sh --token ghp_YOUR_TOKEN_HERE
sudo systemctl enable --now p3-bridge-client
```

### Step 4: AI Side — Send Commands

```bash
# Set environment
export P3_GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE

# One-shot command
python3 bridge/p3_bridge.py cmd "uname -a"

# System status
python3 bridge/p3_bridge.py status

# Interactive REPL
python3 bridge/p3_bridge.py repl
```

### Step 5: Verify

```bash
# From AI side, run:
python3 bridge/p3_bridge.py cmd "echo 'P3 Bridge ONLINE!' && hostname"

# Expected output:
# P3 Bridge ONLINE!
# your-pc-hostname
```

## Security

P³ Bridge is designed for **production use** with multiple security layers:

### Command Validation

Two modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| `blacklist` | Block dangerous commands, allow everything else | **Default**. Best for personal use |
| `whitelist` | Only allow pre-approved commands | **Production**. Best for shared/team use |

**Always blocked** (regardless of mode):
- `rm -rf /` — filesystem destruction
- `dd if=... of=/dev/` — disk overwrite
- `mkfs.*`, `fdisk` — partition operations
- `reboot`, `shutdown`, `poweroff` — system power
- `nc -e /bin/sh` — reverse shells
- `curl ... | sh` — download-and-execute
- `xmrig`, `cryptonight` — crypto miners
- Fork bombs, privilege escalation, kernel module injection

### Rate Limiting

Default: **30 commands per minute** (sliding window).
Configurable via `P3_RATE_LIMIT` environment variable.

### HMAC Signing

When `P3_SECRET` is set, every command is HMAC-SHA256 signed.
This prevents tampering with `cmd.json` in transit.

```bash
# Generate a shared secret
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Set on BOTH sides
export P3_SECRET=your_shared_secret_here
```

### Channel Encryption

When `P3_SECRET` is set + `cryptography` package installed,
all `cmd.json` and `result.json` content is Fernet-encrypted.
GitHub only sees encrypted blobs — passive observers learn nothing.

```bash
pip install cryptography  # Required for encryption
```

### Audit Logging

Every command execution is logged (SHA-256 hashed, never plaintext) to:
- `/var/log/p3-bridge/audit-YYYY-MM-DD.jsonl`

Each entry: timestamp, cmd_id, cmd_hash, returncode, elapsed, source

### Output Sanitization

All command output is sanitized before transmission:
- GitHub tokens (`ghp_*`, `github_pat_*`, etc.) → `***TOKEN***`
- Passwords, secrets, credentials → `***REDACTED***`
- Output length capped at 8000 chars

### Systemd Hardening

When installed as a systemd service:
- `NoNewPrivileges=yes` — no privilege escalation
- `ProtectSystem=strict` — read-only filesystem
- `ProtectHome=read-only` — home dir read-only
- `PrivateTmp=yes` — isolated /tmp

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `P3_GITHUB_TOKEN` | ✅ Yes | — | GitHub Classic PAT (repo+gist) |
| `P3_SECRET` | No | — | Shared secret for HMAC + encryption |
| `P3_SECURITY_MODE` | No | `blacklist` | `blacklist` or `whitelist` |
| `P3_RATE_LIMIT` | No | `30` | Max commands per minute |
| `P3_REPO_OWNER` | No | `Kotokvit` | GitHub repo owner |
| `P3_REPO_NAME` | No | `p3-agent-cell` | GitHub repo name |
| `P3_RELAY_PATH` | No | `relay` | Path within repo |
| `P3_ENGINE_DIR` | No | `~/Стільниця/P3_Engine_repo` | Default CWD for commands |
| `P3_AUDIT_DIR` | No | `/var/log/p3-bridge` | Audit log directory |
| `P3_SANDBOX_ENABLED` | No | `0` | Docker sandbox (1=on) |
| `P3_MAX_CMD_LEN` | No | `4096` | Max command length |

### Custom Security Rules

Create `~/.p3/security.json`:

```json
{
  "mode": "whitelist",
  "extra_allowed": [
    "my-custom-app",
    "/opt/myapp/bin/"
  ],
  "extra_blocked": [
    "dangerous-pattern"
  ]
}
```

## Architecture

```
p3-agent-cell/
├── bridge/                    # Bridge code
│   ├── p3_bridge.py          # AI-side bridge (send commands)
│   ├── p3_client.py          # PC-side client (execute commands)
│   └── p3_security.py        # Security module
├── setup/                     # Setup & deployment
│   ├── install_pc.sh         # Automated PC setup
│   ├── config.env.example    # Configuration template
│   └── systemd/              # Systemd service
│       └── p3-bridge-client.service
├── relay/                     # Communication channel
│   ├── cmd.json              # AI → PC (auto-created)
│   └── result.json           # PC → AI (auto-created)
├── README.md                  # This file
└── LICENSE                    # MIT License
```

### GitHub API Rate Limits

| Resource | Limit | Bridge usage |
|----------|-------|-------------|
| Core API | 5,000 req/hr | ~6 per command cycle (read+write cmd, read+write result) |
| So max ~800 commands/hour on free account |

With GitHub Pro ($4/mo): 10,000 req/hr → ~1,600 commands/hour.

## For AI Agent Integrators

### Sending Commands from AI Sandbox

```python
import subprocess, os

os.environ["P3_GITHUB_TOKEN"] = "ghp_..."
os.environ["P3_SECRET"] = "shared_secret"  # optional

# One-shot
result = subprocess.run(
    ["python3", "bridge/p3_bridge.py", "cmd", "ls -la /home"],
    capture_output=True, text=True
)
print(result.stdout)

# Or import directly
sys.path.insert(0, "bridge")
from p3_bridge import do_cmd, do_status

result = do_cmd("nvidia-smi", timeout=15, wait=30)
status = do_status()
```

### Multiple PCs

Each PC runs its own client instance pointing to its own relay path:

```bash
# PC 1
python3 bridge/p3_client.py --token TOKEN --poll 10
# Uses relay/cmd.json, relay/result.json

# PC 2 (separate repo or relay path)
P3_RELAY_PATH=relay-pc2 python3 bridge/p3_client.py --token TOKEN --poll 10
# Uses relay-pc2/cmd.json, relay-pc2/result.json
```

## Troubleshooting

### Token Permission Errors (403)

Make sure you're using a **Classic PAT** (not Fine-grained):
- GitHub Settings → Tokens → **Tokens (classic)**
- Scopes: `repo` + `gist`
- Fine-grained tokens have limited write access

### Client Not Picking Up Commands

1. Check client is running: `systemctl status p3-bridge-client`
2. Check logs: `journalctl -u p3-bridge-client -f`
3. Verify relay files exist in GitHub repo
4. Check poll interval (default 10s — commands may take up to 10s to be picked up)

### SHA Conflict Errors (409/422)

Both sides handle SHA conflicts automatically. If persistent:
- Delete `relay/cmd.json` and `relay/result.json` from the repo
- Restart client

### Rate Limiting Hit

GitHub allows 5,000 API calls/hour. Each command cycle uses ~6 calls.
If you hit limits:
- Reduce poll frequency: `--poll 30`
- Upgrade to GitHub Pro for 10,000 calls/hr

## License

MIT License — see [LICENSE](LICENSE).

## Security Disclosure

If you find a security vulnerability, please report it privately.
Do NOT open a public GitHub issue for security bugs.
