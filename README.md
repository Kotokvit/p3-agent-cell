# P³ Bridge — Remote Command Bridge

> AI Sandbox ←→ Relay ←→ Your PC — **Dual backend: GitHub + Gitea (unlimited!)**

Execute commands on your PC from any AI agent. Zero open ports. Zero VPN.

## How It Works

```
┌─────────────┐     cmd.json      ┌──────────────┐    poll     ┌───────────┐
│  AI Agent   │ ──────────────▶  │  Relay        │ ◀───────── │  Your PC  │
│  (Sandbox)  │                   │  GitHub/Gitea │            │  (Client)  │
│             │  ◀──────────────  │  relay/       │ ────────▶ │             │
└─────────────┘    result.json    └──────────────┘   write     └───────────┘
```

### Dual Backend Architecture

| Backend | Rate Limit | Poll Speed | Use Case |
|---------|-----------|------------|----------|
| **GitHub** | 5,000 req/hr | 10s | External access from AI sandbox |
| **Gitea** | **∞ UNLIMITED** | 3s | Local ops, high-throughput |

The PC client polls **both** relays. Gitea is checked first (faster + unlimited).
AI sandbox uses GitHub (reachable from anywhere). When both are available,
Gitea handles the load and GitHub stays as backup.

## Quick Start (5 minutes)

### Prerequisites

- Python 3.8+ on both machines
- GitHub account + Classic PAT with `repo` + `gist` scopes
- Gitea on PC (optional, but recommended for unlimited access)

### Step 1: Create GitHub PAT

Go to [GitHub Settings → Tokens → Tokens (classic)](https://github.com/settings/tokens)

Create a token with scopes: ✅ `repo` + ✅ `gist`

### Step 2: PC Side — Install & Run

```bash
# Clone the repo
git clone https://github.com/Kotokvit/p3-agent-cell.git
cd p3-agent-cell

# Option A: Automated setup
chmod +x setup/install_pc.sh
./setup/install_pc.sh --token ghp_YOUR_TOKEN_HERE

# Option B: Manual — GitHub only
python3 bridge/p3_client.py --token ghp_YOUR_TOKEN_HERE

# Option C: Manual — GitHub + Gitea (UNLIMITED!)
python3 bridge/p3_client.py \
  --token ghp_YOUR_GITHUB_PAT \
  --gitea-token YOUR_GITEA_TOKEN \
  --gitea-url http://localhost:3000

# Option D: Systemd service (auto-start on boot)
sudo systemctl enable --now p3-bridge-client
```

### Step 3: AI Side — Send Commands

```bash
export P3_GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE

# One-shot command
python3 bridge/p3_bridge.py cmd "uname -a"

# System status
python3 bridge/p3_bridge.py status

# Interactive REPL
python3 bridge/p3_bridge.py repl
```

### Step 4: Verify

```bash
python3 bridge/p3_bridge.py cmd "echo 'P3 Bridge ONLINE!' && hostname"
# → P3 Bridge ONLINE!
# → your-pc-hostname
```

## Gitea Setup (Unlimited Access)

Gitea is a self-hosted GitHub alternative with **ZERO API rate limits**.

```bash
# Install Gitea via Docker
docker run -d --name=gitea -p 3000:3000 -p 222:22 \
  -v /var/lib/gitea:/data \
  gitea/gitea:latest

# Open http://localhost:3000, create admin account
# Create repo: p3admin/p3-relay
# Generate API token in Settings → Applications

# Start client with Gitea
python3 bridge/p3_client.py \
  --token ghp_GITHUB_PAT \
  --gitea-token GITEA_TOKEN
```

Now your bridge has **unlimited** command throughput through Gitea,
with GitHub as fallback for external access.

## Token Rotation (Multiply Rate Limit)

Add multiple GitHub PATs to multiply your effective rate limit:
1 token = 5,000/hr → **N tokens = N × 5,000/hr**

```bash
# Register tokens
python3 bridge/p3_token_rotation.py add ghp_TOKEN1 --name "account-1"
python3 bridge/p3_token_rotation.py add ghp_TOKEN2 --name "account-2"
python3 bridge/p3_token_rotation.py add ghp_TOKEN3 --name "account-3"

# Check rate limits
python3 bridge/p3_token_rotation.py status

# Get next available token (smart: picks token with most remaining)
python3 bridge/p3_token_rotation.py next
```

## Security

P³ Bridge is designed for **production use** with multiple security layers:

### Command Validation

| Mode | Description | Use Case |
|------|-------------|----------|
| `blacklist` | Block dangerous commands, allow everything else | **Default** |
| `whitelist` | Only allow pre-approved commands | **Production** |

**Always blocked**: `rm -rf /`, `dd of=/dev/`, `mkfs`, `reboot`, reverse shells,
`curl|sh`, crypto miners, fork bombs, kernel module injection.

### Rate Limiting: 30 commands/minute (sliding window)

### HMAC-SHA256 Signing (prevents tampering in transit)

### Fernet Channel Encryption (GitHub sees only encrypted blobs)

### Audit Logging (SHA-256 hashed commands, never plaintext)

### Output Sanitization (tokens → `***TOKEN***`)

### Systemd Hardening (NoNewPrivileges, ProtectSystem, PrivateTmp)

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `P3_GITHUB_TOKEN` | ✅ Yes | — | GitHub Classic PAT (repo+gist) |
| `P3_GITEA_URL` | No | `http://localhost:3000` | Gitea URL |
| `P3_GITEA_TOKEN` | No | — | Gitea API token |
| `P3_GITEA_REPO` | No | `p3admin/p3-relay` | Gitea repo |
| `P3_SECRET` | No | — | Shared secret for HMAC + encryption |
| `P3_SECURITY_MODE` | No | `blacklist` | `blacklist` or `whitelist` |
| `P3_RATE_LIMIT` | No | `30` | Max commands per minute |
| `P3_REPO_OWNER` | No | `Kotokvit` | GitHub repo owner |
| `P3_REPO_NAME` | No | `p3-agent-cell` | GitHub repo name |
| `P3_ENGINE_DIR` | No | `~/` | Default CWD for commands |
| `P3_AUDIT_DIR` | No | `/var/log/p3-bridge` | Audit log directory |

## Architecture

```
p3-agent-cell/
├── bridge/                        # Bridge code
│   ├── p3_bridge.py              # AI-side bridge (GitHub relay)
│   ├── p3_client.py              # PC client v5 (dual backend + security)
│   ├── p3_security.py            # Security module (validation, audit, encrypt)
│   ├── p3_gitea_relay.py         # Gitea relay (UNLIMITED) + GitHub fallback
│   └── p3_token_rotation.py      # Token rotation (N × 5000/hr)
├── setup/                         # Setup & deployment
│   ├── install_pc.sh             # Automated PC setup
│   ├── config.env.example        # Configuration template
│   └── systemd/                  # Systemd service
├── relay/                         # Communication channel
│   ├── cmd.json                  # AI → PC
│   └── result.json               # PC → AI
├── README.md
└── LICENSE                        # MIT License
```

## Rate Limits Comparison

| Backend | Limit | Commands/hr | Cost |
|---------|-------|-------------|------|
| GitHub Free | 5,000 req/hr | ~800/hr | Free |
| GitHub Pro | 10,000 req/hr | ~1,600/hr | $4/mo |
| GitHub App | 15,000 req/hr | ~2,500/hr | Free setup |
| **Gitea** | **∞** | **∞** | **Free** |
| N GitHub PATs | N × 5,000/hr | N × 800/hr | Free |

## For AI Agent Integrators

```python
import subprocess, os

os.environ["P3_GITHUB_TOKEN"] = "ghp_..."

# One-shot
result = subprocess.run(
    ["python3", "bridge/p3_bridge.py", "cmd", "ls -la /home"],
    capture_output=True, text=True
)

# Or import directly
from p3_bridge import do_cmd, do_status
result = do_cmd("nvidia-smi", timeout=15, wait=30)
```

## Troubleshooting

**Token Permission Errors (403)**: Use Classic PAT (not Fine-grained) with `repo` + `gist`.

**Client Not Picking Up**: Check `systemctl status p3-bridge-client`, `journalctl -u p3-bridge-client -f`.

**SHA Conflicts (409)**: Handled automatically. If persistent, delete relay/*.json and restart.

**Rate Limiting Hit**: Add Gitea (unlimited) or rotate tokens, or reduce `--poll 30`.

## License

MIT License — see [LICENSE](LICENSE).
