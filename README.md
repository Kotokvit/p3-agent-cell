# P³ Bridge — Remote Command Bridge

> AI Sandbox ←→ Relay ←→ Your PC — **Hardened, fail-closed, dual backend**

Execute commands on your PC from any AI agent. Zero open ports. Zero VPN.

## Security Model

**P³ Bridge is fail-closed by default:**
- No `P3_SECRET` set → **unauthenticated mode** (no HMAC, no encryption)
- `P3_SECRET` set → **authenticated mode** (HMAC + Fernet required, no XOR fallback)
- `P3_REQUIRE_AUTH=1` (default) → HMAC **must** be present or command is **REJECTED**
- Replay protection: timestamp skew > 120s → **REJECTED**, duplicate nonce → **REJECTED**

**All AI commands execute through whitelist by executable (not prefix):**
- `python3 script.py` → ✅ allowed
- `python3 -c '...'` → ❌ blocked (arbitrary code execution)
- `docker ps` → ✅ allowed
- `docker run --privileged` → ❌ blocked (host escape)
- `find /tmp -name '*.log'` → ✅ allowed
- `find /tmp -exec rm {} \;` → ❌ blocked (arbitrary execution)

**Audit log stores sanitized command** (forensic-usable, not just hash).

## How It Works

```
┌─────────────┐   signed+encrypted   ┌───────────┐   decrypt+verify   ┌───────────┐
│  AI Agent   │ ──────────────────▶  │  Relay     │ ───────────────▶  │  Your PC  │
│  (Sandbox)  │                      │  GitHub/   │   HMAC check     │  (Client)  │
│             │  ◀──────────────────  │  Gitea     │ ────────▶        │             │
└─────────────┘    result.json       └───────────┘   validate+exec    └───────────┘
```

### Command Pipeline (PC side, in order):

```
read cmd.json
    ↓
decrypt (if P3_SECRET set, fail-closed)
    ↓
parse JSON
    ↓
verify HMAC signature (REJECT if invalid)
    ↓
replay protection (timestamp + nonce check)
    ↓
whitelist validation (by executable, not prefix)
    ↓
rate limit check
    ↓
execute (subprocess, stdin=/dev/null)
    ↓
sanitize output (strip tokens/secrets)
    ↓
audit log (sanitized cmd, not hash)
    ↓
write result.json
```

## Quick Start

### Step 1: Generate shared secret

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# Save this — both sides need it
```

### Step 2: PC Side — Install & Run

```bash
git clone https://github.com/Kotokvit/p3-agent-cell.git
cd p3-agent-cell

# Install encryption dependency (REQUIRED when P3_SECRET is set)
pip install cryptography

# Run with authentication
export P3_SECRET=your_shared_secret_here
python3 bridge/p3_client.py \
  --token ghp_YOUR_GITHUB_PAT \
  --gitea-token YOUR_GITEA_TOKEN
```

### Step 3: AI Side — Send Commands

```bash
export P3_GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE
export P3_SECRET=your_shared_secret_here

python3 bridge/p3_bridge.py cmd "uname -a"
python3 bridge/p3_bridge.py status
```

## Dual Backend

| Backend | Rate Limit | Poll Speed | Use Case |
|---------|-----------|------------|----------|
| **Gitea** | **∞ UNLIMITED** | 3s | Local ops, high-throughput |
| **GitHub** | 5,000 req/hr | 10s | External access from AI sandbox |

## Security Features

| Feature | Implementation | Default |
|---------|---------------|---------|
| HMAC-SHA256 | **Verified on receiver** | Required when P3_SECRET set |
| Fernet encryption | **No insecure fallback** | Required when P3_SECRET set |
| Key derivation | PBKDF2 (600K iterations) | Fail-closed if cryptography missing |
| Replay protection | Timestamp + nonce tracking | 120s skew window |
| Command validation | Whitelist by executable (shlex) | whitelist mode |
| Dangerous flags | `python -c`, `docker --privileged`, `find -exec` | Always blocked |
| Rate limiting | 30 commands/minute sliding window | Configurable |
| Audit log | Sanitized command + hash | Forensic-usable |
| Output sanitization | Tokens, AWS keys, generic secrets | Always active |

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `P3_GITHUB_TOKEN` | ✅ | — | GitHub Classic PAT (repo+gist) |
| `P3_SECRET` | Recommended | — | Shared secret for HMAC + encryption |
| `P3_REQUIRE_AUTH` | No | `1` | Fail-closed: require HMAC (1=on) |
| `P3_SECURITY_MODE` | No | `whitelist` | `whitelist` (recommended) or `blacklist` |
| `P3_GITEA_URL`<br>`P3_GITEA_TOKEN` | No | — | Gitea relay (unlimited) |
| `P3_RATE_LIMIT` | No | `30` | Max commands per minute |
| `P3_TIMESTAMP_SKEW` | No | `120` | Max clock skew in seconds |
| `P3_MAX_CMD_LEN` | No | `4096` | Max command length |

## Architecture

```
p3-agent-cell/
├── bridge/
│   ├── p3_client.py          # PC client (dual backend + security pipeline)
│   ├── p3_bridge.py          # AI-side bridge (sign + encrypt + send)
│   ├── p3_security.py        # Security module (hardened v2)
│   ├── p3_gitea_relay.py     # Gitea relay (UNLIMITED)
│   └── p3_token_rotation.py  # Token rotation
├── setup/
│   ├── install_pc.sh
│   ├── config.env.example
│   └── systemd/
├── relay/                     # .gitignore — NEVER commit live data
├── .gitignore                 # Protects relay/*.json and secrets
├── README.md
└── LICENSE
```

## Known Limitations

- **GitHub polling is not real-time** (~10s latency). For lower latency, use Gitea locally.
- **Single cmd.json without queue** — if PC is offline, only last command is preserved.
- **Blacklist mode is fundamentally insufficient** for shell — use `whitelist`.
- **Classic PAT has broad access** — consider GitHub App with minimal permissions.
- **Audit log is local** — if PC is compromised, logs can be tampered with.
- **Rate limiter resets on restart** — not distributed/persistent.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Tampered cmd.json in transit | HMAC-SHA256 signature verified on receiver |
| Passive observer on GitHub | Fernet encryption (PBKDF2-derived key) |
| Replay attack | Timestamp + nonce tracking |
| Arbitrary code execution | Whitelist by executable, dangerous flags blocked |
| Host escape via docker | `--privileged` and `/` mount blocked |
| Token leakage in output | Regex sanitization for tokens/secrets |
| Credential theft via PAT | Minimal scope, .gitignore prevents exposure |

## License

MIT License — see [LICENSE](LICENSE).
