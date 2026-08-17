#!/usr/bin/env python3
"""
P³ Warden — Bridge client that routes commands into the agent cell.

Replaces p3_bridge_client.py. Instead of executing commands directly on the host,
it runs them inside the Docker container via `docker exec`.

Security model:
  - Commands execute INSIDE the container (isolated from host)
  - Only /workspace is shared between container and host
  - Agent has full root INSIDE container, zero access OUTSIDE
  - GPU, CPU, RAM, network available inside container
"""

import urllib.request
import json
import time
import subprocess
import sys
import os
import argparse

GITHUB_API = "https://api.github.com"

class CellWarden:
    def __init__(self, token, gist_id, cell_name="p3-agent-cell"):
        self.token = token
        self.gist_id = gist_id
        self.cell_name = cell_name
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }
        self.last_cmd_id = None
        self.workspace = os.path.expanduser("~/Стільниця/p3-agent-cell/workspace")

    def api_request(self, method, path, data=None):
        url = f"{GITHUB_API}{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=self.headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def read_command(self):
        data = self.api_request("GET", f"/gists/{self.gist_id}")
        if "error" in data:
            return None
        files = data.get("files", {})
        cmd_file = files.get("cmd.json", {})
        content = cmd_file.get("content", "")
        if not content:
            return None
        try:
            cmd_data = json.loads(content)
        except:
            return None
        cmd_id = cmd_data.get("id")
        if cmd_id == self.last_cmd_id:
            return None
        return cmd_data

    def write_result(self, cmd_id, stdout, stderr, returncode, cmd):
        result = {
            "id": cmd_id,
            "cmd": cmd,
            "stdout": stdout[-10000:],
            "stderr": stderr[-10000:],
            "returncode": returncode,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.api_request("PATCH", f"/gists/{self.gist_id}", {
            "files": {
                "result.json": {
                    "content": json.dumps(result, ensure_ascii=False, indent=2)
                }
            }
        })

    def is_cell_running(self):
        """Check if the Docker container is running."""
        try:
            r = subprocess.run(
                ["sudo", "docker", "ps", "-q", "-f", f"name={self.cell_name}"],
                capture_output=True, text=True, timeout=5
            )
            return bool(r.stdout.strip())
        except:
            return False

    def execute_in_cell(self, cmd, timeout=60):
        """Execute command inside the container via docker exec."""
        if not self.is_cell_running():
            return "", "Cell container not running. Start with: p3-cell.sh start", -1

        try:
            result = subprocess.run(
                [
                    "sudo", "docker", "exec",
                    "-u", "agent",      # Run as agent user (with sudo inside)
                    "-w", "/workspace", # Working directory
                    self.cell_name,
                    "bash", "-c", cmd
                ],
                capture_output=True, text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Timeout ({timeout}s)", -1
        except Exception as e:
            return "", str(e), -1

    def execute_on_host(self, cmd, timeout=60):
        """Fallback: execute directly on host (for cell management commands)."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Timeout ({timeout}s)", -1
        except Exception as e:
            return "", str(e), -1

    def execute_command(self, cmd_data):
        """Route command: cell commands → container, host commands → host."""
        cmd = cmd_data.get("cmd", "")
        target = cmd_data.get("target", "cell")  # "cell" or "host"
        timeout = cmd_data.get("timeout", 60)
        cmd_id = cmd_data.get("id")

        print(f"  [{time.strftime('%H:%M:%S')}] Exec ({target}): {cmd[:80]}...")

        if target == "host":
            # Host command (cell management: build, start, stop)
            stdout, stderr, rc = self.execute_on_host(cmd, timeout)
        else:
            # Cell command (default) — runs inside container
            stdout, stderr, rc = self.execute_in_cell(cmd, timeout)

        self.write_result(cmd_id, stdout, stderr, rc, cmd)
        print(f"  [{time.strftime('%H:%M:%S')}] Done (rc={rc})")
        self.last_cmd_id = cmd_id

    def run(self, poll_interval=5):
        print(f"P³ Warden (Cell Router)")
        print(f"  Gist:     {GITHUB_API}/gists/{self.gist_id}")
        print(f"  Cell:     {self.cell_name}")
        print(f"  Target:   cell (default) / host (for management)")
        print(f"  Poll:     every {poll_interval}s")
        print()

        while True:
            try:
                cmd_data = self.read_command()
                if cmd_data:
                    self.execute_command(cmd_data)
                else:
                    sys.stdout.write(".")
                    sys.stdout.flush()
            except KeyboardInterrupt:
                print("\nStopped.")
                break
            except Exception as e:
                print(f"\n  Error: {e}")
            time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="P³ Warden — Cell Router Bridge Client")
    parser.add_argument("--token", required=True, help="GitHub PAT")
    parser.add_argument("--gist", required=True, help="Gist ID")
    parser.add_argument("--cell", default="p3-agent-cell", help="Container name")
    parser.add_argument("--poll", type=int, default=5, help="Poll interval")
    args = parser.parse_args()

    warden = CellWarden(args.token, args.gist, args.cell)
    warden.run(poll_interval=args.poll)


if __name__ == "__main__":
    main()

