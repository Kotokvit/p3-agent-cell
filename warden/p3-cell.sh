#!/bin/bash
# P³ Agent Cell — Container lifecycle manager
# Usage: p3-cell.sh {build|start|stop|exec|status|shell|destroy}

set -euo pipefail

CELL_NAME="p3-agent-cell"
CELL_IMAGE="p3-agent-cell:latest"
CELL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE="$CELL_DIR/workspace"
CONTAINERFILE="$CELL_DIR/cell/Containerfile"

# GPU devices for passthrough
GPU_DEVICES="--device=/dev/nvidia0 --device=/dev/nvidiactl --device=/dev/nvidia-modeset --device=/dev/nvidia-uvm --device=/dev/nvidia-uvm-tools"

# Isolation flags: FULL hardware, ZERO host access
RUN_FLAGS=(
    --hostname p3-cell              # Isolated hostname
    --network bridge                 # Internet access via Docker bridge (isolated from host LAN)
    --memory="12g"                   # RAM limit (leave 4GB for host)
    --cpus="6"                       # CPU limit (leave 2 cores for host)
    --pids-limit=4096                # Process limit
    --read-only-tmpfs=false          # Allow tmpfs writes
    --security-opt=no-new-privileges # No privilege escalation
    --cap-drop=ALL                   # Drop ALL capabilities first
    --cap-add=SYS_ADMIN              # Add only what's needed for pacman/apt
    --cap-add=NET_RAW                # Network access
    ${GPU_DEVICES}                   # GPU passthrough
    -e NVIDIA_VISIBLE_DEVICES=all
    -e NVIDIA_DRIVER_CAPABILITIES=compute,utility
    -e TERM=xterm-256color
)

# Volume mounts: ONLY workspace, NOTHING else
# NO /home, NO /etc, NO /var, NO /root, NO /opt from host
MOUNT_FLAGS=(
    -v "$WORKSPACE:/workspace:rw"    # Agent workspace (bidirectional)
)

ensure_workspace() {
    mkdir -p "$WORKSPACE"
    # Copy bridge client into workspace so agent can use it
    if [ -f "$CELL_DIR/bridge/p3_bridge_client.py" ]; then
        cp "$CELL_DIR/bridge/p3_bridge_client.py" "$WORKSPACE/"
    fi
}

case "${1:-help}" in
    build)
        echo "→ Building P³ Agent Cell image..."
        sudo docker build -t "$CELL_IMAGE" -f "$CONTAINERFILE" "$CELL_DIR/cell/"
        echo "✅ Image built: $CELL_IMAGE"
        ;;
    start)
        if sudo docker ps -q -f "name=$CELL_NAME" | grep -q .; then
            echo "Cell already running"
            exit 0
        fi
        ensure_workspace
        echo "→ Starting P³ Agent Cell..."
        sudo docker run -d \
            --name "$CELL_NAME" \
            "${RUN_FLAGS[@]}" \
            "${MOUNT_FLAGS[@]}" \
            "$CELL_IMAGE"
        echo "✅ Cell started: $CELL_NAME"
        echo "   Workspace: $WORKSPACE"
        echo "   Shell:     $0 shell"
        ;;
    stop)
        echo "→ Stopping cell..."
        sudo docker stop "$CELL_NAME" 2>/dev/null && sudo docker rm "$CELL_NAME" 2>/dev/null
        echo "✅ Cell stopped"
        ;;
    exec)
        # Execute command inside the cell (used by bridge)
        shift
        sudo docker exec -u agent -w /workspace "$CELL_NAME" bash -c "$*"
        ;;
    status)
        if sudo docker ps -q -f "name=$CELL_NAME" | grep -q .; then
            echo "🟢 Cell running"
            sudo docker stats --no-stream "$CELL_NAME"
        else
            echo "🔴 Cell stopped"
        fi
        ;;
    shell)
        sudo docker exec -it -u agent -w /workspace "$CELL_NAME" bash
        ;;
    destroy)
        echo "→ Destroying cell (image + containers)..."
        sudo docker stop "$CELL_NAME" 2>/dev/null; sudo docker rm "$CELL_NAME" 2>/dev/null
        sudo docker rmi "$CELL_IMAGE" 2>/dev/null
        echo "✅ Destroyed"
        ;;
    help|*)
        echo "P³ Agent Cell — Isolated container for AI agents"
        echo ""
        echo "Commands:"
        echo "  build    Build the cell image (first time)"
        echo "  start    Start the cell container"
        echo "  stop     Stop the cell"
        echo "  exec CMD Run command inside the cell"
        echo "  status   Show cell status"
        echo "  shell    Interactive shell inside the cell"
        echo "  destroy  Remove cell image + containers"
        ;;
esac

