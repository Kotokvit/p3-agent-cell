#!/bin/bash
# P³ Agent Cell — Build script
cd ~/Стільниця/p3-agent-cell
echo "Building P³ Agent Cell image..."
echo "This takes 5-10 minutes. Output:"
sudo -n docker build -t p3-agent-cell:latest -f cell/Containerfile cell/ 2>&1
echo ""
echo "=== Result ==="
sudo -n docker images p3-agent-cell

