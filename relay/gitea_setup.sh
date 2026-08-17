#!/bin/bash
# P³ Gitea Full Setup — runs on the PC
# Configures: first-run install, admin user, API token, relay repo

set -e
echo "=== P3 GITEA FULL SETUP ==="

# 1. Check Gitea is running
HTTP_CODE=$(curl -s http://localhost:3000/ -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
echo "Gitea HTTP: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ]; then
    echo "Starting Gitea..."
    sudo systemctl start gitea
    sleep 3
    HTTP_CODE=$(curl -s http://localhost:3000/ -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
    echo "Gitea HTTP after start: $HTTP_CODE"
fi

# 2. Check if API is available (already installed)
API_CHECK=$(curl -s http://localhost:3000/api/v1/nodeinfo 2>/dev/null | head -c 5)
echo "API check: [$API_CHECK]"

if [ "$API_CHECK" = "{" ]; then
    echo "Gitea already configured, API works"
else
    echo "Gitea needs first-run install..."
    curl -s -X POST http://localhost:3000/install \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data-urlencode "db_type=SQLite3" \
      --data-urlencode "db_path=/var/lib/gitea/data/gitea.db" \
      --data-urlencode "app_name=P3 Gitea" \
      --data-urlencode "repo_root_path=/var/lib/gitea/repositories" \
      --data-urlencode "lfs_root_path=/var/lib/gitea/data/lfs" \
      --data-urlencode "run_user=gitea" \
      --data-urlencode "domain=localhost" \
      --data-urlencode "ssh_port=22" \
      --data-urlencode "http_port=3000" \
      --data-urlencode "app_url=http://localhost:3000/" \
      --data-urlencode "log_root_path=/var/lib/gitea/log" \
      --data-urlencode "admin_name=p3admin" \
      --data-urlencode "admin_passwd=P3Gitea2024xSecure" \
      --data-urlencode "admin_email=p3admin@localhost" \
      -o /tmp/gitea_install_result.txt -w "INSTALL_HTTP:%{http_code}" 2>&1
    echo ""
    echo "Install HTTP code and output:"
    cat /tmp/gitea_install_result.txt 2>/dev/null | head -c 500
    echo ""
    sleep 3
fi

# 3. Verify API works now
API_V2=$(curl -s http://localhost:3000/api/v1/nodeinfo 2>/dev/null | head -c 100)
echo "API after install: $API_V2"

# 4. List existing tokens
echo "Checking existing tokens..."
TOKEN_LIST=$(curl -s -u "p3admin:P3Gitea2024xSecure" http://localhost:3000/api/v1/users/p3admin/tokens 2>/dev/null)
echo "Token list: $(echo "$TOKEN_LIST" | head -c 300)"

# 5. Create p3-relay token if not exists
P3_TOKEN=""
P3_TOKEN_EXISTS=$(echo "$TOKEN_LIST" | grep -c "p3-relay" 2>/dev/null || echo "0")

if [ "$P3_TOKEN_EXISTS" = "0" ]; then
    echo "Creating p3-relay token..."
    NEW_TOKEN_JSON=$(curl -s -X POST -u "p3admin:P3Gitea2024xSecure" \
      http://localhost:3000/api/v1/users/p3admin/tokens \
      -H "Content-Type: application/json" \
      -d '{"name":"p3-relay","scopes":["write:repository","write:issue"]}' 2>/dev/null)
    echo "New token response: $(echo "$NEW_TOKEN_JSON" | head -c 300)"
    P3_TOKEN=$(echo "$NEW_TOKEN_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sha1','') or d.get('token',''))" 2>/dev/null || echo "")
else
    echo "p3-relay token already exists"
    P3_TOKEN=$(echo "$TOKEN_LIST" | python3 -c "import sys,json; ts=json.load(sys.stdin); [print(t.get('sha1','') or t.get('token','')) for t in ts if t.get('name')=='p3-relay']" 2>/dev/null | head -1 || echo "")
fi
echo "P3_TOKEN=$P3_TOKEN"

# 6. Create relay repo if not exists
echo "Checking relay repo..."
REPO_CHECK=$(curl -s "http://localhost:3000/api/v1/repos/p3admin/p3-relay" \
  -H "Authorization: token $P3_TOKEN" 2>/dev/null)
echo "Repo check: $(echo "$REPO_CHECK" | head -c 200)"

REPO_EXISTS=$(echo "$REPO_CHECK" | grep -c "full_name" 2>/dev/null || echo "0")
if [ "$REPO_EXISTS" = "0" ]; then
    echo "Creating relay repo..."
    REPO_RESULT=$(curl -s -X POST "http://localhost:3000/api/v1/user/repos" \
      -H "Authorization: token $P3_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"name":"p3-relay","private":true,"auto_init":true}' 2>/dev/null)
    echo "Repo created: $(echo "$REPO_RESULT" | head -c 300)"
else
    echo "Relay repo already exists"
fi

# 7. Final verification
echo "Final verification..."
FINAL=$(curl -s "http://localhost:3000/api/v1/repos/p3admin/p3-relay" \
  -H "Authorization: token $P3_TOKEN" 2>/dev/null)
FINAL_NAME=$(echo "$FINAL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('full_name','FAIL'))" 2>/dev/null || echo "FAIL")
FINAL_PRIVATE=$(echo "$FINAL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('private','?'))" 2>/dev/null || echo "?")
echo "Repo: $FINAL_NAME (private=$FINAL_PRIVATE)"

# 8. Write config file
CONFIG_DIR="$HOME/.config/p3-gitea"
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.json" << CONFEOF
{
  "gitea_url": "http://localhost:3000",
  "gitea_user": "p3admin",
  "gitea_token": "$P3_TOKEN",
  "gitea_repo": "p3admin/p3-relay",
  "gitea_admin_pass": "P3Gitea2024xSecure"
}
CONFEOF
chmod 600 "$CONFIG_DIR/config.json"
echo "Config saved to $CONFIG_DIR/config.json"

echo "=== SETUP COMPLETE ==="
