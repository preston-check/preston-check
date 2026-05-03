#!/bin/bash
###############################################################################
# Deploy Preston-Check to a new project
#
# Usage:
#   ./deploy-to-project.sh /path/to/target/project [app-name] [ssh-host]
#
# Examples:
#   ./deploy-to-project.sh ~/projects/supefina-gateway supefina-gateway supefina-prod
#   ./deploy-to-project.sh ~/projects/amapay-backend amapay amapay-cluster-001
#   ./deploy-to-project.sh /opt/services/payment-processor payment-api
#
# This script:
#   1. Copies the entire preston-check tool to the target project
#   2. Generates a config.yml tailored to the target
#   3. Makes everything executable
#   4. Runs the first audit
#   5. Outputs instructions for CI/CD integration
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target-project-path> [app-name] [ssh-host]"
  echo ""
  echo "Examples:"
  echo "  $0 ~/projects/my-fintech-app my-app prod-server-001"
  echo "  $0 /opt/services/payment-processor payment-api"
  exit 1
fi

TARGET_DIR="$1"
APP_NAME="${2:-$(basename "$TARGET_DIR")}"
SSH_HOST="${3:-}"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "Error: Target directory does not exist: $TARGET_DIR"
  exit 1
fi

DEST="$TARGET_DIR/tools/preston-check"

echo "============================================================================"
echo "  Deploying Preston-Check to: $TARGET_DIR"
echo "  App name: $APP_NAME"
echo "  SSH host: ${SSH_HOST:-<none>}"
echo "============================================================================"
echo ""

# 1. Copy the tool
mkdir -p "$DEST/checks" "$DEST/lib" "$DEST/lang" "$DEST/templates"
cp "$SCRIPT_DIR/preston-check.sh" "$DEST/"
cp "$SCRIPT_DIR/checks/"*.sh "$DEST/checks/" 2>/dev/null
[[ -d "$SCRIPT_DIR/checks/core" ]] && cp -r "$SCRIPT_DIR/checks/core" "$DEST/checks/"
[[ -d "$SCRIPT_DIR/checks/community" ]] && cp -r "$SCRIPT_DIR/checks/community" "$DEST/checks/"
cp "$SCRIPT_DIR/lib/"*.sh "$DEST/lib/" 2>/dev/null
cp "$SCRIPT_DIR/lib/"*.pem "$DEST/lib/" 2>/dev/null
cp "$SCRIPT_DIR/lang/"*.sh "$DEST/lang/" 2>/dev/null
cp "$SCRIPT_DIR/templates/"*.sh "$DEST/templates/" 2>/dev/null

# 2. Generate config.yml
cat > "$DEST/config.yml" << EOF
# Preston-Check Configuration for $APP_NAME
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Customize these paths for your environment.

app_name: $APP_NAME
source_dir: $TARGET_DIR
log_dir: /home/ec2-user
ssh_host: $SSH_HOST
api_base_url:
redis_host: localhost
db_host:
EOF

# 3. Make executable
chmod +x "$DEST/preston-check.sh" "$DEST/checks/"*.sh 2>/dev/null
find "$DEST/checks" "$DEST/lib" "$DEST/lang" "$DEST/templates" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

echo "  Copied: preston-check.sh"
echo "  Copied: $(ls "$DEST/checks/"*.sh | wc -l) check scripts"
echo "  Generated: config.yml"
echo ""

# 4. Run first audit
echo "  Running first audit..."
echo ""
bash "$DEST/preston-check.sh" --config "$DEST/config.yml"

echo ""
echo "============================================================================"
echo "  DEPLOYMENT COMPLETE"
echo "============================================================================"
echo ""
echo "  Location:  $DEST"
echo "  Config:    $DEST/config.yml"
echo ""
echo "  Run manually:"
echo "    cd $TARGET_DIR"
echo "    ./tools/preston-check/preston-check.sh"
echo ""
echo "  CI/CD integration (GitHub Actions):"
echo "    - name: Security Audit"
echo "      run: ./tools/preston-check/preston-check.sh --ci --report security-audit.md"
echo ""
echo "  CI/CD integration (GitLab CI):"
echo "    security_audit:"
echo "      script: ./tools/preston-check/preston-check.sh --ci --report security-audit.md"
echo "      artifacts:"
echo "        paths: [security-audit.md]"
echo ""
echo "  Pre-commit hook:"
echo "    echo './tools/preston-check/preston-check.sh --ci' >> .git/hooks/pre-push"
echo "    chmod +x .git/hooks/pre-push"
echo ""
echo "  New Claude session handoff:"
echo "    \"Read tools/preston-check/preston-check.sh and run a security audit"
echo "     on this project. Fix any FAIL results.\""
echo ""
