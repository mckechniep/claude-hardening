#!/bin/bash
set -euo pipefail

# Claude Code Security Hardening — Installer
# Installs deny-destructive and network-egress PreToolUse hooks.

CLAUDE_DIR="${HOME}/.claude"
HOOKS_DIR="${CLAUDE_DIR}/scripts/hooks"
SETTINGS="${CLAUDE_DIR}/settings.json"
ALLOWLIST="${CLAUDE_DIR}/network-allowlist.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Claude Code Security Hardening"
echo "=============================="
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
  echo "ERROR: Node.js is required but not installed."
  echo "Install it from https://nodejs.org (v18+)"
  exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo "ERROR: Node.js 18+ required. Found: $(node -v)"
  exit 1
fi

echo "[1/4] Creating directories..."
mkdir -p "$HOOKS_DIR"

echo "[2/4] Installing hook scripts..."
cp "$SCRIPT_DIR/hooks/deny-destructive.js" "$HOOKS_DIR/deny-destructive.js"
cp "$SCRIPT_DIR/hooks/network-egress.js" "$HOOKS_DIR/network-egress.js"
echo "  -> $HOOKS_DIR/deny-destructive.js"
echo "  -> $HOOKS_DIR/network-egress.js"

echo "[3/4] Installing network allowlist..."
if [ -f "$ALLOWLIST" ]; then
  echo "  -> $ALLOWLIST already exists — skipping (won't overwrite)"
else
  cp "$SCRIPT_DIR/network-allowlist.example.json" "$ALLOWLIST"
  echo "  -> $ALLOWLIST"
fi

echo "[4/4] Configuring settings.json..."
if [ ! -f "$SETTINGS" ]; then
  # No settings.json — create one with the hooks
  sed "s|CLAUDE_DIR|${CLAUDE_DIR}|g" "$SCRIPT_DIR/settings.example.json" > "$SETTINGS"
  echo "  -> Created $SETTINGS with security hooks"
else
  # settings.json exists — check if hooks are already present
  if grep -q "deny-destructive" "$SETTINGS" 2>/dev/null; then
    echo "  -> deny-destructive hook already present — skipping"
  else
    echo ""
    echo "  NOTE: $SETTINGS already exists."
    echo "  Add these hooks MANUALLY to the beginning of your PreToolUse array:"
    echo ""
    echo '  {'
    echo '    "matcher": "Bash",'
    echo '    "hooks": [{'
    echo '      "type": "command",'
    echo "      \"command\": \"node \\\"${HOOKS_DIR}/deny-destructive.js\\\"\""
    echo '    }],'
    echo '    "description": "Block destructive commands (rm -rf /, sudo, force push, etc.)",'
    echo '    "id": "pre:bash:deny-destructive"'
    echo '  },'
    echo '  {'
    echo '    "matcher": "Bash",'
    echo '    "hooks": [{'
    echo '      "type": "command",'
    echo "      \"command\": \"node \\\"${HOOKS_DIR}/network-egress.js\\\"\""
    echo '    }],'
    echo '    "description": "Block outbound network requests to domains not in allowlist",'
    echo '    "id": "pre:bash:network-egress"'
    echo '  }'
    echo ""
  fi
fi

echo ""
echo "Done. Installed files:"
echo "  $HOOKS_DIR/deny-destructive.js"
echo "  $HOOKS_DIR/network-egress.js"
echo "  $ALLOWLIST"
echo ""
echo "To customize allowed network domains, edit:"
echo "  $ALLOWLIST"
echo ""
echo "To verify, start a Claude Code session and ask the agent to run:"
echo "  sudo ls              (should be blocked by deny-destructive)"
echo "  curl https://example.com  (should be blocked by network-egress)"
