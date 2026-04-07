#!/bin/bash
set -euo pipefail

# Claude Code Hardening Kit — Installer
# Installs all security hooks into ~/.claude.

CLAUDE_DIR="${HOME}/.claude"
HOOKS_DIR="${CLAUDE_DIR}/scripts/hooks"
SETTINGS="${CLAUDE_DIR}/settings.json"
ALLOWLIST="${CLAUDE_DIR}/network-allowlist.json"
FILE_POLICY="${CLAUDE_DIR}/file-access-policy.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Claude Code Hardening Kit"
echo "========================="
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

echo "[1/5] Creating directories..."
mkdir -p "$HOOKS_DIR"

echo "[2/5] Installing hook scripts..."
for hook in deny-destructive network-egress git-guard file-access secret-scan audit-log; do
  cp "$SCRIPT_DIR/hooks/${hook}.js" "$HOOKS_DIR/${hook}.js"
  echo "  -> $HOOKS_DIR/${hook}.js"
done

echo "[3/5] Installing config files..."
if [ -f "$ALLOWLIST" ]; then
  echo "  -> $ALLOWLIST already exists — skipping (won't overwrite)"
else
  cp "$SCRIPT_DIR/network-allowlist.example.json" "$ALLOWLIST"
  echo "  -> $ALLOWLIST"
fi

if [ -f "$FILE_POLICY" ]; then
  echo "  -> $FILE_POLICY already exists — skipping (won't overwrite)"
else
  cat > "$FILE_POLICY" <<'EOF'
{
  "_comment": "File access policy for claude-hardening. See README for full options.",
  "blockedDirs": [],
  "blockedFiles": [],
  "blockedAbsolute": [],
  "allowedPaths": []
}
EOF
  echo "  -> $FILE_POLICY"
fi

echo "[4/5] Configuring settings.json..."
if [ ! -f "$SETTINGS" ]; then
  # No settings.json — create one with all hooks
  sed "s|CLAUDE_DIR|${CLAUDE_DIR}|g" "$SCRIPT_DIR/settings.example.json" > "$SETTINGS"
  echo "  -> Created $SETTINGS with all security hooks"
else
  # settings.json exists — check if hooks are already present
  if grep -q "deny-destructive" "$SETTINGS" 2>/dev/null; then
    echo "  -> Hooks already present in $SETTINGS — skipping"
  else
    echo ""
    echo "  NOTE: $SETTINGS already exists and does not contain the hardening hooks."
    echo "  Add the following to your settings.json (see settings.example.json for"
    echo "  the full structure, or copy a profile from profiles/):"
    echo ""
    echo "  Hooks to add under PreToolUse:"
    echo "    pre:bash:deny-destructive   node \"${HOOKS_DIR}/deny-destructive.js\""
    echo "    pre:bash:network-egress     node \"${HOOKS_DIR}/network-egress.js\""
    echo "    pre:bash:git-guard          node \"${HOOKS_DIR}/git-guard.js\""
    echo "    pre:file:file-access        node \"${HOOKS_DIR}/file-access.js\""
    echo "    pre:file:secret-scan        node \"${HOOKS_DIR}/secret-scan.js\""
    echo ""
    echo "  Hook to add under PostToolUse:"
    echo "    post:all:audit-log          node \"${HOOKS_DIR}/audit-log.js\""
    echo ""
    echo "  Or use a pre-built profile:"
    echo "    cat $SCRIPT_DIR/profiles/standard.json"
    echo ""
  fi
fi

echo "[5/5] Verifying hook scripts..."
all_ok=true
for hook in deny-destructive network-egress git-guard file-access secret-scan audit-log; do
  if node --check "$HOOKS_DIR/${hook}.js" 2>/dev/null; then
    echo "  -> ${hook}.js OK"
  else
    echo "  -> ${hook}.js SYNTAX ERROR"
    all_ok=false
  fi
done

if [ "$all_ok" = false ]; then
  echo ""
  echo "ERROR: One or more hooks have syntax errors. Check Node.js version."
  exit 1
fi

echo ""
echo "Done. Installed:"
echo "  Hooks:    $HOOKS_DIR/"
echo "  Allowlist: $ALLOWLIST"
echo "  Policy:   $FILE_POLICY"
echo "  Settings: $SETTINGS"
echo ""
echo "Quick customization:"
echo "  Network domains  — edit $ALLOWLIST"
echo "  Protected files  — edit $FILE_POLICY"
echo "  Permission level — see profiles/ for strict/standard/readonly presets"
echo ""
echo "Verify the install:"
echo "  npm test   (from the repo root)"
echo ""
echo "To verify in a live Claude Code session:"
echo "  sudo ls                    (blocked by deny-destructive)"
echo "  curl https://example.com   (blocked by network-egress)"
echo "  cat ~/.env                 (blocked by file-access)"
