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

# Check bwrap
BWRAP_AVAILABLE=false
if command -v bwrap &> /dev/null; then
  if bwrap --bind / / --dev /dev --proc /proc -- true 2>/dev/null; then
    BWRAP_AVAILABLE=true
    echo "bwrap detected — OS-level sandbox protection will be active."
  else
    echo "WARNING: bwrap found but not functional (user namespaces may be disabled)."
    echo "Sandbox hook will fall back to regex-based protection."
  fi
else
  echo "NOTE: bubblewrap (bwrap) not found."
  echo "  Install it for OS-level sandbox protection: sudo apt install bubblewrap"
  echo "  The sandbox hook will fall back to regex-based protection without it."
fi
echo ""

echo "[1/7] Creating directories..."
mkdir -p "$HOOKS_DIR"

echo "[2/7] Installing hook scripts..."
for hook in sandbox-exec deny-destructive network-egress git-guard file-access secret-scan audit-log; do
  cp "$SCRIPT_DIR/hooks/${hook}.js" "$HOOKS_DIR/${hook}.js"
  echo "  -> $HOOKS_DIR/${hook}.js"
done

echo "[3/7] Installing config files..."
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
  "sandboxMode": "standard",
  "blockedDirs": [],
  "blockedFiles": [],
  "blockedAbsolute": [],
  "allowedPaths": [],
  "writablePaths": ["/tmp"]
}
EOF
  echo "  -> $FILE_POLICY"
fi

echo "[4/7] Configuring settings.json..."
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
    echo "  Found existing $SETTINGS without hardening hooks."
    echo ""
    read -rp "  Merge hardening hooks into existing settings.json? [y/N] " merge_answer
    if [[ "$merge_answer" =~ ^[Yy]$ ]]; then
      # Back up before touching anything
      backup="${SETTINGS}.backup.$(date +%Y%m%d%H%M%S)"
      cp "$SETTINGS" "$backup"
      echo "  -> Backed up to $backup"

      # Merge using node — deduplicates by hook id, preserves everything else
      # Paths passed via process.argv to avoid shell interpolation issues
      EXAMPLE=$(sed "s|CLAUDE_DIR|${CLAUDE_DIR}|g" "$SCRIPT_DIR/settings.example.json")
      node -e "
        const fs = require('fs');
        const settingsPath = process.argv[1];
        const existing = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
        const incoming = JSON.parse(process.argv[2]);

        if (!existing.hooks) existing.hooks = {};
        if (!existing.hooks.PreToolUse) existing.hooks.PreToolUse = [];
        if (!existing.hooks.PostToolUse) existing.hooks.PostToolUse = [];

        const existingIds = new Set([
          ...existing.hooks.PreToolUse.map(h => h.id).filter(Boolean),
          ...existing.hooks.PostToolUse.map(h => h.id).filter(Boolean),
        ]);

        let added = 0;
        for (const hook of (incoming.hooks.PreToolUse || [])) {
          if (!existingIds.has(hook.id)) {
            existing.hooks.PreToolUse.push(hook);
            existingIds.add(hook.id);
            added++;
          }
        }
        for (const hook of (incoming.hooks.PostToolUse || [])) {
          if (!existingIds.has(hook.id)) {
            existing.hooks.PostToolUse.push(hook);
            existingIds.add(hook.id);
            added++;
          }
        }

        fs.writeFileSync(settingsPath, JSON.stringify(existing, null, 2) + '\n');
        console.log('  -> Merged ' + added + ' hook(s) into ' + settingsPath);
      " "$SETTINGS" "$EXAMPLE"
    else
      echo ""
      echo "  Skipped. To add hooks manually, see settings.example.json or profiles/."
      echo "  You can re-run the installer later to merge."
    fi
  fi
fi

echo "[5/7] CLAUDE.md template..."
# Offer to copy the behavioral template — never overwrite an existing CLAUDE.md
if [ -n "${PROJECT_DIR:-}" ] && [ -d "$PROJECT_DIR" ]; then
  target="$PROJECT_DIR/CLAUDE.md"
elif git rev-parse --show-toplevel &>/dev/null; then
  target="$(git rev-parse --show-toplevel)/CLAUDE.md"
else
  target=""
fi

if [ -n "$target" ]; then
  if [ -f "$target" ]; then
    echo "  -> $target already exists — skipping (won't overwrite)"
  else
    read -rp "  Copy hardening CLAUDE.md template to $target? [y/N] " claude_answer
    if [[ "$claude_answer" =~ ^[Yy]$ ]]; then
      cp "$SCRIPT_DIR/templates/CLAUDE.md" "$target"
      echo "  -> Copied to $target"
    else
      echo "  -> Skipped. Template available at templates/CLAUDE.md"
    fi
  fi
else
  echo "  -> No project directory detected. Template available at templates/CLAUDE.md"
  echo "     Copy it manually: cp templates/CLAUDE.md /path/to/your/project/CLAUDE.md"
fi

echo "[6/7] Verifying hook scripts..."
all_ok=true
for hook in sandbox-exec deny-destructive network-egress git-guard file-access secret-scan audit-log; do
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

echo "[7/7] Sandbox status..."
if [ "$BWRAP_AVAILABLE" = true ]; then
  echo "  -> bwrap sandbox: ACTIVE"
  echo "  -> Sandbox mode: standard (configure in $FILE_POLICY)"
  echo "  -> Change to strict mode for read-only filesystem protection"
else
  echo "  -> bwrap sandbox: INACTIVE (install bubblewrap to enable)"
  echo "  -> Regex-based file-access protection is still active"
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
