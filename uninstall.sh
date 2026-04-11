#!/bin/bash
set -euo pipefail

# Claude Code Hardening Kit — Uninstaller
# Removes all hooks, configs, and restores settings.json from backup.

CLAUDE_DIR="${HOME}/.claude"
HOOKS_DIR="${CLAUDE_DIR}/scripts/hooks"
SETTINGS="${CLAUDE_DIR}/settings.json"
ALLOWLIST="${CLAUDE_DIR}/network-allowlist.json"
FILE_POLICY="${CLAUDE_DIR}/file-access-policy.json"
AUDIT_LOG="${CLAUDE_DIR}/audit.log"

HOOK_FILES=(
  sandbox-exec.js
  deny-destructive.js
  network-egress.js
  git-guard.js
  file-access.js
  secret-scan.js
  audit-log.js
)

# Hook IDs installed by claude-hardening (used to surgically remove from settings.json)
HOOK_IDS=(
  "pre:bash:sandbox-exec"
  "pre:bash:deny-destructive"
  "pre:bash:network-egress"
  "pre:bash:git-guard"
  "pre:file:file-access"
  "pre:file:secret-scan"
  "post:all:audit-log"
)

# Surgically remove hardening hook entries from settings.json by ID,
# preserving all other hooks and settings the user has.
remove_hooks_from_settings() {
  if [ ! -f "$SETTINGS" ]; then return; fi

  node -e "
    const fs = require('fs');
    const settingsPath = process.argv[1];
    const idsToRemove = new Set(process.argv.slice(2));

    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    if (!settings.hooks) { process.exit(0); }

    let removed = 0;
    for (const phase of ['PreToolUse', 'PostToolUse', 'Stop']) {
      if (!Array.isArray(settings.hooks[phase])) continue;
      const before = settings.hooks[phase].length;
      settings.hooks[phase] = settings.hooks[phase].filter(h => !idsToRemove.has(h.id));
      removed += before - settings.hooks[phase].length;
      // Clean up empty arrays
      if (settings.hooks[phase].length === 0) delete settings.hooks[phase];
    }
    // Clean up empty hooks object
    if (Object.keys(settings.hooks).length === 0) delete settings.hooks;

    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
    console.log('  -> Removed ' + removed + ' hook(s) from ' + settingsPath);
  " "$SETTINGS" "${HOOK_IDS[@]}"
}

echo "Claude Code Hardening Kit — Uninstaller"
echo "========================================"
echo ""

# ── Step 1: Remove hook scripts ──────────────────────────────────────

echo "[1/4] Removing hook scripts..."
removed=0
for hook in "${HOOK_FILES[@]}"; do
  if [ -f "$HOOKS_DIR/$hook" ]; then
    rm "$HOOKS_DIR/$hook"
    echo "  -> Removed $HOOKS_DIR/$hook"
    ((removed++))
  fi
done
if [ "$removed" -eq 0 ]; then
  echo "  -> No hook scripts found — already removed or never installed"
fi

# Clean up hooks dir if empty
if [ -d "$HOOKS_DIR" ] && [ -z "$(ls -A "$HOOKS_DIR" 2>/dev/null)" ]; then
  rmdir "$HOOKS_DIR" 2>/dev/null && echo "  -> Removed empty $HOOKS_DIR/"
fi

# ── Step 2: Restore or clean settings.json ───────────────────────────

echo "[2/4] Restoring settings.json..."

# Look for the most recent backup created by install.sh
latest_backup=""
if compgen -G "${SETTINGS}.backup.*" > /dev/null 2>&1; then
  latest_backup=$(ls -t "${SETTINGS}".backup.* 2>/dev/null | head -1)
fi

if [ -n "$latest_backup" ]; then
  echo ""
  echo "  Found backup from install: $latest_backup"
  echo ""
  read -rp "  Restore settings.json from this backup? [Y/n] " restore_answer
  if [[ ! "$restore_answer" =~ ^[Nn]$ ]]; then
    cp "$SETTINGS" "${SETTINGS}.pre-uninstall.$(date +%Y%m%d%H%M%S)"
    cp "$latest_backup" "$SETTINGS"
    echo "  -> Restored from backup"
    echo "  -> Current settings saved to ${SETTINGS}.pre-uninstall.* (just in case)"
  else
    echo "  -> Skipped restore. Removing hooks from current settings.json instead."
    remove_hooks_from_settings
  fi
else
  # No backup found — surgically remove hook entries by ID
  if [ -f "$SETTINGS" ] && grep -q "deny-destructive\|sandbox-exec\|network-egress\|git-guard\|file-access\|secret-scan\|audit-log" "$SETTINGS" 2>/dev/null; then
    echo "  -> No backup found. Removing hardening hooks from settings.json..."
    remove_hooks_from_settings
  else
    echo "  -> No hardening hooks found in settings.json — nothing to remove"
  fi
fi

# ── Step 3: Remove config files ──────────────────────────────────────

echo "[3/4] Config files..."

for cfg_file in "$ALLOWLIST" "$FILE_POLICY"; do
  if [ -f "$cfg_file" ]; then
    echo ""
    read -rp "  Remove $cfg_file? [y/N] " cfg_answer
    if [[ "$cfg_answer" =~ ^[Yy]$ ]]; then
      rm "$cfg_file"
      echo "  -> Removed"
    else
      echo "  -> Kept"
    fi
  fi
done

# ── Step 4: Audit log ────────────────────────────────────────────────

echo "[4/4] Audit log..."

audit_found=false
for f in "$AUDIT_LOG" "${AUDIT_LOG}.1"; do
  if [ -f "$f" ]; then
    audit_found=true
  fi
done

if [ "$audit_found" = true ]; then
  echo ""
  read -rp "  Remove audit log(s)? [y/N] " audit_answer
  if [[ "$audit_answer" =~ ^[Yy]$ ]]; then
    rm -f "$AUDIT_LOG" "${AUDIT_LOG}.1"
    echo "  -> Removed"
  else
    echo "  -> Kept (at $AUDIT_LOG)"
  fi
else
  echo "  -> No audit log found"
fi

# ── Clean up backups ─────────────────────────────────────────────────

if compgen -G "${SETTINGS}.backup.*" > /dev/null 2>&1; then
  echo ""
  read -rp "  Remove install backup files (${SETTINGS}.backup.*)? [y/N] " backup_answer
  if [[ "$backup_answer" =~ ^[Yy]$ ]]; then
    rm -f "${SETTINGS}".backup.*
    echo "  -> Removed"
  else
    echo "  -> Kept"
  fi
fi

echo ""
echo "Done. Claude Code hardening has been removed."
echo ""
echo "If you kept config files, you can re-install later by running:"
echo "  ./install.sh"
