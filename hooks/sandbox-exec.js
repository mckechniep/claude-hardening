#!/usr/bin/env node
/**
 * Sandbox Execution Hook (PreToolUse:Bash)
 *
 * Rewrites Bash commands to run inside a bubblewrap (bwrap) sandbox,
 * providing OS-level filesystem protection that cannot be bypassed by
 * shell indirection, variable expansion, encoding, or aliasing.
 *
 * Two modes controlled by sandboxMode in ~/.claude/file-access-policy.json:
 *
 *   "standard" (default)
 *     - Filesystem is read-write
 *     - Blocked dirs (e.g. ~/.ssh, ~/.aws) are replaced with empty tmpfs
 *     - Protects credentials from reads and writes
 *     - Normal commands work without restriction
 *
 *   "strict"
 *     - Filesystem is read-only by default
 *     - Only writablePaths (+ $PWD) are writable
 *     - Blocked dirs still hidden via tmpfs
 *     - Destructive commands (rm, dd, etc.) can only affect writable paths
 *
 * Falls back to pass-through when bwrap is not available, letting the
 * regex-based file-access.js hook provide best-effort protection.
 *
 * Policy: ~/.claude/file-access-policy.json
 *
 * Exit codes:
 *   0  — always (this hook rewrites, never blocks)
 */

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const POLICY_PATH = process.env.CLAUDE_HARDENING_POLICY
  || path.join(os.homedir(), '.claude', 'file-access-policy.json');
const HOME = os.homedir();

// Directories blocked in all modes (tmpfs overlay — appears empty)
const DEFAULT_BLOCKED_DIRS = [
  '.ssh',
  '.gnupg',
  '.aws',
  '.azure',
  '.gcloud',
  '.kube',
  '.config/gcloud',
  '.docker',
];

// System files blocked in all modes (bind /dev/null — permission denied)
const DEFAULT_BLOCKED_FILES = [
  '/etc/shadow',
  '/etc/sudoers',
  '/etc/master.passwd',
];

// Default writable paths for strict mode (in addition to $PWD which is always writable)
const DEFAULT_WRITABLE_PATHS = [
  '/tmp',
  path.join(HOME, '.cache'),
  path.join(HOME, '.npm'),
  path.join(HOME, '.local'),
  path.join(HOME, '.yarn'),
  path.join(HOME, '.pnpm-store'),
  path.join(HOME, 'go', 'pkg'),
  path.join(HOME, '.cargo', 'registry'),
];

// ── bwrap detection ─────────────────────────────────────────────────
// Cached at module load so we only check once per session.

let bwrapAvailable = null;
let bwrapPath = null;

function checkBwrap() {
  if (bwrapAvailable !== null) return bwrapAvailable;
  try {
    const result = spawnSync('which', ['bwrap'], {
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    });
    if (result.status === 0) {
      bwrapPath = result.stdout.toString().trim();
      // Verify it actually works (some containers have it but disable namespaces)
      const test = spawnSync(bwrapPath, [
        '--bind', '/', '/',
        '--dev', '/dev',
        '--proc', '/proc',
        '--', 'true',
      ], { stdio: 'ignore', timeout: 5000 });
      bwrapAvailable = test.status === 0;
    } else {
      bwrapAvailable = false;
    }
  } catch {
    bwrapAvailable = false;
  }
  return bwrapAvailable;
}

// ── Policy loading ──────────────────────────────────────────────────

function loadPolicy() {
  try {
    return JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function resolveBlockedDirs(policy) {
  const extra = Array.isArray(policy.blockedDirs) ? policy.blockedDirs : [];
  const all = [...DEFAULT_BLOCKED_DIRS, ...extra];
  return all.map(d => d.startsWith('/') ? d : path.join(HOME, d));
}

function resolveBlockedFiles(policy) {
  const extra = Array.isArray(policy.blockedAbsolute) ? policy.blockedAbsolute : [];
  return [...DEFAULT_BLOCKED_FILES, ...extra];
}

function resolveWritablePaths(policy) {
  const configured = Array.isArray(policy.writablePaths) ? policy.writablePaths : [];
  const resolved = configured.map(p => p.replace(/^\$HOME\b/, HOME).replace(/^~/, HOME));
  // Merge with defaults, deduplicate
  const all = [...DEFAULT_WRITABLE_PATHS, ...resolved];
  return [...new Set(all)];
}

// ── Sandbox command builder ─────────────────────────────────────────

function buildSandboxCommandSafe(originalCmd, policy) {
  const mode = policy.sandboxMode || 'standard';
  const blockedDirs = resolveBlockedDirs(policy);
  const blockedFiles = resolveBlockedFiles(policy);
  const cwd = process.cwd();

  const parts = [shellQuote(bwrapPath)];

  if (mode === 'strict') {
    parts.push('--ro-bind', '/', '/');

    const writable = resolveWritablePaths(policy);
    writable.push(cwd);

    for (const wp of writable) {
      try {
        fs.statSync(wp);
        parts.push('--bind', shellQuote(wp), shellQuote(wp));
      } catch {
        // skip
      }
    }
  } else {
    parts.push('--bind', '/', '/');
  }

  parts.push('--dev', '/dev');
  parts.push('--proc', '/proc');

  // Resolve symlinks to real targets and dedup before emitting mount args.
  // Critical on WSL2 where credential dirs are often symlinked to /mnt/c/...
  // (Azure CLI, gcloud, kubectl config shared with the Windows side). A tmpfs
  // on the symlink path is a no-op once the kernel follows the link.
  const tmpfsTargets = new Set();
  const wslBases = new Set();
  for (const dir of blockedDirs) {
    try {
      const realDir = fs.realpathSync(dir);
      if (fs.statSync(realDir).isDirectory()) {
        tmpfsTargets.add(realDir);
        const m = realDir.match(/^(\/mnt\/[a-z]\/Users\/[^/]+)(\/|$)/i);
        if (m) wslBases.add(m[1]);
      }
    } catch {
      // broken symlink or missing — skip
    }
  }

  // WSL2 inference: for each Windows user base discovered above, also tmpfs
  // any DEFAULT_BLOCKED_DIRS that exist on the Windows side. bwrap requires
  // the path to exist, so non-existent derived paths are silently skipped.
  for (const base of wslBases) {
    for (const dir of DEFAULT_BLOCKED_DIRS) {
      const derived = path.join(base, dir);
      try {
        if (fs.statSync(derived).isDirectory()) {
          tmpfsTargets.add(derived);
        }
      } catch {
        // not present on Windows side either — no need to mount
      }
    }
  }

  for (const realDir of tmpfsTargets) {
    parts.push('--tmpfs', shellQuote(realDir));
  }

  const roBindTargets = new Set();
  for (const file of blockedFiles) {
    try {
      roBindTargets.add(fs.realpathSync(file));
    } catch {
      // skip
    }
  }
  for (const realFile of roBindTargets) {
    parts.push('--ro-bind', '/dev/null', shellQuote(realFile));
  }

  const allowedPaths = Array.isArray(policy.allowedPaths) ? policy.allowedPaths : [];
  const allowedDirs = new Set();
  const allowedFiles = new Set();
  for (const allowed of allowedPaths) {
    const expanded = allowed.replace(/^~/, HOME);
    try {
      const realPath = fs.realpathSync(expanded);
      if (fs.statSync(realPath).isDirectory()) {
        allowedDirs.add(realPath);
      } else {
        allowedFiles.add(realPath);
      }
    } catch {
      // skip
    }
  }
  for (const d of allowedDirs) {
    parts.push('--bind', shellQuote(d), shellQuote(d));
  }
  for (const f of allowedFiles) {
    parts.push('--ro-bind', shellQuote(f), shellQuote(f));
  }

  parts.push('--', 'sh', '-c', shellQuote(originalCmd));

  return parts.join(' ');
}

function shellQuote(s) {
  if (/^[a-zA-Z0-9_./:=@-]+$/.test(s)) return s;
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

// ── Main ────────────────────────────────────────────────────────────

const MAX_STDIN = 1024 * 1024;
let data = '';
process.stdin.setEncoding('utf8');

process.stdin.on('data', chunk => {
  if (data.length < MAX_STDIN) {
    const remaining = MAX_STDIN - data.length;
    data += chunk.substring(0, remaining);
  }
});

process.stdin.on('end', () => {
  let input;
  try {
    input = JSON.parse(data);
  } catch {
    process.stdout.write(data);
    process.exit(0);
  }

  const cmd = (input.tool_input?.command || '').trim();
  if (!cmd) {
    process.stdout.write(data);
    process.exit(0);
  }

  // Check bwrap availability
  if (!checkBwrap()) {
    // No bwrap — pass through, let regex-based hooks handle it
    process.stderr.write(
      '[sandbox-exec] NOTICE: bwrap not available — falling back to regex-based protection.\n' +
      'Install bubblewrap for OS-level sandboxing: sudo apt install bubblewrap\n'
    );
    process.stdout.write(data);
    process.exit(0);
  }

  const policy = loadPolicy();
  const sandboxed = buildSandboxCommandSafe(cmd, policy);

  // Rewrite the command
  input.tool_input.command = sandboxed;
  process.stdout.write(JSON.stringify(input));
  process.exit(0);
});

process.stdin.on('error', () => {
  process.exit(0);
});
