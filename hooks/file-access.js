#!/usr/bin/env node
/**
 * File Access Hook (PreToolUse:Read,Write,Edit,Glob,Bash)
 *
 * Blocks access to sensitive files and directories that an AI agent
 * should not read or write — credentials, SSH keys, env files, etc.
 *
 * For Read/Write/Edit/Glob tools, inspects the file_path parameter.
 * For Bash tool, extracts path arguments from common file commands
 * (cat, head, tail, less, more, cp, mv, vim, nano, etc.) as a
 * regex-based fallback when bwrap sandboxing is not available.
 *
 * Policy: ~/.claude/file-access-policy.json
 * Falls back to built-in defaults when the policy file is missing.
 *
 * Exit codes:
 *   0  — path is safe, pass through
 *   2  — path is blocked (message on stderr shown to the agent)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const POLICY_PATH = process.env.CLAUDE_HARDENING_POLICY
  || path.join(os.homedir(), '.claude', 'file-access-policy.json');

// Built-in sensitive path patterns (always applied unless overridden)
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

const DEFAULT_BLOCKED_FILES = [
  // Env files
  /^\.env(\.|$)/,
  // Credential filenames — restricted to config/data extensions to avoid
  // false positives on source files (e.g. tokens.css, secrets.ts, apikeys.py)
  /^\.?(credentials|creds)(\.(json|ya?ml|env|txt|cfg|conf|ini|toml|xml))?$/i,
  /^\.?(secrets?)(\.(json|ya?ml|env|txt|cfg|conf|ini|toml|xml))?$/i,
  /^\.?(tokens?|auth[_-]tokens?)(\.(json|ya?ml|env|txt|cfg|conf|ini|toml|xml))?$/i,
  /^\.?(api[_-]?keys?)(\.(json|ya?ml|env|txt|cfg|conf|ini|toml|xml))?$/i,
  // Certificate and key files
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.jks$/i,
  // Auth config files
  /^\.netrc$/,
  /^\.git-credentials$/,
  /^\.npmrc$/,
  /^\.pypirc$/,
  // System sensitive files
  /^passwd$/,
  /^shadow$/,
  /^sudoers$/,
];

const DEFAULT_BLOCKED_ABSOLUTE = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/sudoers',
  '/etc/master.passwd',
];

// Shell commands that take file path arguments. Captures the argument after
// the command name and optional flags (tokens starting with -).
const FILE_COMMANDS = [
  'cat', 'head', 'tail', 'less', 'more', 'tac', 'nl',
  'cp', 'mv', 'ln',
  'vim', 'vi', 'nano', 'emacs',
  'source', '\\.',
  'chmod', 'chown', 'chgrp',
  'stat', 'file', 'wc',
  'diff', 'cmp',
  'tar', 'zip', 'unzip', 'gzip', 'gunzip',
  'base64',
  'openssl',
  'gpg',
];

const FILE_CMD_PATTERN = new RegExp(
  '\\b(' + FILE_COMMANDS.join('|') + ')\\s+' +
  '(?:-[a-zA-Z0-9]+\\s+)*' +   // skip flags
  '([~/.][^\\s;|&><]+)',        // capture path-like argument
  'g'
);

function extractPathsFromBash(cmd) {
  const paths = [];
  let match;
  // Reset lastIndex for global regex
  FILE_CMD_PATTERN.lastIndex = 0;
  while ((match = FILE_CMD_PATTERN.exec(cmd)) !== null) {
    const p = match[2].replace(/^~/, os.homedir());
    paths.push(p);
  }
  // Also catch redirection targets: > /path, >> /path, < /path
  const redirectPattern = /[<>]+\s*([~/.][^\s;|&><]+)/g;
  while ((match = redirectPattern.exec(cmd)) !== null) {
    const p = match[1].replace(/^~/, os.homedir());
    paths.push(p);
  }
  return paths;
}

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

  // Extract the file path from whichever tool is being used
  const toolName = input.tool_name || '';
  const toolInput = input.tool_input || {};

  let filePath = '';
  if (toolName === 'Read' || toolName === 'Write') {
    filePath = toolInput.file_path || '';
  } else if (toolName === 'Edit') {
    filePath = toolInput.file_path || '';
  } else if (toolName === 'Glob') {
    filePath = toolInput.path || toolInput.pattern || '';
  } else if (toolName === 'Bash') {
    // Extract file paths from common shell commands as a regex fallback.
    // This is best-effort — the sandbox-exec.js hook provides comprehensive
    // protection via bwrap when available.
    const cmd = (toolInput.command || '').trim();
    if (cmd) {
      const pathsFromBash = extractPathsFromBash(cmd);
      for (const p of pathsFromBash) {
        const result = checkPath(p, input);
        if (result === 'blocked') process.exit(2);
      }
    }
    // If we get here, all extracted paths are safe (or no paths found)
    process.stdout.write(data);
    process.exit(0);
  }

  if (!filePath) {
    process.stdout.write(data);
    process.exit(0);
  }

  // Check the file path
  const result = checkPath(filePath, input);
  if (result === 'blocked') process.exit(2);

  // Path is safe
  process.stdout.write(data);
  process.exit(0);
});

// ── Path checking logic (shared by tool-path and bash-path branches) ──

// Resolve symlinks; for non-existent files, resolve the parent and reattach.
// The parent fallback matters for Write tool calls creating new files under
// symlinked credential dirs (e.g. writing into ~/.azure/ when that's a
// symlink to /mnt/c/.../.azure/ on WSL2).
function realPathOrParent(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    try {
      return path.join(fs.realpathSync(path.dirname(p)), path.basename(p));
    } catch {
      return p;
    }
  }
}

function isUnderOrEqual(candidate, target) {
  return candidate === target || candidate.startsWith(target + path.sep);
}

function checkPath(filePath) {
  // Load policy overrides if present
  let policy = {};
  try {
    policy = JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
  } catch {
    // Use defaults only
  }

  const extraBlockedDirs = Array.isArray(policy.blockedDirs) ? policy.blockedDirs : [];
  const extraBlockedFiles = Array.isArray(policy.blockedFiles) ? policy.blockedFiles : [];
  const allowedPaths = Array.isArray(policy.allowedPaths) ? policy.allowedPaths : [];

  const resolved = path.resolve(filePath);
  const realResolved = realPathOrParent(resolved);
  const basename = path.basename(resolved);
  const home = os.homedir();

  // Check explicit allow list first (escape hatch for intentional access).
  // Matches against both literal and realpath'd forms so allow-by-symlink works.
  for (const allowed of allowedPaths) {
    const absAllowed = path.resolve(allowed.replace(/^~/, home));
    const realAllowed = realPathOrParent(absAllowed);
    if (isUnderOrEqual(resolved, absAllowed) || isUnderOrEqual(realResolved, realAllowed)) {
      return 'allowed';
    }
  }

  // Check absolute blocked paths (both literal and realpath'd input)
  const blockedAbsolute = [...DEFAULT_BLOCKED_ABSOLUTE, ...(policy.blockedAbsolute || [])];
  for (const blocked of blockedAbsolute) {
    const realBlocked = realPathOrParent(blocked);
    if (resolved === blocked || realResolved === blocked || realResolved === realBlocked) {
      block(filePath, `${basename} is a protected system file`);
      return 'blocked';
    }
  }

  // Check blocked directory prefixes. Resolve BOTH the input path and each
  // blocklist dir to real targets, so symlinked credential dirs (common on
  // WSL2 where ~/.azure → /mnt/c/.../.azure) are caught whether the agent
  // supplies the symlink path or the Windows-side target path.
  const allBlockedDirs = [...DEFAULT_BLOCKED_DIRS, ...extraBlockedDirs];
  const effectiveBlocked = [];
  for (const dir of allBlockedDirs) {
    const absDir = dir.startsWith('/') ? dir : path.join(home, dir);
    const realDir = realPathOrParent(absDir);
    effectiveBlocked.push({ label: dir, abs: absDir, real: realDir });
  }

  // WSL2 inference: any blocked dir whose realpath sits under
  // /mnt/<drive>/Users/<user>/ reveals the Windows-side base for this WSL2
  // host. Auto-derive the same DEFAULT_BLOCKED_DIRS under that base so that
  // tools installed on Windows only (no WSL symlink) are still protected.
  const wslBases = new Set();
  for (const { real } of effectiveBlocked) {
    const m = real.match(/^(\/mnt\/[a-z]\/Users\/[^/]+)(\/|$)/i);
    if (m) wslBases.add(m[1]);
  }
  for (const base of wslBases) {
    for (const dir of DEFAULT_BLOCKED_DIRS) {
      const derived = path.join(base, dir);
      if (!effectiveBlocked.some(e => e.abs === derived || e.real === derived)) {
        effectiveBlocked.push({ label: `${dir} (WSL2-derived)`, abs: derived, real: derived });
      }
    }
  }

  for (const { label, abs, real } of effectiveBlocked) {
    if (isUnderOrEqual(resolved, abs) || isUnderOrEqual(realResolved, real)) {
      block(filePath, `path is inside protected directory: ${label}`);
      return 'blocked';
    }
  }

  // Check filename patterns (basename-only; symlinks don't change the basename)
  const allBlockedFiles = [...DEFAULT_BLOCKED_FILES, ...extraBlockedFiles.map(p => new RegExp(p, 'i'))];
  for (const pattern of allBlockedFiles) {
    if (pattern.test(basename)) {
      block(filePath, `filename matches sensitive pattern: ${pattern}`);
      return 'blocked';
    }
  }

  return 'allowed';
}

function block(filePath, reason) {
  process.stderr.write(
    '[file-access] BLOCKED: ' + reason + '\n' +
    'Path: ' + filePath + '\n' +
    'If this is intentional, add the path to ~/.claude/file-access-policy.json allowedPaths.\n'
  );
}

process.stdin.on('error', () => {
  process.exit(0);
});
