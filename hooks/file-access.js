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

const POLICY_PATH = path.join(os.homedir(), '.claude', 'file-access-policy.json');

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
  // Credential filenames (anchored to avoid matching source files like TokenService.ts)
  /^\.?(credentials|creds)(\..+)?$/i,
  /^\.?(secrets?)(\..+)?$/i,
  /^\.?(tokens?|auth[_-]tokens?)(\..+)?$/i,
  /^\.?(api[_-]?keys?)(\..+)?$/i,
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
  const basename = path.basename(resolved);
  const home = os.homedir();

  // Check explicit allow list first (escape hatch for intentional access)
  for (const allowed of allowedPaths) {
    const resolvedAllowed = path.resolve(allowed.replace(/^~/, home));
    if (resolved === resolvedAllowed || resolved.startsWith(resolvedAllowed + path.sep)) {
      return 'allowed';
    }
  }

  // Check absolute blocked paths
  const blockedAbsolute = [...DEFAULT_BLOCKED_ABSOLUTE, ...(policy.blockedAbsolute || [])];
  for (const blocked of blockedAbsolute) {
    if (resolved === blocked) {
      block(filePath, `${basename} is a protected system file`);
      return 'blocked';
    }
  }

  // Check blocked directory prefixes (relative to home or absolute)
  const allBlockedDirs = [...DEFAULT_BLOCKED_DIRS, ...extraBlockedDirs];
  for (const dir of allBlockedDirs) {
    const absDir = dir.startsWith('/') ? dir : path.join(home, dir);
    if (resolved.startsWith(absDir + path.sep) || resolved === absDir) {
      block(filePath, `path is inside protected directory: ~/${dir}`);
      return 'blocked';
    }
  }

  // Check filename patterns
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
