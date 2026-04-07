#!/usr/bin/env node
/**
 * File Access Hook (PreToolUse:Read,Write,Edit,Glob)
 *
 * Blocks access to sensitive files and directories that an AI agent
 * should not read or write — credentials, SSH keys, env files, etc.
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
  // Credential filenames
  /credentials/i,
  /secret/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.jks$/i,
  // Common token files
  /token/i,
  /apikey/i,
  /api[_-]key/i,
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
    // For Glob, check the pattern and path for suspicious targets
    filePath = toolInput.path || toolInput.pattern || '';
  }

  if (!filePath) {
    process.stdout.write(data);
    process.exit(0);
  }

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

  // Resolve to absolute path for matching
  const resolved = path.resolve(filePath);
  const basename = path.basename(resolved);
  const home = os.homedir();

  // Check explicit allow list first (escape hatch for intentional access)
  for (const allowed of allowedPaths) {
    const resolvedAllowed = path.resolve(allowed.replace(/^~/, home));
    if (resolved === resolvedAllowed || resolved.startsWith(resolvedAllowed + path.sep)) {
      process.stdout.write(data);
      process.exit(0);
    }
  }

  // Check absolute blocked paths
  const blockedAbsolute = [...DEFAULT_BLOCKED_ABSOLUTE, ...(policy.blockedAbsolute || [])];
  for (const blocked of blockedAbsolute) {
    if (resolved === blocked) {
      block(filePath, `${basename} is a protected system file`);
    }
  }

  // Check blocked directory prefixes (relative to home or absolute)
  const allBlockedDirs = [...DEFAULT_BLOCKED_DIRS, ...extraBlockedDirs];
  for (const dir of allBlockedDirs) {
    const absDir = dir.startsWith('/') ? dir : path.join(home, dir);
    if (resolved.startsWith(absDir + path.sep) || resolved === absDir) {
      block(filePath, `path is inside protected directory: ~/${dir}`);
    }
  }

  // Check filename patterns
  const allBlockedFiles = [...DEFAULT_BLOCKED_FILES, ...extraBlockedFiles.map(p => new RegExp(p, 'i'))];
  for (const pattern of allBlockedFiles) {
    if (pattern.test(basename)) {
      block(filePath, `filename matches sensitive pattern: ${pattern}`);
    }
  }

  // Path is safe
  process.stdout.write(data);
  process.exit(0);
});

function block(filePath, reason) {
  process.stderr.write(
    '[file-access] BLOCKED: ' + reason + '\n' +
    'Path: ' + filePath + '\n' +
    'If this is intentional, add the path to ~/.claude/file-access-policy.json allowedPaths.\n'
  );
  process.exit(2);
}

process.stdin.on('error', () => {
  process.exit(0);
});
