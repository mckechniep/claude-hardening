#!/usr/bin/env node
/**
 * Network Egress Hook (PreToolUse:Bash)
 *
 * Blocks outbound network requests to domains not on the allowlist.
 * Prevents data exfiltration via curl/wget/nc/ssh when an AI agent
 * has shell access.
 *
 * Allowlist: ~/.claude/network-allowlist.json
 *
 * Exit codes:
 *   0  — command has no network calls, or all targets are allowed
 *   2  — command targets an unknown domain (blocked)
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ALLOWLIST_PATH = path.join(require('os').homedir(), '.claude', 'network-allowlist.json');

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

  // Load allowlist
  let config;
  try {
    config = JSON.parse(fs.readFileSync(ALLOWLIST_PATH, 'utf8'));
  } catch {
    // No allowlist file — pass through rather than breaking all network commands
    process.stdout.write(data);
    process.exit(0);
  }

  const allowedDomains = Array.isArray(config.allowedDomains) ? config.allowedDomains : [];
  const allowLocalhost = config.allowLocalhost !== false;
  const warnOnVariableUrls = config.warnOnVariableUrls !== false;

  // Build domain set with wildcard subdomain support
  const domainSet = new Set(allowedDomains.map(d => d.toLowerCase()));

  function isDomainAllowed(domain) {
    const d = domain.toLowerCase();
    if (domainSet.has(d)) return true;
    for (const allowed of domainSet) {
      if (d.endsWith('.' + allowed)) return true;
    }
    return false;
  }

  function isLocalhost(host) {
    return /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])$/.test(host);
  }

  // ── Detect network tools ────────────────────────────────────────────

  const networkTools = [
    { pattern: /\b(curl|wget)\s/, name: 'curl/wget' },
    { pattern: /\b(nc|ncat|netcat)\s/, name: 'netcat' },
    { pattern: /\b(ssh|scp|rsync)\s/, name: 'ssh/scp/rsync' },
  ];

  let hasNetworkTool = false;
  let toolName = '';
  for (const tool of networkTools) {
    if (tool.pattern.test(cmd)) {
      hasNetworkTool = true;
      toolName = tool.name;
      break;
    }
  }

  if (!hasNetworkTool) {
    process.stdout.write(data);
    process.exit(0);
  }

  // ── Check for variable/dynamic URLs ─────────────────────────────────
  // Shell variables in URLs cannot be resolved at hook time — block by default

  const variableUrlPattern = /https?:\/\/[^\s'"]*\$[{(a-zA-Z_]/;
  if (warnOnVariableUrls && variableUrlPattern.test(cmd)) {
    process.stderr.write(
      '[network-egress] BLOCKED: ' + toolName + ' with dynamic/variable URL\n' +
      'Command: ' + cmd.substring(0, 200) + '\n' +
      'Cannot verify destination domain. Run it yourself:\n' +
      '  ! ' + cmd.substring(0, 300) + '\n'
    );
    process.exit(2);
  }

  // ── Extract URLs and check domains ──────────────────────────────────

  const urlPattern = /https?:\/\/([^/:@\s'"]+)/g;
  const hostArgPattern = /(?:@|(?:nc|ncat|netcat|ssh|scp|rsync)\s+(?:-[^\s]*\s+)*)([a-zA-Z0-9][-a-zA-Z0-9.]+)/g;

  const domains = new Set();

  let match;
  while ((match = urlPattern.exec(cmd)) !== null) {
    domains.add(match[1]);
  }

  if (/\b(nc|ncat|netcat|ssh|scp|rsync)\b/.test(cmd)) {
    while ((match = hostArgPattern.exec(cmd)) !== null) {
      const host = match[1];
      if (!host.startsWith('-') && host.includes('.')) {
        domains.add(host);
      }
    }
  }

  if (domains.size === 0) {
    if (/\b(nc|ncat|netcat)\b/.test(cmd)) {
      process.stderr.write(
        '[network-egress] BLOCKED: ' + toolName + ' with no identifiable target\n' +
        'Command: ' + cmd.substring(0, 200) + '\n' +
        'Raw socket tools require an identifiable destination. Run it yourself:\n' +
        '  ! ' + cmd.substring(0, 300) + '\n'
      );
      process.exit(2);
    }
    // curl/wget with no URL is probably --help or similar
    process.stdout.write(data);
    process.exit(0);
  }

  // Check each domain against allowlist
  const blocked = [];
  for (const domain of domains) {
    if (allowLocalhost && isLocalhost(domain)) continue;
    if (isDomainAllowed(domain)) continue;
    blocked.push(domain);
  }

  if (blocked.length > 0) {
    const plural = blocked.length > 1 ? 's' : '';
    process.stderr.write(
      '[network-egress] BLOCKED: ' + toolName + ' to unknown domain' + plural + ': ' + blocked.join(', ') + '\n' +
      'Command: ' + cmd.substring(0, 200) + '\n' +
      'Add to ~/.claude/network-allowlist.json if trusted, or run it yourself:\n' +
      '  ! ' + cmd.substring(0, 300) + '\n'
    );
    process.exit(2);
  }

  // All domains allowed
  process.stdout.write(data);
  process.exit(0);
});

process.stdin.on('error', () => {
  process.exit(0);
});
