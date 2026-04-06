#!/usr/bin/env node
/**
 * Deny Destructive Commands Hook (PreToolUse:Bash)
 *
 * Two-tier protection for AI agent shell access:
 *   HARD BLOCK — commands that are never safe for autonomous execution
 *   WARN+STOP  — commands that are legitimate but require human intent
 *
 * Exit codes:
 *   0  — command is safe, pass through
 *   2  — command is blocked (message on stderr shown to the agent)
 */

'use strict';

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

  const normalized = cmd.replace(/\s+/g, ' ');

  // ── TIER 1: HARD BLOCK ──────────────────────────────────────────────
  // These are never legitimate when run by an AI agent autonomously.

  const hardBlock = [
    { pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\b.*--force|-[a-zA-Z]*f[a-zA-Z]*r)\s+[/~]/, desc: 'recursive force-delete at root or home' },
    { pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\b.*--force|-[a-zA-Z]*f[a-zA-Z]*r)\s+\*\s*$/, desc: 'recursive force-delete wildcard' },
    { pattern: /\bmkfs\b/, desc: 'filesystem format' },
    { pattern: /\bdd\s+if=/, desc: 'raw disk write' },
    { pattern: /:\(\)\{\s*:\|:&\s*\}\s*;/, desc: 'fork bomb' },
    { pattern: />\s*\/dev\/[sh]d[a-z]/, desc: 'overwrite disk device' },
    { pattern: /\bshred\s+/, desc: 'secure file destruction' },
    { pattern: /\bwipefs\b/, desc: 'wipe filesystem signatures' },
  ];

  for (const rule of hardBlock) {
    if (rule.pattern.test(normalized)) {
      process.stderr.write(
        '[deny-destructive] BLOCKED: ' + rule.desc + '\n' +
        'Command: ' + cmd.substring(0, 200) + '\n' +
        'This command is never safe to run autonomously.\n'
      );
      process.exit(2);
    }
  }

  // ── TIER 2: WARN + STOP ────────────────────────────────────────────
  // Legitimate commands that require human intent. The agent is told to
  // instruct the user to run them manually with the ! prefix.

  const warnStop = [
    { pattern: /\bsudo\b/, desc: 'privilege escalation (sudo)' },
    { pattern: /\bgit\s+push\s+.*--force\b/, desc: 'force push' },
    { pattern: /\bgit\s+push\s+-f\b/, desc: 'force push (-f)' },
    { pattern: /\bgit\s+reset\s+--hard\b/, desc: 'hard reset (destructive)' },
    { pattern: /\bgit\s+clean\s+.*-f/, desc: 'git clean -f (deletes untracked files)' },
    { pattern: /\bgit\s+checkout\s+--\s+\./, desc: 'discard all working changes' },
    { pattern: /\bchmod\s+777\b/, desc: 'world-writable permissions' },
    { pattern: /\bchmod\s+-R\s+777\b/, desc: 'recursive world-writable permissions' },
    { pattern: /\bkill\s+-9\b/, desc: 'force kill process' },
    { pattern: /\bkillall\b/, desc: 'kill all processes by name' },
    { pattern: /\bsystemctl\s+(stop|disable|mask)\b/, desc: 'stop/disable system service' },
    { pattern: /\breboot\b/, desc: 'system reboot' },
    { pattern: /\bshutdown\b/, desc: 'system shutdown' },
  ];

  for (const rule of warnStop) {
    if (rule.pattern.test(normalized)) {
      process.stderr.write(
        '[deny-destructive] STOPPED: ' + rule.desc + '\n' +
        'Command: ' + cmd.substring(0, 200) + '\n' +
        'This needs human intent. Run it yourself:\n' +
        '  ! ' + cmd.substring(0, 300) + '\n'
      );
      process.exit(2);
    }
  }

  // ── PASS THROUGH ────────────────────────────────────────────────────
  process.stdout.write(data);
  process.exit(0);
});

process.stdin.on('error', () => {
  process.exit(0);
});
