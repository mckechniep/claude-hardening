#!/usr/bin/env node
/**
 * Git Guard Hook (PreToolUse:Bash)
 *
 * Warns and stops when the agent tries to commit directly to main/master
 * or push to those branches without explicit human intent.
 *
 * These operations are legitimate but risky — the agent is instructed
 * to use a feature branch instead, or ask the operator to run it.
 *
 * Exit codes:
 *   0  — command is safe, pass through
 *   2  — command blocked (message on stderr shown to the agent)
 */

'use strict';

const { spawnSync } = require('child_process');

/**
 * Get the current git branch. Returns null if not in a git repo or on a
 * detached HEAD. This runs as a direct subprocess — it does NOT go through
 * Claude Code's hook system, so there is no recursion risk.
 */
function getCurrentBranch() {
  try {
    const result = spawnSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    });
    if (result.status === 0) {
      const branch = result.stdout.trim();
      return branch === 'HEAD' ? null : branch; // detached HEAD
    }
  } catch {
    // not in a git repo
  }
  return null;
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

  const cmd = (input.tool_input?.command || '').trim();
  if (!cmd) {
    process.stdout.write(data);
    process.exit(0);
  }

  const normalized = cmd.replace(/\s+/g, ' ');

  // ── Rules ────────────────────────────────────────────────────────────

  const rules = [
    {
      pattern: /\bgit\s+push\b(?!.*--force)(?!.*-f\b).*\b(origin\s+)?(main|master)\b/,
      desc: 'push directly to main/master',
      advice: 'Push to a feature branch instead:\n' +
              '  git push origin HEAD:your-branch-name\n' +
              'Or run it yourself if you intend to push to main:\n',
    },
    {
      pattern: /\bgit\s+commit\b/,
      desc: 'git commit on main/master',
      advice: 'Switch to a feature branch first:\n' +
              '  git checkout -b your-branch-name\n' +
              'Or run it yourself if a direct commit to main is intentional:\n',
      checkBranch: true,
    },
    {
      // Block deleting main/master branch
      pattern: /\bgit\s+branch\s+(-d|-D|--delete)\s+(main|master)\b/,
      desc: 'delete main/master branch',
      advice: 'Deleting the primary branch is irreversible. Run it yourself if intentional:\n',
    },
  ];

  for (const rule of rules) {
    if (rule.checkBranch) {
      if (!rule.pattern.test(normalized)) continue;
      // Check actual branch — only block on main/master
      const branch = getCurrentBranch();
      if (branch === 'main' || branch === 'master') {
        process.stderr.write(
          '[git-guard] STOPPED: ' + rule.desc + '\n' +
          'Command: ' + cmd.substring(0, 200) + '\n' +
          'Currently on branch: ' + branch + '\n' +
          rule.advice +
          '  ! ' + cmd.substring(0, 300) + '\n'
        );
        process.exit(2);
      }
      // On a feature branch or detached HEAD — pass through
      continue;
    }

    if (rule.pattern && rule.pattern.test(normalized)) {
      process.stderr.write(
        '[git-guard] STOPPED: ' + rule.desc + '\n' +
        'Command: ' + cmd.substring(0, 200) + '\n' +
        rule.advice +
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
