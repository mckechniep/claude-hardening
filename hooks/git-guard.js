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
      desc: 'git commit on protected branch',
      advice: 'If you are on main/master, switch to a feature branch first:\n' +
              '  git checkout -b your-branch-name\n' +
              'Or run it yourself if a direct commit to main is intentional:\n',
      // Only block if currently on main/master — checked dynamically below
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
    // For commit, we need to check the current branch — but we can't run git
    // from within the hook without risk of recursion. Instead, we check if the
    // command itself specifies a branch explicitly (e.g. `git commit -m "..."`)
    // and let it through. The advice message covers the case.
    if (rule.checkBranch) {
      // Only intercept if the command looks like a plain commit (not amend to
      // a historical ref, not --no-commit, etc.) — still allow but warn.
      if (!/\bgit\s+commit\b/.test(normalized)) continue;
      // We warn rather than hard-block for commits, since we can't know the
      // current branch without running a subprocess.
      process.stderr.write(
        '[git-guard] NOTICE: git commit detected\n' +
        'If you are on main/master, create a feature branch first:\n' +
        '  git checkout -b your-branch-name\n' +
        'If you are already on a feature branch, this message is informational only.\n' +
        'To proceed on main (if intentional), run it yourself:\n' +
        '  ! ' + cmd.substring(0, 300) + '\n'
      );
      process.exit(2);
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
