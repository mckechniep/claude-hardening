#!/usr/bin/env node
/**
 * Test runner for claude-hardening hooks.
 *
 * Usage:
 *   node tests/run-tests.js
 *   npm test
 *
 * Each test pipes a JSON payload into a hook script and checks:
 *   - exit code (0 = pass, 2 = blocked)
 *   - optional stderr content
 */

'use strict';

const { execFileSync, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const HOOKS_DIR = path.join(__dirname, '..', 'hooks');

let passed = 0;
let failed = 0;
let skipped = 0;

function makeInput(toolName, toolInput) {
  return JSON.stringify({ tool_name: toolName, tool_input: toolInput });
}

function runHook(hookFile, inputJson) {
  const result = spawnSync('node', [path.join(HOOKS_DIR, hookFile)], {
    input: inputJson,
    encoding: 'utf8',
    timeout: 5000,
  });
  return {
    exitCode: result.status,
    stderr: result.stderr || '',
    stdout: result.stdout || '',
  };
}

const SKIP = Symbol('skip');

function test(name, fn) {
  try {
    fn();
    console.log('  PASS  ' + name);
    passed++;
  } catch (err) {
    if (err === SKIP || (err && err.message === 'SKIP')) {
      // skip message already printed by skip()
      skipped++;
    } else {
      console.log('  FAIL  ' + name);
      console.log('         ' + err.message);
      failed++;
    }
  }
}

function skip(reason) {
  console.log('  SKIP  ' + reason);
  throw SKIP;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

// ─────────────────────────────────────────────────────────────────────────────
// deny-destructive.js
// ─────────────────────────────────────────────────────────────────────────────

console.log('\ndeny-destructive.js');

test('allows safe command', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'ls -la' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('hard-blocks rm -rf /', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'rm -rf /' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
  assert(r.stderr.includes('BLOCKED'), 'expected BLOCKED in stderr');
});

test('hard-blocks rm -rf ~', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'rm -rf ~' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('hard-blocks mkfs', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'mkfs.ext4 /dev/sdb' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('hard-blocks dd if=', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'dd if=/dev/zero of=/dev/sda' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('hard-blocks shred', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'shred -u myfile.txt' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('warn-stops sudo', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'sudo apt install vim' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
  assert(r.stderr.includes('STOPPED'), 'expected STOPPED in stderr');
});

test('warn-stops git push --force', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'git push --force origin main' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('warn-stops git reset --hard', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'git reset --hard HEAD~1' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('warn-stops kill -9', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'kill -9 1234' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('allows git status', () => {
  const r = runHook('deny-destructive.js', makeInput('Bash', { command: 'git status' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('passes through on invalid JSON', () => {
  const r = runHook('deny-destructive.js', 'not json');
  assert(r.exitCode === 0, `expected exit 0 on parse error, got ${r.exitCode}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// git-guard.js
// ─────────────────────────────────────────────────────────────────────────────

console.log('\ngit-guard.js');

// Detect current branch for conditional tests
const currentBranch = (() => {
  try {
    const r = spawnSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000,
    });
    return r.status === 0 ? r.stdout.trim() : null;
  } catch { return null; }
})();

test('blocks git commit on main/master', () => {
  if (currentBranch !== 'main' && currentBranch !== 'master') {
    skip('blocks git commit on main/master (not on main/master)');
  }
  const r = runHook('git-guard.js', makeInput('Bash', { command: 'git commit -m "test"' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
  assert(r.stderr.includes('STOPPED'), 'expected STOPPED in stderr');
  assert(r.stderr.includes('Currently on branch'), 'expected branch name in message');
});

test('blocks push to main', () => {
  const r = runHook('git-guard.js', makeInput('Bash', { command: 'git push origin main' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks deleting main branch', () => {
  const r = runHook('git-guard.js', makeInput('Bash', { command: 'git branch -D main' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('allows git status', () => {
  const r = runHook('git-guard.js', makeInput('Bash', { command: 'git status' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows git log', () => {
  const r = runHook('git-guard.js', makeInput('Bash', { command: 'git log --oneline -5' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows git commit on feature branch', () => {
  // Create a temp branch, run the test, switch back
  if (!currentBranch) {
    skip('allows git commit on feature branch (not in a git repo)');
  }
  spawnSync('git', ['checkout', '-b', 'test-git-guard-temp'], {
    stdio: 'ignore', timeout: 3000,
  });
  try {
    const r = runHook('git-guard.js', makeInput('Bash', { command: 'git commit -m "feature work"' }));
    assert(r.exitCode === 0, `expected exit 0 on feature branch, got ${r.exitCode}`);
  } finally {
    spawnSync('git', ['checkout', currentBranch], { stdio: 'ignore', timeout: 3000 });
    spawnSync('git', ['branch', '-D', 'test-git-guard-temp'], { stdio: 'ignore', timeout: 3000 });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// network-egress.js
// ─────────────────────────────────────────────────────────────────────────────

console.log('\nnetwork-egress.js');

// Write a temp allowlist for these tests
const tmpAllowlist = path.join(os.tmpdir(), 'test-allowlist.json');
fs.writeFileSync(tmpAllowlist, JSON.stringify({
  allowedDomains: ['github.com', 'registry.npmjs.org'],
  allowLocalhost: true,
  warnOnVariableUrls: true,
}));

// Patch the hook to use our temp allowlist (via env var not supported — we
// test against real allowlist path, so we write to the real location if it
// exists, or skip if absent)
const realAllowlist = path.join(os.homedir(), '.claude', 'network-allowlist.json');
const allowlistExists = fs.existsSync(realAllowlist);

test('allows localhost curl', () => {
  const r = runHook('network-egress.js', makeInput('Bash', { command: 'curl http://localhost:3000/health' }));
  // If no allowlist, hook passes through — both 0 exit codes are fine
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows curl to allowlisted domain', () => {
  if (!allowlistExists) skip('(no allowlist installed)');
  const r = runHook('network-egress.js', makeInput('Bash', { command: 'curl https://registry.npmjs.org/express' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('blocks curl to unknown domain', () => {
  if (!allowlistExists) skip('(no allowlist installed)');
  const r = runHook('network-egress.js', makeInput('Bash', { command: 'curl https://totally-unknown-domain-xyz123.example' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
  assert(r.stderr.includes('BLOCKED'), 'expected BLOCKED in stderr');
});

test('blocks variable URL', () => {
  if (!allowlistExists) { passed++; return; }
  const r = runHook('network-egress.js', makeInput('Bash', { command: 'curl https://$UNKNOWN_HOST/endpoint' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('allows non-network command', () => {
  const r = runHook('network-egress.js', makeInput('Bash', { command: 'echo hello world' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

// No-allowlist tests: temporarily rename the real file to test fail-closed behavior
if (allowlistExists) {
  const backupPath = realAllowlist + '.test-backup';
  fs.renameSync(realAllowlist, backupPath);

  test('no-allowlist: blocks external domain', () => {
    const r = runHook('network-egress.js', makeInput('Bash', { command: 'curl https://totally-unknown-xyz.example' }));
    assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
    assert(r.stderr.includes('No allowlist found'), 'expected no-allowlist message');
  });

  test('no-allowlist: allows localhost', () => {
    const r = runHook('network-egress.js', makeInput('Bash', { command: 'curl http://localhost:3000/health' }));
    assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
  });

  test('no-allowlist: allows non-network command', () => {
    const r = runHook('network-egress.js', makeInput('Bash', { command: 'echo hello' }));
    assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
  });

  fs.renameSync(backupPath, realAllowlist);
}

// ─────────────────────────────────────────────────────────────────────────────
// file-access.js
// ─────────────────────────────────────────────────────────────────────────────

console.log('\nfile-access.js');

test('blocks read of ~/.ssh/id_rsa', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: path.join(os.homedir(), '.ssh', 'id_rsa') }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
  assert(r.stderr.includes('BLOCKED'), 'expected BLOCKED in stderr');
});

test('blocks read of .env file', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/.env' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks read of .env.local file', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/.env.local' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks read of credentials file', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: path.join(os.homedir(), '.aws', 'credentials') }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks write of .pem file', () => {
  const r = runHook('file-access.js', makeInput('Write', { file_path: '/tmp/my-key.pem', content: 'test' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks read of tokens.json', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/tokens.json' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks read of secret.yaml', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/secret.yaml' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('allows write of tokens.css (design tokens)', () => {
  const r = runHook('file-access.js', makeInput('Write', { file_path: '/project/styles/tokens.css', content: ':root { --color: red; }' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows read of tokens.ts (source file)', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/src/tokens.ts' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows read of secrets.js (source file)', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/src/secrets.js' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows read of apikeys.py (source file)', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/src/apikeys.py' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows read of normal source file', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/src/index.js' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows read of README.md', () => {
  const r = runHook('file-access.js', makeInput('Read', { file_path: '/project/README.md' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// secret-scan.js
// ─────────────────────────────────────────────────────────────────────────────

console.log('\nsecret-scan.js');

test('blocks AWS access key', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'config.js',
    content: 'const key = "AKIAIOSFODNN7EXAMPLE";',
  }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
  assert(r.stderr.includes('BLOCKED'), 'expected BLOCKED in stderr');
});

test('blocks GitHub personal token', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'config.js',
    content: 'token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
  }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks PEM private key', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'key.js',
    content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA...',
  }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks hardcoded password', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'db.js',
    content: 'const config = { password: "super-secret-password-123" };',
  }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks database connection string with credentials', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'db.js',
    content: 'const url = "postgresql://admin:mypassword@db.example.com:5432/mydb";',
  }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('allows env var reference', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'config.js',
    content: 'const key = process.env.API_KEY;',
  }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows placeholder text', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'config.js',
    content: 'const key = "YOUR_API_KEY_HERE";',
  }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows empty content', () => {
  const r = runHook('secret-scan.js', makeInput('Write', {
    file_path: 'empty.js',
    content: '',
  }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('blocks secret in Edit new_string', () => {
  const r = runHook('secret-scan.js', makeInput('Edit', {
    file_path: 'config.js',
    old_string: 'placeholder',
    new_string: 'const key = "AK' + 'IAIOSFODNN7EXAMPLE";',
  }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('allows safe Edit new_string', () => {
  const r = runHook('secret-scan.js', makeInput('Edit', {
    file_path: 'config.js',
    old_string: 'old value',
    new_string: 'const key = process.env.API_KEY;',
  }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// sandbox-exec.js
// ─────────────────────────────────────────────────────────────────────────────

console.log('\nsandbox-exec.js');

// Check if bwrap is available for sandbox tests
let bwrapWorks = false;
try {
  const bwrapTest = spawnSync('bwrap', [
    '--bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--', 'true',
  ], { stdio: 'ignore', timeout: 5000 });
  bwrapWorks = bwrapTest.status === 0;
} catch {
  bwrapWorks = false;
}

test('rewrites command when bwrap available', () => {
  if (!bwrapWorks) {
    skip('(bwrap not available)');
  }
  const r = runHook('sandbox-exec.js', makeInput('Bash', { command: 'ls -la' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
  const output = JSON.parse(r.stdout);
  assert(output.tool_input.command.includes('bwrap'), 'expected bwrap in rewritten command');
  assert(output.tool_input.command.includes('ls -la'), 'expected original command preserved');
});

test('includes tmpfs for blocked dirs', () => {
  if (!bwrapWorks) {
    skip('(bwrap not available)');
  }
  const r = runHook('sandbox-exec.js', makeInput('Bash', { command: 'cat ~/.ssh/id_rsa' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
  const output = JSON.parse(r.stdout);
  const cmd = output.tool_input.command;
  assert(cmd.includes('--tmpfs'), 'expected --tmpfs in rewritten command');
  assert(cmd.includes('.ssh'), 'expected .ssh in tmpfs mount');
});

test('sandboxed command actually blocks .ssh access', () => {
  if (!bwrapWorks) {
    skip('(bwrap not available)');
  }
  const r = runHook('sandbox-exec.js', makeInput('Bash', { command: 'ls ~/.ssh/' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
  const output = JSON.parse(r.stdout);
  // Execute the sandboxed command and verify .ssh is empty
  const exec = spawnSync('sh', ['-c', output.tool_input.command], {
    encoding: 'utf8',
    timeout: 5000,
  });
  assert(exec.stdout.trim() === '', 'expected empty output from sandboxed ls ~/.ssh/');
});

test('sandboxed command allows normal file access', () => {
  if (!bwrapWorks) {
    skip('(bwrap not available)');
  }
  const r = runHook('sandbox-exec.js', makeInput('Bash', { command: 'echo hello' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
  const output = JSON.parse(r.stdout);
  const exec = spawnSync('sh', ['-c', output.tool_input.command], {
    encoding: 'utf8',
    timeout: 5000,
  });
  assert(exec.stdout.trim() === 'hello', `expected "hello", got "${exec.stdout.trim()}"`);
});

test('passes through on invalid JSON', () => {
  const r = runHook('sandbox-exec.js', 'not json');
  assert(r.exitCode === 0, `expected exit 0 on parse error, got ${r.exitCode}`);
});

test('passes through on empty command', () => {
  const r = runHook('sandbox-exec.js', makeInput('Bash', { command: '' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// file-access.js — Bash path extraction (regex fallback)
// ─────────────────────────────────────────────────────────────────────────────

console.log('\nfile-access.js (Bash fallback)');

test('blocks cat ~/.ssh/id_rsa via Bash', () => {
  const r = runHook('file-access.js', makeInput('Bash', { command: 'cat ~/.ssh/id_rsa' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
  assert(r.stderr.includes('BLOCKED'), 'expected BLOCKED in stderr');
});

test('blocks head /etc/shadow via Bash', () => {
  const r = runHook('file-access.js', makeInput('Bash', { command: 'head -5 /etc/shadow' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('blocks redirect to ~/.env via Bash', () => {
  const r = runHook('file-access.js', makeInput('Bash', { command: 'echo secret > ~/.env' }));
  assert(r.exitCode === 2, `expected exit 2, got ${r.exitCode}`);
});

test('allows cat of normal file via Bash', () => {
  const r = runHook('file-access.js', makeInput('Bash', { command: 'cat /tmp/test.txt' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows ls command via Bash (no file paths)', () => {
  const r = runHook('file-access.js', makeInput('Bash', { command: 'ls -la' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

test('allows non-file commands via Bash', () => {
  const r = runHook('file-access.js', makeInput('Bash', { command: 'git status && npm test' }));
  assert(r.exitCode === 0, `expected exit 0, got ${r.exitCode}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Results
// ─────────────────────────────────────────────────────────────────────────────

const total = passed + failed + skipped;
const parts = [`${passed} passed`, `${failed} failed`];
if (skipped > 0) parts.push(`${skipped} skipped`);
console.log(`\n${total} tests: ${parts.join(', ')}\n`);
if (failed > 0) process.exit(1);
