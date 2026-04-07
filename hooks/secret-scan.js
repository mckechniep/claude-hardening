#!/usr/bin/env node
/**
 * Secret Scanner Hook (PreToolUse:Write,Edit)
 *
 * Scans file content before it is written to disk and blocks the write
 * if it contains credential patterns — API keys, private keys,
 * connection strings with passwords, etc.
 *
 * Exit codes:
 *   0  — content looks clean, pass through
 *   2  — credential pattern detected (message on stderr shown to the agent)
 */

'use strict';

// Patterns that indicate embedded secrets.
// Each entry has a name (for the error message) and a regex.
const SECRET_PATTERNS = [
  // AWS
  { name: 'AWS access key ID',        pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS secret access key',    pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?/i },

  // GitHub / GitLab tokens
  { name: 'GitHub personal token',    pattern: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub Actions token',     pattern: /\bghs_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub OAuth token',       pattern: /\bgho_[A-Za-z0-9]{36}\b/ },
  { name: 'GitLab personal token',    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },

  // Anthropic / OpenAI / common AI providers
  { name: 'Anthropic API key',        pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { name: 'OpenAI API key',           pattern: /\bsk-[A-Za-z0-9]{32,}\b/ },

  // Slack
  { name: 'Slack bot token',          pattern: /\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/ },
  { name: 'Slack user token',         pattern: /\bxoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/ },

  // Stripe
  { name: 'Stripe secret key',        pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/ },
  { name: 'Stripe test key',          pattern: /\bsk_test_[A-Za-z0-9]{24,}\b/ },

  // Twilio
  { name: 'Twilio account SID',       pattern: /\bAC[a-f0-9]{32}\b/ },
  { name: 'Twilio auth token',        pattern: /twilio[_-]?auth[_-]?token\s*[:=]\s*['"]?[a-f0-9]{32}['"]?/i },

  // Private key blocks
  { name: 'PEM private key',          pattern: /-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },

  // Generic high-confidence patterns
  { name: 'hardcoded password',       pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i },
  { name: 'hardcoded API key',        pattern: /api[_-]?key\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i },
  { name: 'hardcoded auth token',     pattern: /(?:auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-.]{16,}['"]/i },
  { name: 'hardcoded secret',         pattern: /(?:^|[^a-z])secret\s*[:=]\s*['"][^'"]{8,}['"]/im },

  // Connection strings with embedded credentials
  { name: 'connection string with password', pattern: /(?:mongodb|postgres|postgresql|mysql|redis|amqp|jdbc)[+a-z]*:\/\/[^:]+:[^@]{3,}@/i },
];

const MAX_STDIN = 10 * 1024 * 1024; // 10MB — Write can have large content
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

  const toolInput = input.tool_input || {};

  // For Write: check `content`. For Edit: check `new_string`.
  const content = toolInput.content || toolInput.new_string || '';

  if (!content) {
    process.stdout.write(data);
    process.exit(0);
  }

  const filePath = toolInput.file_path || '(unknown file)';

  for (const { name, pattern } of SECRET_PATTERNS) {
    if (pattern.test(content)) {
      process.stderr.write(
        '[secret-scan] BLOCKED: ' + name + ' detected in content\n' +
        'File: ' + filePath + '\n' +
        'Do not hardcode credentials. Use environment variables or a secret manager:\n' +
        '  const value = process.env.MY_SECRET\n' +
        '  // or read from a vault, .env file that is .gitignored, etc.\n'
      );
      process.exit(2);
    }
  }

  // Content is clean
  process.stdout.write(data);
  process.exit(0);
});

process.stdin.on('error', () => {
  process.exit(0);
});
