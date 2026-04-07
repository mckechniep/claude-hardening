#!/usr/bin/env node
/**
 * Audit Log Hook (PostToolUse:Bash,Write,Edit)
 *
 * Appends a JSONL entry to ~/.claude/audit.log for every tool use.
 * Never blocks — exit code is always 0.
 *
 * Log format (one JSON object per line):
 *   {
 *     "ts":      "2026-04-06T15:00:00.000Z",
 *     "tool":    "Bash",
 *     "command": "git status",        // Bash only
 *     "file":    "/path/to/file.js",  // Write/Edit only
 *     "exit":    0                    // Bash: exit code of the command
 *   }
 *
 * Exit codes:
 *   0  — always (this hook never blocks)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const LOG_PATH = path.join(os.homedir(), '.claude', 'audit.log');
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
    process.exit(0);
  }

  const toolName = input.tool_name || '';
  const toolInput = input.tool_input || {};
  const toolResponse = input.tool_response || {};

  const entry = {
    ts: new Date().toISOString(),
    tool: toolName,
  };

  if (toolName === 'Bash') {
    entry.command = (toolInput.command || '').substring(0, 500);
    // PostToolUse includes the exit code in the response for Bash
    if (typeof toolResponse.exit_code === 'number') {
      entry.exit = toolResponse.exit_code;
    }
  } else if (toolName === 'Write' || toolName === 'Edit') {
    entry.file = toolInput.file_path || '';
  }

  try {
    fs.appendFileSync(LOG_PATH, JSON.stringify(entry) + '\n', 'utf8');
  } catch {
    // Silently fail — never block the agent due to a logging failure
  }

  process.exit(0);
});

process.stdin.on('error', () => {
  process.exit(0);
});
