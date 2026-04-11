<p align="center">
  <img src="logo.png" alt="claude-hardening" width="200" />
</p>

<h1 align="center">claude-hardening</h1>

<p align="center">A hardening kit for Claude Code that blocks destructive commands, controls network egress, protects credentials, and keeps AI agents from going rogue.</p>

## What it does

Seven hooks that intercept tool calls before or after the agent executes them:

### PreToolUse hooks

**sandbox-exec** — wraps Bash commands in a bubblewrap (bwrap) sandbox

| Mode | Behavior |
|---|---|
| `standard` (default) | Filesystem is read-write. Credential directories (`.ssh`, `.aws`, `.gnupg`, etc.) are replaced with empty tmpfs overlays. The agent can work normally but cannot access sensitive files regardless of how the command is structured — variable expansion, encoding, subshells, and aliasing are all ineffective because protection is at the OS level, not regex. |
| `strict` | Filesystem is read-only by default. Only `writablePaths` (+ the project directory) are writable. Credential directories are still hidden. Disguised destructive commands like `rm -rf ~` hit a read-only filesystem and fail. |

Falls back to regex-based protection when bwrap is not available.
Config: `~/.claude/file-access-policy.json` (`sandboxMode`, `writablePaths`)

**deny-destructive** — blocks dangerous shell commands

| Tier | Commands | Behavior |
|---|---|---|
| Hard block | `rm -rf /`, `mkfs`, `dd if=`, fork bombs, `shred`, `wipefs` | Permanently blocked — never safe for autonomous execution |
| Warn + stop | `sudo`, `git push --force`, `git reset --hard`, `chmod 777`, `kill -9`, `reboot`, `shutdown` | Blocked with instructions for the user to run it manually |

**network-egress** — blocks outbound network requests to unknown domains

| What | Behavior |
|---|---|
| `curl`/`wget` to unknown domains | Blocked — prevents data exfiltration |
| `ftp`/`ftps`/`sftp` URLs | Blocked — same as http/https |
| `nc`/`ncat`/`netcat` | Blocked unless target domain is on allowlist |
| `ssh`/`scp`/`rsync` to unknown hosts | Blocked |
| `git clone`/`fetch`/`pull`/`push` to unknown hosts | Blocked |
| Dynamic/variable URLs (`curl $URL`) | Blocked — destination can't be verified |
| No allowlist file | All external blocked, localhost still allowed |
| Requests to allowlisted domains | Passes through normally |
| localhost / 127.0.0.1 | Always allowed |

**git-guard** — blocks commits and pushes to main/master

| What | Behavior |
|---|---|
| `git push origin main` | Blocked — redirected to feature branch |
| `git commit` on main/master | Blocked — checks actual branch via `git rev-parse` |
| `git commit` on feature branch | Passes through normally |
| `git branch -D main` | Blocked — deleting primary branch |

**file-access** — blocks reads and writes to sensitive files

| What | Behavior |
|---|---|
| `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.kube/` | Blocked |
| `.env`, `.env.*`, `.env.local` | Blocked |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | Blocked |
| Files named `credentials`, `secret`, `token`, `apikey` (+ plurals, with any extension) | Blocked |
| `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | Blocked |
| `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc` | Blocked |
| Normal project files | Pass through |

Applies to **Bash, Read, Write, Edit, and Glob** tool calls. For Bash, extracts file paths from common commands (`cat`, `head`, `tail`, `cp`, `mv`, etc.) as a regex fallback when bwrap is unavailable.
Config: `~/.claude/file-access-policy.json`

**secret-scan** — scans file content before it is written to disk

| What | Behavior |
|---|---|
| AWS access key IDs (`AKIA...`) | Blocked |
| GitHub tokens (`ghp_...`, `ghs_...`) | Blocked |
| OpenAI / Anthropic API keys (`sk-...`) | Blocked |
| Slack tokens (`xoxb-...`, `xoxp-...`) | Blocked |
| Stripe keys (`sk_live_...`, `sk_test_...`) | Blocked |
| PEM private key blocks | Blocked |
| Hardcoded `password = "..."` patterns | Blocked |
| Database connection strings with credentials | Blocked |
| `process.env.MY_SECRET` references | Passes through |

Applies to **Write and Edit** tool calls.

### PostToolUse hooks

**audit-log** — appends a JSONL entry to `~/.claude/audit.log` for every Bash command and file write. Rotates at 10MB (renames to `audit.log.1`). Never blocks — silent observer only.

```json
{"ts":"2026-04-06T15:00:00.000Z","tool":"Bash","command":"git status","exit":0}
{"ts":"2026-04-06T15:01:00.000Z","tool":"Write","file":"/project/src/index.js"}
```

## Install

```bash
git clone https://github.com/mckechniep/claude-hardening.git
cd claude-hardening
./install.sh
```

The installer:
1. Checks for Node.js 18+ and bubblewrap (bwrap)
2. Copies all seven hook scripts to `~/.claude/scripts/hooks/`
3. Creates `~/.claude/network-allowlist.json` and `~/.claude/file-access-policy.json` (won't overwrite)
4. Configures `~/.claude/settings.json` — offers to **merge** hooks if the file already exists (backs up first, deduplicates by hook id)
5. Offers to copy the `CLAUDE.md` template to your project (never overwrites)
6. Syntax-checks each hook with Node.js
7. Reports sandbox status (active if bwrap available, regex fallback if not)

Requires Node.js 18+. Bubblewrap recommended: `sudo apt install bubblewrap`

## Verify

```bash
npm test
```

Runs 55 tests covering every hook — sandbox rewrites, pass/fail rules, edge cases, and allow-list behavior.

## Files

```
claude-hardening/
├── hooks/
│   ├── sandbox-exec.js              # bwrap sandbox (OS-level filesystem protection)
│   ├── deny-destructive.js          # Destructive shell command deny list
│   ├── network-egress.js            # Network egress allowlist control
│   ├── git-guard.js                 # Git branch protection
│   ├── file-access.js               # Sensitive file path protection (+ Bash fallback)
│   ├── secret-scan.js               # Credential pattern detection
│   └── audit-log.js                 # Session audit trail (PostToolUse)
├── profiles/
│   ├── standard.json                # All hooks, sandbox in standard mode
│   ├── strict.json                  # All hooks, sandbox in strict mode + Read audit
│   └── readonly.json                # Blocks all Bash and file writes
├── templates/
│   └── CLAUDE.md                    # Behavioral guardrails for agents
├── tests/
│   └── run-tests.js                 # 55 tests across all hooks
├── network-allowlist.example.json   # Default trusted domains
├── file-access-policy.example.json  # File access + sandbox policy template
├── settings.example.json            # Example settings.json with all hooks
├── package.json                     # npm test entry point
├── install.sh                       # Installer script
└── uninstall.sh                     # Uninstaller (restores pre-install state)
```

After install, your `~/.claude/` will contain:

```
~/.claude/
├── scripts/hooks/
│   ├── sandbox-exec.js
│   ├── deny-destructive.js
│   ├── network-egress.js
│   ├── git-guard.js
│   ├── file-access.js
│   ├── secret-scan.js
│   └── audit-log.js
├── network-allowlist.json
├── file-access-policy.json
├── audit.log                        # Created on first session
└── settings.json
```

## Profiles

Pre-built permission levels in `profiles/`:

| Profile | Sandbox | Bash | Writes | Network | File reads | Audit |
|---|---|---|---|---|---|---|
| `standard.json` | Standard (credential dirs hidden) | Guarded | Secret-scanned | Allowlisted | Sensitive blocked | Yes |
| `strict.json` | Strict (read-only base) | Guarded | Secret-scanned | Allowlisted | Sensitive blocked | Yes (incl. reads) |
| `readonly.json` | — | Blocked | Blocked | — | Sensitive blocked | No |

To apply a profile, merge its contents into `~/.claude/settings.json`.

## Templates

`templates/CLAUDE.md` is a ready-to-use behavioral policy file. Drop it into a project root as `CLAUDE.md` to give the agent explicit instructions about:

- Not hardcoding secrets
- Using feature branches instead of committing to main
- Asking before destructive operations
- Escalating with `! command` when human intent is needed

The hook layer and the CLAUDE.md layer are complementary — hooks are enforced mechanically; CLAUDE.md shapes intent before the agent tries.

## Customizing the network allowlist

Edit `~/.claude/network-allowlist.json` to add trusted domains:

```json
{
  "allowedDomains": [
    "github.com",
    "api.github.com",
    "registry.npmjs.org",
    "your-internal-api.company.com"
  ],
  "allowLocalhost": true,
  "warnOnVariableUrls": true
}
```

Changes take effect immediately — no restart needed. Subdomains are matched automatically: adding `github.com` also allows `api.github.com`.

## Customizing file access and sandbox

Edit `~/.claude/file-access-policy.json` to configure both the file-access hook and the sandbox:

```json
{
  "sandboxMode": "standard",
  "blockedDirs": [
    ".vault",
    "secrets"
  ],
  "blockedFiles": [
    "*.secret"
  ],
  "allowedPaths": [
    "~/.ssh/known_hosts"
  ],
  "writablePaths": [
    "/tmp",
    "$HOME/.cache",
    "$HOME/.npm",
    "$HOME/.local"
  ]
}
```

- `sandboxMode` — `"standard"` (credential dirs hidden, filesystem read-write) or `"strict"` (read-only base, only `writablePaths` are writable)
- `blockedDirs` — additional directories to block (relative to `~` or absolute)
- `blockedFiles` — additional filename regex patterns to block
- `allowedPaths` — explicit escape hatch for paths you intentionally need access to
- `writablePaths` — directories the agent can write to in strict mode (the project directory is always writable). Supports `$HOME` and `~` prefixes.

### Sandbox modes explained

**Standard** — the agent can read and write freely. Credential directories (`~/.ssh`, `~/.aws`, etc.) are replaced with empty tmpfs overlays so they appear empty to any command, regardless of how it's invoked.

**Strict** — the entire filesystem is mounted read-only. Only the project directory and paths in `writablePaths` are writable. A disguised `rm -rf ~` hits a read-only filesystem and fails. Credential dirs are still hidden via tmpfs.

Both modes are enforced at the OS level via bubblewrap. Shell indirection, variable expansion, base64 encoding, and subshell tricks cannot bypass the sandbox.

## When commands get blocked

The agent sees the block message and tells you what happened. You have two options:

1. **Run it yourself** — type `! <command>` in Claude Code to execute it as the human operator
2. **Add to allowlist** — if it's a legitimate network domain, add it to `network-allowlist.json`

Example block message the agent sees:
```
[network-egress] BLOCKED: curl/wget to unknown domain: example.com
Add to ~/.claude/network-allowlist.json if trusted, or run it yourself:
  ! curl https://example.com
```

## Temporarily disabling

**Network egress:** add the domain you need to `~/.claude/network-allowlist.json`. Do not delete the file — a missing allowlist blocks all external traffic (localhost still works).

**Single hook:** remove that hook's entry from `~/.claude/settings.json`. Re-run `./install.sh` later to re-add it (the merge is idempotent).

**All hooks:** run `./uninstall.sh` and re-install later with `./install.sh`.

## Coverage and limitations

| Threat | Covered | How |
|---|---|---|
| Recursive filesystem deletion | Yes | deny-destructive (regex) + sandbox-exec (strict mode: read-only FS) |
| Privilege escalation (sudo) | Yes | deny-destructive |
| Destructive git operations | Yes | deny-destructive + git-guard |
| Direct commits to main/master | Yes | git-guard |
| Data exfiltration via curl/wget | Yes | network-egress |
| Raw socket connections (netcat) | Yes | network-egress |
| SSH/SCP to unknown hosts | Yes | network-egress |
| Dynamic/variable URLs | Yes | network-egress |
| Fork bombs / disk destruction | Yes | deny-destructive |
| Reading credential files (.ssh, .aws, .env) | Yes | **sandbox-exec** (OS-level) + file-access (regex fallback) |
| Shell indirection to read credentials | Yes | **sandbox-exec** (OS-level — immune to encoding, variables, subshells) |
| Disguised destructive writes | Yes (strict) | **sandbox-exec** strict mode (read-only filesystem) |
| Writing secrets / API keys to files | Yes | secret-scan |
| Session audit trail | Yes | audit-log |
| DNS tunneling | No | — |
| Non-shell exfiltration via MCP tools | No | — |
| Secrets leaked through stdout/response | No | — |

The sandbox hook (`sandbox-exec.js`) operates at the OS level via bubblewrap, making it immune to shell indirection attacks (base64 encoding, variable expansion, subshells, aliasing). The other hooks use regex-based text analysis — effective against unintentional leaks and basic prompt injection, but bypassable by sophisticated evasion. Both layers run together for defense in depth.

## Roadmap

Ideas under consideration for future releases:

### v0.2.0

**Rate limiting** — detect repeated blocked attempts within a session. If an agent hammers a blocked command pattern (e.g., retrying `sudo` or probing different exfiltration domains), escalate from a per-call block to a session-level warning or halt. Useful for catching prompt injection loops that brute-force past individual denials.

**MCP tool interception** — extend hook coverage beyond Bash and file tools to MCP server tool calls. Currently, an agent could use an MCP tool (e.g., a database connector or HTTP client) to exfiltrate data without triggering network-egress or file-access hooks. This would add a configurable matcher layer for MCP tool names and their parameters.

**Obfuscation detection** — catch base64-encoded commands (`echo dW5hbWU= | base64 -d | sh`), hex-encoded payloads, and multi-stage shell evasion patterns. The current deny-destructive hook inspects the literal command string, which means encoded or aliased invocations can bypass it.

**Audit log viewer** — a CLI command (`npx claude-hardening audit`) that parses `~/.claude/audit.log` and outputs a human-readable summary: commands run, files touched, blocks triggered, session timeline. Makes post-session review practical without manually reading JSONL.

**CI integration** — a test harness that runs the full hook suite in CI (GitHub Actions, etc.) so that changes to hook logic or allowlists are validated before deployment. Includes a matrix of known-good and known-bad inputs for regression testing.

## Uninstall

```bash
cd claude-hardening
./uninstall.sh
```

The uninstaller:
1. Removes all 7 hook scripts from `~/.claude/scripts/hooks/`
2. Restores `settings.json` from the backup created during install (or surgically removes just the hardening hooks if no backup exists, preserving your other settings)
3. Asks whether to remove config files (`network-allowlist.json`, `file-access-policy.json`)
4. Asks whether to remove audit logs
5. Asks whether to remove backup files

Every step asks before deleting. Your `settings.json` is backed up again before the restore, so you can always undo.

## License

MIT
