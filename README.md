<p align="center">
  <img src="logo.png" alt="claude-hardening" width="200" />
</p>

<h1 align="center">claude-hardening</h1>

<p align="center">A hardening kit for Claude Code that blocks destructive commands, controls network egress, protects credentials, and keeps AI agents from going rogue.</p>

## What it does

Six hooks that intercept tool calls before or after the agent executes them:

### PreToolUse hooks

**deny-destructive** — blocks dangerous shell commands

| Tier | Commands | Behavior |
|---|---|---|
| Hard block | `rm -rf /`, `mkfs`, `dd if=`, fork bombs, `shred`, `wipefs` | Permanently blocked — never safe for autonomous execution |
| Warn + stop | `sudo`, `git push --force`, `git reset --hard`, `chmod 777`, `kill -9`, `reboot`, `shutdown` | Blocked with instructions for the user to run it manually |

**network-egress** — blocks outbound network requests to unknown domains

| What | Behavior |
|---|---|
| `curl`/`wget` to unknown domains | Blocked — prevents data exfiltration |
| `nc`/`ncat`/`netcat` | Blocked unless target domain is on allowlist |
| `ssh`/`scp`/`rsync` to unknown hosts | Blocked |
| Dynamic/variable URLs (`curl $URL`) | Blocked — destination can't be verified |
| Requests to allowlisted domains | Passes through normally |
| localhost / 127.0.0.1 | Always allowed |

**git-guard** — warns on direct commits or pushes to main/master

| What | Behavior |
|---|---|
| `git push origin main` | Blocked — redirected to feature branch |
| `git commit` (any) | Stopped with branch-check reminder |
| `git branch -D main` | Blocked — deleting primary branch |

**file-access** — blocks reads and writes to sensitive files

| What | Behavior |
|---|---|
| `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.kube/` | Blocked |
| `.env`, `.env.*`, `.env.local` | Blocked |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | Blocked |
| Files matching `credentials`, `secret`, `token`, `apikey` | Blocked |
| `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | Blocked |
| `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc` | Blocked |
| Normal project files | Pass through |

Applies to **Read, Write, Edit, and Glob** tool calls.
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

**audit-log** — appends a JSONL entry to `~/.claude/audit.log` for every Bash command and file write. Never blocks — silent observer only.

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
1. Copies all six hook scripts to `~/.claude/scripts/hooks/`
2. Creates `~/.claude/network-allowlist.json` (won't overwrite if it exists)
3. Creates `~/.claude/file-access-policy.json` (won't overwrite if it exists)
4. Configures `~/.claude/settings.json` (or prints manual instructions if the file already exists)
5. Syntax-checks each hook with Node.js

Requires Node.js 18+.

## Verify

```bash
npm test
```

Runs 32 tests covering every hook — pass/fail rules, edge cases, and allow-list behavior.

## Files

```
claude-hardening/
├── hooks/
│   ├── deny-destructive.js          # Destructive shell command deny list
│   ├── network-egress.js            # Network egress allowlist control
│   ├── git-guard.js                 # Git branch protection
│   ├── file-access.js               # Sensitive file path protection
│   ├── secret-scan.js               # Credential pattern detection
│   └── audit-log.js                 # Session audit trail (PostToolUse)
├── profiles/
│   ├── standard.json                # All hooks — good default
│   ├── strict.json                  # All hooks + Read in audit log
│   └── readonly.json                # Blocks all Bash and file writes
├── templates/
│   └── CLAUDE.md                    # Behavioral guardrails for agents
├── tests/
│   └── run-tests.js                 # 32 tests across all hooks
├── network-allowlist.example.json   # Default trusted domains
├── file-access-policy.example.json  # File access policy template
├── settings.example.json            # Example settings.json with all hooks
├── package.json                     # npm test entry point
└── install.sh                       # Installer script
```

After install, your `~/.claude/` will contain:

```
~/.claude/
├── scripts/hooks/
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

| Profile | Bash | Writes | Network | File reads | Audit |
|---|---|---|---|---|---|
| `standard.json` | Guarded | Secret-scanned | Allowlisted | Sensitive blocked | Yes |
| `strict.json` | Guarded | Secret-scanned | Allowlisted | Sensitive blocked | Yes (incl. reads) |
| `readonly.json` | Blocked | Blocked | — | Sensitive blocked | No |

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

## Customizing file access

Edit `~/.claude/file-access-policy.json` to extend or override the defaults:

```json
{
  "blockedDirs": [
    ".vault",
    "secrets"
  ],
  "blockedFiles": [
    "*.secret"
  ],
  "allowedPaths": [
    "~/.ssh/known_hosts"
  ]
}
```

- `blockedDirs` — additional directories to block (relative to `~` or absolute)
- `blockedFiles` — additional filename regex patterns to block
- `allowedPaths` — explicit escape hatch for paths you intentionally need access to

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

**Network egress only:** rename the allowlist file. The hook passes through safely when the file is missing:
```bash
mv ~/.claude/network-allowlist.json ~/.claude/network-allowlist.json.disabled
# ... do work ...
mv ~/.claude/network-allowlist.json.disabled ~/.claude/network-allowlist.json
```

**All hooks:** remove the hook entries from `~/.claude/settings.json`.

## Coverage and limitations

| Threat | Covered |
|---|---|
| Recursive filesystem deletion | Yes |
| Privilege escalation (sudo) | Yes |
| Destructive git operations | Yes |
| Direct commits to main/master | Yes |
| Data exfiltration via curl/wget | Yes |
| Raw socket connections (netcat) | Yes |
| SSH/SCP to unknown hosts | Yes |
| Dynamic/variable URLs | Yes |
| Fork bombs / disk destruction | Yes |
| Reading credential files (.ssh, .aws, .env) | Yes |
| Writing secrets / API keys to files | Yes |
| Session audit trail | Yes |
| DNS tunneling | No |
| Obfuscated/aliased commands | Partial |
| Non-shell exfiltration via MCP tools | No |
| Secrets leaked through stdout/response | No |

These hooks inspect the command string and file path/content, not the shell execution environment. Sophisticated evasion through aliasing, encoding, or subshell tricks is possible but raises the bar significantly against prompt injection attacks.

## Uninstall

```bash
cd ~/.claude/scripts/hooks/
rm deny-destructive.js network-egress.js git-guard.js file-access.js secret-scan.js audit-log.js
rm ~/.claude/network-allowlist.json
rm ~/.claude/file-access-policy.json
```

Then remove the hook entries from `~/.claude/settings.json`.

## License

MIT
