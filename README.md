# claude-hardening

Security hooks for Claude Code that prevent AI agents from running destructive commands or exfiltrating data through shell access.

## What it does

Two PreToolUse hooks that intercept every Bash command before the agent executes it:

**deny-destructive** — blocks dangerous system commands

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

## Install

```bash
git clone https://github.com/YOUR_ORG/claude-hardening.git
cd claude-hardening
./install.sh
```

The installer:
1. Copies hook scripts to `~/.claude/scripts/hooks/`
2. Creates `~/.claude/network-allowlist.json` (won't overwrite if it exists)
3. Configures `~/.claude/settings.json` (or prints manual instructions if the file already exists)

Requires Node.js 18+.

## Files

```
claude-hardening/
├── hooks/
│   ├── deny-destructive.js          # Destructive command deny list
│   └── network-egress.js            # Network egress control
├── network-allowlist.example.json   # Default trusted domains
├── settings.example.json            # Example settings.json snippet
├── install.sh                       # Installer script
└── README.md
```

After install, your `~/.claude/` will contain:

```
~/.claude/
├── scripts/hooks/
│   ├── deny-destructive.js
│   └── network-egress.js
├── network-allowlist.json
└── settings.json
```

## Customizing the allowlist

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

Changes take effect immediately — the hook reads the file on every command. No restart needed.

Subdomains are matched automatically: adding `github.com` also allows `api.github.com`, `raw.githubusercontent.com` won't match though — add it explicitly if needed.

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

**Both hooks:** remove the hook entries from `~/.claude/settings.json`.

## Coverage and limitations

| Threat | Covered |
|---|---|
| Recursive filesystem deletion | Yes |
| Privilege escalation (sudo) | Yes |
| Destructive git operations | Yes |
| Data exfiltration via curl/wget | Yes |
| Raw socket connections (netcat) | Yes |
| SSH/SCP to unknown hosts | Yes |
| Dynamic/variable URLs | Yes |
| Fork bombs / disk destruction | Yes |
| DNS tunneling | No |
| Obfuscated/aliased commands | Partial |
| Non-shell exfiltration (MCP tools) | No |

These hooks inspect the command string, not the shell execution environment. Sophisticated evasion through aliasing, encoding, or subshell tricks is possible but raises the bar significantly against prompt injection attacks.

## Uninstall

```bash
rm ~/.claude/scripts/hooks/deny-destructive.js
rm ~/.claude/scripts/hooks/network-egress.js
rm ~/.claude/network-allowlist.json
```

Then remove the two hook entries from `~/.claude/settings.json`.

## License

MIT
