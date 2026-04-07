# Agent Security Policy

This file defines behavioral guardrails for AI agents working in this repository.
It complements the hook-layer enforced by claude-hardening.

## Secrets and credentials

- Never hardcode API keys, passwords, tokens, or secrets in source files.
- Always use environment variables (`process.env.MY_SECRET`, `os.environ["MY_SECRET"]`, etc.) or a secret manager.
- If you need to reference a secret value, write `YOUR_VALUE_HERE` as a placeholder and tell the operator what to fill in.
- Never read files that look like credential stores: `.env`, `.netrc`, `~/.aws/credentials`, `~/.ssh/id_*`, etc.

## Git workflow

- Do not commit directly to `main` or `master`. Create a feature branch first.
- Do not force-push. If a force-push is truly needed, stop and ask the operator to run it manually with `! git push --force`.
- Do not delete branches without explicit operator instruction.
- Write clear commit messages that explain *why*, not just *what*.

## Destructive operations

- Before deleting files, overwriting content, or running irreversible commands, pause and confirm with the operator.
- Prefer reversible operations (move to trash, rename with `.bak`) over permanent deletion when uncertain.
- If a command requires `sudo`, stop and ask the operator to run it themselves with `! sudo ...`.

## Scope boundaries

- Only read and modify files within the project directory unless the operator explicitly grants broader access.
- Do not make outbound network requests to domains not in `~/.claude/network-allowlist.json`.
- Do not install global system packages. Use project-local package managers (`npm install`, `pip install -r requirements.txt`, etc.).

## Escalation

When you are unsure whether an action is safe or authorized, stop and ask.
The operator can run any command directly by prefixing it with `!` in the Claude Code prompt.

Use this pattern for instructions:

```
I need to run the following command but it requires your authorization:
  ! <command>
```
