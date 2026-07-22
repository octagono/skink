# `.agents/` — Agent Skills

## Purpose

Project-level agent skills shipped with the skink repo. Each skill is a self-contained instruction set in the [agentskills.io](https://agentskills.io) format that an AI coding agent (opencode, Claude Code, Cursor, etc.) discovers and loads on demand to perform skink-related tasks correctly.

This directory mirrors the user-level install at `~/.agents/skills/`, so anyone who clones the repo gets the same skills automatically without a separate install step.

## Ownership

Owned by the skink maintainers. Skills here document the skink CLI as it exists in this repo — update a skill whenever the CLI surface it documents changes (flags, ports, defaults, transports, gotchas).

## Local Contracts

- **Format:** agentskills.io. Each skill lives in `skills/<name>/SKILL.md` with YAML frontmatter (`name` = `<name>`, required; `description` required, ≤1024 chars, imperative + keyword-rich; optional `license`, `metadata`).
- **Folder name MUST equal the `name` field** (lowercase + hyphens).
- **Body:** markdown, <500 lines. Lead with what agents get wrong (gotchas), command patterns, and defaults — not menu dumps.
- **Deep scenarios** go in `skills/<name>/references/` (one level deep), keeping `SKILL.md` lean.
- **Discovery paths** (opencode): `~/.agents/skills/`, `~/.config/opencode/skills/`, `~/.claude/skills/`, and project-level `.agents/skills/`, `.opencode/skills/`, `.claude/skills/`. This project uses `.agents/skills/`.
- **Triggering is model-driven** from the `description` field — pack it with the keywords and "Use when..." triggers an agent would actually say, including cases where the user does not name skink explicitly.
- **Sync with `~/.agents/skills/skink/`:** when the project skill changes, mirror it to the user-level install and vice versa.

## Work Guidance

- Keep the skill accurate to the installed binary's behavior, not aspirational features.
- The highest-value content is the **gotchas** section — the flags, ports, and transport constraints an agent would otherwise rediscover by failing. Add new gotchas as they are learned.
- Reference the repo `README.md` for user-facing prose; the skill should be agent-facing (commands, defaults, failure modes).

## Verification

No automated check. Manual validation when editing a skill:
1. Frontmatter parses; `name` matches the folder; `description` ≤1024 chars.
2. Body <500 lines; deep scenarios in `references/`.
3. Commands in the skill match the current CLI flags (`skink --help`, `skink <subcommand> --help`).
4. If the project skill was edited, mirror to `~/.agents/skills/skink/`.

## Child DOX Index

- **`skills/skink/`** — The skink CLI skill. `SKILL.md` (command reference + gotchas + agent integration) and `references/operations.md` (reverse-shell patterns, Tor/onion relay setup, multi-hop chaining, VPS hardening, opsec notes).
