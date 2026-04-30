# AGENTS.md

This file is intended for AI coding agents. It is kept human-readable so contributors can also use it as a quick-reference guide.

When official documentation is not explicitly provided or it's insufficient, you MUST delegate to the `docs-explorer` subagent (see `.agents/subagents/docs-explorer.md`) to look up current official documentation for the relevant libraries and technologies.

## What This Project Is

An Ansible collection (`community.rabbitmq`) providing modules and lookup plugins for managing RabbitMQ servers. It includes modules for managing exchanges, queues, bindings, users, vhosts, policies, parameters, plugins, feature flags, and upgrades, as well as a lookup plugin.

## Development Environment

The collection must reside at `ansible_collections/community/rabbitmq/` (relative to a directory on `ANSIBLE_COLLECTIONS_PATHS`) for imports to resolve correctly.

For test commands, patterns, and requirements see `.agents/skills/run-tests/SKILL.md`.

## Coding Guidelines

- Follow these software development principles: KISS (Keep It Simple, Stupid), DRY (Don't Repeat Yourself), YAGNI (You Aren't Gonna Need It), Separation of Concerns, Composition over Inheritance, and Convention Over Configuration.
- Prioritize code simplicity and readability over flexibility.
- Favor simple, short, and easily testable functions with no side effects over classes. Use classes only when they naturally fit the problem and help avoid boilerplate code while grouping tightly related functionality.
- Use `snake_case` for all variable and parameter names.
- Shared code used by multiple modules belongs in `plugins/module_utils/`. Do not duplicate connection or utility logic in individual modules.
- All modules must pass sanity, unit, and integration tests before merging.
- Keep each piece of work focused on solving a single, specific issue or task. Do not mix unrelated changes (e.g., a bugfix and an unrelated refactoring) in the same branch or PR.
- Use conventional commit message prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`. Example: `fix: handle missing vhost in rabbitmq_user`.

## Development Conventions

- Every new module parameter and new module requires `version_added: 'x.y.z'` in its DOCUMENTATION block, set to the next planned release version.
- Every PR that changes module behavior needs a changelog fragment in `changelogs/fragments/<something>.yaml`. Docs/tests/refactoring PRs are exempt. Valid fragment sections: `major_changes`, `minor_changes`, `bugfixes`, `breaking_changes`, `deprecated_features`, `removed_features`, `security_fixes`, `known_issues`. Fragments are consumed (deleted) at release time (`keep_fragments: false` in `changelogs/config.yaml`).
- Tests are required for code changes; see `.agents/skills/run-tests/SKILL.md` for test commands, patterns, and requirements.

## Subagents

Subagent definitions live in `.agents/subagents/`. When a task matches a subagent's trigger conditions, delegate to it.

## Agent Skills

Skills live in `.agents/skills/*/SKILL.md` (YAML frontmatter + instructions). At session start, scan and register all skills. When a request matches a skill's trigger, load and apply it.
