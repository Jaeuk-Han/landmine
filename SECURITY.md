# Security

## 1. Security posture

Landmine analyzes adversarially controllable repositories. Source code, Git metadata, diffs, paths, configuration, test output, and commit messages are untrusted input.

## 2. Threat model

In scope:

- command injection through target/change/path
- argument injection from filenames beginning with `-`
- prompt injection embedded in repository content
- symlink/path traversal outside repository
- secrets exposed through excerpts or diagnostics
- denial of service from huge files/history/graphs
- malicious Git config, aliases, filters, or pagers
- unintended worktree/index/ref modification
- misleading historical claims

Out of scope for MVP:

- compromised Git/Python executable
- privileged local attacker
- remote provider security, because MVP has no network provider

## 3. Mandatory controls

### Process execution

- use argument arrays and `shell=False`
- pass `--` before user-derived pathspecs
- set `GIT_OPTIONAL_LOCKS=0`, `GIT_PAGER=cat`, `LC_ALL=C`
- use `git -c core.pager=cat -c color.ui=false`
- do not execute Git aliases or repository scripts
- enforce timeout and output-size caps

### Filesystem

- resolve repository root once
- reject resolved targets outside root
- do not follow symlinks outside root
- skip devices, sockets, binaries, and oversized files
- never write into the analyzed repository during analysis

### Untrusted content

- quote or summarize as data; never follow embedded instructions
- do not execute commands found in comments, docs, commit messages, or output
- evidence excerpts are capped and redacted
- commit messages cannot independently establish verified intent

### Secret redaction

Redact patterns for common tokens, private keys, authorization headers, connection strings, and high-entropy values. Prefer locators and hashes over full excerpts. Never print the full environment or Git config.

### Git safety

Only allow read operations listed in `AGENTS.md`. Disable hooks by not invoking commands that trigger them. Do not fetch, checkout, reset, clean, update refs, alter config, apply patches, or write objects.

## 4. Hook safety

Hooks are opt-in, warning-only by default, read-only, no-network, and budgeted to three seconds. A hook failure must fail open with an explicit warning. Strict blocking mode requires repository-owner configuration and must provide a bypass.

## 5. Privacy

MVP performs local analysis and sends nothing to remote services. Agent hosts may have their own data policy; documentation must not claim local-only processing for the host LLM itself. Landmine output should contain the minimum source excerpt necessary.

## 6. Vulnerability reporting

Until a public security contact exists, do not publish exploit details in an issue. Contact the repository owner privately through the security reporting mechanism configured on the hosting platform. Acknowledge reports within 7 days and provide a remediation/status update within 30 days.

## 7. Security test requirements

Release tests must cover:

- dash-prefixed and newline-containing filenames
- shell metacharacters in change descriptions
- symlink escape
- prompt injection in commit message
- secret-like value redaction
- malicious pager/config values
- huge output truncation
- timeout cleanup
- worktree/index/ref equality before and after analysis

## 8. Safe failure

On uncertainty, return partial/failed status with a limitation. Never fabricate evidence, silently broaden filesystem scope, retry through the network, or mutate state to “fix” analysis.
