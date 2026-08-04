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
- use `git -c core.pager=cat -c color.ui=false -c core.fsmonitor=false`
- remove inherited Git repository/config redirection and external-diff environment variables
- set `GIT_CONFIG_NOSYSTEM=1` and `GIT_ATTR_NOSYSTEM=1`
- do not execute Git aliases or repository scripts
- do not request external diff or textconv processing
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

Redact patterns for common tokens, private keys, authorization headers, and credential-bearing common connection strings. Prefer locators and hashes over full excerpts. Never print the full environment or Git config. Arbitrary high-entropy-string detection is not implemented because it would over-redact ordinary source; this remains an alpha limitation.

### Git safety

Only allow read operations listed in `AGENTS.md`. Disable hooks by not invoking commands that trigger them. Do not fetch, checkout, reset, clean, update refs, alter config, apply patches, or write objects.

## 4. Hook safety

This alpha does not install or ship an analysis hook. If hooks are added later, they must be opt-in, warning-only by default, read-only, no-network, and budgeted. Strict blocking behavior is outside the current release scope.

## 5. Privacy

MVP performs local analysis and sends nothing to remote services. Agent hosts may have their own data policy; documentation must not claim local-only processing for the host LLM itself. Landmine output should contain the minimum source excerpt necessary.

## 6. Vulnerability reporting

Until a public security contact exists, do not publish exploit details in an issue. Contact the repository owner privately through the security reporting mechanism configured on the hosting platform. Acknowledge reports within 7 days and provide a remediation/status update within 30 days.

## 7. Security test requirements

`python -m pytest tests/release/test_security_gate.py` is the release security gate. Together with
the focused unit/integration tests, it covers:

- dash-prefixed and newline-containing filenames
- shell metacharacters in change descriptions
- symlink escape
- prompt injection in commit message
- secret-like value redaction
- malicious pager/config values
- huge output truncation
- timeout cleanup
- worktree/index/ref equality before and after analysis

Newline filenames and symlink escape run on Linux/macOS. Windows uses explicit skips because its
filename rules and default symlink permissions do not reliably support those fixtures. The gate uses
subprocess spies, sentinel paths, and repository digests; it never executes repository source or an
embedded instruction.

## 8. Safe failure

On uncertainty, return partial/failed status with a limitation. Never fabricate evidence, silently broaden filesystem scope, retry through the network, or mutate state to “fix” analysis.
