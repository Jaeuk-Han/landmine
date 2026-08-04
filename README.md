# Landmine

Landmine finds hidden code-change risks from local Git history and current repository evidence.

This repository is an **alpha release candidate**. The `why`, `assumptions`, `blast`, and
`defuse` commands are implemented, but their scope is deliberately bounded. Results are evidence-led
review aids, not definitive security verdicts or complete static analysis.

## Requirements and installation

Landmine requires Python 3.11 or newer and Git. It has no runtime Python dependencies and does not
need network access during analysis.

No package has been claimed as published yet. After obtaining or building the candidate wheel,
install that local artifact:

```bash
python -m pip install dist/landmine-0.1.0a1-py3-none-any.whl
landmine --version
```

For development from a checkout:

```bash
python -m venv .venv
# Activate .venv using the command for your shell, then:
python -m pip install -e ".[dev]"
landmine --help
```

With `uv`, `uv sync --extra dev` and `uv run landmine --help` provide the equivalent development
setup.

## Five-minute quick start

Run Landmine inside any local Git repository, or pass `--repo`:

```bash
# Whole path
landmine why src/routing.py

# One line or an inclusive line range
landmine why src/routing.py:214
landmine assumptions src/routing.py:200-230

# Exact lexical symbol target; ambiguous symbols return candidate locations
landmine why symbol:select_route

# Direct Python impact and a non-executing change plan
landmine blast "change empty-result handling" --target symbol:select_route
landmine defuse symbol:select_route --goal "support empty results"
```

Markdown is the default. A shortened example looks like this:

```markdown
# Landmine why

## Summary
Recovered local Git evidence for `src/routing.py:214`.

## Findings
- Historical intent — verified (evidence: `ev_...`)

## Evidence
- Excerpt (untrusted data): ...
```

Use `--format json` for the stable `landmine.result.v1` envelope:

```json
{
  "schema_version": "landmine.result.v1",
  "analysis_status": "complete",
  "command": "why",
  "repository": {"root": ".", "head": "<40-hex-sha>", "dirty": false, "shallow": false, "base": null},
  "findings": [],
  "evidence": [],
  "plan": {"preconditions": [], "tests": [], "steps": [], "verification": [], "rollback_triggers": []},
  "limitations": [],
  "metrics": {"elapsed_ms": 0, "files_scanned": 0, "commits_scanned": 0, "evidence_count": 0}
}
```

The JSON above is illustrative and omits required identity and timestamp fields. Validate real output
against [`schemas/result-v1.schema.json`](schemas/result-v1.schema.json).

## Implemented command scope

### `why TARGET`

Accepts a path, `path:line`, `path:start-end`, or `symbol:name`. It uses bounded `blame`, line
history, follow-history, commit metadata, diffs, and related-test evidence. Symbol discovery is exact
lexical matching in tracked Python and JavaScript/TypeScript source. Rename following is always on;
`--no-follow-renames` is accepted for compatibility but does not disable it in this alpha.

### `assumptions TARGET`

Runs implemented Python detectors for non-empty collections, required mapping keys, required
environment variables, required external JSON response fields, arbitrary set selection,
working-directory-relative file access, and wall-clock duration/deadline use. `--category` can select
`data`, `environment`, `external_contract`, `ordering`, `filesystem`, or `time`. It does not claim
coverage for every category represented by the schema.

### `blast CHANGE --target TARGET`

Requires a target and accepts the change description only as data. The current slice supports Python
and `.pyi`, depth `1`, exact definitions, same-module references, direct imports/references, direct
tests, candidate tests, and public-package re-export evidence. It does not compute second-hop,
co-change, behavioral, or operational impact. Other languages and `--depth` values above one return
an explicit partial or failed result.

### `defuse TARGET --goal GOAL`

Runs `why`, `assumptions`, and `blast` against one repository snapshot, then proposes preconditions,
characterization tests, modification steps, verification commands, rollback triggers, and unknowns.
It never executes source, pytest, rollback commands, or plan items. `--from-result` is reserved and
returns a structured failed result in this alpha.

All commands accept `--repo`, `--format`, `--output`, `--timeout`, `--max-files`, and
`--max-commits`; a command can reserve a shared budget option when its current implementation does
not use that dimension. The help output is the source of truth. `--base`, `--include`, `--exclude`,
and `--verbose` are currently reserved and have no analysis effect; output is always plain even
though `--no-color` is accepted.

## Status and exit codes

The JSON `analysis_status` and process exit code have different roles:

| Result | Meaning | Exit code |
|---|---|---:|
| `complete` | The implemented scope completed without a reported limitation. | `0` |
| `partial` | Useful evidence exists, but a budget, history, language, or provider limitation remains. | `1` |
| `failed` | No usable result was produced for the request; JSON includes `error`. | `2` |

Argument/target parsing errors also use `2`. A Git query timeout before a result exists uses `1`, and
another Git/preflight failure uses `3`; these are written to stderr. Automation should inspect both
the exit code and JSON status.

## Safety and privacy

Analyzers are read-only. They use an allowlist of non-mutating Git operations with argument arrays,
`shell=False`, time and output limits, pager/config hardening, and `--` before path arguments where
applicable. Repository source, filenames, commit subjects, diffs, and tool output are untrusted data:
Landmine reads them but does not execute them. Evidence excerpts are bounded and common private keys,
authorization values, tokens, passwords, and credential-bearing connection strings are redacted.

Landmine has no network provider and makes no application-level network request during analysis.
The host agent or installation tool can have a separate data and network policy. See
[`SECURITY.md`](SECURITY.md) for the threat model and reporting guidance.

## Python CLI and agent packaging

The Python wheel contains the `landmine` package, console command, metadata, README, and license. The
JSON schema and public release documents are included in the source distribution. The Codex bundle is
a separate repository artifact consisting of `.codex-plugin/plugin.json` and `skills/landmine/`;
those files are not Python runtime data and are intentionally not copied into the wheel.

There is no official marketplace registration yet. Until a verified marketplace installer is
documented, use the repository files for manual Codex integration: place the `skills/landmine`
directory in the skills location managed by your Codex installation and keep the manifest with the
repository plugin bundle. Consult the documentation for your installed Codex version for its exact
user-level path; this project does not guess a platform-specific command.

Claude Code has no dedicated command, hook, or marketplace bundle in this alpha. It can invoke the
installed Python CLI manually, but repository plugin installation is not claimed. Official Codex or
Claude marketplace publication is a future plan.

## Known alpha limitations

- Local Git repositories only; no GitHub/GitLab lookup, fetch, issue, or pull-request provider.
- No automatic edits, hook installation, blocking hook, UI, cache, SARIF, or remote service.
- `assumptions` is a bounded Python detector set, not general semantic or security analysis.
- `blast` is Python-only direct impact; dynamic/wildcard imports become limitations.
- Symbol lookup is lexical and can be ambiguous; generated, binary, oversized, and unsupported files
  are skipped or reported.
- Shallow/incomplete history, dirty worktrees, timeouts, and scan/output budgets can produce partial
  results.
- Reserved CLI options described above do not yet change analysis.
- The schema is v1, but the product and detector behavior remain alpha and may evolve compatibly.

## Development and release-candidate verification

Run the narrowest relevant test first, then the complete gates:

```bash
python -m pytest
ruff format --check .
ruff check .
mypy src
python -m build
python tools/inspect_artifacts.py dist
python tools/fresh_install_smoke.py --dist dist --schema schemas/result-v1.schema.json
python -m pytest tests/release/test_security_gate.py
git diff --check
```

The plugin and skill validators are also required before handoff when the corresponding Codex
development validators are installed. They are not downloaded or executed from repository content.

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and
[`CHANGELOG.md`](CHANGELOG.md). All README links point to files included in the public repository.
