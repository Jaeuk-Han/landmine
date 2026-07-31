# Contributing

## Development setup

Preferred:

```bash
uv sync --all-groups
uv run pytest
```

Fallback:

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pytest
```

Exact dependency groups will be defined in `pyproject.toml` during Phase 0.

## Working agreement

1. Open or reference a focused issue.
2. Add a fixture when changing analysis behavior.
3. Keep pull requests small enough to review evidence logic.
4. Preserve schema compatibility.
5. Include before/after output for scoring or renderer changes.
6. Do not mix unrelated refactors with behavior changes.

## Commit conventions

Use imperative Conventional Commits:

```text
feat(why): follow file history across renames
fix(git): pass dash-prefixed paths after separator
test(blast): add co-change decoy fixture
docs(schema): clarify partial result behavior
```

## Pull request checklist

- [ ] behavior is within current product scope
- [ ] tests/fixtures cover the change
- [ ] no unsupported claim is promoted to verified
- [ ] analyzers remain read-only
- [ ] output is deterministic
- [ ] schema and docs are updated
- [ ] security implications are reviewed
- [ ] `pytest`, `ruff`, and `mypy` pass
- [ ] no secrets, private repository content, or personal paths are committed

## Adding an assumption detector

Document:

- category
- observable signal
- evidence requirements
- likely false positives
- suppression conditions
- confidence ceiling
- positive and negative fixtures

A lexical match alone has a maximum status of `inferred`.

## Adding a language adapter

Implement a narrow interface for definitions, references, imports, and test mapping. Failure must return a limitation and fall back to lexical analysis. Adapters may not change stable schema fields or invoke the network.

## Changing scoring

Scoring changes require:

- rationale and expected user impact
- fixture pairwise ranking results
- old/new component values
- no hidden LLM-generated numeric score
- documentation update

## Reporting bugs

Include Landmine version, OS, Python/Git versions, command with secrets removed, exit code, sanitized output, and whether the repository is shallow or dirty. Do not attach proprietary source or full Git history unless you are authorized.

## Code of conduct

Be specific, respectful, and evidence-oriented. Critique claims and implementations, not people.
