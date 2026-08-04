# Changelog

All notable changes to this project will be documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0-alpha.2] - 2026-08-04

### Fixed

- Prevented zero-OID blame placeholders from reaching `git show` in CRLF checkouts, restoring
  historical recovery for `why` and `defuse`.
- Restored direct blast references and tests reached through package-module aliases.
- Reduced non-empty collection false positives after terminating guards and in short-circuit
  collection access.
- Removed unrelated substring matches from candidate-test discovery.
- Distinguished multiple call occurrences on the same line with stable occurrence locations.

### Changed

- Added bounded coverage and evaluated-signal risk interpretation to assumptions results.
- Added optional Unicode column locations to Python AST blast reference and test impacts when
  available.
- Kept `landmine.result.v1`; coverage and column are optional additive fields. Consumers must use
  the latest schema included with alpha.2 because older schema copies reject unknown fields.

## [0.1.0-alpha.1] - 2026-08-04

### Added

- Implemented `why`, `assumptions`, `blast`, and `defuse` for bounded local analysis.
- Added Python assumption detectors and deterministic Markdown/JSON output using
  `landmine.result.v1`.
- Added read-only Git analysis with repository-content execution defenses.
- Added sdist/wheel inspection, fresh-install CLI/schema smoke tests, and a security release gate.

### Known limitations

- Assumption detection is a bounded Python rule set, and blast analysis is depth-one Python impact.
- Remote providers, automatic edits, hooks, marketplace publication, and definitive security or
  complete static-analysis claims are not supported.
