# Password Strength Architect — Project Conventions

This document defines the coding and architectural conventions for the Password Strength Architect project.

## Core principles

1. Use type hints everywhere.
2. Prefer dataclasses for structured result models.
3. Keep functions small and single-purpose.
4. Separate orchestration from domain logic.
5. Prefer explicit, serializable outputs.
6. Use custom exceptions instead of generic runtime failures.
7. Keep CLI output stable for automation.
8. Mask sensitive values by default.
9. Write tests for every new behavior.
10. Avoid hidden side effects.

## Module responsibilities

### `passwords.py`
Top-level orchestration only. This module coordinates the pipeline and should not contain deep validation logic.

### `models.py`
Structured data containers for password input, validation results, scoring, audit results, and run summaries.

### `policy.py`
Deterministic policy checks such as length, character classes, uniqueness, and allowed character constraints.

### `patterns.py`
Pattern-detection logic such as repeated characters, repeated chunks, sequences, reverse sequences, and keyboard patterns.

### `dictionary.py`
Common-password, banned-token, and normalization-based weak-token checks.

### `scoring.py`
Strength scoring, entropy estimation, penalties, bonuses, and classification inputs.

### `feedback.py`
Human-readable remediation guidance and warning summaries.

### `exporters.py`
JSON, JSONL, CSV, and console-safe rendering helpers.

### `exceptions.py`
Custom exception hierarchy only.

### `cli.py`
Argument parsing, command routing, top-level process exit behavior.

## Naming conventions

- Use `snake_case` for functions, variables, and module-level helpers.
- Use `PascalCase` for dataclasses and exceptions.
- Use clear domain names such as `PasswordAuditResult`, not vague names like `ResultData`.
- Prefer `*_result`, `*_record`, `*_summary`, and `*_config` suffixes where appropriate.

## Function conventions

- Public functions must have docstrings.
- Functions should return structured values, not mixed tuples with unclear meaning.
- Avoid boolean flags when an enum-like value or explicit function would be clearer.
- Validate inputs near boundaries.

## Security conventions

- Never print raw passwords by default.
- Never log plaintext passwords in debug helpers.
- Preserve raw values in memory only when necessary for audit workflows.
- Prefer masked or fingerprinted display values in terminal output.

## Testing conventions

- Add at least one test file per new behavior area.
- Test both expected success and expected failure conditions.
- Keep tests deterministic and fast.
- Avoid network access and time-dependent behavior unless explicitly mocked.

## CLI conventions

- Command names must stay stable once introduced.
- Output should be machine-friendly when requested.
- Exit codes should be deterministic.
- Help text should include practical examples once commands are implemented.

## Serialization conventions

- Export-facing models should support a `to_dict()` method.
- Serialized output keys should remain stable over time.
- Export logic should live outside core scoring and validation modules.

## Scope discipline

If code does not support the defined v1 scope, defer it instead of partially implementing it.