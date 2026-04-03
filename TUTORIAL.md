Phase 1 — Foundation and project wiring
Step 1

Goal: Create the project skeleton and package layout.
Short description: Sets up the Python package, CLI package, tests folder, and resource folders.
Build: pyproject.toml, base package folders, empty modules, .gitignore, basic README update.
Commit message: chore: initialize project structure for password strength cli

Step 2

Goal: Add package metadata and installable CLI entrypoint.
Short description: Makes the project runnable as a CLI with a console command.
Build: CLI entrypoint in pyproject.toml, __init__.py, placeholder main() in cli.py.
Commit message: feat: add installable cli entrypoint

Step 3

Goal: Add a minimal Typer or argparse CLI shell.
Short description: Creates the base CLI app with help text and a version command.
Build: password_strength/cli.py, --version, top-level help.
Commit message: feat: add base cli shell with version command

Step 4

Goal: Add shared constants and project paths.
Short description: Centralizes app name, version lookup, resource paths, and default filenames.
Build: constants.py or settings.py.
Commit message: refactor: add shared constants and resource path helpers

Step 5

Goal: Add structured exception classes.
Short description: Creates custom exceptions for input, config, policy, export, and internal errors.
Build: exceptions.py.
Commit message: feat: add structured exception hierarchy

Step 6

Goal: Add a logging utility.
Short description: Provides quiet, verbose, and debug logging modes for the whole app.
Build: logging_utils.py.
Commit message: feat: add configurable cli logging utilities

Step 7

Goal: Add the main orchestration module.
Short description: Creates passwords.py as the central pipeline coordinator.
Build: pipeline shell with stub stages.
Commit message: feat: add central password audit orchestrator

Step 8

Goal: Add a first-pass test setup.
Short description: Configures pytest and adds a smoke test so the repo is testable immediately.
Build: tests/test_smoke.py, pytest config.
Commit message: test: add initial pytest setup and smoke coverage

Step 9

Goal: Add code quality tooling.
Short description: Sets up formatting, linting, and optional type checking.
Build: Ruff/Black/MyPy config in pyproject.toml.
Commit message: chore: add linting formatting and type checking config

Step 10

Goal: Document the pipeline design.
Short description: Adds architecture notes so every later commit follows the same flow.
Build: docs/architecture.md or README section.
Commit message: docs: add end to end password audit pipeline design

Phase 2 — Data models, config, and shared plumbing
Step 11

Goal: Add PasswordCandidate.
Short description: Represents one raw input password and its source metadata.
Build: models.py dataclass.
Commit message: feat: add PasswordCandidate model

Step 12

Goal: Add SanitizationResult.
Short description: Stores raw text, cleaned text, actions taken, and warnings.
Build: dataclass in models.py or separate module.
Commit message: feat: add SanitizationResult model

Step 13

Goal: Add PolicyCheckResult.
Short description: Stores per-rule pass/fail outcomes and failed rule names.
Build: dataclass with booleans and summary properties.
Commit message: feat: add PolicyCheckResult model

Step 14

Goal: Add PatternMatchResult.
Short description: Stores regex hits like repeated chars, sequences, dates, and keyboard patterns.
Build: dataclass with pattern hit lists.
Commit message: feat: add PatternMatchResult model

Step 15

Goal: Add DictionaryMatchResult.
Short description: Stores banned-password and dictionary matches, including normalized hits.
Build: dataclass.
Commit message: feat: add DictionaryMatchResult model

Step 16

Goal: Add PasswordScore.
Short description: Stores entropy, penalties, bonuses, final score, and strength label.
Build: dataclass.
Commit message: feat: add PasswordScore model

Step 17

Goal: Add PasswordAuditResult.
Short description: Represents the final per-password exportable result.
Build: dataclass combining all sub-results.
Commit message: feat: add PasswordAuditResult model

Step 18

Goal: Add BatchAuditSummary.
Short description: Tracks totals, duplicates, counts by severity, and summary metrics.
Build: dataclass.
Commit message: feat: add BatchAuditSummary model

Step 19

Goal: Add RunReport.
Short description: Stores global run metadata, timing, counts, exit code, and output destinations.
Build: dataclass.
Commit message: feat: add RunReport model

Step 20

Goal: Add to_dict() serialization for all public models.
Short description: Makes every export-facing model JSON- and CSV-friendly.
Build: serialization helpers.
Commit message: feat: add serialization helpers for audit models

Phase 3 — Config and validation layer
Step 21

Goal: Add the config model.
Short description: Creates a structured policy/config object with defaults.
Build: config.py, PasswordPolicyConfig.
Commit message: feat: add password policy config model

Step 22

Goal: Add config loading from JSON.
Short description: Loads policy config from a JSON file safely.
Build: load_config() function.
Commit message: feat: add json policy config loading

Step 23

Goal: Add optional YAML config support.
Short description: Supports enterprise-style policy files in YAML.
Build: safe YAML loading fallback.
Commit message: feat: add yaml policy config support

Step 24

Goal: Add config validation rules.
Short description: Rejects invalid thresholds and contradictory settings early.
Build: validate_config() with custom exceptions.
Commit message: feat: validate password policy config values

Step 25

Goal: Add built-in policy presets.
Short description: Provides default, strict, and passphrase-friendly preset policies.
Build: resource preset files and loader helpers.
Commit message: feat: add built in password policy presets

Step 26

Goal: Add CLI overrides for config values.
Short description: Lets command-line flags override config file settings cleanly.
Build: config merge logic.
Commit message: feat: add cli overrides for policy config

Phase 4 — Input ingestion and preprocessing
Step 27

Goal: Add single password input mode.
Short description: Supports --password for one password directly from CLI.
Build: input parser helpers.
Commit message: feat: add single password cli input mode

Step 28

Goal: Add hidden interactive password prompt.
Short description: Uses secure hidden input for interactive auditing.
Build: getpass() integration.
Commit message: feat: add hidden interactive password prompt

Step 29

Goal: Add file input mode.
Short description: Supports reading one file containing one password per line.
Build: file reader utility.
Commit message: feat: add batch password file ingestion

Step 30

Goal: Add multi-file input mode.
Short description: Lets one run ingest several files and preserve source metadata.
Build: --files support.
Commit message: feat: add multi file password ingestion

Step 31

Goal: Add stdin piping support.
Short description: Supports shell pipelines and script-based input.
Build: stdin reader.
Commit message: feat: add stdin password ingestion mode

Step 32

Goal: Add robust encoding and file error handling.
Short description: Handles UTF-8, fallback encodings, missing files, unreadable files, and empty inputs.
Build: safer readers and custom exceptions.
Commit message: feat: harden file reading and encoding fallback behavior

Step 33

Goal: Add preprocessing into normalized candidates.
Short description: Converts all input types into a common list of PasswordCandidate records.
Build: normalization pipeline.
Commit message: feat: normalize all inputs into PasswordCandidate records

Phase 5 — Sanitization integration
Step 34

Goal: Add sanitization utilities.
Short description: Removes BOMs, control chars, zero-width chars, and ANSI escapes.
Build: sanitizer.py.
Commit message: feat: add password input sanitization utilities

Step 35

Goal: Add whitespace normalization rules.
Short description: Normalizes Unicode whitespace and supports optional trimming.
Build: sanitization options in config.
Commit message: feat: add unicode whitespace normalization and trim controls

Step 36

Goal: Add suspicious hidden-character detection.
Short description: Warns when invisible or unexpected characters were found.
Build: warning codes and audit actions.
Commit message: feat: detect suspicious hidden characters in password input

Step 37

Goal: Preserve raw and cleaned values with action logs.
Short description: Keeps original values in memory while tracking exactly what changed.
Build: sanitization audit trail.
Commit message: feat: preserve raw and cleaned password values for audit mode

Step 38

Goal: Add duplicate-password detection in preprocessing.
Short description: Detects reused passwords across a batch before scoring.
Build: duplicate tracking helper.
Commit message: feat: add duplicate password detection across batch input

Phase 6 — Core policy engine
Step 39

Goal: Add minimum/maximum length checks.
Short description: Validates password length against policy thresholds.
Build: policy.py basic validators.
Commit message: feat: add length policy validation

Step 40

Goal: Add lowercase, uppercase, digit, and special character checks.
Short description: Validates required character classes.
Build: policy checks for class presence.
Commit message: feat: add character class policy validation

Step 41

Goal: Add unique character count and class count checks.
Short description: Measures diversity beyond simple presence checks.
Build: unique-count validation.
Commit message: feat: add password diversity policy checks

Step 42

Goal: Add prohibited and allowed character checks.
Short description: Supports enterprise restrictions on specific characters and special sets.
Build: policy validation for allowed/prohibited chars.
Commit message: feat: add prohibited and allowed character policy checks

Step 43

Goal: Add repeat-threshold and whitespace edge rules.
Short description: Enforces no excessive repeated symbols and no leading/trailing spaces.
Build: extra policy rules.
Commit message: feat: add repeat threshold and edge whitespace policy rules

Phase 7 — Pattern detection engine
Step 44

Goal: Add repeated-character regex detection.
Short description: Flags runs like aaaaaa or 111111.
Build: regex helpers in patterns.py.
Commit message: feat: detect repeated character patterns

Step 45

Goal: Add repeated-chunk detection.
Short description: Flags patterns like abcabc, 121212, and passpass.
Build: regex/chunk analysis logic.
Commit message: feat: detect repeated chunk patterns

Step 46

Goal: Add sequential and reverse-sequential detection.
Short description: Flags predictable sequences like abcd, 1234, dcba, and 4321.
Build: sequence scanning helpers.
Commit message: feat: detect sequential and reverse sequence patterns

Step 47

Goal: Add keyboard pattern detection.
Short description: Flags strings like qwerty, asdf, zxcvbn, and row variants.
Build: resource-driven keyboard matching.
Commit message: feat: detect keyboard row patterns

Step 48

Goal: Add year/date pattern detection.
Short description: Flags years, birthdays, and common date-shaped fragments.
Build: year/date regexes.
Commit message: feat: detect year and date patterns in passwords

Step 49

Goal: Add personal identifier pattern detection.
Short description: Detects email-like, phone-like, username-like, and domain-like substrings.
Build: pattern matchers with optional user context.
Commit message: feat: detect personal identifier patterns

Step 50

Goal: Add the first complete audit pipeline command.
Short description: Connects input, sanitization, policy, pattern checks, and scoring into a working audit command.
Build: end-to-end CLI run path with console output.
Commit message: feat: deliver first complete password audit command