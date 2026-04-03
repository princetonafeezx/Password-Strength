# Password Strength Architect — Feature Scope

## Version 1.0 scope

The first production version of Password Strength Architect includes these core capabilities:

1. Input sanitization integration
2. Password policy validation
3. Regex-based pattern detection
4. Dictionary and banned-password checks
5. Strength scoring
6. Human-readable feedback
7. Structured export formats
8. CLI commands for audit, validate, score, and export
9. Safe masking by default
10. Basic test coverage for core flows

## In scope for v1

### Input and preprocessing
- Single password input
- File-based batch input
- Standard input support
- Preservation of raw and cleaned values
- Source metadata tracking
- Duplicate password detection
- Hidden character warnings

### Validation and detection
- Minimum and maximum length checks
- Lowercase, uppercase, digit, and special character checks
- Minimum unique character count
- Repeated character detection
- Repeated chunk detection
- Sequential and reverse sequential detection
- Keyboard pattern detection
- Year and date detection
- Email-like and phone-like pattern detection
- Common password blacklist checks
- Custom banned token checks
- Leetspeak-aware normalization

### Scoring and classification
- Weighted scoring model
- Entropy estimation
- Compliance result separate from strength result
- Classification labels
- Ordered remediation suggestions

### Output and CLI
- Masked terminal output by default
- JSON export
- JSONL export
- CSV export
- Stable CLI command names
- Structured exit codes

### Engineering quality
- Dataclass-based models
- Config validation
- Custom exceptions
- Unit tests
- Type hints

## Explicitly out of scope for v1

These features are planned later and should not block the first release:

- Offline breach corpus matching
- Password generator mode
- Side-by-side comparison mode
- Rule tuning simulator
- Policy diff mode
- Department-specific plugins
- Historical trend dashboards
- Keyboard-layout localization
- Locale-specific linguistic models
- Secure memory guarantees beyond practical Python limits

## Scope rule

If a new feature request does not support the v1 capabilities listed above, do not implement it until the core pipeline is complete and tested.