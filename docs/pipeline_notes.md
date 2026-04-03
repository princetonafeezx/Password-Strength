# Password Strength Architect — Pipeline Notes

This document describes the intended end-to-end execution flow for the password auditing system.

## Pipeline stages

1. **read_input**
   - Accept input from CLI flags, files, stdin, or future interactive modes.
   - Normalize the source into a consistent raw input shape.

2. **sanitize_input**
   - Remove unsafe or malformed characters.
   - Preserve audit visibility into what changed.
   - Prepare the input for downstream parsing.

3. **parse_passwords**
   - Convert sanitized input into one or more password candidates.
   - Support single-password and batch-password modes.

4. **validate_policy**
   - Apply deterministic password policy checks.
   - Evaluate rules like length, character classes, and uniqueness.

5. **detect_patterns**
   - Detect weak structural patterns such as sequences, repeats, keyboard rows, and predictable chunks.

6. **check_dictionary**
   - Compare normalized passwords against common-password lists, banned tokens, and weak substitutions.

7. **score_passwords**
   - Produce weighted strength scores and entropy estimates.
   - Distinguish structural quality from risk signals.

8. **classify_results**
   - Separate compliance from strength.
   - Assign labels such as compliant, weak, suspicious, or non-compliant.

9. **export_results**
   - Convert results into console, JSON, JSONL, or CSV representations.
   - Support safe masked output by default.

10. **build_report**
    - Build a run-level summary with totals, findings, warnings, and exit behavior inputs.

## Pipeline design principles

- Stages should run in a stable, deterministic order.
- Each stage should have a single responsibility.
- The pipeline context should carry intermediate data between stages.
- Export logic should not contain validation logic.
- CLI commands should use the shared pipeline instead of bypassing it.

## Implementation note

At this stage, some stages are placeholders. Future commits will replace placeholder behavior with real implementations while preserving the same stage order and context flow.