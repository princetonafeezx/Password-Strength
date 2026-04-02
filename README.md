Day 3 — The Password Strength Architect
App: Password Policy Auditor
What it does: Accepts a password (or a file of passwords) and scores each one against configurable rules: length, character diversity, common password dictionary check, sequential character detection, keyboard pattern detection (e.g., "qwerty"), entropy calculation. Outputs a detailed strength report with specific, actionable feedback. 
Why it matters: Demonstrates rule-based validation with layered criteria, not just "strong/weak" binary output.
Key skills: RegEx for pattern detection (sequential chars, keyboard rows, repeated patterns), dictionary lookup, entropy math, scoring algorithms with weighted criteria.
Standalone value: Audit any password and get a professional-grade strength report. 
Mega-approle: dataguard/passwords.py — validates credential data within the pipeline.
