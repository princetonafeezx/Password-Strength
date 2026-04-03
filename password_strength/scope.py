"""Feature scope definition for Password Strength Architect."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FeatureScope:
    """Defines what is included and excluded in a given project version."""

    version: str
    in_scope: tuple[str, ...] = field(default_factory=tuple)
    out_of_scope: tuple[str, ...] = field(default_factory=tuple)

    def is_in_scope(self, feature_name: str) -> bool:
        """Return True if the given feature is included in the current version scope."""
        normalized = feature_name.strip().lower()
        return any(item.lower() == normalized for item in self.in_scope)

    def is_out_of_scope(self, feature_name: str) -> bool:
        """Return True if the feature is explicitly excluded from scope."""
        normalized = feature_name.strip().lower()
        return any(item.lower() == normalized for item in self.out_of_scope)


V1_SCOPE = FeatureScope(
    version="1.0",
    in_scope=(
        "input sanitization integration",
        "password policy validation",
        "regex-based pattern detection",
        "dictionary and banned-password checks",
        "strength scoring",
        "human-readable feedback",
        "structured export formats",
        "cli commands for audit, validate, score, and export",
        "safe masking by default",
        "basic test coverage for core flows",
    ),
    out_of_scope=(
        "offline breach corpus matching",
        "password generator mode",
        "side-by-side comparison mode",
        "rule tuning simulator",
        "policy diff mode",
        "department-specific plugins",
        "historical trend dashboards",
        "keyboard-layout localization",
        "locale-specific linguistic models",
        "secure memory guarantees beyond practical python limits",
    ),
)
