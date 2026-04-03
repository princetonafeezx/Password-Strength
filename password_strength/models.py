"""Data models for password analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PasswordCandidate:
    """Represents one password input moving through the audit pipeline."""

    raw_password: str
    cleaned_password: str
    source: str = "unknown"
    source_file: str | None = None
    line_number: int | None = None
    source_line: str | None = None
    sanitizer_actions: list[str] = field(default_factory=list)

    @property
    def original_length(self) -> int:
        """Return the length of the raw password."""
        return len(self.raw_password)

    @property
    def cleaned_length(self) -> int:
        """Return the length of the cleaned password."""
        return len(self.cleaned_password)

    @property
    def was_modified_by_sanitizer(self) -> bool:
        """Return True if sanitization changed the password or recorded actions."""
        return self.raw_password != self.cleaned_password or len(self.sanitizer_actions) > 0
