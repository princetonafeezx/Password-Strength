"""Input sanitization helpers for Password Strength Architect."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from password_strength.models import SourceDocument


BOM_CHARACTER = "\ufeff"
ZERO_WIDTH_CHARACTERS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # BOM / zero width no-break space
}
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
CONTROL_CHARACTERS_PATTERN = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

@dataclass(slots=True)
class SanitizedDocument:
    """Represents a source document before and after sanitization."""

    original_document: SourceDocument
    cleaned_content: str
    actions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def source(self) -> str:
        """Return the original document source."""
        return self.original_document.source

    @property
    def source_name(self) -> str | None:
        """Return the original document source name."""
        return self.original_document.source_name

    @property
    def document_id(self) -> str | None:
        """Return the original document identifier."""
        return self.original_document.document_id

    @property
    def was_modified(self) -> bool:
        """Return True if sanitization changed content or recorded actions."""
        return (
            self.original_document.content != self.cleaned_content
            or len(self.actions) > 0
        )

    def to_source_document(self) -> SourceDocument:
        """Convert the sanitized result back into a normalized source document."""
        metadata = dict(self.original_document.metadata)
        metadata["sanitizer_actions"] = list(self.actions)
        metadata["sanitizer_warnings"] = list(self.warnings)
        metadata["original_content"] = self.original_document.content

        return SourceDocument(
            content=self.cleaned_content,
            source=self.original_document.source,
            source_name=self.original_document.source_name,
            document_id=self.original_document.document_id,
            metadata=metadata,
        )


def _remove_bom(text: str) -> tuple[str, bool]:
    """Remove BOM characters from text."""
    cleaned = text.replace(BOM_CHARACTER, "")
    return cleaned, cleaned != text


def _remove_zero_width_characters(text: str) -> tuple[str, bool]:
    """Remove zero-width and invisible characters from text."""
    cleaned = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARACTERS)
    return cleaned, cleaned != text


def _strip_ansi_escapes(text: str) -> tuple[str, bool]:
    """Strip ANSI escape sequences from text."""
    cleaned = ANSI_ESCAPE_PATTERN.sub("", text)
    return cleaned, cleaned != text


def _remove_control_characters(text: str) -> tuple[str, bool]:
    """Remove unsupported control characters while preserving common newlines and tabs."""
    cleaned = CONTROL_CHARACTERS_PATTERN.sub("", text)
    return cleaned, cleaned != text


def _normalize_unicode_whitespace(text: str) -> tuple[str, bool]:
    """Normalize unusual Unicode whitespace to standard spaces and newlines."""
    cleaned = []
    modified = False

    for character in text:
        if character in {"\n", "\r", "\t", " "}:
            cleaned.append(character)
            continue

        if unicodedata.category(character) == "Zs":
            cleaned.append(" ")
            modified = True
        else:
            cleaned.append(character)

    normalized = "".join(cleaned)
    return normalized, modified

def sanitize_text(text: str) -> tuple[str, list[str]]:
    """Sanitize raw text and return cleaned text plus applied actions."""
    cleaned = text
    actions: list[str] = []

    if any(char in cleaned for char in _ZERO_WIDTH_CHARS):
        had_bom = "\ufeff" in cleaned
        cleaned = "".join(char for char in cleaned if char not in _ZERO_WIDTH_CHARS)
        actions.append("removed_zero_width_characters")
        if had_bom:
            actions.append("removed_bom")

    ansi_cleaned = _ANSI_ESCAPE_PATTERN.sub("", cleaned)
    if ansi_cleaned != cleaned:
        cleaned = ansi_cleaned
        actions.append("stripped_ansi_escapes")

    control_cleaned = _CONTROL_CHAR_PATTERN.sub("", cleaned)
    if control_cleaned != cleaned:
        cleaned = control_cleaned
        actions.append("removed_control_characters")

    normalized = unicodedata.normalize("NFKC", cleaned)
    if normalized != cleaned:
        cleaned = normalized
        actions.append("normalized_unicode")

    return cleaned, actions

def sanitize_source_document(document: SourceDocument) -> SanitizedDocument:
    """Sanitize one source document and return both raw and cleaned views."""
    text = document.content
    actions: list[str] = []
    warnings: list[str] = []

    text, removed_bom = _remove_bom(text)
    if removed_bom:
        actions.append("removed_bom")

    text, removed_zero_width = _remove_zero_width_characters(text)
    if removed_zero_width:
        actions.append("removed_zero_width_characters")
        warnings.append("Hidden zero-width or invisible characters were removed.")

    text, stripped_ansi = _strip_ansi_escapes(text)
    if stripped_ansi:
        actions.append("stripped_ansi_escapes")

    text, removed_controls = _remove_control_characters(text)
    if removed_controls:
        actions.append("removed_control_characters")

    text, normalized_whitespace = _normalize_unicode_whitespace(text)
    if normalized_whitespace:
        actions.append("normalized_unicode_whitespace")

    return SanitizedDocument(
        original_document=document,
        cleaned_content=text,
        actions=actions,
        warnings=warnings,
    )

def sanitize_source_document(
    document: SourceDocument,
    *,
    config: PasswordConfig | None = None,
) -> SourceDocument:
    """Return a sanitized copy of a source document."""
    effective_config = config or PasswordConfig()

    sanitized_lines: list[str] = []
    combined_actions: list[str] = []

    for line in document.content.splitlines():
        cleaned_line, line_actions = sanitize_password_line(line, config=effective_config)
        sanitized_lines.append(cleaned_line)
        for action in line_actions:
            if action not in combined_actions:
                combined_actions.append(action)

    cleaned_content = "\n".join(sanitized_lines)

    metadata = dict(document.metadata)
    metadata["sanitizer_actions"] = list(combined_actions)
    metadata["raw_content"] = document.content
    metadata["passphrase_mode"] = effective_config.passphrase_mode
    metadata["allow_spaces"] = effective_config.allow_spaces

    return SourceDocument(
        content=cleaned_content,
        source=document.source,
        source_name=document.source_name,
        document_id=document.document_id,
        metadata=metadata,
        raw_content=document.content,
        sanitizer_actions=combined_actions,
    )