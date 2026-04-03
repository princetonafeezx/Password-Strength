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


def sanitize_source_documents(documents: list[SourceDocument]) -> list[SanitizedDocument]:
    """Sanitize a batch of source documents."""
    return [sanitize_source_document(document) for document in documents]