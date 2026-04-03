"""Shared input loading helpers for Password Strength Architect."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from password_strength.exceptions import PasswordInputError
from password_strength.models import SourceDocument


@dataclass(slots=True)
class LoadedInput:
    """Represents normalized input loaded from CLI flags or files."""

    values: list[str]
    source: str
    source_files: list[str]

    @property
    def is_empty(self) -> bool:
        """Return True if no password values were loaded."""
        return len(self.values) == 0


def _read_text_from_file(path: Path) -> str:
    """Read raw text from a file."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PasswordInputError(f"Unable to read input file: {path}") from exc


def _extract_non_empty_lines(text: str) -> list[str]:
    """Extract non-empty lines from text."""
    return [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]


def _build_document(
    *,
    content: str,
    source: str,
    source_name: str | None,
    document_id: str,
) -> SourceDocument:
    """Build a normalized source document."""
    return SourceDocument(
        content=content,
        source=source,
        source_name=source_name,
        document_id=document_id,
    )


def load_password_input(
    *,
    password: str | None = None,
    file: str | None = None,
    files: list[str] | None = None,
    use_stdin: bool = False,
    stdin: TextIO | None = None,
) -> LoadedInput:
    """Load password input from one supported source mode."""
    provided_sources = sum(
        [
            password is not None,
            file is not None,
            bool(files),
            use_stdin,
        ]
    )

    if provided_sources == 0:
        raise PasswordInputError(
            "No input provided. Use --password, --file, --files, or --stdin."
        )

    if provided_sources > 1:
        raise PasswordInputError(
            "Choose exactly one input source: --password, --file, --files, or --stdin."
        )

    if password is not None:
        return LoadedInput(values=[password], source="cli_password", source_files=[])

    if file is not None:
        path = Path(file)
        text = _read_text_from_file(path)
        values = _extract_non_empty_lines(text)
        return LoadedInput(values=values, source="file", source_files=[str(path)])

    if files:
        all_values: list[str] = []
        source_files: list[str] = []

        for file_name in files:
            path = Path(file_name)
            text = _read_text_from_file(path)
            all_values.extend(_extract_non_empty_lines(text))
            source_files.append(str(path))

        return LoadedInput(values=all_values, source="files", source_files=source_files)

    if use_stdin:
        if stdin is None:
            raise PasswordInputError("stdin input requested, but no stdin stream was provided.")

        text = stdin.read()
        values = _extract_non_empty_lines(text)
        return LoadedInput(values=values, source="stdin", source_files=[])

    raise PasswordInputError("Unsupported input configuration.")


def load_source_documents(
    *,
    password: str | None = None,
    file: str | None = None,
    files: list[str] | None = None,
    use_stdin: bool = False,
    stdin: TextIO | None = None,
) -> list[SourceDocument]:
    """Load input and normalize it into source documents."""
    provided_sources = sum(
        [
            password is not None,
            file is not None,
            bool(files),
            use_stdin,
        ]
    )

    if provided_sources == 0:
        raise PasswordInputError(
            "No input provided. Use --password, --file, --files, or --stdin."
        )

    if provided_sources > 1:
        raise PasswordInputError(
            "Choose exactly one input source: --password, --file, --files, or --stdin."
        )

    if password is not None:
        return [
            _build_document(
                content=password,
                source="cli_password",
                source_name=None,
                document_id="cli_password_1",
            )
        ]

    if file is not None:
        path = Path(file)
        text = _read_text_from_file(path)
        return [
            _build_document(
                content=text,
                source="file",
                source_name=str(path),
                document_id="file_1",
            )
        ]

    if files:
        documents: list[SourceDocument] = []
        for index, file_name in enumerate(files, start=1):
            path = Path(file_name)
            text = _read_text_from_file(path)
            documents.append(
                _build_document(
                    content=text,
                    source="files",
                    source_name=str(path),
                    document_id=f"file_{index}",
                )
            )
        return documents

    if use_stdin:
        if stdin is None:
            raise PasswordInputError("stdin input requested, but no stdin stream was provided.")

        text = stdin.read()
        return [
            _build_document(
                content=text,
                source="stdin",
                source_name=None,
                document_id="stdin_1",
            )
        ]

    raise PasswordInputError("Unsupported input configuration.")