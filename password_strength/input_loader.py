"""Shared input loading helpers for Password Strength Architect."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from password_strength.exceptions import PasswordInputError


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


def _read_lines_from_file(path: Path) -> list[str]:
    """Read non-empty lines from a text file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PasswordInputError(f"Unable to read input file: {path}") from exc

    return [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]


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
        values = _read_lines_from_file(path)
        return LoadedInput(values=values, source="file", source_files=[str(path)])

    if files:
        all_values: list[str] = []
        source_files: list[str] = []

        for file_name in files:
            path = Path(file_name)
            all_values.extend(_read_lines_from_file(path))
            source_files.append(str(path))

        return LoadedInput(values=all_values, source="files", source_files=source_files)

    if use_stdin:
        if stdin is None:
            raise PasswordInputError("stdin input requested, but no stdin stream was provided.")

        text = stdin.read()
        values = [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]
        return LoadedInput(values=values, source="stdin", source_files=[])

    raise PasswordInputError("Unsupported input configuration.")