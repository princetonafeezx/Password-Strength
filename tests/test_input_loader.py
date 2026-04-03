from io import StringIO
from pathlib import Path

from password_strength.exceptions import PasswordInputError
from password_strength.input_loader import LoadedInput
from password_strength.input_loader import load_password_input
from password_strength.input_loader import load_source_documents
from password_strength.models import SourceDocument


def test_load_single_password() -> None:
    loaded = load_password_input(password="Example123!")

    assert isinstance(loaded, LoadedInput)
    assert loaded.values == ["Example123!"]
    assert loaded.source == "cli_password"
    assert loaded.source_files == []


def test_load_single_file(tmp_path: Path) -> None:
    file_path = tmp_path / "passwords.txt"
    file_path.write_text("one\ntwo\n\nthree\n", encoding="utf-8")

    loaded = load_password_input(file=str(file_path))

    assert loaded.values == ["one", "two", "three"]
    assert loaded.source == "file"
    assert loaded.source_files == [str(file_path)]


def test_load_multiple_files(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("one\n", encoding="utf-8")
    second.write_text("two\nthree\n", encoding="utf-8")

    loaded = load_password_input(files=[str(first), str(second)])

    assert loaded.values == ["one", "two", "three"]
    assert loaded.source == "files"
    assert loaded.source_files == [str(first), str(second)]


def test_load_from_stdin() -> None:
    loaded = load_password_input(
        use_stdin=True,
        stdin=StringIO("one\ntwo\n\n"),
    )

    assert loaded.values == ["one", "two"]
    assert loaded.source == "stdin"


def test_load_source_documents_for_single_password() -> None:
    documents = load_source_documents(password="Example123!")

    assert len(documents) == 1
    assert isinstance(documents[0], SourceDocument)
    assert documents[0].content == "Example123!"
    assert documents[0].source == "cli_password"


def test_load_source_documents_for_file(tmp_path: Path) -> None:
    file_path = tmp_path / "passwords.txt"
    file_path.write_text("one\ntwo\n", encoding="utf-8")

    documents = load_source_documents(file=str(file_path))

    assert len(documents) == 1
    assert documents[0].source == "file"
    assert documents[0].source_name == str(file_path)
    assert documents[0].line_count == 2


def test_load_source_documents_for_multiple_files(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("one\n", encoding="utf-8")
    second.write_text("two\nthree\n", encoding="utf-8")

    documents = load_source_documents(files=[str(first), str(second)])

    assert len(documents) == 2
    assert documents[0].source_name == str(first)
    assert documents[1].source_name == str(second)


def test_reject_no_input() -> None:
    try:
        load_password_input()
        assert False, "Expected PasswordInputError for missing input"
    except PasswordInputError as exc:
        assert str(exc) == "No input provided. Use --password, --file, --files, or --stdin."


def test_reject_multiple_input_sources() -> None:
    try:
        load_password_input(password="a", use_stdin=True, stdin=StringIO("b"))
        assert False, "Expected PasswordInputError for multiple sources"
    except PasswordInputError as exc:
        assert (
            str(exc)
            == "Choose exactly one input source: --password, --file, --files, or --stdin."
        )


def test_reject_missing_file() -> None:
    try:
        load_password_input(file="does-not-exist.txt")
        assert False, "Expected PasswordInputError for missing file"
    except PasswordInputError as exc:
        assert "Unable to read input file:" in str(exc)