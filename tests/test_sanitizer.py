from password_strength.models import SourceDocument
from password_strength.sanitizer import sanitize_source_document
from password_strength.sanitizer import sanitize_source_documents


def test_sanitize_source_document_removes_bom() -> None:
    document = SourceDocument(
        content="\ufeffPassword1!",
        source="cli_password",
    )

    result = sanitize_source_document(document)

    assert result.cleaned_content == "Password1!"
    assert "removed_bom" in result.actions
    assert result.was_modified is True


def test_sanitize_source_document_removes_zero_width_characters() -> None:
    document = SourceDocument(
        content="Pass\u200bword1!",
        source="cli_password",
    )

    result = sanitize_source_document(document)

    assert result.cleaned_content == "Password1!"
    assert "removed_zero_width_characters" in result.actions
    assert len(result.warnings) == 1


def test_sanitize_source_document_strips_ansi_escapes() -> None:
    document = SourceDocument(
        content="\x1b[31mPassword1!\x1b[0m",
        source="stdin",
    )

    result = sanitize_source_document(document)

    assert result.cleaned_content == "Password1!"
    assert "stripped_ansi_escapes" in result.actions


def test_sanitize_source_document_removes_control_characters() -> None:
    document = SourceDocument(
        content="Pass\x07word1!",
        source="stdin",
    )

    result = sanitize_source_document(document)

    assert result.cleaned_content == "Password1!"
    assert "removed_control_characters" in result.actions


def test_sanitize_source_documents_handles_batch() -> None:
    documents = [
        SourceDocument(content="\ufeffone", source="file"),
        SourceDocument(content="two\u200b", source="file"),
    ]

    results = sanitize_source_documents(documents)

    assert len(results) == 2
    assert results[0].cleaned_content == "one"
    assert results[1].cleaned_content == "two"


def test_sanitized_document_converts_back_to_source_document() -> None:
    document = SourceDocument(
        content="\ufeffPass\u200bword1!",
        source="file",
        source_name="passwords.txt",
        document_id="doc_1",
    )

    result = sanitize_source_document(document)
    converted = result.to_source_document()

    assert converted.content == "Password1!"
    assert converted.source == "file"
    assert converted.source_name == "passwords.txt"
    assert converted.metadata["sanitizer_actions"] == [
        "removed_bom",
        "removed_zero_width_characters",
    ]