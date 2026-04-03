"""Shared project conventions for Password Strength Architect."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProjectConventions:
    """Represents the core engineering conventions for the project."""

    naming_rules: tuple[str, ...] = field(default_factory=tuple)
    architecture_rules: tuple[str, ...] = field(default_factory=tuple)
    security_rules: tuple[str, ...] = field(default_factory=tuple)
    testing_rules: tuple[str, ...] = field(default_factory=tuple)
    cli_rules: tuple[str, ...] = field(default_factory=tuple)

    def all_rules(self) -> tuple[str, ...]:
        """Return every convention rule as a single ordered tuple."""
        return (
            self.naming_rules
            + self.architecture_rules
            + self.security_rules
            + self.testing_rules
            + self.cli_rules
        )

    def contains_rule(self, rule_text: str) -> bool:
        """Return True if the exact rule exists in the conventions set."""
        normalized = rule_text.strip().lower()
        return any(rule.lower() == normalized for rule in self.all_rules())


DEFAULT_CONVENTIONS = ProjectConventions(
    naming_rules=(
        "use snake_case for functions, variables, and helpers",
        "use PascalCase for dataclasses and exceptions",
        "prefer explicit domain names for models and results",
    ),
    architecture_rules=(
        "keep orchestration separate from domain logic",
        "prefer dataclasses for structured results",
        "use custom exceptions for domain failures",
        "return structured values instead of ambiguous tuples",
    ),
    security_rules=(
        "never print raw passwords by default",
        "never log plaintext passwords in debug helpers",
        "prefer masked or fingerprinted display values",
    ),
    testing_rules=(
        "write tests for every new behavior area",
        "keep tests deterministic and fast",
        "test success and failure conditions",
    ),
    cli_rules=(
        "keep command names stable once introduced",
        "make output deterministic for automation",
        "document practical usage examples in help text",
    ),
)