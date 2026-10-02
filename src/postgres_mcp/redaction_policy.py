from __future__ import annotations

import json
import os
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any

import yaml

REDACTION_PLACEHOLDER = "[REDACTED]"
SUPPORTED_DETECTORS = {"none", "simple", "presidio"}
SUPPORTED_FALLBACK_MODES = {"best_effort"}
SUPPORTED_MASKING_STYLES = {"full", "partial"}


@dataclass(frozen=True)
class QualifiedTable:
    schema: str | None
    table: str

    @classmethod
    def parse(cls, value: str) -> QualifiedTable:
        normalized = normalize_identifier(value)
        parts = normalized.split(".")
        if len(parts) == 1:
            return cls(schema=None, table=parts[0])
        if len(parts) == 2:
            return cls(schema=parts[0], table=parts[1])
        raise ValueError(f"Invalid table identifier: {value}")

    def matches(self, schema: str | None, table: str) -> bool:
        normalized_schema = normalize_optional_identifier(schema)
        normalized_table = normalize_identifier(table)
        if self.table != normalized_table:
            return False
        if self.schema is None:
            return True
        return self.schema == normalized_schema


@dataclass(frozen=True)
class QualifiedColumn:
    schema: str | None
    table: str
    column: str

    @classmethod
    def parse(cls, value: str) -> QualifiedColumn:
        normalized = normalize_identifier(value)
        parts = normalized.split(".")
        if len(parts) == 2:
            return cls(schema=None, table=parts[0], column=parts[1])
        if len(parts) == 3:
            return cls(schema=parts[0], table=parts[1], column=parts[2])
        raise ValueError(f"Invalid column identifier: {value}")

    def matches(self, schema: str | None, table: str, column: str) -> bool:
        normalized_schema = normalize_optional_identifier(schema)
        normalized_table = normalize_identifier(table)
        normalized_column = normalize_identifier(column)
        if self.table != normalized_table or self.column != normalized_column:
            return False
        if self.schema is None:
            return True
        return self.schema == normalized_schema


@dataclass(frozen=True)
class ColumnRule:
    column: QualifiedColumn
    masking_style: str | None = None
    force_redact: bool = False
    skip_detector: bool = False


@dataclass(frozen=True)
class RedactionPolicy:
    protected_tables: tuple[QualifiedTable, ...] = ()
    protected_columns: tuple[QualifiedColumn, ...] = ()
    column_rules: tuple[ColumnRule, ...] = ()
    detector: str = "none"
    fallback_mode: str = "best_effort"
    replacement_text: str = REDACTION_PLACEHOLDER

    def is_enabled(self) -> bool:
        return bool(self.protected_tables or self.protected_columns or self.column_rules or self.detector != "none")

    def is_table_protected(self, schema: str | None, table: str) -> bool:
        return any(entry.matches(schema, table) for entry in self.protected_tables)

    def is_column_protected(self, schema: str | None, table: str, column: str) -> bool:
        if self.is_table_protected(schema, table):
            return True
        return any(entry.matches(schema, table, column) for entry in self.protected_columns)

    def rule_for_column(self, schema: str | None, table: str, column: str) -> ColumnRule | None:
        for rule in self.column_rules:
            if rule.column.matches(schema, table, column):
                return rule
        return None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> RedactionPolicy:
        detector = normalize_identifier(str(raw.get("detector", "none")))
        fallback_mode = normalize_identifier(str(raw.get("fallback_mode", "best_effort")))
        replacement_text = str(raw.get("replacement_text", REDACTION_PLACEHOLDER))

        if detector not in SUPPORTED_DETECTORS:
            raise ValueError(f"Unsupported redaction detector: {detector}")
        if fallback_mode not in SUPPORTED_FALLBACK_MODES:
            raise ValueError(f"Unsupported redaction fallback mode: {fallback_mode}")

        protected_tables = tuple(QualifiedTable.parse(item) for item in ensure_string_list(raw.get("protected_tables", [])))
        protected_columns = tuple(QualifiedColumn.parse(item) for item in ensure_string_list(raw.get("protected_columns", [])))

        column_rules = []
        for raw_rule in raw.get("column_rules", []) or []:
            if not isinstance(raw_rule, dict):
                raise ValueError("Each column rule must be a mapping")
            if "column" not in raw_rule:
                raise ValueError("Column rules must include a 'column' field")
            masking_style = None
            if "masking_style" in raw_rule:
                masking_style = normalize_identifier(str(raw_rule["masking_style"]))
            if bool(raw_rule.get("force_redact", False)):
                masking_style = "full"
            if masking_style is not None and masking_style not in SUPPORTED_MASKING_STYLES:
                raise ValueError(f"Unsupported masking style: {masking_style}")
            column_rules.append(
                ColumnRule(
                    column=QualifiedColumn.parse(str(raw_rule["column"])),
                    masking_style=masking_style,
                    force_redact=bool(raw_rule.get("force_redact", False)),
                    skip_detector=bool(raw_rule.get("skip_detector", False)),
                )
            )

        return cls(
            protected_tables=protected_tables,
            protected_columns=protected_columns,
            column_rules=tuple(column_rules),
            detector=detector,
            fallback_mode=fallback_mode,
            replacement_text=replacement_text,
        )


@dataclass(frozen=True)
class RedactionSettings:
    policy_file: str | None = None
    detector: str = "none"
    fallback_mode: str = "best_effort"


@dataclass(frozen=True)
class RedactionConfig:
    settings: RedactionSettings | None = None
    policy: RedactionPolicy = field(default_factory=RedactionPolicy)


def load_redaction_config(args: Any, environ: dict[str, str] | None = None) -> RedactionConfig:
    env = environ or dict(os.environ)

    policy_file = first_non_empty(
        getattr(args, "redaction_policy_file", None),
        env.get("POSTGRES_MCP_REDACTION_POLICY_FILE"),
    )
    detector = normalize_identifier(
        first_non_empty(
            getattr(args, "redaction_detector", None),
            env.get("POSTGRES_MCP_REDACTION_DETECTOR"),
            "none",
        )
        or "none"
    )
    fallback_mode = normalize_identifier(
        first_non_empty(
            getattr(args, "redaction_fallback_mode", None),
            env.get("POSTGRES_MCP_REDACTION_FALLBACK_MODE"),
            "best_effort",
        )
        or "best_effort"
    )

    inline_config = {
        "protected_tables": split_csv(env.get("POSTGRES_MCP_REDACT_TABLES")),
        "protected_columns": split_csv(env.get("POSTGRES_MCP_REDACT_COLUMNS")),
        "detector": detector,
        "fallback_mode": fallback_mode,
    }

    merged = dict(inline_config)
    if policy_file:
        file_config = read_policy_file(policy_file)
        merged = merge_policy_dicts(merged, file_config)

    policy = RedactionPolicy.from_dict(merged)
    settings = RedactionSettings(
        policy_file=policy_file,
        detector=policy.detector,
        fallback_mode=policy.fallback_mode,
    )
    return RedactionConfig(settings=settings, policy=policy)


def merge_policy_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        merged[key] = value
    return merged


def read_policy_file(path: str) -> dict[str, Any]:
    policy_path = Path(path)
    if not policy_path.exists():
        raise ValueError(f"Redaction policy file does not exist: {path}")

    raw_text = policy_path.read_text()
    suffix = policy_path.suffix.lower()
    if suffix == ".json":
        parsed = json.loads(raw_text)
    else:
        parsed = yaml.safe_load(raw_text)

    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError("Redaction policy file must contain a mapping at the top level")
    return parsed


def ensure_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return split_csv(value)
    if not isinstance(value, list):
        raise ValueError("Expected a list of strings")
    return [str(item).strip() for item in value if str(item).strip()]


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def first_non_empty(*values: str | None) -> str | None:
    for value in values:
        if value:
            return value
    return None


def normalize_identifier(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith('"') and stripped.endswith('"') and len(stripped) >= 2:
        stripped = stripped[1:-1]
    return stripped.lower()


def normalize_optional_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return normalize_identifier(value)
