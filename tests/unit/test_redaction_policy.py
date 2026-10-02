from pathlib import Path
from types import SimpleNamespace

import pytest

from postgres_mcp.redaction_policy import load_redaction_config


def make_args(**overrides):
    defaults = {
        "redaction_policy_file": None,
        "redaction_detector": None,
        "redaction_fallback_mode": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_load_redaction_config_from_inline_env_vars():
    config = load_redaction_config(
        make_args(),
        {
            "POSTGRES_MCP_REDACT_TABLES": "public.patients, public.insurance_subscribers",
            "POSTGRES_MCP_REDACT_COLUMNS": "public.patients.first_name,patients.last_name",
            "POSTGRES_MCP_REDACTION_DETECTOR": "simple",
            "POSTGRES_MCP_REDACTION_FALLBACK_MODE": "best_effort",
        },
    )

    assert config.settings is not None
    assert config.settings.detector == "simple"
    assert sorted((entry.schema, entry.table) for entry in config.policy.protected_tables) == [
        ("public", "insurance_subscribers"),
        ("public", "patients"),
    ]
    assert sorted(
        ((entry.schema, entry.table, entry.column) for entry in config.policy.protected_columns),
        key=lambda item: (item[0] or "", item[1], item[2]),
    ) == [
        (None, "patients", "last_name"),
        ("public", "patients", "first_name"),
    ]


def test_policy_file_overrides_inline_env_vars(tmp_path: Path):
    policy_path = tmp_path / "redaction-policy.yml"
    policy_path.write_text(
        """
protected_tables:
  - public.patients
protected_columns:
  - public.encounters.patient_name
detector: none
        """.strip()
    )

    config = load_redaction_config(
        make_args(),
        {
            "POSTGRES_MCP_REDACTION_POLICY_FILE": str(policy_path),
            "POSTGRES_MCP_REDACT_TABLES": "public.telephony_events",
            "POSTGRES_MCP_REDACT_COLUMNS": "public.telephony_events.caller_number",
            "POSTGRES_MCP_REDACTION_DETECTOR": "simple",
        },
    )

    assert [(entry.schema, entry.table) for entry in config.policy.protected_tables] == [("public", "patients")]
    assert [(entry.schema, entry.table, entry.column) for entry in config.policy.protected_columns] == [("public", "encounters", "patient_name")]
    assert config.policy.detector == "none"


def test_load_redaction_config_raises_for_invalid_policy(tmp_path: Path):
    policy_path = tmp_path / "redaction-policy.yml"
    policy_path.write_text("protected_columns: invalid")

    with pytest.raises(ValueError, match="Invalid column identifier"):
        load_redaction_config(
            make_args(redaction_policy_file=str(policy_path)),
            {},
        )


def test_load_redaction_config_accepts_presidio_detector():
    config = load_redaction_config(
        make_args(),
        {
            "POSTGRES_MCP_REDACTION_DETECTOR": "presidio",
        },
    )

    assert config.settings is not None
    assert config.settings.detector == "presidio"


def test_load_redaction_config_accepts_partial_masking_style(tmp_path: Path):
    policy_path = tmp_path / "redaction-policy.yml"
    policy_path.write_text(
        """
column_rules:
  - column: public.patients.email
    masking_style: partial
        """.strip()
    )

    config = load_redaction_config(
        make_args(redaction_policy_file=str(policy_path)),
        {},
    )

    assert len(config.policy.column_rules) == 1
    assert config.policy.column_rules[0].masking_style == "partial"


def test_load_redaction_config_rejects_unsupported_masking_style(tmp_path: Path):
    policy_path = tmp_path / "redaction-policy.yml"
    policy_path.write_text(
        """
column_rules:
  - column: public.patients.email
    masking_style: pseudonymize
        """.strip()
    )

    with pytest.raises(ValueError, match="Unsupported masking style"):
        load_redaction_config(
            make_args(redaction_policy_file=str(policy_path)),
            {},
        )
