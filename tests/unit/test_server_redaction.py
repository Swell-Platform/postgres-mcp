from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

import postgres_mcp.server as server
from postgres_mcp.redaction_policy import RedactionConfig
from postgres_mcp.redaction_policy import RedactionPolicy
from postgres_mcp.result_redactor import ResultRedactor
from postgres_mcp.sql.sql_driver import SqlDriver


@pytest.mark.asyncio
async def test_execute_sql_applies_result_redaction():
    mock_driver = MagicMock(spec=SqlDriver)
    mock_driver.execute_query = AsyncMock(return_value=[SqlDriver.RowResult(cells={"email": "alice@example.com"})])

    redactor = MagicMock(spec=ResultRedactor)
    redactor.redact_rows = AsyncMock(return_value=[SqlDriver.RowResult(cells={"email": "[REDACTED]"})])

    with patch.object(server, "result_redactor", redactor), patch.object(server, "get_sql_driver", AsyncMock(return_value=mock_driver)):
        result = await server.execute_sql("SELECT email FROM public.patients")

    assert "[REDACTED]" in result[0].text
    redactor.redact_rows.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_object_details_marks_protected_columns():
    async def fake_execute_param_query(sql_driver, query, params=None):
        del sql_driver
        if "information_schema.columns" in query:
            return [MagicMock(cells={"column_name": "email", "data_type": "text", "is_nullable": "YES", "column_default": None})]
        if "information_schema.table_constraints" in query:
            return []
        if "pg_indexes" in query:
            return []
        raise AssertionError(f"Unexpected query: {query}")

    mock_driver = MagicMock(spec=SqlDriver)

    with (
        patch.object(server, "get_sql_driver", AsyncMock(return_value=mock_driver)),
        patch.object(
            server,
            "current_redaction_config",
            RedactionConfig(policy=RedactionPolicy.from_dict({"protected_columns": ["public.patients.email"]})),
        ),
        patch("postgres_mcp.server.SafeSqlDriver.execute_param_query", side_effect=fake_execute_param_query),
    ):
        result = await server.get_object_details("public", "patients", "table")

    assert "'protected': True" in result[0].text
