from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from mcp.types import TextContent

import postgres_mcp.server as server
from postgres_mcp.redaction_policy import RedactionConfig
from postgres_mcp.redaction_policy import RedactionPolicy
from postgres_mcp.sql.sql_driver import SqlDriver


@pytest.mark.asyncio
async def test_diagnostic_driver_masks_plan_literals_but_preserves_metrics():
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.contacts.email"]})
    plan = {
        "Plan": {
            "Node Type": "Index Scan",
            "Relation Name": "contacts",
            "Total Cost": 12.5,
            "Index Cond": "(email = 'synthetic@example.test'::text)",
            "Output": ["email", "'synthetic private words'::text"],
        },
        "Execution Time": 3.0,
    }
    with (
        patch.object(server, "current_redaction_config", RedactionConfig(policy=policy)),
        patch.object(server, "current_access_mode", server.AccessMode.UNRESTRICTED),
        patch.object(SqlDriver, "execute_query", AsyncMock(return_value=[SqlDriver.RowResult({"QUERY PLAN": [plan]})])),
    ):
        driver = await server.get_sql_driver()
        result = await driver.execute_query("EXPLAIN SELECT email FROM public.contacts")
    assert result is not None
    assert "synthetic" not in str(result)
    assert result[0].cells["QUERY PLAN"][0]["Plan"]["Total Cost"] == 12.5
    assert result[0].cells["QUERY PLAN"][0]["Plan"]["Relation Name"] == "contacts"


@pytest.mark.asyncio
async def test_execute_sql_error_does_not_return_or_log_sensitive_database_detail(caplog):
    driver = MagicMock(spec=SqlDriver)
    driver.execute_query = AsyncMock(side_effect=ValueError("invalid input: synthetic-private-message"))
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.twilio_messages.text"]})
    with (
        patch.object(server, "current_redaction_config", RedactionConfig(policy=policy)),
        patch.object(server, "get_sql_driver", AsyncMock(return_value=driver)),
    ):
        response = await server.execute_sql("SELECT text::integer FROM public.twilio_messages")
    assert isinstance(response[0], TextContent)
    assert "synthetic-private-message" not in response[0].text
    assert "synthetic-private-message" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["query", "readonly_explain"])
async def test_diagnostic_driver_strips_nested_fields_and_error_details(method):
    from postgres_mcp.diagnostic_redaction import DiagnosticSqlDriver

    rows = [
        SqlDriver.RowResult(
            {
                "query": "SELECT 'synthetic private text' /* synthetic comment */",
                "calls": 3,
                "nested": {"Filter": "(text = 'synthetic private text')", "error": "synthetic private text"},
            }
        )
    ]
    parent_method = "execute_query" if method == "query" else "execute_readonly_explain"
    with patch.object(SqlDriver, parent_method, AsyncMock(return_value=rows)):
        driver = DiagnosticSqlDriver(conn=MagicMock())
        result = (
            await driver.execute_query("SELECT 1") if method == "query" else await driver.execute_readonly_explain("EXPLAIN SELECT 1", timeout_ms=100)
        )
    assert result is not None
    assert "synthetic" not in str(result)
    assert result[0].cells["calls"] == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["analyze_workload_indexes", "analyze_query_indexes", "get_top_queries"])
async def test_diagnostic_tool_formatting_preserves_metadata(tool):
    from postgres_mcp.diagnostic_redaction import redact_diagnostics

    payload = {
        "query": "SELECT 'synthetic private text'",
        "calls": 9,
        "error": "synthetic private text",
        "_langfuse_trace": ["synthetic private text"],
    }
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.twilio_messages.text"]})
    presentation = MagicMock()
    presentation.analyze_workload = AsyncMock(return_value=payload)
    presentation.analyze_queries = AsyncMock(return_value=payload)
    top = MagicMock()
    top.get_top_resource_queries = AsyncMock(return_value=payload)
    with (
        patch.object(server, "current_redaction_config", RedactionConfig(policy=policy)),
        patch.object(server, "get_sql_driver", AsyncMock(return_value=MagicMock())),
        patch.object(server, "TextPresentation", return_value=presentation),
        patch.object(server, "DatabaseTuningAdvisor", return_value=MagicMock()),
        patch.object(server, "TopQueriesCalc", return_value=top),
    ):
        if tool == "analyze_query_indexes":
            response = await server.analyze_query_indexes(["SELECT 1"], method="dta")
        elif tool == "analyze_workload_indexes":
            response = await server.analyze_workload_indexes(method="dta")
        else:
            response = await server.get_top_queries(sort_by="resources")
    assert "synthetic" not in response[0].text
    assert "9" in response[0].text
    assert redact_diagnostics(payload)["calls"] == 9


def test_unicode_and_all_sql_literal_forms_are_redacted():
    from postgres_mcp.diagnostic_redaction import redact_sql_literals

    query = "SELECT 'é synthetic', $$synthetic$$, E'synthetic', B'101', X'abcdef', 987, 12.34 -- synthetic comment"
    result = redact_sql_literals(query)
    for value in ["synthetic", "987", "12.34", "abcdef", "101"]:
        assert value not in result
    assert "SELECT" in result


@pytest.mark.asyncio
async def test_optimizer_inputs_remain_original_but_rendered_plans_are_masked():
    from postgres_mcp.artifacts import ExplainPlanArtifact
    from postgres_mcp.diagnostic_redaction import DiagnosticSqlDriver
    from postgres_mcp.index.index_opt_base import IndexRecommendation
    from postgres_mcp.index.index_opt_base import IndexRecommendationAnalysis
    from postgres_mcp.index.index_opt_base import IndexTuningResult
    from postgres_mcp.index.presentation import TextPresentation

    query = "SELECT text FROM twilio_messages WHERE text='synthetic private words'"
    plan = {"Plan": {"Filter": "(text = 'synthetic private words')", "Total Cost": 12.5}}
    tuning = MagicMock()
    tuning.get_explain_plan_with_indexes = AsyncMock(return_value=plan)
    tuning.extract_cost_from_json_plan.return_value = 12.5
    session = IndexTuningResult(
        session_id="synthetic",
        budget_mb=1,
        recommendations=[
            IndexRecommendationAnalysis(IndexRecommendation("twilio_messages", ("text",)), 12.5, 12.5, 12.5, 12.5, [query], "synthetic")
        ],
    )
    with (
        patch.object(ExplainPlanArtifact, "format_plan_summary", side_effect=lambda p: str(p)),
        patch.object(ExplainPlanArtifact, "create_plan_diff", side_effect=lambda a, b: str(a) + str(b)),
    ):
        result = await TextPresentation(MagicMock(), tuning, redact_output=True)._generate_query_impact(session)  # pyright: ignore[reportPrivateUsage]
    assert tuning.get_explain_plan_with_indexes.call_args.args[0] == query
    assert "synthetic private words" in plan["Plan"]["Filter"]
    assert "synthetic private words" not in result[0]["before_explain_plan"]
    assert result[0]["base_cost"] == "12.5"
    with patch.object(SqlDriver, "execute_query", AsyncMock(return_value=[SqlDriver.RowResult({"query": query})])):
        rows = await DiagnosticSqlDriver(conn=MagicMock(), sanitize_rows=False).execute_query("SELECT query FROM pg_stat_statements")
    assert rows is not None
    assert rows[0].cells["query"] == query


@pytest.mark.parametrize("identifier", ["café", "患者", "😀"])
def test_unicode_identifiers_before_literals_preserve_exact_redaction(identifier):
    from postgres_mcp.diagnostic_redaction import redact_sql_literals

    query = f"SELECT \"{identifier}\", 'synthetic secret', \"{identifier}\" = 'another secret'"
    assert redact_sql_literals(query) == f"SELECT \"{identifier}\", '[REDACTED]', \"{identifier}\" = '[REDACTED]'"
