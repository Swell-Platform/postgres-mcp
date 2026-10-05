"""Synthetic contract coverage for the versioned WorkPane policy snapshots."""

import json
from pathlib import Path
from unittest.mock import AsyncMock
from unittest.mock import patch

import pytest
from mcp.types import TextContent
from test_result_redactor import make_driver

import postgres_mcp.server as server
from postgres_mcp.redaction_policy import RedactionConfig
from postgres_mcp.redaction_policy import RedactionPolicy
from postgres_mcp.result_redactor import ResultRedactor
from postgres_mcp.sql.sql_driver import SqlDriver

POLICIES = [json.loads(p.read_text()) for p in sorted((Path(__file__).parents[1] / "fixtures/workpane-policies").glob("*.yml"))]
FULL = [(policy, column) for policy in POLICIES for column in policy["protected_columns"]]
PARTIAL = [(policy, rule["column"]) for policy in POLICIES for rule in policy["column_rules"] if rule["masking_style"] == "partial"]
FORMS = ["direct", "alias", "cast", "function", "join", "json", "star"]


def query_and_rows(column, form, value):
    schema, table, name = column.split(".")
    expressions = {
        "direct": name,
        "alias": f"t.{name}",
        "cast": f"t.{name}::text",
        "function": f"lower(t.{name}::text)",
        "join": f"t.{name}",
        "json": f"jsonb_build_object('value', t.{name})",
    }
    driver = make_driver({(schema, table): ["id", name], ("public", "diagnostics"): ["status"]})
    if form == "star":
        return driver, f"SELECT t.* FROM {schema}.{table} t", {"id": 7, name: value}, name
    sql = f"SELECT {expressions[form]} AS masked, t.id FROM {schema}.{table} t"
    if form == "join":
        sql += " JOIN public.diagnostics d ON d.status = 'synthetic'"
    return driver, sql, {"masked": {"value": value} if form == "json" else value, "id": 7}, "masked"


@pytest.mark.asyncio
@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("policy_dict,column", FULL, ids=[c for _, c in FULL])
async def test_all_full_policy_fields_remain_hidden_even_with_reveal(policy_dict, column, form):
    driver, sql, cells, key = query_and_rows(column, form, "synthetic private value")
    redactor = ResultRedactor(driver, RedactionPolicy.from_dict(policy_dict))
    result = await redactor.redact_rows(sql, [SqlDriver.RowResult(cells)], reveal_columns={key})
    assert result[0].cells == {**cells, key: "[REDACTED]"}
    assert result[0].cells["id"] == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("policy_dict,column", PARTIAL, ids=[c for _, c in PARTIAL])
async def test_all_partial_fields_mask_and_only_direct_fields_can_reveal(policy_dict, column, form):
    value = (
        "synthetic@example.test"
        if "email" in column
        else "303-555-0101"
        if "phone" in column
        else "1985-07-14"
        if "birthdate" in column
        else "Synthetic Person"
    )
    driver, sql, cells, key = query_and_rows(column, form, value)
    redactor = ResultRedactor(driver, RedactionPolicy.from_dict(policy_dict))
    result = await redactor.redact_rows(sql, [SqlDriver.RowResult(cells)])
    assert result[0].cells[key] != cells[key]
    assert result[0].cells["id"] == 7
    revealed = await redactor.redact_rows(sql, [SqlDriver.RowResult(cells)], reveal_columns={key})
    expected = value if form in {"direct", "alias", "join", "star"} else "[REDACTED]"
    assert revealed[0].cells[key] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "confirmation,expected",
    [(None, "S******** P*****"), ("incorrect", "S******** P*****"), ("EXPLICIT_USER_REQUESTED_UNMASKED_DATA", "Synthetic Person")],
)
async def test_confirmation_contract_at_actual_server_seam(confirmation, expected):
    policy = RedactionPolicy.from_dict(POLICIES[0])
    driver = make_driver({("public", "contacts"): ["id", "name"]})
    redactor = ResultRedactor(driver, policy)
    original_execute = driver.execute_query.side_effect

    async def execute(query, *args, **kwargs):
        if query == "SELECT name FROM public.contacts":
            return [SqlDriver.RowResult({"name": "Synthetic Person"})]
        return await original_execute(query, *args, **kwargs)

    driver.execute_query = AsyncMock(side_effect=execute)
    with (
        patch.object(server, "get_sql_driver", AsyncMock(return_value=driver)),
        patch.object(server, "result_redactor", redactor),
        patch.object(server, "current_redaction_config", RedactionConfig(policy=policy)),
    ):
        response = await server.execute_sql("SELECT name FROM public.contacts", reveal_columns=["name"], reveal_confirmation=confirmation)
    assert isinstance(response[0], TextContent)
    assert expected in response[0].text
