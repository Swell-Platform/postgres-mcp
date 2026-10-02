from unittest.mock import AsyncMock
from unittest.mock import Mock

import pytest

from postgres_mcp import server
from postgres_mcp.sql import SafeSqlDriver
from postgres_mcp.sql import SqlDriver


@pytest.mark.asyncio
async def test_analyze_is_registered_with_bounded_timeout():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert "explain_query" in tools
    tool = tools["explain_query"]
    assert "explain_analyze_query" not in tools
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    assert tool.inputSchema["required"] == ["sql"]
    timeout = tool.inputSchema["properties"]["timeout_ms"]
    assert timeout["default"] == 30000
    assert timeout["minimum"] == 1
    assert timeout["maximum"] == 60000


@pytest.mark.asyncio
@pytest.mark.parametrize("sql", ["SELECT 1", "WITH sample AS (SELECT 1 AS n) SELECT n FROM sample"])
async def test_safe_analyze_select(sql):
    base = Mock(spec=SqlDriver)
    base.execute_readonly_explain = AsyncMock(return_value=[SqlDriver.RowResult(cells={"QUERY PLAN": [{"Plan": {}}]})])
    driver = SafeSqlDriver(base)
    await driver.explain_analyze_query(sql, timeout_ms=1000)
    base.execute_readonly_explain.assert_awaited_once_with(
        f"EXPLAIN (ANALYZE, BUFFERS TRUE, VERBOSE FALSE, SETTINGS FALSE, TIMING TRUE, SUMMARY TRUE, FORMAT JSON) {sql}",
        timeout_ms=1000,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "",
        "-- comment",
        "SELECT 1; SELECT 2",
        "SELECT 1; COMMIT",
        "SET TRANSACTION READ WRITE",
        "SELECT 1; SET statement_timeout = 0",
        "SELECT set_config('statement_timeout', '0', true)",
        "SELECT pg_catalog.set_config('transaction_read_only', 'off', true)",
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET n = 2",
        "DELETE FROM t",
        "DROP TABLE t",
        "COPY t TO STDOUT",
        "WITH changed AS (DELETE FROM t RETURNING *) SELECT * FROM changed",
        "WITH changed AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM changed",
        "WITH changed AS (UPDATE t SET n = 2 RETURNING *) SELECT * FROM changed",
        "SELECT 1 INTO new_table",
        "SELECT * FROM t FOR UPDATE",
        "EXPLAIN ANALYZE SELECT 1",
    ],
)
async def test_unsafe_analyze_rejected_before_execution(sql):
    base = Mock(spec=SqlDriver)
    base.execute_readonly_explain = AsyncMock()
    with pytest.raises(ValueError):
        await SafeSqlDriver(base).explain_analyze_query(sql)
    base.execute_readonly_explain.assert_not_awaited()
