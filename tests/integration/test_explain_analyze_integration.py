"""Harmless execution tests against an isolated local PostgreSQL container."""

import asyncio
import os
import sys
import time
from unittest.mock import patch

import docker
import psycopg
import pytest
import pytest_asyncio
from docker.errors import DockerException
from mcp import ClientSession
from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent
from psycopg.pq import TransactionStatus
from psycopg_pool import AsyncConnectionPool

from postgres_mcp import server
from postgres_mcp.sql import DbConnPool
from postgres_mcp.sql import SafeSqlDriver
from postgres_mcp.sql import SqlDriver


@pytest.fixture(scope="module")
def analyze_database_url():
    try:
        client = docker.from_env()
        client.ping()
    except DockerException:
        pytest.skip("Docker is not available")
    container = client.containers.run(
        "postgres:16-alpine",
        environment={"POSTGRES_HOST_AUTH_METHOD": "trust"},
        ports={"5432/tcp": ("127.0.0.1", 0)},
        detach=True,
    )
    try:
        container.reload()
        port = container.ports["5432/tcp"][0]["HostPort"]
        url = f"postgresql://postgres@127.0.0.1:{port}/postgres"
        deadline = time.monotonic() + 30
        while True:
            try:
                with psycopg.connect(url, connect_timeout=1):
                    break
            except psycopg.OperationalError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        yield url
    finally:
        container.remove(force=True, v=True)
        client.close()


@pytest_asyncio.fixture
async def analyze_connection(analyze_database_url):
    async with await psycopg.AsyncConnection.connect(analyze_database_url, autocommit=True) as conn:
        yield conn


async def assert_clean_connection(conn):
    assert conn.info.transaction_status == TransactionStatus.IDLE
    cursor = await conn.execute("SHOW statement_timeout")
    assert (await cursor.fetchone())[0] == "0"
    cursor = await conn.execute("SHOW transaction_read_only")
    assert (await cursor.fetchone())[0] == "off"
    cursor = await conn.execute("SELECT 1")
    assert (await cursor.fetchone())[0] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "WITH sample AS (SELECT 1 AS n) SELECT n FROM sample",
        "WITH RECURSIVE n AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM n WHERE n < 3) SELECT * FROM n",
    ],
)
async def test_select_and_cte_execution(analyze_connection, sql):
    driver = SafeSqlDriver(SqlDriver(conn=analyze_connection))
    rows = await driver.explain_analyze_query(sql, timeout_ms=1000)
    plan = rows[0].cells["QUERY PLAN"][0]
    assert plan["Plan"]["Actual Rows"] >= 1
    assert "Execution Time" in plan
    assert "Shared Hit Blocks" in plan["Plan"]
    await assert_clean_connection(analyze_connection)


@pytest.mark.asyncio
async def test_options_and_readonly_transaction(analyze_connection):
    driver = SafeSqlDriver(SqlDriver(conn=analyze_connection))
    # Division by zero makes this fail unless the query observes the enforced settings.
    sql = "SELECT 1 / CASE WHEN current_setting('transaction_read_only') = 'on' AND current_setting('statement_timeout') = '1234ms' THEN 1 ELSE 0 END"
    rows = await driver.explain_analyze_query(sql, timeout_ms=1234, buffers=False, verbose=True, timing=False, settings=True, summary=False)
    plan = rows[0].cells["QUERY PLAN"][0]
    assert "Output" in plan["Plan"]
    assert "Actual Total Time" not in plan["Plan"]
    assert "Shared Hit Blocks" not in plan["Plan"]
    assert "Execution Time" not in plan
    assert "Settings" in plan
    await assert_clean_connection(analyze_connection)


@pytest.mark.asyncio
async def test_failure_cleanup(analyze_connection):
    driver = SafeSqlDriver(SqlDriver(conn=analyze_connection))
    with pytest.raises(psycopg.errors.DivisionByZero):
        await driver.explain_analyze_query("SELECT 1 / 0", timeout_ms=1000)
    await assert_clean_connection(analyze_connection)


@pytest.mark.asyncio
async def test_statement_timeout_and_pool_reuse(analyze_database_url):
    db_pool = DbConnPool(analyze_database_url)
    try:
        # Limit the real pool before opening it: pool_connect's health check can
        # trigger growth, and resizing afterward doesn't immediately close extras.
        with patch("postgres_mcp.sql.sql_driver.AsyncConnectionPool", new=lambda **kwargs: AsyncConnectionPool(**{**kwargs, "max_size": 1})):
            pool = await db_pool.pool_connect()
        async with pool.connection() as conn:
            backend_pid = conn.info.backend_pid
        driver = SafeSqlDriver(SqlDriver(conn=db_pool))
        # Recursive SELECT is deliberately unbounded; the 10ms database timeout bounds all work.
        with pytest.raises(psycopg.errors.QueryCanceled, match="statement timeout"):
            await driver.explain_analyze_query(
                "WITH RECURSIVE n AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM n) SELECT count(*) FROM n", timeout_ms=10
            )
        assert db_pool.is_valid
        async with pool.connection() as conn:
            assert conn.info.backend_pid == backend_pid
            assert conn.info.transaction_status == TransactionStatus.IDLE
            cursor = await conn.execute("SHOW statement_timeout")
            row = await cursor.fetchone()
            assert row is not None and row[0] == "0"
            cursor = await conn.execute("SHOW transaction_read_only")
            row = await cursor.fetchone()
            assert row is not None and row[0] == "off"
        rows = await driver.explain_analyze_query("SELECT 1", timeout_ms=1000)
        assert rows[0].cells["QUERY PLAN"][0]["Plan"]["Actual Rows"] == 1
    finally:
        await db_pool.close()


@pytest.mark.asyncio
async def test_task_cancellation_cleanup(analyze_connection):
    driver = SafeSqlDriver(SqlDriver(conn=analyze_connection))
    task = asyncio.create_task(
        driver.explain_analyze_query("WITH RECURSIVE n AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM n) SELECT count(*) FROM n", timeout_ms=1000)
    )
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await assert_clean_connection(analyze_connection)


@pytest.mark.asyncio
async def test_reject_nested_transaction(analyze_connection):
    driver = SafeSqlDriver(SqlDriver(conn=analyze_connection))
    async with analyze_connection.transaction():
        with pytest.raises(ValueError, match="idle connection"):
            await driver.explain_analyze_query("SELECT 1")
    await assert_clean_connection(analyze_connection)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [server.AccessMode.RESTRICTED, server.AccessMode.UNRESTRICTED])
async def test_server_analyze_in_both_access_modes(analyze_connection, mode):
    with patch.object(
        server,
        "get_sql_driver",
        return_value=SafeSqlDriver(SqlDriver(conn=analyze_connection))
        if mode == server.AccessMode.RESTRICTED
        else SqlDriver(conn=analyze_connection),
    ):
        result = await server.explain_query("SELECT 1", analyze=True)
        assert isinstance(result, server.types.CallToolResult)
        assert result.structuredContent is not None
        assert result.structuredContent["Plan"]["Actual Rows"] == 1
        result = await server.explain_query("DELETE FROM missing_table", analyze=True)
        assert isinstance(result, server.types.CallToolResult)
        assert result.isError
    await assert_clean_connection(analyze_connection)


@pytest.mark.asyncio
async def test_stdio_mcp_registration_and_call(analyze_database_url):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-c",
            "from postgres_mcp import main; main()",
            analyze_database_url,
            "--access-mode=restricted",
            "--restricted-query-timeout-seconds=0.2",
        ],
        env={**os.environ, "PYTHONPATH": os.path.abspath("src")},
    )
    async with stdio_client(parameters) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = {tool.name: tool for tool in (await session.list_tools()).tools}
        assert "explain_query" in tools
        assert "explain_analyze_query" not in tools
        result = await session.call_tool("explain_query", {"analyze": True, "sql": "WITH sample AS (SELECT 1 AS n) SELECT n FROM sample"})
        assert not result.isError
        assert result.structuredContent is not None
        assert result.structuredContent["Plan"]["Actual Rows"] == 1
        assert "Shared Hit Blocks" in result.structuredContent["Plan"]
        for sql in [
            "DELETE FROM t",
            "WITH changed AS (DELETE FROM t RETURNING *) SELECT * FROM changed",
            "SELECT 1; SELECT 2",
            "SELECT set_config('statement_timeout', '0', true)",
        ]:
            result = await session.call_tool("explain_query", {"analyze": True, "sql": sql})
            assert result.isError
        for timeout in [0, 60001, True]:
            result = await session.call_tool("explain_query", {"analyze": True, "sql": "SELECT 1", "timeout_ms": timeout})
            assert result.isError
        result = await session.call_tool(
            "explain_query",
            {
                "analyze": True,
                "sql": "WITH RECURSIVE n AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM n) SELECT count(*) FROM n",
                "timeout_ms": 60000,
            },
        )
        assert result.isError
        assert isinstance(result.content[0], TextContent)
        assert "statement timeout" in result.content[0].text
        # Plain EXPLAIN still works after cancellation.
        result = await session.call_tool("explain_query", {"sql": "SELECT 1"})
        assert not result.isError
        assert isinstance(result.content[0], TextContent)
        assert "Error:" not in result.content[0].text
        result = await session.call_tool("explain_query", {"sql": "SELECT 1", "analyze": True})
        assert isinstance(result.content[0], TextContent)
        assert "Actual Rows" in result.content[0].text
