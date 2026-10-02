"""Exercise the release image through MCP against an isolated local database."""

import asyncio
import os
import uuid

import docker
import pytest
from mcp import ClientSession
from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent


@pytest.mark.asyncio
async def test_release_image_is_callable_and_readonly():
    image = os.environ.get("POSTGRES_MCP_TEST_IMAGE")
    if not image:
        pytest.skip("Set POSTGRES_MCP_TEST_IMAGE to exercise the built container")
    client = docker.from_env()
    network_name = "postgres-mcp-smoke-" + uuid.uuid4().hex
    network = client.networks.create(network_name)
    database = None
    try:
        database = client.containers.run(
            "postgres:16-alpine",
            environment={"POSTGRES_HOST_AUTH_METHOD": "trust"},
            network=network_name,
            detach=True,
        )
        async with asyncio.timeout(30):
            while database.exec_run("pg_isready -U postgres").exit_code != 0:
                await asyncio.sleep(0.2)
        parameters = StdioServerParameters(
            command="docker",
            args=[
                "run",
                "--rm",
                "-i",
                "--network",
                network_name,
                "-e",
                f"DATABASE_URI=postgresql://postgres@{database.name}/postgres",
                "-e",
                "POSTGRES_MCP_REDACTION_DETECTOR=presidio",
                image,
                "--access-mode=restricted",
            ],
        )
        async with asyncio.timeout(60):
            async with stdio_client(parameters) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    explain = next(tool for tool in tools.tools if tool.name == "explain_query")
                    assert "timeout_ms" in explain.inputSchema["properties"]
                    plan = await session.call_tool("explain_query", {"sql": "SELECT 1", "analyze": True})
                    assert not plan.isError
                    assert plan.structuredContent is not None
                    assert plan.structuredContent["Plan"]["Actual Rows"] == 1
                    readonly = await session.call_tool("execute_sql", {"sql": "SELECT current_setting('transaction_read_only') AS mode"})
                    assert not readonly.isError
                    assert any("on" in item.text for item in readonly.content if isinstance(item, TextContent))
                    mutation = await session.call_tool("execute_sql", {"sql": "CREATE TABLE smoke_mutation (id integer)"})
                    assert "Error" in "".join(item.text for item in mutation.content if isinstance(item, TextContent))
                    # A derived-table column has unknown provenance and exercises
                    # the configured detector, rather than a known SQL literal.
                    redacted = await session.call_tool(
                        "execute_sql", {"sql": "SELECT lower(value) AS value FROM (SELECT 'release-smoke@example.com' AS value) sample"}
                    )
                    assert not redacted.isError
                    output = "".join(item.text for item in redacted.content if isinstance(item, TextContent))
                    assert "release-smoke@example.com" not in output
                    assert "[REDACTED]" in output
    finally:
        if database is not None:
            database.remove(force=True, v=True)
        network.remove()
        client.close()
