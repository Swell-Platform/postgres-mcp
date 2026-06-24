import asyncio
from pathlib import Path
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from postgres_mcp.server import AccessMode
from postgres_mcp.server import get_sql_driver
from postgres_mcp.sql.safe_sql import SafeSqlDriver
from postgres_mcp.sql.sql_driver import DbConnPool
from postgres_mcp.sql.sql_driver import SqlDriver


@pytest.fixture
def mock_db_connection():
    """Mock database connection pool."""
    conn = MagicMock(spec=DbConnPool)
    conn.is_valid = True
    return conn


@pytest.mark.parametrize(
    "access_mode,expected_driver_type",
    [
        (AccessMode.UNRESTRICTED, SqlDriver),
        (AccessMode.RESTRICTED, SafeSqlDriver),
    ],
)
@pytest.mark.asyncio
async def test_get_sql_driver_returns_correct_driver(access_mode, expected_driver_type, mock_db_connection):
    """Test that get_sql_driver returns the correct driver type based on access mode."""
    with (
        patch("postgres_mcp.server.current_access_mode", access_mode),
        patch("postgres_mcp.server.db_connection", mock_db_connection),
    ):
        driver = await get_sql_driver()
        assert isinstance(driver, expected_driver_type)

        # When in RESTRICTED mode, verify timeout is set
        if access_mode == AccessMode.RESTRICTED:
            assert isinstance(driver, SafeSqlDriver)
            assert driver.timeout == 30.0


@pytest.mark.asyncio
async def test_get_sql_driver_sets_timeout_in_restricted_mode(mock_db_connection):
    """Test that get_sql_driver sets the timeout in restricted mode."""
    with (
        patch("postgres_mcp.server.current_access_mode", AccessMode.RESTRICTED),
        patch("postgres_mcp.server.db_connection", mock_db_connection),
    ):
        driver = await get_sql_driver()
        assert isinstance(driver, SafeSqlDriver)
        assert driver.timeout == 30.0
        assert hasattr(driver, "sql_driver")


@pytest.mark.asyncio
async def test_get_sql_driver_uses_configured_timeout_in_restricted_mode(mock_db_connection):
    """Test that get_sql_driver uses the configured timeout in restricted mode."""
    with (
        patch("postgres_mcp.server.current_access_mode", AccessMode.RESTRICTED),
        patch("postgres_mcp.server.current_restricted_query_timeout_seconds", 75.0),
        patch("postgres_mcp.server.db_connection", mock_db_connection),
    ):
        driver = await get_sql_driver()
        assert isinstance(driver, SafeSqlDriver)
        assert driver.timeout == 75.0


@pytest.mark.asyncio
async def test_get_sql_driver_in_unrestricted_mode_no_timeout(mock_db_connection):
    """Test that get_sql_driver in unrestricted mode is a regular SqlDriver."""
    with (
        patch("postgres_mcp.server.current_access_mode", AccessMode.UNRESTRICTED),
        patch("postgres_mcp.server.db_connection", mock_db_connection),
    ):
        driver = await get_sql_driver()
        assert isinstance(driver, SqlDriver)
        assert not hasattr(driver, "timeout")


@pytest.mark.asyncio
async def test_command_line_parsing():
    """Test that command-line arguments correctly set the access mode."""
    import sys

    from postgres_mcp.server import main

    # Mock sys.argv and asyncio.run
    original_argv = sys.argv
    original_run = asyncio.run

    try:
        # Test with --access-mode=restricted
        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--access-mode=restricted",
        ]
        asyncio.run = AsyncMock()

        with (
            patch("postgres_mcp.server.current_access_mode", AccessMode.UNRESTRICTED),
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_stdio_async", AsyncMock()),
            patch("postgres_mcp.server.shutdown", AsyncMock()),
        ):
            # Reset the current_access_mode to UNRESTRICTED
            import postgres_mcp.server

            postgres_mcp.server.current_access_mode = AccessMode.UNRESTRICTED

            # Run main (partially mocked to avoid actual connection)
            try:
                await main()
            except Exception:
                pass

            # Verify the mode was changed to RESTRICTED
            assert postgres_mcp.server.current_access_mode == AccessMode.RESTRICTED

    finally:
        # Restore original values
        sys.argv = original_argv
        asyncio.run = original_run


@pytest.mark.asyncio
async def test_command_line_parsing_sets_restricted_query_timeout():
    """Test that command-line arguments correctly set the restricted query timeout."""
    import sys

    from postgres_mcp.server import main

    original_argv = sys.argv
    original_run = asyncio.run

    try:
        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--access-mode=restricted",
            "--restricted-query-timeout-seconds=75",
        ]
        asyncio.run = AsyncMock()

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_stdio_async", AsyncMock()),
            patch("postgres_mcp.server.shutdown", AsyncMock()),
        ):
            import postgres_mcp.server

            postgres_mcp.server.current_restricted_query_timeout_seconds = 30.0

            try:
                await main()
            except Exception:
                pass

            assert postgres_mcp.server.current_restricted_query_timeout_seconds == 75.0

    finally:
        sys.argv = original_argv
        asyncio.run = original_run


@pytest.mark.asyncio
async def test_env_var_sets_restricted_query_timeout(monkeypatch):
    import sys

    from postgres_mcp.server import main

    original_argv = sys.argv

    try:
        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--access-mode=restricted",
        ]
        monkeypatch.setenv("POSTGRES_MCP_RESTRICTED_QUERY_TIMEOUT_SECONDS", "45")

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_stdio_async", AsyncMock()),
            patch("postgres_mcp.server.shutdown", AsyncMock()),
        ):
            import postgres_mcp.server

            postgres_mcp.server.current_restricted_query_timeout_seconds = 30.0

            try:
                await main()
            except Exception:
                pass

            assert postgres_mcp.server.current_restricted_query_timeout_seconds == 45.0
    finally:
        sys.argv = original_argv


@pytest.mark.asyncio
async def test_main_fails_fast_on_invalid_restricted_timeout():
    import sys

    from postgres_mcp.server import main

    original_argv = sys.argv

    try:
        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--restricted-query-timeout-seconds=0",
        ]

        with pytest.raises(ValueError, match="Restricted query timeout must be greater than 0"):
            await main()
    finally:
        sys.argv = original_argv


@pytest.mark.asyncio
async def test_main_fails_fast_on_nan_restricted_timeout():
    import sys

    from postgres_mcp.server import main

    original_argv = sys.argv

    try:
        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--restricted-query-timeout-seconds=nan",
        ]

        with pytest.raises(ValueError, match="Restricted query timeout must be a finite number greater than 0"):
            await main()
    finally:
        sys.argv = original_argv


@pytest.mark.asyncio
async def test_main_fails_fast_on_invalid_redaction_policy(tmp_path: Path):
    import sys

    from postgres_mcp.server import main

    policy_path = tmp_path / "invalid-redaction.yml"
    policy_path.write_text("protected_columns: invalid")

    original_argv = sys.argv

    try:
        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            f"--redaction-policy-file={policy_path}",
        ]

        with pytest.raises(ValueError, match="Invalid column identifier"):
            await main()
    finally:
        sys.argv = original_argv
