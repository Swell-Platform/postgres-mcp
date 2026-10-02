# PostgreSQL Explain Tools

This module provides tools for analyzing PostgreSQL query execution plans.

## Tools

### ExplainPlanTool

Provides methods for generating different types of EXPLAIN plans.

## Usage

The explain tool is integrated into the PostgreSQL MCP server and can be used through the MCP API via the function:

- `explain_query`

This function accepts parameters to control the behavior:
- `sql` - The SQL query to explain (required)
- `analyze` - When true, executes the query to get real statistics (default: false)
- `hypothetical_indexes` - Optional list of indexes to simulate without creating them

For `analyze: true`, the server validates one read-only SELECT (including CTEs),
then uses a dedicated driver path with a read-only transaction and database
statement timeout. ANALYZE actually executes the query and can create database
load. It is supported in restricted mode through `explain_query`; raw ANALYZE
through `execute_sql` remains blocked there. Plain EXPLAIN is unchanged.

ANALYZE options: `timeout_ms` (default 30000, range 1–60000, also capped by the
restricted-mode timeout), `buffers` (true), `verbose` (false), `settings` (false),
`timing` (true), and `summary` (true). The server returns the complete JSON plan as
MCP structured content and JSON text rather than the text-oriented
`ExplainPlanArtifact`, which does not retain every execution statistic.

See the main [README](../../../README.md#explain-analyze-for-performance-investigation)
for the input schema, safety constraints and an MCP example call.

## Benefits

- **Query Understanding**: Helps understand how PostgreSQL executes queries
- **Performance Analysis**: Identifies bottlenecks and optimization opportunities
- **Index Testing**: Tests hypothetical indexes without actually creating them
