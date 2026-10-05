"""Remove data literals before diagnostic results reach renderers."""

from typing import Any

from pglast import scan

from .redaction_policy import REDACTION_PLACEHOLDER
from .sql.sql_driver import SqlDriver

SQL_FIELDS = {
    "query",
    "query_text",
    "filter",
    "index cond",
    "recheck cond",
    "hash cond",
    "merge cond",
    "join filter",
    "one-time filter",
    "tid cond",
    "output",
    "remote sql",
    "indexdef",
    "definition",
    "sort key",
    "group key",
    "presorted key",
    "cache key",
    "sampling parameters",
    "function call",
    "run condition",
}


def redact_sql_literals(value: str) -> str:
    try:
        tokens = scan(value)
        # Scanner offsets are character offsets, including for Unicode input.
        for token in reversed(tokens):
            if token.name in {"SCONST", "USCONST", "BCONST", "XCONST", "ICONST", "FCONST", "C_COMMENT", "SQL_COMMENT"}:
                value = value[: token.start] + "'[REDACTED]'" + value[token.end + 1 :]
        return value
    except Exception:
        return REDACTION_PLACEHOLDER


def redact_diagnostics(value: Any, key: str = "") -> Any:
    # Optimizer traces contain free-form SQL and sampled values, not metrics.
    if key == "_langfuse_trace":
        return REDACTION_PLACEHOLDER
    if isinstance(value, dict):
        return {name: redact_diagnostics(child, str(name).lower()) for name, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_diagnostics(child, key) for child in value]
    if key == "error" and value:
        return REDACTION_PLACEHOLDER
    if isinstance(value, str) and key in SQL_FIELDS:
        return redact_sql_literals(value)
    return value


class DiagnosticSqlDriver(SqlDriver):
    """Keep diagnostic metadata; strip literals before any text/JSON rendering."""

    def __init__(self, *args, sanitize_rows=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.sanitize_rows = sanitize_rows

    async def execute_query(self, query, params=None, force_readonly=False):
        try:
            rows = await super().execute_query(query, params, force_readonly)
            return self._redact(rows) if rows is not None and self.sanitize_rows else rows
        except Exception as error:
            raise RuntimeError(f"{type(error).__name__}: database details withheld by redaction policy") from None

    async def execute_readonly_explain(self, query, *, timeout_ms):
        try:
            return self._redact(await super().execute_readonly_explain(query, timeout_ms=timeout_ms))
        except Exception as error:
            raise RuntimeError(f"{type(error).__name__}: database details withheld by redaction policy") from None

    @staticmethod
    def _redact(rows):
        return [SqlDriver.RowResult(cells=redact_diagnostics(row.cells)) for row in rows]
