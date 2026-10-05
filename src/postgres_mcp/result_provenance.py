from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pglast import parse_sql
from pglast.ast import A_Star
from pglast.ast import ColumnRef
from pglast.ast import JoinExpr
from pglast.ast import Node
from pglast.ast import RangeVar
from pglast.ast import ResTarget
from pglast.ast import SelectStmt

from .redaction_policy import normalize_identifier
from .redaction_policy import normalize_optional_identifier
from .sql.safe_sql import SafeSqlDriver
from .sql.sql_driver import SqlDriver


@dataclass(frozen=True)
class SourceColumn:
    schema: str | None
    table: str
    column: str


@dataclass(frozen=True)
class FieldProvenance:
    sources: tuple[SourceColumn, ...]
    is_known: bool
    is_direct_column: bool = False


@dataclass(frozen=True)
class TableRef:
    schema: str | None
    table: str
    alias: str | None


UNKNOWN_PROVENANCE = FieldProvenance(sources=(), is_known=False)


class ResultProvenanceResolver:
    def __init__(self, sql_driver: SqlDriver):
        self.sql_driver = sql_driver
        self._table_columns_cache: dict[tuple[str | None, str], tuple[SourceColumn, ...]] = {}
        self._visible_schema_cache: dict[str, str | None] = {}

    async def resolve(self, sql: str, result_columns: list[str]) -> dict[str, FieldProvenance]:
        if not result_columns:
            return {}

        try:
            parsed = parse_sql(sql)
        except Exception:
            return {column: UNKNOWN_PROVENANCE for column in result_columns}

        if len(parsed) != 1 or not isinstance(parsed[0].stmt, SelectStmt):
            return {column: UNKNOWN_PROVENANCE for column in result_columns}

        stmt = parsed[0].stmt
        # CTE names can shadow real tables. Until CTE lineage is resolved,
        # they must never be treated as physical unprotected relations.
        if getattr(stmt, "withClause", None) is not None:
            return {column: UNKNOWN_PROVENANCE for column in result_columns}
        scope = self._collect_scope(stmt)
        target_provenance = await self._resolve_target_list(stmt, scope)

        # dict_row collapses duplicate aliases; JOIN USING/NATURAL can also
        # change star ordering. Never map sources positionally after a mismatch.
        if len(target_provenance) != len(result_columns):
            return {column: UNKNOWN_PROVENANCE for column in result_columns}

        results: dict[str, FieldProvenance] = {}
        for idx, column_name in enumerate(result_columns):
            if idx < len(target_provenance):
                results[column_name] = target_provenance[idx]
            else:
                results[column_name] = UNKNOWN_PROVENANCE
        return results

    def _collect_scope(self, stmt: SelectStmt) -> list[TableRef]:
        tables: list[TableRef] = []
        for from_item in getattr(stmt, "fromClause", None) or []:
            self._collect_from_item(from_item, tables)
        return tables

    def _collect_from_item(self, from_item: Any, tables: list[TableRef]) -> None:
        if isinstance(from_item, RangeVar):
            table_alias = from_item.alias
            alias = table_alias.aliasname if table_alias is not None else None
            tables.append(
                TableRef(
                    schema=normalize_optional_identifier(getattr(from_item, "schemaname", None)),
                    table=normalize_identifier(str(from_item.relname)),
                    alias=normalize_optional_identifier(alias),
                )
            )
            return

        if isinstance(from_item, JoinExpr):
            if getattr(from_item, "larg", None) is not None:
                self._collect_from_item(from_item.larg, tables)
            if getattr(from_item, "rarg", None) is not None:
                self._collect_from_item(from_item.rarg, tables)

    async def _resolve_target_list(self, stmt: SelectStmt, scope: list[TableRef]) -> list[FieldProvenance]:
        provenance: list[FieldProvenance] = []
        for target in getattr(stmt, "targetList", None) or []:
            provenance.extend(await self._expand_target(target, scope))
        return provenance

    async def _expand_target(self, target: ResTarget, scope: list[TableRef]) -> list[FieldProvenance]:
        value = getattr(target, "val", None)
        if isinstance(value, ColumnRef):
            fields = self._extract_fields(value)
            if len(fields) == 1 and fields[0] == "*":
                return await self._expand_all_tables(scope)
            if len(fields) == 2 and fields[1] == "*":
                table_ref = self._resolve_table_reference(scope, fields[0])
                if table_ref is None:
                    return [UNKNOWN_PROVENANCE]
                return await self._expand_table(table_ref)

        sources, is_known = await self._collect_expression_sources(value, scope)
        return [
            FieldProvenance(
                sources=tuple(sorted(sources, key=lambda item: ((item.schema or ""), item.table, item.column))),
                is_known=is_known,
                is_direct_column=isinstance(value, ColumnRef),
            )
        ]

    async def _expand_all_tables(self, scope: list[TableRef]) -> list[FieldProvenance]:
        provenance: list[FieldProvenance] = []
        for table_ref in scope:
            provenance.extend(await self._expand_table(table_ref))
        return provenance

    async def _expand_table(self, table_ref: TableRef) -> list[FieldProvenance]:
        columns = await self._get_table_columns(table_ref.schema, table_ref.table)
        source_schema = await self._resolve_table_schema(table_ref.schema, table_ref.table)
        return [
            FieldProvenance(
                sources=(SourceColumn(schema=source_schema, table=table_ref.table, column=column),),
                is_known=True,
                is_direct_column=True,
            )
            for column in columns
        ]

    async def _collect_expression_sources(self, node: Any, scope: list[TableRef]) -> tuple[set[SourceColumn], bool]:
        if node is None:
            return set(), True
        if isinstance(node, ColumnRef):
            return await self._resolve_column_ref(node, scope)
        if isinstance(node, SelectStmt):
            return set(), False
        if isinstance(node, (list, tuple)):
            combined_sources: set[SourceColumn] = set()
            all_known = True
            for item in node:
                item_sources, item_known = await self._collect_expression_sources(item, scope)
                combined_sources.update(item_sources)
                all_known = all_known and item_known
            return combined_sources, all_known

        if isinstance(node, (str, int, float, bool)):
            return set(), True

        if isinstance(node, Node):
            combined_sources: set[SourceColumn] = set()
            all_known = True
            for value in self._iter_node_values(node):
                child_sources, child_known = await self._collect_expression_sources(value, scope)
                combined_sources.update(child_sources)
                all_known = all_known and child_known
            return combined_sources, all_known

        if hasattr(node, "__dict__"):
            combined_sources = set()
            all_known = True
            for value in vars(node).values():
                child_sources, child_known = await self._collect_expression_sources(value, scope)
                combined_sources.update(child_sources)
                all_known = all_known and child_known
            return combined_sources, all_known

        return set(), True

    def _iter_node_values(self, node: Node) -> list[Any]:
        slot_names = getattr(node, "__slots__", ())
        if isinstance(slot_names, dict):
            return [getattr(node, attr_name) for attr_name in slot_names]
        if isinstance(slot_names, (list, tuple, set)):
            return [getattr(node, attr_name) for attr_name in slot_names]
        if hasattr(node, "__dict__"):
            return list(vars(node).values())
        return []

    async def _resolve_column_ref(self, node: ColumnRef, scope: list[TableRef]) -> tuple[set[SourceColumn], bool]:
        fields = self._extract_fields(node)
        if not fields:
            return set(), False

        if "*" in fields:
            table_ref = self._resolve_table_reference(scope, fields[0]) if len(fields) == 2 else None
            if table_ref is None:
                return set(), False
            return {source for field in await self._expand_table(table_ref) for source in field.sources}, True

        if len(fields) == 3:
            schema_name, table_name, column_name = fields
            return {
                SourceColumn(
                    schema=normalize_identifier(schema_name),
                    table=normalize_identifier(table_name),
                    column=normalize_identifier(column_name),
                )
            }, True

        if len(fields) == 2:
            table_ref = self._resolve_table_reference(scope, fields[0])
            if table_ref is None:
                return set(), False
            source_schema = await self._resolve_table_schema(table_ref.schema, table_ref.table)
            return {
                SourceColumn(
                    schema=source_schema,
                    table=table_ref.table,
                    column=normalize_identifier(fields[1]),
                )
            }, True

        if len(fields) == 1:
            matches: list[SourceColumn] = []
            column_name = normalize_identifier(fields[0])
            # A table alias by itself is a whole-row value (e.g. row_to_json(t)).
            table_ref = self._resolve_table_reference(scope, column_name)
            if table_ref is not None:
                return {source for field in await self._expand_table(table_ref) for source in field.sources}, True
            for table_ref in scope:
                if await self._table_has_column(table_ref.schema, table_ref.table, column_name):
                    matches.append(
                        SourceColumn(
                            schema=await self._resolve_table_schema(table_ref.schema, table_ref.table),
                            table=table_ref.table,
                            column=column_name,
                        )
                    )

            if len(matches) == 1:
                return set(matches), True
            return set(matches), False

        return set(), False

    def _resolve_table_reference(self, scope: list[TableRef], table_or_alias: str) -> TableRef | None:
        normalized = normalize_identifier(table_or_alias)
        for table_ref in scope:
            if table_ref.alias == normalized or table_ref.table == normalized:
                return table_ref
        return None

    def _extract_fields(self, node: ColumnRef) -> list[str]:
        extracted: list[str] = []
        for field in getattr(node, "fields", None) or []:
            if isinstance(field, A_Star):
                extracted.append("*")
            elif hasattr(field, "sval"):
                extracted.append(str(field.sval))
        return extracted

    async def _table_has_column(self, schema: str | None, table: str, column: str) -> bool:
        columns = await self._get_table_columns(schema, table)
        return column in columns

    async def _resolve_table_schema(self, schema: str | None, table: str) -> str | None:
        if schema is not None:
            return schema

        if table in self._visible_schema_cache:
            return self._visible_schema_cache[table]

        rows = await SafeSqlDriver.execute_param_query(
            self.sql_driver,
            """
            SELECT n.nspname AS table_schema
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = {}
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND pg_catalog.pg_table_is_visible(c.oid)
            ORDER BY n.nspname
            LIMIT 1
            """,
            [table],
        )

        resolved_schema = normalize_identifier(str(rows[0].cells["table_schema"])) if rows else None
        self._visible_schema_cache[table] = resolved_schema
        return resolved_schema

    async def _get_table_columns(self, schema: str | None, table: str) -> list[str]:
        cache_key = (schema, table)
        if cache_key in self._table_columns_cache:
            return [source.column for source in self._table_columns_cache[cache_key]]

        effective_schema = await self._resolve_table_schema(schema, table)
        if effective_schema is None:
            self._table_columns_cache[cache_key] = ()
            return []

        rows = await SafeSqlDriver.execute_param_query(
            self.sql_driver,
            """
            SELECT table_schema, column_name
            FROM information_schema.columns
            WHERE table_schema = {} AND table_name = {}
            ORDER BY ordinal_position
            """,
            [effective_schema, table],
        )

        columns = (
            tuple(
                SourceColumn(
                    schema=normalize_identifier(str(row.cells["table_schema"])),
                    table=normalize_identifier(table),
                    column=normalize_identifier(str(row.cells["column_name"])),
                )
                for row in rows
            )
            if rows
            else ()
        )
        self._table_columns_cache[cache_key] = columns
        return [source.column for source in columns]
