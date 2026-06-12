import re
import sys
import types
from unittest.mock import AsyncMock
from unittest.mock import MagicMock

import pytest

from postgres_mcp.redaction_policy import RedactionPolicy
from postgres_mcp.result_redactor import ResultRedactor
from postgres_mcp.sql.sql_driver import SqlDriver


class MockCell:
    def __init__(self, data):
        self.cells = data


def make_driver(schema_map):
    driver = MagicMock(spec=SqlDriver)

    async def execute_query(query, params=None, force_readonly=False):
        del force_readonly
        normalized_query = " ".join(query.split()).lower()
        if "pg_catalog.pg_table_is_visible" in normalized_query:
            table_match = re.search(r"c\.relname = '([^']+)'", normalized_query)
            if not table_match:
                raise AssertionError(f"Could not parse visible schema query: {query}")
            table_name = table_match.group(1)
            matching_schemas = sorted(schema_name for schema_name, candidate_table in schema_map if candidate_table == table_name)
            if not matching_schemas:
                return []
            return [MockCell({"table_schema": matching_schemas[0]})]

        if "information_schema.columns" not in query:
            raise AssertionError(f"Unexpected schema lookup query: {query}")

        schema_match = re.search(r"table_schema = '([^']+)' and table_name = '([^']+)'", normalized_query)

        if schema_match:
            schema_name, table_name = schema_match.groups()
            columns = schema_map.get((schema_name, table_name), [])
            return [MockCell({"table_schema": schema_name, "column_name": column}) for column in columns]

        raise AssertionError(f"Could not parse schema lookup query: {query}")

    driver.execute_query = AsyncMock(side_effect=execute_query)
    return driver


@pytest.mark.asyncio
async def test_redacts_direct_protected_columns():
    driver = make_driver({("public", "patients"): ["email"]})
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.patients.email"]})
    redactor = ResultRedactor(driver, policy)

    rows = [SqlDriver.RowResult(cells={"email": "alice@example.com"})]
    result = await redactor.redact_rows("SELECT email FROM public.patients", rows)

    assert result[0].cells["email"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_redacts_aliased_protected_columns():
    driver = make_driver({("public", "patients"): ["email"]})
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.patients.email"]})
    redactor = ResultRedactor(driver, policy)

    rows = [SqlDriver.RowResult(cells={"contact": "alice@example.com"})]
    result = await redactor.redact_rows("SELECT p.email AS contact FROM public.patients p", rows)

    assert result[0].cells["contact"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_redacts_only_protected_fields_for_star_queries():
    driver = make_driver({("public", "patients"): ["id", "email", "name"]})
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.patients.email"]})
    redactor = ResultRedactor(driver, policy)

    rows = [SqlDriver.RowResult(cells={"id": 1, "email": "alice@example.com", "name": "Alice"})]
    result = await redactor.redact_rows("SELECT p.* FROM public.patients p", rows)

    assert result[0].cells == {"id": 1, "email": "[REDACTED]", "name": "Alice"}


@pytest.mark.asyncio
async def test_redacts_schema_qualified_policy_for_unqualified_selected_column():
    driver = make_driver({("public", "contacts"): ["email"]})
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.contacts.email"]})
    redactor = ResultRedactor(driver, policy)

    rows = [SqlDriver.RowResult(cells={"email": "alice@example.com"})]
    result = await redactor.redact_rows("SELECT email FROM contacts", rows)

    assert result[0].cells["email"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_redacts_schema_qualified_policy_for_unqualified_star_query():
    driver = make_driver({("public", "contacts"): ["id", "email", "phone_number"]})
    policy = RedactionPolicy.from_dict(
        {
            "protected_columns": ["public.contacts.email"],
            "column_rules": [{"column": "public.contacts.phone_number", "force_redact": True}],
        }
    )
    redactor = ResultRedactor(driver, policy)

    rows = [
        SqlDriver.RowResult(
            cells={"id": 1, "email": "alice@example.com", "phone_number": "303-555-0101"}
        )
    ]
    result = await redactor.redact_rows("SELECT * FROM contacts", rows)

    assert result[0].cells == {"id": 1, "email": "[REDACTED]", "phone_number": "[REDACTED]"}


@pytest.mark.asyncio
async def test_redacts_protected_columns_inside_computed_expressions():
    driver = make_driver({("public", "patients"): ["email"]})
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.patients.email"]})
    redactor = ResultRedactor(driver, policy)

    rows = [SqlDriver.RowResult(cells={"lowered": "alice@example.com"})]
    result = await redactor.redact_rows("SELECT lower(p.email) AS lowered FROM public.patients p", rows)

    assert result[0].cells["lowered"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_protected_join_columns_can_be_used_without_redacting_safe_output():
    driver = make_driver(
        {
            ("public", "orders"): ["id", "patient_id"],
            ("public", "patients"): ["id"],
        }
    )
    policy = RedactionPolicy.from_dict({"protected_tables": ["public.patients"]})
    redactor = ResultRedactor(driver, policy)

    rows = [SqlDriver.RowResult(cells={"id": 11, "count": 3})]
    result = await redactor.redact_rows(
        """
        SELECT o.id, count(*)
        FROM public.orders o
        JOIN public.patients p ON p.id = o.patient_id
        GROUP BY o.id
        """,
        rows,
    )

    assert result[0].cells == {"id": 11, "count": 3}


@pytest.mark.asyncio
async def test_detector_fallback_only_runs_for_unresolved_provenance():
    driver = make_driver(
        {
            ("public", "patients"): ["contact"],
            ("public", "contacts"): ["contact"],
            ("public", "telephony_events"): ["caller_number"],
        }
    )
    policy = RedactionPolicy.from_dict(
        {
            "detector": "simple",
            "column_rules": [{"column": "public.telephony_events.caller_number", "skip_detector": True}],
        }
    )
    redactor = ResultRedactor(driver, policy)

    unresolved_rows = [SqlDriver.RowResult(cells={"contact": "alice@example.com"})]
    unresolved_result = await redactor.redact_rows(
        """
        SELECT contact
        FROM public.patients p
        JOIN public.contacts c ON c.contact = p.contact
        """,
        unresolved_rows,
    )

    known_rows = [SqlDriver.RowResult(cells={"caller_number": "303-555-0100"})]
    known_result = await redactor.redact_rows(
        "SELECT caller_number FROM public.telephony_events",
        known_rows,
    )

    assert unresolved_result[0].cells["contact"] == "[REDACTED]"
    assert known_result[0].cells["caller_number"] == "303-555-0100"


@pytest.mark.asyncio
async def test_unknown_provenance_redacts_when_detector_is_disabled():
    driver = make_driver({})
    policy = RedactionPolicy.from_dict({"protected_columns": ["public.patients.email"]})
    redactor = ResultRedactor(driver, policy)

    rows = [SqlDriver.RowResult(cells={"masked": "alice@example.com"})]
    result = await redactor.redact_rows("SELECT lower(email) FROM (SELECT email FROM public.patients) p", rows)

    assert result[0].cells["masked"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_column_rules_can_force_redaction_for_specific_phone_columns():
    driver = make_driver(
        {
            ("public", "patients"): ["phone"],
            ("public", "telephony_events"): ["caller_number"],
        }
    )
    policy = RedactionPolicy.from_dict(
        {
            "detector": "simple",
            "column_rules": [
                {"column": "public.telephony_events.caller_number", "skip_detector": True},
                {"column": "public.patients.phone", "force_redact": True},
            ],
        }
    )
    redactor = ResultRedactor(driver, policy)

    patient_rows = [SqlDriver.RowResult(cells={"phone": "303-555-0101"})]
    caller_rows = [SqlDriver.RowResult(cells={"caller_number": "303-555-0102"})]

    patient_result = await redactor.redact_rows("SELECT phone FROM public.patients", patient_rows)
    caller_result = await redactor.redact_rows("SELECT caller_number FROM public.telephony_events", caller_rows)

    assert patient_result[0].cells["phone"] == "[REDACTED]"
    assert caller_result[0].cells["caller_number"] == "303-555-0102"


def test_presidio_detector_requires_optional_dependency(monkeypatch):
    real_import_module = __import__("importlib").import_module

    def fake_import_module(name, package=None):
        if name.startswith("presidio_analyzer"):
            raise ImportError("missing presidio")
        return real_import_module(name, package)

    monkeypatch.setattr("postgres_mcp.result_redactor.importlib.import_module", fake_import_module)

    driver = make_driver({})
    policy = RedactionPolicy.from_dict({"detector": "presidio"})

    with pytest.raises(ValueError, match="presidio-analyzer"):
        ResultRedactor(driver, policy)


def test_presidio_detector_uses_analyzer_results(monkeypatch):
    fake_module = types.ModuleType("presidio_analyzer")
    fake_nlp_module = types.ModuleType("presidio_analyzer.nlp_engine")
    fake_registry_module = types.ModuleType("presidio_analyzer.recognizer_registry")
    captured = {}

    class FakeRegistry:
        def __init__(self, supported_languages):
            captured["registry_supported_languages"] = supported_languages

        def load_predefined_recognizers(self, languages):
            captured["predefined_languages"] = languages

        def add_nlp_recognizer(self, nlp_engine):
            captured["registry_nlp_engine"] = nlp_engine

    class FakeRecognizerRegistry:
        def __init__(self, supported_languages):
            captured["registry_created"] = True
            self.registry = FakeRegistry(supported_languages)

        def load_predefined_recognizers(self, languages):
            self.registry.load_predefined_recognizers(languages)

        def add_nlp_recognizer(self, nlp_engine):
            self.registry.add_nlp_recognizer(nlp_engine)

    class FakeNlpEngineProvider:
        def __init__(self, nlp_configuration):
            captured["nlp_configuration"] = nlp_configuration

        def create_engine(self):
            captured["engine_created"] = True
            return "fake-nlp-engine"

    class FakeAnalyzerEngine:
        def __init__(self, registry, nlp_engine, supported_languages):
            captured["analyzer_registry"] = registry
            captured["analyzer_nlp_engine"] = nlp_engine
            captured["analyzer_supported_languages"] = supported_languages

        def analyze(self, text, language):
            assert language == "en"
            return ["match"] if "alice@example.com" in text else []

    fake_module.AnalyzerEngine = FakeAnalyzerEngine
    fake_nlp_module.NlpEngineProvider = FakeNlpEngineProvider
    fake_registry_module.RecognizerRegistry = FakeRecognizerRegistry
    monkeypatch.setitem(sys.modules, "presidio_analyzer", fake_module)
    monkeypatch.setitem(sys.modules, "presidio_analyzer.nlp_engine", fake_nlp_module)
    monkeypatch.setitem(sys.modules, "presidio_analyzer.recognizer_registry", fake_registry_module)

    driver = make_driver({})
    policy = RedactionPolicy.from_dict({"detector": "presidio"})
    redactor = ResultRedactor(driver, policy)

    assert redactor.detector is not None
    assert captured["registry_supported_languages"] == ["en"]
    assert captured["predefined_languages"] == ["en"]
    assert captured["nlp_configuration"] == {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    }
    assert captured["analyzer_supported_languages"] == ["en"]
    assert captured["analyzer_nlp_engine"] == "fake-nlp-engine"
    assert redactor.detector.should_redact("alice@example.com") is True
    assert redactor.detector.should_redact("safe value") is False
