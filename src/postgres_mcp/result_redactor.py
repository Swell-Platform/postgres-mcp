from __future__ import annotations

import importlib
import logging
import re
from dataclasses import dataclass
from typing import Any
from typing import Protocol

from .redaction_policy import RedactionPolicy
from .result_provenance import FieldProvenance
from .result_provenance import ResultProvenanceResolver
from .sql.sql_driver import SqlDriver

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RedactionDecision:
    redact: bool
    used_detector: bool = False


class Detector(Protocol):
    def should_redact(self, value: Any) -> bool: ...


class PatternDetector:
    PHONE_PATTERN = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
    EMAIL_PATTERN = re.compile(r"\b[^@\s]+@[^@\s]+\.[^@\s]+\b")
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    def should_redact(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        return bool(
            self.PHONE_PATTERN.search(value)
            or self.EMAIL_PATTERN.search(value)
            or self.SSN_PATTERN.search(value)
        )


class PresidioDetector:
    def __init__(self):
        try:
            analyzer_module = importlib.import_module("presidio_analyzer")
            nlp_engine_module = importlib.import_module("presidio_analyzer.nlp_engine")
            recognizer_registry_module = importlib.import_module("presidio_analyzer.recognizer_registry")
            analyzer_engine_cls = analyzer_module.AnalyzerEngine
            recognizer_registry_cls = recognizer_registry_module.RecognizerRegistry
            nlp_engine_provider_cls = nlp_engine_module.NlpEngineProvider

            nlp_provider = nlp_engine_provider_cls(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [
                        {
                            "lang_code": "en",
                            "model_name": "en_core_web_lg",
                        }
                    ],
                }
            )
            nlp_engine = nlp_provider.create_engine()

            registry = recognizer_registry_cls(
                supported_languages=["en"],
            )
            registry.load_predefined_recognizers(languages=["en"])
            registry.add_nlp_recognizer(nlp_engine)

            self.analyzer = analyzer_engine_cls(
                registry=registry,
                nlp_engine=nlp_engine,
                supported_languages=["en"],
            )
        except ImportError as exc:
            raise ValueError(
                "Presidio redaction detector requires the optional 'presidio-analyzer' package and its NLP dependencies"
            ) from exc
        except Exception as exc:
            raise ValueError(
                "Presidio redaction detector could not be initialized. Ensure Presidio and its NLP model dependencies are installed"
            ) from exc

    def should_redact(self, value: Any) -> bool:
        if not isinstance(value, str) or not value.strip():
            return False
        results = self.analyzer.analyze(text=value, language="en")
        return bool(results)


class ResultRedactor:
    def __init__(self, sql_driver: SqlDriver, policy: RedactionPolicy):
        self.sql_driver = sql_driver
        self.policy = policy
        self.provenance_resolver = ResultProvenanceResolver(sql_driver)
        self.detector = self._build_detector(policy.detector)

    async def redact_rows(self, sql: str, rows: list[SqlDriver.RowResult]) -> list[SqlDriver.RowResult]:
        if not rows or not self.policy.is_enabled():
            return rows

        result_columns = list(rows[0].cells.keys())
        provenance_by_column = await self.provenance_resolver.resolve(sql, result_columns)

        redacted_rows: list[SqlDriver.RowResult] = []
        redacted_columns: set[str] = set()
        for row in rows:
            redacted_cells = dict(row.cells)
            for column_name, value in row.cells.items():
                provenance = provenance_by_column.get(column_name)
                decision = self._decide_redaction(provenance, value)
                if decision.redact:
                    redacted_cells[column_name] = self.policy.replacement_text
                    redacted_columns.add(column_name)
            redacted_rows.append(SqlDriver.RowResult(cells=redacted_cells))

        logger.info(
            "Applied redaction to %s of %s result columns: %s",
            len(redacted_columns),
            len(result_columns),
            sorted(redacted_columns),
        )
        return redacted_rows

    def _decide_redaction(self, provenance: FieldProvenance | None, value: Any) -> RedactionDecision:
        if provenance is None:
            return self._detector_decision(value)

        matched_rules = [self.policy.rule_for_column(source.schema, source.table, source.column) for source in provenance.sources]
        rules = [rule for rule in matched_rules if rule is not None]
        if any(rule.force_redact for rule in rules):
            return RedactionDecision(redact=True)

        if any(self.policy.is_column_protected(source.schema, source.table, source.column) for source in provenance.sources):
            return RedactionDecision(redact=True)

        if provenance.is_known:
            return RedactionDecision(redact=False)

        if any(rule.skip_detector for rule in rules):
            return RedactionDecision(redact=False)

        if self.policy.fallback_mode == "best_effort":
            if self.detector is None and self.policy.is_enabled():
                return RedactionDecision(redact=True)
            return self._detector_decision(value)

        return RedactionDecision(redact=False)

    def _detector_decision(self, value: Any) -> RedactionDecision:
        if self.detector is None:
            return RedactionDecision(redact=False)
        return RedactionDecision(redact=self.detector.should_redact(value), used_detector=True)

    def _build_detector(self, detector_name: str) -> Detector | None:
        if detector_name == "none":
            return None

        if detector_name == "simple":
            return PatternDetector()

        if detector_name == "presidio":
            return PresidioDetector()

        raise ValueError(f"Unsupported redaction detector: {detector_name}")
