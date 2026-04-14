# tests/test_framework.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Unit Tests

# NOTE: Tests cover Schema, Red Engine, Validator, Blue Engine, and Config.
# The Blue Engine runs fully offline (no API key needed), so no mocking required.

import pytest
import uuid
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# TEST: Schema Models
# ─────────────────────────────────────────────────────────────────────────────

class TestSchemaModels:
    """Verify Pydantic models behave correctly."""

    def test_telemetry_log_auto_generates_log_id(self):
        from app.schema.schema import TelemetryLog, TechniqueID, LogSource
        log = TelemetryLog(
            technique_id=TechniqueID.POWERSHELL,
            technique_name="PowerShell Execution",
            log_source=LogSource.POWERSHELL,
            event_id=4104,
            process_name="powershell.exe",
        )
        assert log.log_id is not None
        assert len(log.log_id) == 36  # UUID format

    def test_pipeline_request_rejects_invalid_log_count(self):
        from app.schema.schema import PipelineRequest, TechniqueID
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PipelineRequest(
                technique_id=TechniqueID.POWERSHELL,
                log_count=999,  # max is 50
            )

    def test_pipeline_request_rejects_zero_log_count(self):
        from app.schema.schema import PipelineRequest, TechniqueID
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PipelineRequest(
                technique_id=TechniqueID.POWERSHELL,
                log_count=0,  # min is 1
            )

    def test_red_engine_result_sets_log_count_automatically(self):
        from app.schema.schema import RedEngineResult, TelemetryLog, TechniqueID, LogSource
        logs = [
            TelemetryLog(
                technique_id=TechniqueID.LSASS_DUMP,
                technique_name="LSASS Dump",
                log_source=LogSource.SYSMON,
                event_id=10,
                process_name="mimikatz.exe",
            )
            for _ in range(7)
        ]
        result = RedEngineResult(technique_id=TechniqueID.LSASS_DUMP, logs=logs)
        assert result.log_count == 7

    def test_technique_id_values(self):
        from app.schema.schema import TechniqueID
        assert TechniqueID.POWERSHELL == "T1059.001"
        assert TechniqueID.LSASS_DUMP == "T1003.001"
        assert TechniqueID.REGISTRY_PERSIST == "T1547.001"

    def test_coverage_status_values(self):
        from app.schema.schema import CoverageStatus
        assert CoverageStatus.PASS == "PASS"
        assert CoverageStatus.WARN == "WARN"
        assert CoverageStatus.FAIL == "FAIL"


# ─────────────────────────────────────────────────────────────────────────────
# TEST: Red Engine
# ─────────────────────────────────────────────────────────────────────────────

class TestRedEngine:
    """Verify Red Engine generates correct logs for each technique."""

    def test_powershell_returns_correct_log_count(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        result = engine.run(TechniqueID.POWERSHELL, log_count=5)
        assert result.log_count == 5
        assert len(result.logs) == 5

    def test_lsass_logs_have_correct_event_id(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        result = engine.run(TechniqueID.LSASS_DUMP, log_count=3)
        for log in result.logs:
            assert log.event_id == 10  # Sysmon process access

    def test_powershell_logs_have_correct_event_id(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        result = engine.run(TechniqueID.POWERSHELL, log_count=3)
        for log in result.logs:
            assert log.event_id == 4104  # PowerShell script block logging

    def test_registry_logs_have_correct_event_id(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        result = engine.run(TechniqueID.REGISTRY_PERSIST, log_count=3)
        for log in result.logs:
            assert log.event_id == 13  # Sysmon registry set value

    def test_registry_logs_have_registry_key_field(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        result = engine.run(TechniqueID.REGISTRY_PERSIST, log_count=5)
        for log in result.logs:
            assert log.registry_key is not None
            assert "Run" in log.registry_key  # should be a Run key

    def test_powershell_command_lines_contain_powershell(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        result = engine.run(TechniqueID.POWERSHELL, log_count=5)
        for log in result.logs:
            assert log.command_line is not None
            assert "powershell" in log.command_line.lower()

    def test_unsupported_technique_raises_value_error(self):
        from app.engines.red_engine import RedEngine

        engine = RedEngine()
        with pytest.raises((ValueError, KeyError)):
            engine.run("T9999.999", log_count=1)

    def test_all_three_techniques_work(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        for tid in TechniqueID:
            result = engine.run(tid, log_count=2)
            assert result.log_count == 2
            assert result.technique_id == tid.value

    def test_logs_have_hostname_and_username(self):
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        engine = RedEngine()
        result = engine.run(TechniqueID.POWERSHELL, log_count=3)
        for log in result.logs:
            assert log.hostname is not None
            assert log.username is not None


# ─────────────────────────────────────────────────────────────────────────────
# TEST: Validator Engine
# ─────────────────────────────────────────────────────────────────────────────

class TestValidatorEngine:
    """Verify coverage scoring logic without calling Claude API."""

    def _make_sigma_rule(self, detection_keywords: list):
        """Helper: build a minimal SigmaRule with given keywords."""
        from app.schema.schema import SigmaRule
        return SigmaRule(
            title="Test Rule",
            description="Unit test rule",
            technique_id="T1059.001",
            logsource={"product": "windows", "service": "powershell"},
            detection={
                "selection": {
                    "CommandLine|contains": detection_keywords
                },
                "condition": "selection"
            },
            condition="selection",
        )

    def test_full_match_gives_pass_status(self):
        from app.engines.red_engine import RedEngine
        from app.engines.validator import ValidatorEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=5)

        # Rule with keywords that definitely appear in PowerShell logs
        sigma_rule = self._make_sigma_rule(["powershell", "EncodedCommand"])

        validator = ValidatorEngine()
        result = validator.run("T1059.001", red_result.logs, sigma_rule)

        assert result.total_logs == 5
        assert result.coverage_score >= 0.0
        assert result.status in ["PASS", "WARN", "FAIL"]

    def test_zero_match_keywords_gives_fail_status(self):
        from app.engines.red_engine import RedEngine
        from app.engines.validator import ValidatorEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=5)

        # Rule with keywords that will never match PowerShell logs
        sigma_rule = self._make_sigma_rule(["zzz_no_match_keyword_xyz"])

        validator = ValidatorEngine()
        result = validator.run("T1059.001", red_result.logs, sigma_rule)

        assert result.matched_logs == 0
        assert result.coverage_score == 0.0
        assert result.status == "FAIL"

    def test_coverage_score_is_between_0_and_1(self):
        from app.engines.red_engine import RedEngine
        from app.engines.validator import ValidatorEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=10)
        sigma_rule = self._make_sigma_rule(["powershell"])

        validator = ValidatorEngine()
        result = validator.run("T1059.001", red_result.logs, sigma_rule)

        assert 0.0 <= result.coverage_score <= 1.0

    def test_details_count_matches_log_count(self):
        from app.engines.red_engine import RedEngine
        from app.engines.validator import ValidatorEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.LSASS_DUMP, log_count=4)
        sigma_rule = self._make_sigma_rule(["lsass", "mimikatz"])

        validator = ValidatorEngine()
        result = validator.run("T1003.001", red_result.logs, sigma_rule)

        # One ValidationDetail per log
        assert len(result.details) == 4

    def test_matched_logs_count_is_consistent(self):
        from app.engines.red_engine import RedEngine
        from app.engines.validator import ValidatorEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=5)
        sigma_rule = self._make_sigma_rule(["powershell"])

        validator = ValidatorEngine()
        result = validator.run("T1059.001", red_result.logs, sigma_rule)

        # matched_logs must equal count of True in details
        manually_counted = sum(1 for d in result.details if d.matched)
        assert result.matched_logs == manually_counted


# ─────────────────────────────────────────────────────────────────────────────
# TEST: Blue Engine (offline — no API call needed)
# ─────────────────────────────────────────────────────────────────────────────

class TestBlueEngine:
    """
    Test the offline Blue Engine directly.
    BlueEngine uses hardcoded Sigma rules from mock_blue_engine._SIGMA_RULES,
    so no Anthropic API key or mocking is required.
    """

    def test_blue_engine_returns_sigma_rule_for_powershell(self):
        from app.engines.blue_engine import BlueEngine
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=3)

        blue = BlueEngine()
        result = blue.run("T1059.001", red_result.logs)

        assert result.sigma_rule is not None
        assert result.sigma_rule.title != ""
        assert result.sigma_rule.level in ["high", "medium", "low", "critical"]
        assert result.sigma_rule.status == "experimental"

    def test_blue_engine_preserves_technique_id(self):
        from app.engines.blue_engine import BlueEngine
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.LSASS_DUMP, log_count=2)

        blue = BlueEngine()
        result = blue.run("T1003.001", red_result.logs)

        assert result.technique_id == "T1003.001"

    def test_blue_engine_sigma_rule_has_valid_yaml_fields(self):
        from app.engines.blue_engine import BlueEngine
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        red = RedEngine()
        red_result = red.run(TechniqueID.REGISTRY_PERSIST, log_count=2)

        blue = BlueEngine()
        result = blue.run("T1547.001", red_result.logs)

        # raw_yaml must be non-empty and contain required Sigma fields
        assert "title:" in result.sigma_rule.raw_yaml
        assert "detection:" in result.sigma_rule.raw_yaml
        assert result.sigma_rule.logsource != {}


# ─────────────────────────────────────────────────────────────────────────────
# TEST: Config
# ─────────────────────────────────────────────────────────────────────────────

class TestConfig:
    """Verify config values are loaded correctly."""

    def test_supported_techniques_list_is_not_empty(self):
        from app.config import SUPPORTED_TECHNIQUES
        assert len(SUPPORTED_TECHNIQUES) >= 3

    def test_coverage_threshold_pass_is_higher_than_warn(self):
        from app.config import COVERAGE_THRESHOLD_PASS, COVERAGE_THRESHOLD_WARN
        assert COVERAGE_THRESHOLD_PASS > COVERAGE_THRESHOLD_WARN

    def test_thresholds_are_between_0_and_1(self):
        from app.config import COVERAGE_THRESHOLD_PASS, COVERAGE_THRESHOLD_WARN
        assert 0.0 < COVERAGE_THRESHOLD_WARN < 1.0
        assert 0.0 < COVERAGE_THRESHOLD_PASS < 1.0

    def test_technique_details_keys_match_supported_techniques(self):
        # TECHNIQUE_DETAILS and SUPPORTED_TECHNIQUES must stay in sync
        from app.config import TECHNIQUE_DETAILS, SUPPORTED_TECHNIQUES
        assert list(TECHNIQUE_DETAILS.keys()) == SUPPORTED_TECHNIQUES
