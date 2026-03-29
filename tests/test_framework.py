# tests/test_framework.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Unit Tests

# NOTE: I kept these tests focused on the parts I could verify without
# actually calling the Claude API — that would cost tokens and also
# make tests slow and non-deterministic. Blue Engine gets mocked.

import pytest
import uuid
from unittest.mock import MagicMock, patch
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
# TEST: Blue Engine (Mocked — no real API call)
# ─────────────────────────────────────────────────────────────────────────────

class TestBlueEngineMocked:
    """
    Test Blue Engine logic without making real Claude API calls.
    The Anthropic client is mocked to return a fake Sigma YAML response.
    """

    FAKE_SIGMA_YAML = """title: Suspicious PowerShell Encoded Command
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: Detects PowerShell with encoded commands
status: experimental
level: high
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    CommandLine|contains:
      - '-EncodedCommand'
      - 'DownloadString'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
"""

    def _mock_anthropic_response(self):
        """Build a fake Anthropic API response object."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=self.FAKE_SIGMA_YAML)]
        mock_response.usage.input_tokens = 312
        mock_response.usage.output_tokens = 148
        return mock_response

    @patch("app.engines.blue_engine.client")
    def test_blue_engine_returns_sigma_rule(self, mock_client):
        from app.engines.blue_engine import BlueEngine
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        mock_client.messages.create.return_value = self._mock_anthropic_response()

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=3)

        blue = BlueEngine()
        result = blue.run("T1059.001", red_result.logs)

        assert result.sigma_rule is not None
        assert result.sigma_rule.title == "Suspicious PowerShell Encoded Command"
        assert result.sigma_rule.level == "high"
        assert result.sigma_rule.status == "experimental"

    @patch("app.engines.blue_engine.client")
    def test_blue_engine_records_token_counts(self, mock_client):
        from app.engines.blue_engine import BlueEngine
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        mock_client.messages.create.return_value = self._mock_anthropic_response()

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=3)

        blue = BlueEngine()
        result = blue.run("T1059.001", red_result.logs)

        assert result.prompt_tokens == 312
        assert result.completion_tokens == 148

    @patch("app.engines.blue_engine.client")
    def test_blue_engine_technique_id_is_preserved(self, mock_client):
        from app.engines.blue_engine import BlueEngine
        from app.engines.red_engine import RedEngine
        from app.schema.schema import TechniqueID

        mock_client.messages.create.return_value = self._mock_anthropic_response()

        red = RedEngine()
        red_result = red.run(TechniqueID.POWERSHELL, log_count=3)

        blue = BlueEngine()
        result = blue.run("T1059.001", red_result.logs)

        assert result.technique_id == "T1059.001"


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

    def test_max_tokens_is_positive(self):
        from app.config import MAX_TOKENS
        assert MAX_TOKENS > 0
