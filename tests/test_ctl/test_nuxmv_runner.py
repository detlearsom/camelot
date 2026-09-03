"""
This test is for testing the NuXMV runner in nuxmv_runner.py.

The nuxmv_runner.py module is responsible for running NuXMV, parsing the output,
extracting counterexample traces, identifying provenance / temporal violations,
and converting violations into LLM-friendly repair messages.

This test file focuses on parsing and formatting behavior.

It checks:

- Verification parsing
- Counterexample parsing
- Tool-call extraction
- Provenance violation detection
- Error handling:
- LLM repair messages

Last Checked: 06.05.2026

Run:
 pytest -q tests/test_ctl/test_nuxmv_runner.py

Evaluation: 12/12.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from camel.ext.nuxmv_runner import (
    Counterexample,
    CounterexampleState,
    NuXMVRunner,
    format_counterexample_for_llm,
    _detect_violation_type,
    _extract_liveness_info,
    _extract_temporal_info,
)


def _mock_subprocess_run(monkeypatch, stdout: str, stderr: str = "", returncode: int = 0):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
        )

    monkeypatch.setattr("camel.ext.nuxmv_runner.subprocess.run", fake_run)


# ========================================
# Test 1: Formula extraction works
# ========================================
def test_extract_formula_from_true_line():
    runner = NuXMVRunner()

    line = "-- specification AF(done) is true"

    assert runner._extract_formula(line) == "AF(done)"


# ========================================
# Test 2: Formula extraction works for false property
# ========================================
def test_extract_formula_from_false_line():
    runner = NuXMVRunner()

    line = "-- specification AG(call_send_direct_message -> !body_tainted) is false"

    assert runner._extract_formula(line) == "AG(call_send_direct_message -> !body_tainted)"


# ========================================
# Test 3: verify_model parses verified properties
# ========================================
def test_verify_model_parses_verified_properties(monkeypatch, tmp_path):
    stdout = """\
-- specification AF(done) is true
-- specification EF(call_send_direct_message) is true
"""

    _mock_subprocess_run(monkeypatch, stdout=stdout)

    model_path = tmp_path / "model.smv"
    model_path.write_text("MODULE main")

    result = NuXMVRunner().verify_model(model_path)

    assert result.success is True
    assert result.properties_verified == [
        "AF(done)",
        "EF(call_send_direct_message)",
    ]
    assert result.properties_violated == []
    assert result.counterexamples == []


# ========================================
# Test 4: verify_model parses violated property and counterexample
# ========================================
def test_verify_model_parses_counterexample(monkeypatch, tmp_path):
    stdout = """\
-- specification AG(call_send_direct_message -> !body_tainted) is false
-- as demonstrated by the following execution sequence
Trace Description: CTL Counterexample
Trace Type: Counterexample
  -> State: 1.1 <-
    current_state = INITIAL
    body_tainted = FALSE
    body_trusted = FALSE
  -> State: 1.2 <-
    current_state = CALL_send_direct_message_0
    body_tainted = TRUE
    body_trusted = FALSE
"""

    _mock_subprocess_run(monkeypatch, stdout=stdout)

    model_path = tmp_path / "model.smv"
    model_path.write_text("MODULE main")

    result = NuXMVRunner().verify_model(model_path)

    assert result.success is False
    assert result.properties_violated == [
        "AG(call_send_direct_message -> !body_tainted)"
    ]
    assert len(result.counterexamples) == 1

    ce = result.counterexamples[0]

    assert ce.property_name == "AG(call_send_direct_message -> !body_tainted)"
    assert ce.trace_type == "Counterexample"
    assert len(ce.states) == 2

    assert ce.states[0].state_name == "INITIAL"
    assert ce.states[1].state_name == "CALL_send_direct_message_0"


# ========================================
# Test 5: Counterexample extracts tool-call sequence
# ========================================
def test_counterexample_extracts_tool_call_sequence():
    ce = Counterexample(
        property_name="dummy",
        property_description="dummy",
        trace_type="Counterexample",
        states=[
            CounterexampleState("1.1", "INITIAL", {}),
            CounterexampleState("1.2", "CALL_read_channel_messages_0", {}),
            CounterexampleState("1.3", "CALL_send_direct_message_1", {}),
        ],
    )

    assert ce.get_tool_call_sequence() == [
        "read_channel_messages",
        "send_direct_message",
    ]


# ========================================
# Test 6: Counterexample detects provenance violations
# ========================================
def test_counterexample_detects_provenance_violations():
    ce = Counterexample(
        property_name="AG(call_send_direct_message -> !body_tainted)",
        property_description="DM body must not be tainted",
        trace_type="Counterexample",
        states=[
            CounterexampleState(
                "1.1",
                "INITIAL",
                {
                    "body_tainted": "FALSE",
                    "body_trusted": "FALSE",
                },
            ),
            CounterexampleState(
                "1.2",
                "CALL_send_direct_message_0",
                {
                    "body_tainted": "TRUE",
                },
            ),
        ],
    )

    violations = ce.get_provenance_violations()

    assert violations == [
        {
            "variable": "body",
            "expected": "trusted",
            "actual": "tainted/untrusted",
            "tainted": "TRUE",
            "trusted": "FALSE",
        }
    ]


# ========================================
# Test 7: No provenance violation when variable is trusted
# ========================================
def test_counterexample_no_provenance_violation_when_trusted():
    ce = Counterexample(
        property_name="AG(call_send_direct_message -> body_trusted)",
        property_description="DM body must be trusted",
        trace_type="Counterexample",
        states=[
            CounterexampleState(
                "1.1",
                "CALL_send_direct_message_0",
                {
                    "body_tainted": "FALSE",
                    "body_trusted": "TRUE",
                },
            ),
        ],
    )

    assert ce.get_provenance_violations() == []


# ========================================
# Test 8: verify_model raises RuntimeError on NuXMV syntax error
# ========================================
def test_verify_model_raises_on_nuxmv_error_without_properties(monkeypatch, tmp_path):
    stdout = ""
    stderr = "Parser error: syntax error near CTLSPEC"

    _mock_subprocess_run(
        monkeypatch,
        stdout=stdout,
        stderr=stderr,
        returncode=1,
    )

    model_path = tmp_path / "bad_model.smv"
    model_path.write_text("bad model")

    with pytest.raises(RuntimeError, match="NuXMV exited with code 1"):
        NuXMVRunner().verify_model(model_path)


# ========================================
# Test 9: Violation type detection classifies provenance formula
# ========================================
def test_detect_violation_type_provenance():
    formula = "AG(call_send_direct_message -> !body_tainted)"

    assert _detect_violation_type(formula) == "provenance"


# ========================================
# Test 10: Violation type detection classifies temporal formula
# ========================================
def test_detect_violation_type_temporal():
    formula = "AG(call_escalate_to_tier2 -> check_ip_reputation_called)"

    assert _detect_violation_type(formula) == "temporal"


# ========================================
# Test 11: Violation type detection classifies mixed formula
# ========================================
def test_detect_violation_type_mixed():
    formula = "AG(call_escalate_to_tier2 -> (check_ip_reputation_called & host_trusted))"

    assert _detect_violation_type(formula) == "mixed"


# ========================================
# Test 12: Temporal info extraction identifies violating tool and prerequisites
# ========================================
def test_extract_temporal_info():
    formula = (
        "AG(call_escalate_to_tier2 -> "
        "(check_ip_reputation_called & check_domain_age_called))"
    )

    info = _extract_temporal_info(formula)

    assert info["violating_tool"] == "escalate_to_tier2"
    assert info["prerequisites"] == [
        "check_ip_reputation",
        "check_domain_age",
    ]


# ========================================
# Test 13: LLM message explains provenance violation
# ========================================
def test_format_counterexample_for_llm_provenance_message():
    original_code = 'send_direct_message(recipient="alice", body=messages)'

    ce = Counterexample(
        property_name="AG(call_send_direct_message -> !body_tainted)",
        property_description="DM body must not be tainted",
        trace_type="Counterexample",
        states=[
            CounterexampleState(
                "1.1",
                "INITIAL",
                {
                    "body_tainted": "FALSE",
                    "body_trusted": "FALSE",
                },
            ),
            CounterexampleState(
                "1.2",
                "CALL_send_direct_message_0",
                {
                    "body_tainted": "TRUE",
                },
            ),
        ],
    )

    msg = format_counterexample_for_llm(
        ce,
        original_code=original_code,
        state_machine={},
        property_severity="critical",
    )

    assert "SECURITY POLICY VIOLATION [CRITICAL]" in msg
    assert "Property violated: AG(call_send_direct_message -> !body_tainted)" in msg
    assert "Root cause (provenance violation):" in msg
    assert "`send_direct_message()` was called" in msg
    assert "body (tainted)" in msg
    assert original_code in msg


# ========================================
# Test 14: LLM message explains temporal violation
# ========================================
def test_format_counterexample_for_llm_temporal_message():
    original_code = "escalate_to_tier2(alert)"

    ce = Counterexample(
        property_name="AG(call_escalate_to_tier2 -> check_ip_reputation_called)",
        property_description="Escalation requires prior IP reputation check",
        trace_type="Counterexample",
        states=[
            CounterexampleState("1.1", "INITIAL", {}),
            CounterexampleState("1.2", "CALL_escalate_to_tier2_0", {}),
        ],
    )

    msg = format_counterexample_for_llm(
        ce,
        original_code=original_code,
        state_machine={},
        property_severity="high",
    )

    assert "SECURITY POLICY VIOLATION [HIGH]" in msg
    assert "Root cause (ordering violation):" in msg
    assert "`escalate_to_tier2()` was called without first calling" in msg
    assert "check_ip_reputation()" in msg
    assert "Add the missing prerequisite call" in msg
    assert original_code in msg


# ========================================
# Test 15: Violation type detection classifies liveness
# ========================================
def test_detect_violation_type_liveness():
    formula = "AF(call_send_direct_message)"

    assert _detect_violation_type(formula) == "liveness"


# ========================================
# Test 16: Violation type detection classifies EF required-action liveness
# ========================================
def test_detect_violation_type_liveness_ef():
    formula = "EF(call_create_ticket)"

    assert _detect_violation_type(formula) == "liveness"


# ========================================
# Test 17: LLM message explains missing required action
# ========================================
def test_format_counterexample_for_llm_liveness_message():
    original_code = "# empty plan"

    ce = Counterexample(
        property_name="AF(call_send_direct_message)",
        property_description="The plan must eventually send the requested direct message.",
        trace_type="Counterexample",
        states=[
            CounterexampleState("1.1", "INITIAL", {}),
            CounterexampleState("1.2", "DONE", {}),
        ],
    )

    msg = format_counterexample_for_llm(
        ce,
        original_code=original_code,
        state_machine={},
        property_severity="critical",
    )

    assert "SECURITY POLICY VIOLATION [CRITICAL]" in msg
    assert "Property violated: AF(call_send_direct_message)" in msg
    assert "Root cause (missing required action):" in msg
    assert "send_direct_message()" in msg
    assert "never calls" in msg or "missing" in msg
    assert "Add a call to `send_direct_message()`" in msg
    assert "No call to the required liveness action(s)" in msg


# ========================================
# Test 18: LLM message explains triggered liveness violation
# ========================================
def test_format_counterexample_for_llm_triggered_liveness_message():
    original_code = "create_incident_ticket(alert)"

    ce = Counterexample(
        property_name=(
            "AG(call_create_incident_ticket -> "
            "AF(call_resolve_incident | call_escalate_to_ir_team))"
        ),
        property_description="Created incidents must eventually be resolved or escalated.",
        trace_type="Counterexample",
        states=[
            CounterexampleState("1.1", "INITIAL", {}),
            CounterexampleState("1.2", "CALL_create_incident_ticket_0", {}),
            CounterexampleState("1.3", "DONE", {}),
        ],
    )

    msg = format_counterexample_for_llm(
        ce,
        original_code=original_code,
        state_machine={},
        property_severity="critical",
    )

    assert _detect_violation_type(ce.property_name) == "liveness"
    assert _extract_liveness_info(ce.property_name)["trigger_tool"] == "create_incident_ticket"
    assert _extract_liveness_info(ce.property_name)["required_tools"] == [
        "resolve_incident",
        "escalate_to_ir_team",
    ]
    assert "Root cause (missing required action):" in msg
    assert "After `create_incident_ticket()`" in msg
    assert "`resolve_incident()`" in msg
    assert "`escalate_to_ir_team()`" in msg
    assert "appears at line 1" in msg


# ========================================
# Test 19: verify_model parses liveness violation from NuXMV output
# ========================================
def test_verify_model_parses_liveness_violation(monkeypatch, tmp_path):
    stdout = """\
-- specification AF(call_send_direct_message) is false
-- as demonstrated by the following execution sequence
Trace Description: CTL Counterexample
Trace Type: Counterexample
  -> State: 1.1 <-
    current_state = INITIAL
  -> State: 1.2 <-
    current_state = DONE
"""

    _mock_subprocess_run(monkeypatch, stdout=stdout)

    model_path = tmp_path / "model.smv"
    model_path.write_text("MODULE main")

    result = NuXMVRunner().verify_model(model_path)

    assert result.success is False
    assert result.properties_violated == ["AF(call_send_direct_message)"]
    assert len(result.counterexamples) == 1

    ce = result.counterexamples[0]

    assert ce.property_name == "AF(call_send_direct_message)"
    assert ce.states[0].state_name == "INITIAL"
    assert ce.states[-1].state_name == "DONE"
    assert ce.get_tool_call_sequence() == []
