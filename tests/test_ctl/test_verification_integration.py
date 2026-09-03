"""
This test is for testing verification_integration.py.

The verification integration module connects CTL verification to CaMeL's
P-LLM execution and repair loop.

Last Checked: 06.05.2026

Run:
 pytest -q tests/test_ctl/test_verification_integration.py

Evaluation: 9/9.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from camel.ext.nuxmv_runner import (
    Counterexample,
    CounterexampleState,
    VerificationResult,
)

from camel.ext.verification_integration import (
    CTLVerificationError,
    VerificationFeedback,
    _has_liveness_violation,
    make_repair_messages,
    verify_and_repair_code,
    verify_code,
)

from agentdojo import types as ad_types

@dataclass
class DummyCTLProperty:
    name: str
    formula: str
    description: str = "dummy"
    severity: str = "critical"


def _verified_result() -> VerificationResult:
    return VerificationResult(
        success=True,
        properties_checked=["AF(done)"],
        properties_verified=["AF(done)"],
        properties_violated=[],
        counterexamples=[],
        raw_output="-- specification AF(done) is true",
        stderr="",
        returncode=0,
    )


def _violated_result(formula: str = "AF(call_send_direct_message)") -> VerificationResult:
    ce = Counterexample(
        property_name=formula,
        property_description="The plan must eventually send the requested direct message.",
        trace_type="Counterexample",
        states=[
            CounterexampleState("1.1", "INITIAL", {}),
            CounterexampleState("1.2", "DONE", {}),
        ],
    )

    return VerificationResult(
        success=False,
        properties_checked=[formula],
        properties_verified=[],
        properties_violated=[formula],
        counterexamples=[ce],
        raw_output=f"-- specification {formula} is false",
        stderr="",
        returncode=0,
    )


def _patch_common_verification_deps(monkeypatch, result: VerificationResult):
    """
    Patch the parts of verify_code that would otherwise call the real NuXMV
    exporter / runner.
    """

    def fake_get_properties_for_suite(suite_name, user_task_id=None):
        return [
            DummyCTLProperty(
                name="must_send_direct_message",
                formula="AF(call_send_direct_message)",
                description="The plan must eventually send the requested direct message.",
                severity="critical",
            )
        ]

    def fake_get_llm_tools_for_suite(suite_name):
        return {"query_ai_assistant"}

    class FakeNuXMVPrinter:
        def __init__(self, nuxmv, output_file=None, ctl_properties=None):
            assert output_file is not None
            Path(output_file).write_text("MODULE main\n")

    def fake_verify_model(self, model_path):
        return result

    monkeypatch.setattr(
        "camel.ext.verification_integration.get_properties_for_suite",
        fake_get_properties_for_suite,
    )
    monkeypatch.setattr(
        "camel.ext.verification_integration.get_llm_tools_for_suite",
        fake_get_llm_tools_for_suite,
    )
    monkeypatch.setattr(
        "camel.ext.verification_integration.NuXMVPrinter",
        FakeNuXMVPrinter,
    )
    monkeypatch.setattr(
        "camel.ext.verification_integration.NuXMVRunner.verify_model",
        fake_verify_model,
    )


# ========================================
# Test 1: Parse failures are not treated as CTL failures
# ========================================
def test_verify_code_parse_failure_returns_verified():
    feedback = verify_code(
        code="if:\n    pass",
        tool_functions=["send_direct_message"],
        tool_signatures={"send_direct_message": ["recipient", "body"]},
        suite_name="slack",
        save_artifacts=False,
    )

    assert feedback.verified is True
    assert feedback.counterexamples == []
    assert feedback.verification_result is None


# ========================================
# Test 2: verify_code returns verified=True when model checker succeeds
# ========================================
def test_verify_code_success(monkeypatch):
    _patch_common_verification_deps(monkeypatch, _verified_result())

    feedback = verify_code(
        code='send_direct_message(recipient="alice", body="hello")',
        tool_functions=["send_direct_message"],
        tool_signatures={"send_direct_message": ["recipient", "body"]},
        suite_name="slack",
        save_artifacts=False,
    )

    assert feedback.verified is True
    assert feedback.counterexamples == []
    assert feedback.verification_result is not None
    assert feedback.verification_result.success is True


# ========================================
# Test 3: verify_code returns verified=False when model checker fails
# ========================================
def test_verify_code_failure_returns_counterexample_message(monkeypatch):
    _patch_common_verification_deps(
        monkeypatch,
        _violated_result("AF(call_send_direct_message)"),
    )

    feedback = verify_code(
        code="# empty plan",
        tool_functions=["send_direct_message"],
        tool_signatures={"send_direct_message": ["recipient", "body"]},
        suite_name="slack",
        save_artifacts=False,
    )

    assert feedback.verified is False
    assert feedback.verification_result is not None
    assert feedback.verification_result.success is False
    assert feedback.verification_result.properties_violated == [
        "AF(call_send_direct_message)"
    ]

    assert len(feedback.counterexamples) == 1
    assert "SECURITY POLICY VIOLATION" in feedback.counterexamples[0]
    assert "AF(call_send_direct_message)" in feedback.counterexamples[0]


# ========================================
# Test 4: _has_liveness_violation detects AF/EF required-action properties
# ========================================
def test_has_liveness_violation_detects_required_action():
    feedback = VerificationFeedback(
        verified=False,
        counterexamples=["dummy"],
        verification_result=_violated_result("AF(call_send_direct_message)"),
    )

    assert _has_liveness_violation(feedback) is True


# ========================================
# Test 5: make_repair_messages includes liveness-specific instructions
# ========================================
def test_make_repair_messages_includes_liveness_instructions():
    feedback = VerificationFeedback(
        verified=False,
        counterexamples=[
            "SECURITY POLICY VIOLATION\n"
            "Property violated: AF(call_send_direct_message)\n"
            "Root cause (missing required action):\n"
        ],
        verification_result=_violated_result("AF(call_send_direct_message)"),
    )

    code_echo, violation_report = make_repair_messages(
        original_code="# empty plan",
        verification_feedback=feedback,
        user_query="Send Alice a direct message saying hello.",
    )

    assert code_echo["role"] == "assistant"
    assert violation_report["role"] == "user"

    text = ad_types.get_text_content_as_str(violation_report["content"])

    assert "LIVENESS / REACHABILITY" in text
    assert "Do not repair this by deleting the required action" in text
    assert "safe-but-incomplete" in text
    assert "Keep every side-effecting call required by liveness/reachability policies" in text
    assert "6. Include explicit triage." in text
    assert "7. Include explicit triage." not in text
    assert "Send Alice a direct message saying hello." in text


# ========================================
# Test 6: verify_and_repair_code returns original code if already verified
# ========================================
def test_verify_and_repair_code_returns_original_when_verified(monkeypatch):
    def fake_verify_code(*args, **kwargs):
        return VerificationFeedback(
            verified=True,
            counterexamples=[],
            verification_result=_verified_result(),
        )

    monkeypatch.setattr(
        "camel.ext.verification_integration.verify_code",
        fake_verify_code,
    )

    original = 'send_direct_message(recipient="alice", body="hello")'

    final_code, feedback = verify_and_repair_code(
        generated_code=original,
        tool_functions=["send_direct_message"],
        tool_signatures={"send_direct_message": ["recipient", "body"]},
        suite_name="slack",
        llm_generate_fn=None,
    )

    assert final_code == original
    assert feedback.verified is True


# ========================================
# Test 7: verify_and_repair_code repairs once and returns verified repair
# ========================================
def test_verify_and_repair_code_repairs_once(monkeypatch):
    calls = {"verify": 0, "repair": 0}

    bad_code = "# empty plan"
    repaired_code = 'send_direct_message(recipient="alice", body="hello")'

    def fake_verify_code(code, *args, **kwargs):
        calls["verify"] += 1

        if code == bad_code:
            return VerificationFeedback(
                verified=False,
                counterexamples=["Property violated: AF(call_send_direct_message)"],
                verification_result=_violated_result("AF(call_send_direct_message)"),
            )

        if code == repaired_code:
            return VerificationFeedback(
                verified=True,
                counterexamples=[],
                verification_result=_verified_result(),
            )

        raise AssertionError(f"Unexpected code: {code}")

    def fake_llm_generate_fn(messages):
        calls["repair"] += 1
        return repaired_code

    monkeypatch.setattr(
        "camel.ext.verification_integration.verify_code",
        fake_verify_code,
    )

    final_code, feedback = verify_and_repair_code(
        generated_code=bad_code,
        tool_functions=["send_direct_message"],
        tool_signatures={"send_direct_message": ["recipient", "body"]},
        suite_name="slack",
        max_repair_attempts=3,
        llm_generate_fn=fake_llm_generate_fn,
        user_query="Send Alice a direct message saying hello.",
    )

    assert final_code == repaired_code
    assert feedback.verified is True
    assert calls["verify"] == 2
    assert calls["repair"] == 1


# ========================================
# Test 8: verify_and_repair_code raises if no repair function is provided
# ========================================
def test_verify_and_repair_code_raises_without_repair_fn(monkeypatch):
    def fake_verify_code(*args, **kwargs):
        return VerificationFeedback(
            verified=False,
            counterexamples=["Property violated: AF(call_send_direct_message)"],
            verification_result=_violated_result("AF(call_send_direct_message)"),
        )

    monkeypatch.setattr(
        "camel.ext.verification_integration.verify_code",
        fake_verify_code,
    )

    with pytest.raises(CTLVerificationError):
        verify_and_repair_code(
            generated_code="# empty plan",
            tool_functions=["send_direct_message"],
            tool_signatures={"send_direct_message": ["recipient", "body"]},
            suite_name="slack",
            llm_generate_fn=None,
        )


# ========================================
# Test 9: verify_and_repair_code raises after max repair attempts
# ========================================
def test_verify_and_repair_code_raises_after_max_repairs(monkeypatch):
    calls = {"repair": 0}

    def fake_verify_code(*args, **kwargs):
        return VerificationFeedback(
            verified=False,
            counterexamples=["Property violated: AF(call_send_direct_message)"],
            verification_result=_violated_result("AF(call_send_direct_message)"),
        )

    def fake_llm_generate_fn(messages):
        calls["repair"] += 1
        return "# still empty"

    monkeypatch.setattr(
        "camel.ext.verification_integration.verify_code",
        fake_verify_code,
    )

    with pytest.raises(CTLVerificationError) as exc_info:
        verify_and_repair_code(
            generated_code="# empty plan",
            tool_functions=["send_direct_message"],
            tool_signatures={"send_direct_message": ["recipient", "body"]},
            suite_name="slack",
            max_repair_attempts=2,
            llm_generate_fn=fake_llm_generate_fn,
        )

    assert calls["repair"] == 2
    assert exc_info.value.repairs == 2
