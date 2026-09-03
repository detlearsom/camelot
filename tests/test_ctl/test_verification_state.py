"""
This test is for testing CTL verification end-to-end.

The goal is to check small synthetic programs using the full static-verification
pipeline:

    code -> AST -> state machine -> NuXMV model -> NuXMV runner -> PASS/FAIL verdict

It checks:
- safe message
- untrusted body 
- Q-LLM
-  Dropped action
- required action:

Last Checked: 06.05.2026

Run:
 pytest -q tests/test_ctl/test_verification_state.py

Evaluation: 7/7.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

import camel.ext.ctl_policies.slack  # noqa: F401

from camel.ext.ctl_policies import get_tool_signatures_for_suite
from camel.ext.cast import parse_camel_code
from camel.ext.state_machine import StateMachineBuilder
from camel.ext.json2nuxmv import NuXMV, NuXMVPrinter
from camel.ext.nuxmv_runner import NuXMVRunner

import re


def _normalise_ctl_formula(formula: str) -> str:
    formula = re.sub(r"\s+", "", formula)

    # Normalise simple unary CTL forms:
    #   AF(p) -> AFp
    #   EF(p) -> EFp
    #   AG(p) -> AGp
    # only when the body is a simple identifier.
    match = re.match(r"^(AF|EF|AG|EG|AX|EX)\(([a-zA-Z_][a-zA-Z0-9_]*)\)$", formula)
    if match:
        return match.group(1) + match.group(2)

    return formula


def _formula_in(formula: str, formulas: list[str]) -> bool:
    expected = _normalise_ctl_formula(formula)
    actual = [_normalise_ctl_formula(f) for f in formulas]
    return expected in actual

@dataclass
class DummyCTLProperty:
    name: str
    formula: str
    description: str = "test property"
    severity: str = "critical"


@pytest.fixture(scope="module")
def nuxmv_path():
    path = (
        shutil.which("nuxmv")
        or shutil.which("nuXmv")
        or shutil.which("NuXMV")
    )

    if path is None:
        pytest.skip("NuXMV binary not found on PATH")

    return path


@pytest.fixture(scope="module")
def sigs():
    return get_tool_signatures_for_suite("slack")


@pytest.fixture(scope="module")
def sigs_with_qllm():
    """
    Slack signatures extended with query_ai_assistant so it is parsed as a tool.

    This is needed for Q-LLM laundering tests.
    """
    return {
        **get_tool_signatures_for_suite("slack"),
        "query_ai_assistant": ["query"],
    }


def _build_model(code: str, sigs: dict, ctl_properties: list[DummyCTLProperty]) -> dict:
    fns = list(sigs.keys())

    parsed = parse_camel_code(code, fns, sigs)

    assert parsed["success"], f"Parse failed: {parsed}"

    builder = StateMachineBuilder(parsed)
    model = builder.build_state_machine()

    # We pass CTL properties separately to NuXMVPrinter, but keep them here for
    # debugging consistency.
    model["ctl_properties"] = [
        {
            "name": prop.name,
            "formula": prop.formula,
            "description": prop.description,
            "severity": prop.severity,
        }
        for prop in ctl_properties
    ]

    return model


def _write_smv(
    code: str,
    sigs: dict,
    ctl_properties: list[DummyCTLProperty],
    tmp_path: Path,
) -> Path:
    model = _build_model(code, sigs, ctl_properties)

    smv_path = tmp_path / "model.smv"

    nuxmv = NuXMV(state_machine=model)

    NuXMVPrinter(
        nuxmv,
        output_file=str(smv_path),
        ctl_properties=ctl_properties,
    )

    assert smv_path.exists()

    return smv_path


def _verify(
    code: str,
    sigs: dict,
    ctl_property: DummyCTLProperty,
    tmp_path: Path,
    nuxmv_path: str,
):
    smv_path = _write_smv(
        code=code,
        sigs=sigs,
        ctl_properties=[ctl_property],
        tmp_path=tmp_path,
    )

    runner = NuXMVRunner(nuxmv_path=nuxmv_path)

    return runner.verify_model(smv_path)


# ========================================
# Test 1: Safe literal direct message passes body-taint policy
# ========================================
def test_safe_literal_dm_passes_body_taint_policy(sigs, tmp_path, nuxmv_path):
    code = """\
send_direct_message(recipient="alice", body="hello")
"""

    prop = DummyCTLProperty(
        name="dm_body_not_tainted",
        formula="AG(call_send_direct_message -> !body_tainted)",
        description="DM body must not be tainted.",
    )

    result = _verify(code, sigs, prop, tmp_path, nuxmv_path)

    assert result.success is True
    assert _formula_in(prop.formula, result.properties_verified)
    assert result.properties_violated == []


# ========================================
# Test 2: Untrusted body fails body-taint policy
# ========================================
def test_untrusted_body_fails_body_taint_policy(sigs, tmp_path, nuxmv_path):
    code = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body=messages)
"""

    prop = DummyCTLProperty(
        name="dm_body_not_tainted",
        formula="AG(call_send_direct_message -> !body_tainted)",
        description="DM body must not be tainted.",
    )

    result = _verify(code, sigs, prop, tmp_path, nuxmv_path)

    assert result.success is False
    assert _formula_in(prop.formula, result.properties_violated)
    assert len(result.counterexamples) >= 1


# ========================================
# Test 3: Q-LLM body fails body-taint policy====
def test_qllm_laundered_body_fails_body_taint_policy(
    sigs_with_qllm,
    tmp_path,
    nuxmv_path,
):
    code = """\
messages = read_channel_messages(channel="general")
summary = query_ai_assistant(query=messages)
send_direct_message(recipient="alice", body=summary)
"""

    prop = DummyCTLProperty(
        name="dm_body_not_tainted",
        formula="AG(call_send_direct_message -> !body_tainted)",
        description="DM body must not be tainted.",
    )

    result = _verify(code, sigs_with_qllm, prop, tmp_path, nuxmv_path)

    assert result.success is False
    assert _formula_in(prop.formula, result.properties_violated)
    assert len(result.counterexamples) >= 1


# ========================================
# Test 4: Empty plan fails required-action liveness
# ========================================
def test_empty_plan_fails_required_action_liveness(sigs, tmp_path, nuxmv_path):
    code = ""

    prop = DummyCTLProperty(
        name="must_send_direct_message",
        formula="AF(call_send_direct_message)",
        description="The plan must eventually send a direct message.",
    )

    result = _verify(code, sigs, prop, tmp_path, nuxmv_path)

    assert result.success is False
    assert _formula_in(prop.formula, result.properties_violated)
    assert len(result.counterexamples) >= 1


# ========================================
# Test 5: Required action plan passes liveness
# ========================================
def test_required_action_plan_passes_liveness(sigs, tmp_path, nuxmv_path):
    code = """\
send_direct_message(recipient="alice", body="hello")
"""

    prop = DummyCTLProperty(
        name="must_send_direct_message",
        formula="AF(call_send_direct_message)",
        description="The plan must eventually send a direct message.",
    )

    result = _verify(code, sigs, prop, tmp_path, nuxmv_path)

    assert result.success is True
    assert _formula_in(prop.formula, result.properties_verified)
    assert result.properties_violated == []


# ========================================
# Test 6: Branch that drops required action fails AF liveness
# ========================================
def test_branch_that_drops_required_action_fails_af_liveness(
    sigs,
    tmp_path,
    nuxmv_path,
):
    code = """\
if suspicious:
    send_direct_message(recipient="alice", body="hello")
else:
    x = 1
"""

    prop = DummyCTLProperty(
        name="must_send_direct_message",
        formula="AF(call_send_direct_message)",
        description="All paths must eventually send a direct message.",
    )

    result = _verify(code, sigs, prop, tmp_path, nuxmv_path)

    assert result.success is False
    assert _formula_in(prop.formula, result.properties_violated)


# ========================================
# Test 7: Branch with action on one path passes EF liveness
# ========================================
def test_branch_with_action_on_one_path_passes_ef_liveness(
    sigs,
    tmp_path,
    nuxmv_path,
):
    code = """\
if suspicious:
    send_direct_message(recipient="alice", body="hello")
else:
    x = 1
"""

    prop = DummyCTLProperty(
        name="may_send_direct_message",
        formula="EF(call_send_direct_message)",
        description="Some path sends a direct message.",
    )

    result = _verify(code, sigs, prop, tmp_path, nuxmv_path)

    assert result.success is True
    assert _formula_in(prop.formula, result.properties_verified)