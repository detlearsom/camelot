"""
This test is for testing the state machine builder in state_machine.py.

The state machine module (state_machine.py) takes the parsed regions from the AST and builds a finite state machine that 
models all possible execution paths through the code. 

Each region type is translated into states and transitions:

    Tool calls become individual states with transitions that update provenance variables
    Assignments create states that propagate taint from source expressions to target variables
    Loops generate entry, body, and exit states with nondeterministic transitions (the loop may execute zero, one, or many times)
    Conditionals create branch points with separate paths for true and false cases that merge afterwards

The key function of this module is provenance tracking. Each state maintains a mapping from variables to provenance levels 
(trusted, user, untrusted, qllm). When a tool is called, the provenance of its output is determined by the tool type: read tools 
(like read_inbox) produce untrusted data, query_ai_assistant produces qllm-tainted data, and other tools inherit the maximum provenance of their inputs. 
Assignments propagate provenance transitively.

The state machine also generates atomic propositions for CTL formulas. For each tool call state, we create propositions 
like call_send_message and argument-level provenance flags like recipient_trusted and recipient_tainted. 
These propositions are then used in security policies to specify which arguments must come from trusted sources

Last Checked: 06.05.2026

Run:
 pytest -q tests/test_ctl/test_state_machine.py

Evaluation: 13/13.

"""
from __future__ import annotations

import pytest

import camel.ext.ctl_policies.slack 

from camel.ext.ctl_policies import get_tool_signatures_for_suite
from camel.ext.cast import parse_camel_code
from camel.ext.state_machine import StateMachineBuilder


@pytest.fixture(scope="module")
def sigs():
    return get_tool_signatures_for_suite("slack")


@pytest.fixture(scope="module")
def sigs_with_qllm():
    """
    Slack signatures extended with query_ai_assistant so it is parsed as a tool.

    In reality we don't have this, his is a CaMeL thing, but we want to test the qqlm direction.
    """
    return {
        **get_tool_signatures_for_suite("slack"),
        "query_ai_assistant": ["query"],
    }


def _build(code: str, sigs: dict) -> StateMachineBuilder:
    fns = list(sigs.keys())
    parsed = parse_camel_code(code, fns, sigs)

    assert parsed["success"], f"Parse failed: {parsed}"

    builder = StateMachineBuilder(parsed)
    builder.build_from_regions()

    return builder


def _all_effects(builder: StateMachineBuilder) -> list[str]:
    return [effect for transition in builder.transitions for effect in transition.effect]


# ========================================
# Test 1: Read tool output becomes untrusted
# ========================================
def test_read_tool_output_is_untrusted(sigs):
    b = _build('messages = read_channel_messages(channel="general")', sigs)

    assert b.provenance_map.get("messages") == "untrusted"
    assert "messages" in b.tainted_vars #  messages is included in tainted_vars.


# ========================================
# Test 2: query_ai_assistant output becomes qllm
# ========================================
def test_qllm_output_is_qllm_not_untrusted(sigs_with_qllm):
    code = """\
messages = read_channel_messages(channel="general")
summary = query_ai_assistant(query=messages)
"""

    b = _build(code, sigs_with_qllm)

    assert b.provenance_map.get("messages") == "untrusted"
    assert b.provenance_map.get("summary") == "qllm"
    assert "summary" in b.tainted_vars
    assert b.provenance_map["summary"] != b.provenance_map["messages"]


# ========================================
# Test 3: Literal assignment becomes trusted
# ========================================
def test_literal_assignment_is_trusted(sigs):
    b = _build('greeting = "Hello, You!"', sigs)

    assert b.provenance_map.get("greeting") == "trusted"
    assert "greeting" not in b.tainted_vars


# ========================================
# Test 4: Assignment chain propagates untrusted provenance
# ========================================
def test_assignment_chain_propagates_untrusted(sigs):
    code = """\
messages = read_channel_messages(channel="general")
forwarded = messages
"""

    b = _build(code, sigs)

    assert b.provenance_map.get("forwarded") == "untrusted"
    assert "forwarded" in b.tainted_vars


# ========================================
# Test 5: Assignment chain propagates qllm provenance
# ========================================
def test_assignment_chain_propagates_qllm(sigs_with_qllm):
    code = """\
messages = read_channel_messages(channel="general")
summary = query_ai_assistant(query=messages)
alias = summary
"""

    b = _build(code, sigs_with_qllm)

    assert b.provenance_map.get("alias") == "qllm"
    assert "alias" in b.tainted_vars


# ========================================
# Test 6: Loop variable inherits iterable provenance
# ========================================
def test_loop_var_inherits_iterable_provenance(sigs):
    code = """\
channels = get_channels()
for ch in channels:
    msgs = read_channel_messages(channel=ch)
"""

    b = _build(code, sigs)

    assert b.provenance_map.get("channels") == "untrusted"
    assert b.provenance_map.get("ch") == "untrusted"
    assert "ch" in b.tainted_vars


# ========================================
# Test 7: Tainted body argument creates body_tainted effect
# ========================================
def test_tainted_body_effect_set(sigs):
    code = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body=messages)
"""

    b = _build(code, sigs)

    assert "body_tainted = true" in _all_effects(b)


# ========================================
# Test 8: Literal recipient creates recipient_trusted effect
# ========================================
def test_trusted_recipient_effect_set(sigs):
    code = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body="Hello!")
"""

    b = _build(code, sigs)

    assert "recipient_trusted = true" in _all_effects(b)


# ========================================
# Test 9: Literal body creates body_tainted = false effect
# ========================================
def test_literal_body_effect_is_not_tainted(sigs):
    code = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body="Hello, world!")
"""

    b = _build(code, sigs)

    assert "body_tainted = false" in _all_effects(b)


# ========================================
# Test 10: Q-LLM body argument creates body_tainted effect
# ========================================
def test_qllm_body_marks_body_tainted(sigs_with_qllm):
    code = """\
messages = read_channel_messages(channel="general")
summary = query_ai_assistant(query=messages)
send_direct_message(recipient="alice", body=summary)
"""

    b = _build(code, sigs_with_qllm)

    assert b.provenance_map.get("summary") == "qllm"
    assert "summary" in b.tainted_vars
    assert "body_tainted = true" in _all_effects(b)


# ========================================
# Test 11: Mixed provenance assignment takes maximum provenance
# ========================================
def test_assignment_with_mixed_inputs_takes_max_provenance(sigs_with_qllm):
    code = """\
messages = read_channel_messages(channel="general")
summary = query_ai_assistant(query=messages)
combined = "prefix " + messages + summary
"""

    b = _build(code, sigs_with_qllm)

    assert b.provenance_map.get("combined") == "qllm" # after qllm
    assert "combined" in b.tainted_vars


# ========================================
# Test 12: Standalone tool call records argument provenance
# ========================================
def test_standalone_tool_call_records_argument_provenance(sigs):
    code = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body=messages)
"""

    b = _build(code, sigs)

    send_states = [
        state
        for state in b.states
        if state.state_type == "TOOL_CALL"
        and state.metadata.get("tool") == "send_direct_message"
    ]

    assert len(send_states) == 1

    send_state = send_states[0]

    assert send_state.metadata["arg_provenance"]["recipient"] == "trusted"
    assert send_state.metadata["arg_provenance"]["body"] == "untrusted"


# ========================================
# Test 13: Q-LLM argument provenance is recorded on tool-call state
# ========================================
def test_qllm_argument_provenance_recorded_on_tool_state(sigs_with_qllm):
    code = """\
messages = read_channel_messages(channel="general")
summary = query_ai_assistant(query=messages)
send_direct_message(recipient="alice", body=summary)
"""

    b = _build(code, sigs_with_qllm)

    send_states = [
        state
        for state in b.states
        if state.state_type == "TOOL_CALL"
        and state.metadata.get("tool") == "send_direct_message"
    ]

    assert len(send_states) == 1

    send_state = send_states[0]

    assert send_state.metadata["arg_provenance"]["recipient"] == "trusted"
    assert send_state.metadata["arg_provenance"]["body"] == "qllm"
