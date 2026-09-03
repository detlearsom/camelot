"""
This test is for testing the state machine structure in state_machine.py.

The state machine module takes the parsed regions produced by cast.py and builds
a finite state machine representing all possible execution paths through the
generated P-LLM code.

This test is just to see that the graph structure is correct.

Last Checked: 06.05.2026

Run:
 pytest -q tests/test_ctl/test_state_machine_structure.py

 Evaluation: 15/15

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


def _build(code: str, sigs: dict) -> StateMachineBuilder:
    fns = list(sigs.keys())
    parsed = parse_camel_code(code, fns, sigs)

    assert parsed["success"], f"Parse failed: {parsed}"

    builder = StateMachineBuilder(parsed)
    builder.build_from_regions()

    return builder


def _state_types(builder: StateMachineBuilder) -> list[str]:
    return [state.state_type for state in builder.states]


def _states_of_type(builder: StateMachineBuilder, state_type: str):
    return [state for state in builder.states if state.state_type == state_type]


def _tool_states(builder: StateMachineBuilder):
    return _states_of_type(builder, "TOOL_CALL")


def _edges(builder: StateMachineBuilder) -> set[tuple[str, str]]:
    return {(transition.from_state, transition.to_state) for transition in builder.transitions}


def _transitions_from(builder: StateMachineBuilder, state_id: str):
    return [transition for transition in builder.transitions if transition.from_state == state_id]


def _transition_exists(builder: StateMachineBuilder, from_state: str, to_state: str) -> bool:
    return (from_state, to_state) in _edges(builder)


# ========================================
# Test 1: Empty program creates INITIAL to DONE
# ========================================
def test_empty_program_creates_initial_to_done(sigs):
    b = _build("", sigs)

    assert _state_types(b) == ["INITIAL", "DONE"]

    assert _transition_exists(b, "INITIAL", "DONE")
    assert len(b.transitions) == 1


# ========================================
# Test 2: Single tool call creates INITIAL -> CALL -> DONE
# ========================================
def test_single_tool_call_creates_linear_graph(sigs):
    code = """\
send_direct_message(recipient="alice", body="hello")
"""

    b = _build(code, sigs)

    tool_states = _tool_states(b)

    assert len(tool_states) == 1

    call_state = tool_states[0]

    assert call_state.metadata["tool"] == "send_direct_message"
    assert _transition_exists(b, "INITIAL", call_state.state_id)
    assert _transition_exists(b, call_state.state_id, "DONE")


# ========================================
# Test 3: Sequential tool calls preserve graph order
# ========================================
def test_sequential_tool_calls_preserve_graph_order(sigs):
    code = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body=messages)
"""

    b = _build(code, sigs)

    tool_states = _tool_states(b)

    assert len(tool_states) == 2

    read_state = tool_states[0]
    send_state = tool_states[1]

    assert read_state.metadata["tool"] == "read_channel_messages"
    assert send_state.metadata["tool"] == "send_direct_message"

    assert _transition_exists(b, "INITIAL", read_state.state_id)
    assert _transition_exists(b, read_state.state_id, send_state.state_id)
    assert _transition_exists(b, send_state.state_id, "DONE")


# ========================================
# Test 4: Assignment creates ASSIGNMENT state
# ========================================
def test_assignment_creates_assignment_state(sigs):
    code = """\
x = 1
"""

    b = _build(code, sigs)

    assignment_states = _states_of_type(b, "ASSIGNMENT")

    assert len(assignment_states) == 1

    assign_state = assignment_states[0]

    assert assign_state.metadata["targets"] == ["x"]
    assert assign_state.metadata["value"] == "1"

    assert _transition_exists(b, "INITIAL", assign_state.state_id)
    assert _transition_exists(b, assign_state.state_id, "DONE")


# ========================================
# Test 5: Assignment followed by tool call is linear
# ========================================
def test_assignment_then_tool_call_is_linear(sigs):
    code = """\
body = "hello"
send_direct_message(recipient="alice", body=body)
"""

    b = _build(code, sigs)

    assignment_states = _states_of_type(b, "ASSIGNMENT")
    tool_states = _tool_states(b)

    assert len(assignment_states) == 1
    assert len(tool_states) == 1

    assign_state = assignment_states[0]
    call_state = tool_states[0]

    assert _transition_exists(b, "INITIAL", assign_state.state_id)
    assert _transition_exists(b, assign_state.state_id, call_state.state_id)
    assert _transition_exists(b, call_state.state_id, "DONE")


# ========================================
# Test 6: If/else creates branch, true, false, and merge states
# ========================================
def test_if_else_creates_branch_true_false_and_merge_states(sigs):
    code = """\
if suspicious:
    send_direct_message(recipient="alice", body="suspicious")
else:
    send_direct_message(recipient="bob", body="benign")
"""

    b = _build(code, sigs)

    branch_states = _states_of_type(b, "CONDITIONAL")
    true_states = _states_of_type(b, "TRUE_BRANCH")
    false_states = _states_of_type(b, "FALSE_BRANCH")
    merge_states = _states_of_type(b, "MERGE")

    assert len(branch_states) == 1
    assert len(true_states) == 1
    assert len(false_states) == 1
    assert len(merge_states) == 1

    branch_state = branch_states[0]
    true_state = true_states[0]
    false_state = false_states[0]

    assert branch_state.metadata["condition"] == "suspicious"

    assert _transition_exists(b, "INITIAL", branch_state.state_id)
    assert _transition_exists(b, branch_state.state_id, true_state.state_id)
    assert _transition_exists(b, branch_state.state_id, false_state.state_id)


# ========================================
# Test 7: If/else branches reconnect at merge
# ========================================
def test_if_else_branches_reconnect_at_merge(sigs):
    code = """\
if suspicious:
    send_direct_message(recipient="alice", body="suspicious")
else:
    send_direct_message(recipient="bob", body="benign")
"""

    b = _build(code, sigs)

    merge_state = _states_of_type(b, "MERGE")[0]
    true_state = _states_of_type(b, "TRUE_BRANCH")[0]
    false_state = _states_of_type(b, "FALSE_BRANCH")[0]

    true_outgoing = _transitions_from(b, true_state.state_id)
    false_outgoing = _transitions_from(b, false_state.state_id)

    assert len(true_outgoing) == 1
    assert len(false_outgoing) == 1

    true_call_id = true_outgoing[0].to_state
    false_call_id = false_outgoing[0].to_state

    assert _transition_exists(b, true_call_id, merge_state.state_id)
    assert _transition_exists(b, false_call_id, merge_state.state_id)
    assert _transition_exists(b, merge_state.state_id, "DONE")


# ========================================
# Test 8: If without else still creates false branch and merge
# ========================================
def test_if_without_else_creates_empty_false_branch(sigs):
    code = """\
if suspicious:
    send_direct_message(recipient="alice", body="suspicious")
"""

    b = _build(code, sigs)

    false_state = _states_of_type(b, "FALSE_BRANCH")[0]
    merge_state = _states_of_type(b, "MERGE")[0]

    assert _transition_exists(b, false_state.state_id, merge_state.state_id)
    assert _transition_exists(b, merge_state.state_id, "DONE")


# ========================================
# Test 9: Loop creates entry, body, and exit states
# ========================================
def test_loop_creates_entry_body_and_exit_states(sigs):
    code = """\
channels = get_channels()
for ch in channels:
    read_channel_messages(channel=ch)
"""

    b = _build(code, sigs)

    loop_entry_states = _states_of_type(b, "LOOP_ENTRY")
    loop_body_states = _states_of_type(b, "LOOP_BODY")
    loop_exit_states = _states_of_type(b, "LOOP_EXIT")

    assert len(loop_entry_states) == 1
    assert len(loop_body_states) == 1
    assert len(loop_exit_states) == 1

    entry_state = loop_entry_states[0]

    assert entry_state.metadata["loop_var"] == "ch"
    assert entry_state.metadata["iterable"] == "channels"


# ========================================
# Test 10: Loop entry has zero-iteration path to loop exit
# ========================================
def test_loop_entry_has_zero_iteration_path_to_exit(sigs):
    code = """\
channels = get_channels()
for ch in channels:
    read_channel_messages(channel=ch)
"""

    b = _build(code, sigs)

    entry_state = _states_of_type(b, "LOOP_ENTRY")[0]
    exit_state = _states_of_type(b, "LOOP_EXIT")[0]

    assert _transition_exists(b, entry_state.state_id, exit_state.state_id)


# ========================================
# Test 11: Loop entry has body-execution path
# ========================================
def test_loop_entry_has_body_execution_path(sigs):
    code = """\
channels = get_channels()
for ch in channels:
    read_channel_messages(channel=ch)
"""

    b = _build(code, sigs)

    entry_state = _states_of_type(b, "LOOP_ENTRY")[0]
    body_state = _states_of_type(b, "LOOP_BODY")[0]

    assert _transition_exists(b, entry_state.state_id, body_state.state_id)


# ========================================
# Test 12: Loop body eventually transitions back to loop entry
# ========================================
def test_loop_body_eventually_transitions_back_to_entry(sigs):
    code = """\
channels = get_channels()
for ch in channels:
    read_channel_messages(channel=ch)
"""

    b = _build(code, sigs)

    entry_state = _states_of_type(b, "LOOP_ENTRY")[0]
    tool_states = [
        state
        for state in _tool_states(b)
        if state.metadata["tool"] == "read_channel_messages"
    ]

    body_state = _states_of_type(b, "LOOP_BODY")[0]
    body_outgoing = _transitions_from(b, body_state.state_id)

    assert len(body_outgoing) == 1

    loop_body_call_id = body_outgoing[0].to_state

    assert any(state.state_id == loop_body_call_id for state in tool_states)
    assert _transition_exists(b, loop_body_call_id, entry_state.state_id)


# ========================================
# Test 13: Loop exit transitions to DONE when loop is final region
# ========================================
def test_loop_exit_transitions_to_done_when_final_region(sigs):
    code = """\
channels = get_channels()
for ch in channels:
    read_channel_messages(channel=ch)
"""

    b = _build(code, sigs)

    exit_state = _states_of_type(b, "LOOP_EXIT")[0]

    assert _transition_exists(b, exit_state.state_id, "DONE")


# ========================================
# Test 14: Nested conditional 
# ========================================
def test_nested_conditional_creates_multiple_branch_and_merge_states(sigs):
    code = """\
if suspicious:
    if confirmed:
        send_direct_message(recipient="alice", body="confirmed")
else:
    send_direct_message(recipient="bob", body="benign")
"""

    b = _build(code, sigs)

    branch_states = _states_of_type(b, "CONDITIONAL") # should be 2
    merge_states = _states_of_type(b, "MERGE")

    assert len(branch_states) == 2
    assert len(merge_states) == 2


# ========================================
# Test 15: Final region always connects to DONE
# ========================================
def test_final_region_connects_to_done(sigs):
    code = """\
body = "hello"
if suspicious:
    send_direct_message(recipient="alice", body=body)
else:
    send_direct_message(recipient="bob", body=body)
send_direct_message(recipient="carol", body=body)
"""

    b = _build(code, sigs)

    incoming_to_done = [
        transition
        for transition in b.transitions
        if transition.to_state == "DONE"
    ]

    assert len(incoming_to_done) >= 1

    final_tool_states = [
        state
        for state in _tool_states(b)
        if state.metadata["arguments"].get("recipient") == "'carol'"
    ]

    assert len(final_tool_states) == 1

    final_tool = final_tool_states[0]

    assert _transition_exists(b, final_tool.state_id, "DONE")