
"""
Testing that the repair loop works as intented.

Covers:
  1. Already-safe plans return immediately without repair
  2. Loop blocks after max_repair_attempts and raises CTLVerificationError
  3. Loop raises immediately with repairs=0 when no llm_generate_fn is provided
  4. Loop succeeds when an oracle repair function returns a safe plan

  Last Checked: 06.05.2026

Run:
 pytest -q tests/test_ctl/test_repair_loop.py

Evaluation: 4/4.
"""

from __future__ import annotations


import pytest


import camel.ext.ctl_policies.slack  # noqa: F401

from camel.ext.ctl_policies import get_tool_signatures_for_suite
from camel.ext.verification_integration import (
    CTLVerificationError,
    verify_and_repair_code,
)

SUITE = "slack"

PLAN_TAINTED_BODY = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body=messages)
"""

PLAN_SAFE = """\
messages = read_channel_messages(channel="general")
send_direct_message(recipient="alice", body="Hello!")
"""


@pytest.fixture(scope="module")
def tool_info():
    sigs = get_tool_signatures_for_suite(SUITE)
    return list(sigs.keys()), sigs

# ========================================
# Test 1: Already-safe plan returns immediately
# ========================================
def test_repair_loop_returns_immediately_when_plan_is_safe(tool_info):
    fns, sigs = tool_info

    repaired, feedback = verify_and_repair_code(
        PLAN_SAFE,
        fns,
        sigs,
        SUITE,
        max_repair_attempts=3,
        llm_generate_fn=None,
        save_artifacts=False,
    )

    assert feedback.verified
    assert repaired.strip() == PLAN_SAFE.strip()


# ========================================
# Test 2: Repair loop blocks after max attempts

# ========================================
def test_repair_loop_blocks_after_max_attempts(tool_info):
    fns, sigs = tool_info

    def always_bad(_msgs):
        return PLAN_TAINTED_BODY

    with pytest.raises(CTLVerificationError) as exc_info:
        verify_and_repair_code(
            PLAN_TAINTED_BODY,
            fns,
            sigs,
            SUITE,
            max_repair_attempts=3,
            llm_generate_fn=always_bad,
            save_artifacts=False,
        )

    assert exc_info.value.repairs == 3


# ========================================
# Test 3: No repair function raises immediately
# ========================================
def test_repair_loop_no_llm_raises_immediately(tool_info):
    fns, sigs = tool_info

    with pytest.raises(CTLVerificationError) as exc_info:
        verify_and_repair_code(
            PLAN_TAINTED_BODY,
            fns,
            sigs,
            SUITE,
            llm_generate_fn=None,
            save_artifacts=False,
        )

    assert exc_info.value.repairs == 0


# ========================================
# Test 4: Repair loop succeeds
# ========================================
def test_repair_loop_succeeds_with_oracle(tool_info):
    fns, sigs = tool_info

    def oracle(_msgs):
        return PLAN_SAFE

    repaired, feedback = verify_and_repair_code(
        PLAN_TAINTED_BODY,
        fns,
        sigs,
        SUITE,
        max_repair_attempts=3,
        llm_generate_fn=oracle,
        save_artifacts=False,
    )

    assert feedback.verified
    assert repaired.strip() == PLAN_SAFE.strip()
