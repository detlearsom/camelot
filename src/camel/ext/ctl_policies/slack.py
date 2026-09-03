"""
CTL policies for the Slack suite that overlap with CaMeL policies.
"""

import sys

from . import CTLProperty, register_policy_module

# ----------------------------------------------------------------------
# Tool signatures (identical to slack.py — needed by the verifier)
# ----------------------------------------------------------------------

TOOL_SIGNATURES = {
    "send_direct_message": ["recipient", "body"],
    "send_channel_message": ["channel", "body"],
    "invite_user_to_slack": ["user", "user_email"],
    "remove_user_from_slack": ["user"],
    "add_user_to_channel": ["user", "channel"],
    "get_channels": [],
    "get_users_in_channel": ["channel"],
    "read_channel_messages": ["channel"],
    "read_inbox": ["user"],
    "get_webpage": ["url"],
    "post_webpage": ["url", "content"],
    "check": ["x"],
    "query_ai_assistant": ["query", "output_schema"],
}

LLM_TOOLS = {"query_ai_assistant"}


# ----------------------------------------------------------------------
# Overlapping global sink policies
# ----------------------------------------------------------------------


# send_direct_message 1/2
def _make_direct_message_trusted_recipient_policy() -> CTLProperty:
    return CTLProperty(
        name="send_direct_message_trusted_recipient",
        formula="AG(call_send_direct_message -> recipient_trusted & !recipient_tainted)",
        description=("Direct messages may onlye be sent to a trusted recipient."),
        severity="critical",
    )


# add_user_to_channel 2/2
def _make_add_user_to_channel_policy() -> CTLProperty:
    return CTLProperty(
        name="add_user_to_channel_workspace_mutation_policy",
        formula=(
            "AG(call_add_user_to_channel -> (user_trusted & !user_tainted & channel_trusted & !channel_tainted))"
        ),
        description=("Only add trusted users to trusted workspaces"),
        severity="critical",
    )


# invite_user_to_slack 2/2
def _make_invite_policy() -> CTLProperty:
    return CTLProperty(
        name="invite_user_to_slack_identity_policy",
        formula=(
            "AG(call_invite_user_to_slack -> "
            "(user_trusted & !user_tainted & user_email_trusted & !user_email_tainted))"
        ),
        description=(
            "The invited user and email address must be trusted and untainted."
        ),
        severity="critical",
    )


# remove_user_from_slack 1/1
def _make_remove_user_policy() -> CTLProperty:
    return CTLProperty(
        name="remove_user_from_slack_identity_policy",
        formula=("AG(call_remove_user_from_slack -> (user_trusted & !user_tainted))"),
        description=("The target user must be trusted and untainted."),
        severity="critical",
    )


# ----------------------------------------------------------------------
# Policy list
# ----------------------------------------------------------------------

SLACK_OVERLAP_CTL_PROPERTIES: list[CTLProperty] = [
    _make_direct_message_trusted_recipient_policy(),
    _make_add_user_to_channel_policy(),
    _make_invite_policy(),
    _make_remove_user_policy(),
]

# All policies are already listed in SLACK_OVERLAP_CTL_PROPERTIES, so leave
# this empty — otherwise get_properties_for_suite() concatenates the two
# and each property is checked (and reported) twice.
GENERIC_PROPERTIES: list[CTLProperty] = []


register_policy_module("slack", sys.modules[__name__])
