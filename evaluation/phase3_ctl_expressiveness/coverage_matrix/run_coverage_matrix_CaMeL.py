#!/usr/bin/env python3
"""
SOC Plan Execution Runner — CaMeL interpreter, no LLM

Runs the 14 hardcoded SOC plans from plans_soc.py through CaMeL's interpreter
with a SocSecurityPolicyEngine to observe whether the security policy blocks
execution. No LLM calls, no injections, no AgentDojo end-state checking.

Taint propagation finding:
  P10_FAIL and P12_FAIL are correctly blocked by the SocSecurityPolicyEngine.
  Although CaMeLClassInstance.attr() wraps each attribute with Capabilities.camel()
  (trusted metadata), it also appends the parent instance to the attribute's
  dependency tuple via new_with_dependencies((self,)). is_trusted() calls
  get_all_sources() which recursively unions sources across the full dependency
  graph — Tool('query_ai_assistant', frozenset()) is untrusted (empty inner_sources)
  and propagates through the chain to the attribute, so is_trusted() returns False.

Usage:
    uv run --env-file .env python \\
        evaluation/phase3_ctl_expressiveness/coverage_matrix/run_coverage_matrix_CaMeL.py
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "src"))

import camel.custom_yaml  # noqa: F401
import camel.ext.ctl_policies.soc  # noqa: F401

from agentdojo.functions_runtime import FunctionsRuntime, TaskEnvironment
from pydantic import BaseModel

from camel.interpreter import result as interp_result
from camel.interpreter.interpreter import EvalArgs, MetadataEvalMode, parse_and_interpret_code
from camel.interpreter.namespace import Namespace
from camel.capabilities import is_trusted
from camel.interpreter.value import CaMeLValue
from camel.pipeline_elements.agentdojo_function import make_agentdojo_namespace
from camel.security_policy import (
    NO_SIDE_EFFECT_TOOLS,
    Allowed,
    Denied,
    SecurityPolicyDeniedError,
    SecurityPolicyEngine,
    SecurityPolicyResult,
)
from plans_soc import SOC_PLANS


_CLASS_LABELS = {
    "global_safety":      "Global Safety",
    "forbidden_effects":  "Forbidden Effects",
    "liveness":           "Task Liveness",
    "ordering":           "Temporal Ordering",
    "af_liveness":        "AF Liveness",
    "until":              "Until (AU)",
    "triggered_liveness": "Triggered Liveness",
    "next_step":          "Next Step (AX)",
}

_OPERATOR_LABELS = {
    "AG":      "AG",
    "EF":      "EF",
    "AF":      "AF",
    "AU":      "AU",
    "AG+past": "AG + past",
    "AG→AF":   "AG → AF",
    "AX":      "AX",
}

_SUITE_TITLES = {
    "slack":       "Slack Suite",
    "soc":         "SOC Suite",
    "healthcare":  "Healthcare Suite",
}

_RED = "\033[91m"
_RESET = "\033[0m"


def _maybe_red(text: str, mismatch: bool) -> str:
    if not mismatch:
        return text
    if not sys.stdout.isatty():
        return text
    return f"{_RED}{text}{_RESET}"


# ── Return type for query_ai_assistant ───────────────────────────────────────

class SocAnalysis(BaseModel):
    source_ip: str = "192.168.1.100"
    summary: str = "Suspicious activity detected"


# ── Minimal environment ───────────────────────────────────────────────────────

class SocEnvironment(TaskEnvironment):
    pass


# ── Stub tool implementations ─────────────────────────────────────────────────

def get_last_alert(severity: str) -> str:
    """Returns the last alert with the given severity.

    :param severity: Alert severity level (e.g. HIGH, MEDIUM, LOW).
    """
    return f"alert-{severity}-001"


def check_sender_reputation(sender: str) -> str:
    """Checks the reputation of the given sender address.

    :param sender: Email address of the sender to check.
    """
    return f"reputation-ok:{sender}"


def scan_attachments(alert: str) -> str:
    """Scans attachments associated with the given alert.

    :param alert: Alert identifier to scan attachments for.
    """
    return f"scan-clean:{alert}"


def check_urls(alert: str) -> str:
    """Checks URLs found in the given alert.

    :param alert: Alert identifier to check URLs for.
    """
    return f"urls-safe:{alert}"


def query_logs(host: str) -> str:
    """Queries logs from the given host.

    :param host: Hostname or log source to query.
    """
    return f"logs-from:{host}"


def confirm_host(hostname: str) -> str:
    """Confirms the given hostname is the affected host.

    :param hostname: Hostname to confirm.
    """
    return hostname


def create_incident_ticket(title: str, description: str) -> str:
    """Creates an incident ticket with the given title and description.

    :param title: Title of the incident ticket.
    :param description: Description of the incident.
    """
    return f"ticket:{title}"


def request_ir_approval(incident: str) -> str:
    """Requests IR team approval for the given incident.

    :param incident: Incident identifier to request approval for.
    """
    return f"approved:{incident}"


def escalate_to_ir_team(incident: str) -> str:
    """Escalates the given incident to the IR team.

    :param incident: Incident identifier to escalate.
    """
    return f"escalated:{incident}"


def resolve_incident(incident: str) -> str:
    """Resolves the given incident.

    :param incident: Incident identifier to resolve.
    """
    return f"resolved:{incident}"


def isolate_host(hostname: str) -> str:
    """Isolates the given host from the network.

    :param hostname: Hostname to isolate.
    """
    return f"isolated:{hostname}"


def block_ip(ip: str) -> str:
    """Blocks the given IP address.

    :param ip: IP address to block.
    """
    return f"blocked:{ip}"


def disable_account(account: str) -> str:
    """Disables the given user account.

    :param account: Account identifier to disable.
    """
    return f"disabled:{account}"


def query_ai_assistant(query: str) -> SocAnalysis:
    """Queries the AI assistant with the given query and returns a structured analysis.

    :param query: Query string to send to the AI assistant.
    """
    return SocAnalysis()


_STUB_TOOLS = [
    get_last_alert,
    check_sender_reputation,
    scan_attachments,
    check_urls,
    query_logs,
    confirm_host,
    create_incident_ticket,
    request_ir_approval,
    escalate_to_ir_team,
    resolve_incident,
    isolate_host,
    block_ip,
    disable_account,
    query_ai_assistant,
]


# ── Security policy ───────────────────────────────────────────────────────────

def _make_trusted_fields_policy(fields: tuple[str, ...]):
    def policy(tool_name: str, kwargs: Mapping[str, CaMeLValue]) -> SecurityPolicyResult:
        for field in fields:
            if not is_trusted(kwargs[field]):
                return Denied(f"{field} does not come directly from user")
        return Allowed()
    return policy


_SOC_NO_SIDE_EFFECT_TOOLS = {
    "get_last_alert",
    "check_sender_reputation",
    "scan_attachments",
    "check_urls",
    "query_logs",
    "confirm_host",
}


class SocSecurityPolicyEngine(SecurityPolicyEngine):
    def __init__(self) -> None:
        self.policies = [
            ("block_ip", _make_trusted_fields_policy(("ip",))),
            ("create_incident_ticket", _make_trusted_fields_policy(("title",))),
            ("*", lambda tool_name, kwargs: Allowed()),
        ]
        self.no_side_effect_tools = NO_SIDE_EFFECT_TOOLS | _SOC_NO_SIDE_EFFECT_TOOLS


# ── Runtime and namespace ─────────────────────────────────────────────────────

def _make_runtime() -> FunctionsRuntime:
    runtime = FunctionsRuntime()
    for fn in _STUB_TOOLS:
        runtime.register_function(fn)
    return runtime


def _make_namespace(runtime: FunctionsRuntime) -> Namespace:
    env = SocEnvironment()
    builtins_ns = Namespace.with_builtins()
    return builtins_ns.add_variables(make_agentdojo_namespace(builtins_ns, runtime, env))


# ── Runner ────────────────────────────────────────────────────────────────────

def run() -> int:
    runtime = _make_runtime()
    eval_args = EvalArgs(SocSecurityPolicyEngine(), MetadataEvalMode.NORMAL)

    rows: list[dict] = []
    all_ok = True

    for plan in SOC_PLANS:
        namespace = _make_namespace(runtime)
        tool_calls: list = []
        exec_ok = True
        policy_denied = False
        exec_error: str = ""

        code_block = f"```python\n{plan.code}\n```"
        try:
            eval_result = parse_and_interpret_code(
                code_block, namespace, [], (), eval_args
            )
            val_res, _, tool_calls, _ = eval_result
            if isinstance(val_res, interp_result.Error):
                exec_ok = False
                exec_error = str(val_res.error)
        except SecurityPolicyDeniedError as e:
            policy_denied = True
            exec_error = str(e)
        except Exception as e:
            exec_ok = False
            exec_error = f"{type(e).__name__}: {e}"

        # A plan expected to FAIL should be denied by the policy; one expected
        # to PASS should execute cleanly and not be denied.
        expected_deny = plan.expected == "fail"
        match = (policy_denied == expected_deny) and (exec_ok or policy_denied)
        if not match:
            all_ok = False

        rows.append(dict(
            plan=plan,
            exec_ok=exec_ok,
            policy_denied=policy_denied,
            exec_error=exec_error,
            tools_called=[tc.function for tc in tool_calls],
            match=match,
        ))

    _print_table(rows)
    return 0 if all_ok else 1


def _print_table(rows: list[dict]) -> None:
    W = 115
    print("=" * W)
    print("  CaMeL Execution Matrix — security policy check (no LLM, no injection)")
    print("=" * W)

    header = (
        f"  {'Property Class':<22} {'CTL Operator':<13} {'Expected':<9} "
        f"{'Exec':<9} {'Policy':<9} {'✓?':<4} {'Runtime?':<10} Description"
    )

    last_suite = None
    last_class = None

    for row in rows:
        plan = row["plan"]

        if plan.suite != last_suite:
            if last_suite is not None:
                _print_suite_footer(rows, last_suite, W)
                print()
            print(f"  ── {_SUITE_TITLES.get(plan.suite, plan.suite)} {'─' * (W - 8 - len(plan.suite))}")
            print(header)
            print("─" * W)
            last_suite = plan.suite
            last_class = None

        cls = _CLASS_LABELS.get(plan.property_class, plan.property_class)
        op = _OPERATOR_LABELS.get(plan.ctl_operator, plan.ctl_operator)
        expected = plan.expected.upper()
        exec_label = "OK" if row["exec_ok"] else "FAIL"
        policy_label = "DENY" if row["policy_denied"] else "ALLOW"
        ok = "✓" if row["match"] else "✗ MISMATCH"
        runtime = "yes" if plan.runtime_checkable else "no ← novel"

        if last_class and plan.property_class != last_class:
            print()
        last_class = plan.property_class

        row_text = (
            f"  {cls:<22} {op:<13} {expected:<9} {exec_label:<9} {policy_label:<9} "
            f"{ok:<4} {runtime:<11} {plan.description}"
        )
        print(_maybe_red(row_text, not row["match"]))

    if last_suite:
        _print_suite_footer(rows, last_suite, W)

    print()
    total = len(rows)
    correct = sum(1 for r in rows if r["match"])
    print(f"  Overall: {correct}/{total} plans gave expected policy verdict")
    print()
    print("  Taint propagation works via dependency chaining:")
    print("    CaMeLClassInstance.attr() returns attr.new_with_dependencies((self,)), adding")
    print("    the parent instance (analysis) to the attribute's dependency tuple.")
    print("    is_trusted() calls get_all_sources() which unions sources across the full")
    print("    dependency graph — Tool('query_ai_assistant', {}) (untrusted) propagates up,")
    print("    so analysis.source_ip and analysis.summary fail the trusted-fields policy.")
    print()


def _print_suite_footer(rows: list[dict], suite: str, W: int) -> None:
    suite_rows = [r for r in rows if r["plan"].suite == suite]
    total = len(suite_rows)
    correct = sum(1 for r in suite_rows if r["match"])
    print("─" * W)
    print(f"  {_SUITE_TITLES.get(suite, suite)}: {correct}/{total} correct")


if __name__ == "__main__":
    raise SystemExit(run())
