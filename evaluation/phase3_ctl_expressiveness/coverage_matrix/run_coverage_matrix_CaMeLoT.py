#!/usr/bin/env python3
"""
CTL Coverage Matrix — Phase 3b

Verifies 34 synthetic plans (8 Slack + 14 SOC + 12 Healthcare) against their
respective CTL policy suites and produces a table showing which property
classes CTL can catch and whether a reactive runtime monitor could catch the
same violation.

Usage:
    uv run --env-file .env python \
        evaluation/phase3_ctl_expressiveness/coverage_matrix/run_coverage_matrix_CaMeLoT.py

    # Verbose: print violated formulas for each FAIL case
    uv run --env-file .env python ... --verbose
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "src"))

RESULTS_JSON = REPO_ROOT / "src/camel/ext/verification_runs/coverage_matrix_synthetic.json"

import camel.custom_yaml  # noqa: F401
import camel.ext.ctl_policies.slack  # noqa: F401
import camel.ext.ctl_policies.soc  # noqa: F401
import camel.ext.ctl_policies.healthcare  # noqa: F401

from camel.ext.ctl_policies import get_tool_signatures_for_suite
from camel.ext.verification_integration import verify_code
from plans import Plan, SLACK_PLANS
from plans_soc import SOC_PLANS
from plans_healthcare import HEALTHCARE_PLANS

ALL_PLANS: list[Plan] = SLACK_PLANS + SOC_PLANS + HEALTHCARE_PLANS

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

# Cache tool signatures per suite to avoid repeated lookups
_sig_cache: dict[str, tuple] = {}


_RED = "\033[91m"
_RESET = "\033[0m"


def _maybe_red(text: str, mismatch: bool) -> str:
    if not mismatch:
        return text
    if not sys.stdout.isatty():
        return text
    return f"{_RED}{text}{_RESET}"


def _get_sigs(suite: str):
    if suite not in _sig_cache:
        sigs = get_tool_signatures_for_suite(suite)
        _sig_cache[suite] = (list(sigs), sigs)
    return _sig_cache[suite]


def _verify(plan: Plan) -> tuple[bool, list[str]]:
    tool_fns, tool_sigs = _get_sigs(plan.suite)
    feedback = verify_code(
        plan.code,
        tool_fns,
        tool_sigs,
        plan.suite,
        save_artifacts=False,
        user_task_id=plan.user_task_id,
    )
    result = feedback.verification_result
    violated = (
        result.properties_violated
        if result is not None
        else feedback.counterexamples or []
    )
    return feedback.verified, violated


def run(verbose: bool = False) -> int:
    rows: list[dict] = []
    all_correct = True

    for plan in ALL_PLANS:
        verified, violated = _verify(plan)
        ctl_result = "PASS" if verified else "FAIL"
        expected = plan.expected.upper()
        match = ctl_result == expected
        if not match:
            all_correct = False

        rows.append(dict(
            plan=plan,
            ctl_result=ctl_result,
            match=match,
            violated=violated,
        ))

    _print_table(rows, verbose)
    _save_json(rows)
    return 0 if all_correct else 1


def _save_json(rows: list[dict]) -> None:
    total = len(rows)
    correct = sum(1 for r in rows if r["match"])
    novel_fail = [r for r in rows if not r["plan"].runtime_checkable and r["plan"].expected == "fail"]
    novel_caught = sum(1 for r in novel_fail if r["ctl_result"] == "FAIL")
    payload = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model": None,
        "total": total,
        "correct": correct,
        "novel_total": len(novel_fail),
        "novel_caught": novel_caught,
        "rows": [
            {
                "suite": r["plan"].suite,
                "property_class": r["plan"].property_class,
                "ctl_operator": r["plan"].ctl_operator,
                "expected": r["plan"].expected.upper(),
                "ctl_result": r["ctl_result"],
                "match": r["match"],
                "runtime_checkable": r["plan"].runtime_checkable,
                "description": r["plan"].description,
                "violated": list(r["violated"]),
                "plan": r["plan"].code,
            }
            for r in rows
        ],
    }
    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON.write_text(json.dumps(payload, indent=2))
    print(f"  Results saved → {RESULTS_JSON.relative_to(REPO_ROOT)}")


def _print_table(rows: list[dict], verbose: bool) -> None:
    W = 115
    print("=" * W)
    print("  CTL Coverage Matrix")
    print("=" * W)

    header = (
        f"  {'Property Class':<22} {'CTL Operator':<13} {'Expected':<9} "
        f"{'CTL':<6} {'✓?':<4} {'Runtime?':<10} Description"
    )

    last_suite = None
    last_class = None

    for row in rows:
        plan = row["plan"]

        # Suite section header
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
        ctl = row["ctl_result"]
        ok = "✓" if row["match"] else "✗ MISMATCH"
        runtime = "yes" if plan.runtime_checkable else "no ← novel"

        if last_class and plan.property_class != last_class:
            print()
        last_class = plan.property_class

        row_text = (
            f"  {cls:<22} {op:<13} {expected:<9} {ctl:<6} {ok:<4} {runtime:<11} {plan.description}"
        )
        print(_maybe_red(row_text, not row["match"]))
        if verbose and plan.expected != "pass" and row["violated"]:
            for v in row["violated"][:2]:
                print(f"  {'':>22}   violated: {v[:80]}")

    if last_suite:
        _print_suite_footer(rows, last_suite, W)

    print()
    total = len(rows)
    correct = sum(1 for r in rows if r["match"])
    print(f"  Overall: {correct}/{total} plans gave expected CTL verdict")

    novel = [r for r in rows if not r["plan"].runtime_checkable and r["plan"].expected == "fail"]
    if novel:
        print(f"\n  Novel (not runtime-checkable) violations caught by CTL: {len(novel)}")
        for r in novel:
            plan = r["plan"]
            status = "✓ caught" if r["ctl_result"] == "FAIL" else "✗ missed"
            suite_label = _SUITE_TITLES.get(plan.suite, plan.suite)
            cls_label = _CLASS_LABELS.get(plan.property_class, plan.property_class)
            print(f"    {status}  [{suite_label} / {cls_label}] {plan.description}")
    print()


def _print_suite_footer(rows: list[dict], suite: str, W: int) -> None:
    suite_rows = [r for r in rows if r["plan"].suite == suite]
    total = len(suite_rows)
    correct = sum(1 for r in suite_rows if r["match"])
    print("─" * W)
    print(f"  {_SUITE_TITLES.get(suite, suite)}: {correct}/{total} correct")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Print violated CTL formulas")
    args = parser.parse_args()
    raise SystemExit(run(verbose=args.verbose))
