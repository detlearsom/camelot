"""
Phase 2 — Pure Overlap: compare pure CaMeL vs CaMeL+CTL with slack_overlap.

Two configs:

    CaMeL      - CAMEL_VERIFY=false, enable_secpol=True
                 Pure runtime defense; raises SecurityPolicyDeniedError on
                 tainted arguments at tool-call time.

    CaMeL+CTL  - CAMEL_VERIFY=true,  enable_secpol=False, CAMEL_CTL_SUITE=<ctl_suite>
                 Pre-execution defense; raises CTLVerificationError before the
                 plan is interpreted. secpol is irrelevant when CTL blocks.

The CTL policy module is decoupled from the AgentDojo suite via CAMEL_CTL_SUITE:
the AgentDojo suite (tasks, env, tools) is still --suite (default "slack"),
while CTL looks up properties from --ctl-suite (default same as --suite, or
"slack_overlap" to use the new overlap-only policy file).

Two run modes:

    benign            - benchmark.benchmark_suite_without_injections
                        CaMeL has nothing tainted to detect; everything should
                        pass unless the agent itself fails the task.

    --with-injections - benchmark.benchmark_suite_with_injections + load_attack
                        The setting where pure CaMeL actually "fails" by
                        detecting tainted inputs (blocked_by=secpol).

Output
    evaluation/phase2_benign_tasks/pure_overlap/results.jsonl
    evaluation/phase2_benign_tasks/pure_overlap/summary.json
    evaluation/phase2_benign_tasks/pure_overlap/runs/<timestamp>/

Usage
    # Benign comparison, slack_overlap CTL module
    uv run --env-file .env evaluation/phase2_benign_tasks/pure_overlap/run_overlap.py \\
        --model anthropic:claude-haiku-4-5-20251001 --suite slack --ctl-suite slack_overlap --user-tasks user_task_2

    # Failure-mode demo: pure CaMeL detects tainted inputs
    uv run --env-file .env evaluation/phase2_benign_tasks/pure_overlap/run_overlap.py \\
        --model openai:gpt-4o --suite slack --ctl-suite slack_overlap \\
        --with-injections --user-tasks user_task_1 \\
        --injection-tasks injection_task_1
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import cast

_repo = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_repo / "src"))

import camel.custom_yaml  # noqa
import camel.ext.ctl_policies  # noqa — triggers registration of all CTL modules

from agentdojo import benchmark, logging as ad_logging
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite import get_suite

from pydantic_ai.models import KnownModelName

from camel.models import make_tools_pipeline
from camel.interpreter.interpreter import MetadataEvalMode
from camel import token_tracker as _token_tracker
from camel.security_policy import SecurityPolicyDeniedError
from camel.ext.verification_integration import CTLVerificationError
from camel.pipeline_elements import privileged_llm as _pllm

_OUT_DIR = Path(__file__).parent
_RUNS_DIR = _OUT_DIR / "runs"
_CTL_LOG = _repo / "src" / "camel" / "ext" / "verification_runs" / "ctl_events.jsonl"

_TASK_ERROR = "error"

CONFIG_CAMEL = "CaMeL"
CONFIG_CAMEL_CTL = "CaMeL+CTL"
CONFIG_BOTH = "both"
_VALID_CONFIGS = (CONFIG_CAMEL, CONFIG_CAMEL_CTL, CONFIG_BOTH)


# ---------------------------------------------------------------------------
# pipeline construction
# ---------------------------------------------------------------------------


def _make_pipeline(
    model: str, suite_name: str, config: str, ctl_suite: str, max_repairs: int
):
    """Build a pipeline for the given config.

    Sets CAMEL_VERIFY, CAMEL_CTL_SUITE, and CAMEL_MAX_REPAIRS env vars before
    constructing the pipeline. enable_secpol is True for pure CaMeL, False
    for CaMeL+CTL.
    """
    if config == CONFIG_CAMEL:
        os.environ["CAMEL_VERIFY"] = "false"
        os.environ.pop("CAMEL_CTL_SUITE", None)
        os.environ.pop("CAMEL_MAX_REPAIRS", None)
        enable_secpol = True
    elif config == CONFIG_CAMEL_CTL:
        os.environ["CAMEL_VERIFY"] = "true"
        os.environ["CAMEL_CTL_SUITE"] = ctl_suite
        os.environ["CAMEL_MAX_REPAIRS"] = str(max_repairs)
        enable_secpol = False
    else:
        raise ValueError(f"Unknown config: {config}")

    return make_tools_pipeline(
        cast(KnownModelName, model),
        False,
        False,
        "important_instructions",
        "medium",
        None,
        suite_name,
        None,
        MetadataEvalMode.NORMAL,
        None,
        enable_secpol=enable_secpol,
    )


# ---------------------------------------------------------------------------
# single-task runner
# ---------------------------------------------------------------------------


def _run_task(
    model: str,
    suite_name: str,
    suite,
    task_id: str,
    config: str,
    ctl_suite: str,
    max_repairs: int,
    logdir: Path,
    force_rerun: bool,
    with_injections: bool,
    attack_name: str,
    injection_task_id: str | None,
) -> tuple[bool | str, str | None, str | None]:
    """Run one (task, config) combination.

    Returns (result, blocked_by, blocked_detail) where:
      result         = True | False | "error"
      blocked_by     = "secpol" | "ctl" | "recursion" | "error" | None
      blocked_detail = the exception message (e.g. which tool/arg secpol
                       denied), or None if not blocked.
    """
    pipeline = _make_pipeline(model, suite_name, config, ctl_suite, max_repairs)

    try:
        with ad_logging.OutputLogger(str(logdir)):
            if with_injections:
                attack = load_attack(attack_name, suite, pipeline)
                injection_tasks = [injection_task_id] if injection_task_id else None
                results = benchmark.benchmark_suite_with_injections(
                    pipeline,
                    suite,
                    attack,
                    logdir,
                    force_rerun=force_rerun,
                    user_tasks=[task_id],
                    injection_tasks=injection_tasks,
                )
            else:
                results = benchmark.benchmark_suite_without_injections(
                    pipeline,
                    suite,
                    logdir,
                    force_rerun=force_rerun,
                    user_tasks=[task_id],
                )

        utility_results = list(results["utility_results"].values())
        if not utility_results:
            return _TASK_ERROR, "error", "no utility result"
        return bool(utility_results[0]), None, None

    except CTLVerificationError as exc:
        return False, "ctl", str(exc)
    except SecurityPolicyDeniedError as exc:
        return False, "secpol", str(exc)
    except RecursionError:
        return _TASK_ERROR, "recursion", "RecursionError"
    except Exception as exc:
        # Surface the unexpected error type so it's visible above the result
        # block; the rest of the formatted output still renders normally.
        print(f"     [ERROR] {type(exc).__name__}: {exc}")
        return _TASK_ERROR, "error", f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# CTL event log
# ---------------------------------------------------------------------------


def _ctl_events_for_suite(suite_name: str) -> list[dict]:
    """Read ctl_events.jsonl and return all events for this suite in order."""
    events: list[dict] = []
    if not _CTL_LOG.exists():
        return events
    for line in _CTL_LOG.read_text().splitlines():
        try:
            ev = json.loads(line)
            if ev.get("suite") == suite_name:
                events.append(ev)
        except (json.JSONDecodeError, KeyError):
            pass
    return events


# ---------------------------------------------------------------------------
# pretty-print helpers
# ---------------------------------------------------------------------------

_WIDTH = 88
_HRULE = "─" * _WIDTH
_HRULE_HEAVY = "═" * _WIDTH


def _print_header(
    suite_name: str,
    ctl_suite: str,
    configs: list[str],
    with_injections: bool,
    attack_name: str,
    injection_tasks: list[str] | None,
    max_repairs: int,
) -> None:
    print(_HRULE_HEAVY)
    print(f" Suite (AgentDojo) : {suite_name}")
    print(f" Suite (CTL)       : {ctl_suite}")
    print(f" Configs           : {', '.join(configs)}")
    print(f" Max CTL repairs   : {max_repairs}")
    print(f" With injections   : {with_injections}")
    if with_injections:
        print(f" Attack            : {attack_name}")
        print(
            f" Injection tasks   : {', '.join(injection_tasks) if injection_tasks else 'all'}"
        )
    print(_HRULE_HEAVY)


def _print_pair_header(
    idx: int, total: int, task_id: str, injection_id: str | None
) -> None:
    pair = task_id + (f" × {injection_id}" if injection_id else "")
    print()
    print(_HRULE_HEAVY)
    print(f" [{idx}/{total}] {pair}")
    print(_HRULE_HEAVY)


def _print_config_result(
    config: str,
    result: bool | str,
    blocked_by: str | None,
    blocked_detail: str | None,
    repairs: int,
    initial_violations: list,
    code: str,
    usage=None,
) -> None:
    """Print the result for one (pair, config) including the P-LLM code."""
    print()
    print(f" ▸ {config}")
    print(f"     result            : {result}")
    print(f"     blocked_by        : {blocked_by or '—'}")
    if blocked_detail:
        print(f"     block detail      : {blocked_detail}")
    print(f"     CTL repairs       : {repairs}")
    if usage is not None:
        def _cache(u):
            return f"  cache read={u.cache_read_input_tokens:,} write={u.cache_creation_input_tokens:,}" if (u.cache_read_input_tokens or u.cache_creation_input_tokens) else ""
        print(f"     tokens (P-LLM)    : in={usage.pllm.input_tokens:,}  out={usage.pllm.output_tokens:,}{_cache(usage.pllm)}")
        print(f"     tokens (Q-LLM)    : in={usage.qllm.input_tokens:,}  out={usage.qllm.output_tokens:,}{_cache(usage.qllm)}")
    _print_code_block(code, title=f"P-LLM plan ({config})")


def _print_code_block(code: str, title: str) -> None:
    """Print code inside a labelled box. Empty code → '(no plan captured)'."""
    print()
    print(f"     ┌─ {title} {'─' * max(0, _WIDTH - len(title) - 9)}")
    if not code or not code.strip():
        print("     │ (no plan captured)")
    else:
        for line in code.rstrip().splitlines():
            print(f"     │ {line}")
    print(f"     └{'─' * (_WIDTH - 6)}")


# ---------------------------------------------------------------------------
# main run loop
# ---------------------------------------------------------------------------


def run(
    model: str,
    suite_name: str,
    ctl_suite: str,
    configs: list[str],
    user_tasks: list[str] | None,
    with_injections: bool,
    attack_name: str,
    injection_tasks: list[str] | None,
    max_repairs: int,
    logdir: Path,
    force_rerun: bool,
    sleep_between_tasks: int,
    name: str | None = None,
) -> None:
    _print_header(
        suite_name,
        ctl_suite,
        configs,
        with_injections,
        attack_name,
        injection_tasks,
        max_repairs,
    )

    # Snapshot the global CTL event log so we can slice out only the events
    # appended during this run when archiving.
    ctl_log_lines_before = (
        len(_CTL_LOG.read_text().splitlines()) if _CTL_LOG.exists() else 0
    )

    suite = get_suite("v1.2", suite_name)
    task_ids = list(suite.user_tasks.keys())
    if user_tasks:
        task_ids = [t for t in task_ids if t in user_tasks]

    # Build the (task, injection) pair list. Without injections it's just the
    # task IDs; with injections we iterate over the cross-product of selected
    # user tasks and selected injection tasks (or "all" if not restricted).
    if with_injections:
        all_injection_ids = list(suite.injection_tasks.keys())
        injection_ids = injection_tasks or all_injection_ids
        injection_ids = [i for i in injection_ids if i in suite.injection_tasks]
        pairs = [(t, i) for t in task_ids for i in injection_ids]
    else:
        pairs = [(t, None) for t in task_ids]

    all_records: list[dict] = []
    by_pair: dict[tuple[str, str | None], dict[str, dict]] = {}
    n_pairs = len(pairs)

    # Iterate by pair first so the output groups all configs for the same
    # (task, injection), making the comparison easy to read.
    for pair_idx, (task_id, injection_id) in enumerate(pairs, start=1):
        _print_pair_header(pair_idx, n_pairs, task_id, injection_id)

        for cfg_idx, config in enumerate(configs):
            if (pair_idx > 1 or cfg_idx > 0) and sleep_between_tasks > 0:
                print(f"\n  [sleep {sleep_between_tasks}s ...]")
                time.sleep(sleep_between_tasks)

            # Reset P-LLM capture state so the print reflects only this run.
            _pllm._LAST_CODE[0] = ""
            _pllm._LAST_CTL_VIOLATIONS[0] = []
            _pllm._LAST_CTL_REPAIRS[0] = 0

            events_before = len(_ctl_events_for_suite(suite_name))
            sub_logdir = logdir / config.replace("+", "_")

            _token_tracker.reset()
            result, blocked_by, blocked_detail = _run_task(
                model=model,
                suite_name=suite_name,
                suite=suite,
                task_id=task_id,
                config=config,
                ctl_suite=ctl_suite,
                max_repairs=max_repairs,
                logdir=sub_logdir,
                force_rerun=force_rerun,
                with_injections=with_injections,
                attack_name=attack_name,
                injection_task_id=injection_id,
            )

            new_events = _ctl_events_for_suite(suite_name)[events_before:]
            ev = new_events[0] if new_events else {}

            code = _pllm._LAST_CODE[0]
            initial_violations = (
                ev.get("initial_violations") or _pllm._LAST_CTL_VIOLATIONS[0] or []
            )
            repairs = ev.get("repairs") or _pllm._LAST_CTL_REPAIRS[0] or 0

            _usage = _token_tracker.get()
            _print_config_result(
                config=config,
                result=result,
                blocked_by=blocked_by,
                blocked_detail=blocked_detail,
                repairs=repairs,
                initial_violations=initial_violations,
                code=code,
                usage=_usage,
            )
            rec = {
                "suite": suite_name,
                "ctl_suite": ctl_suite,
                "task_id": task_id,
                "injection_task_id": injection_id,
                "config": config,
                "with_injections": with_injections,
                "attack": attack_name if with_injections else None,
                "passed": result if result == _TASK_ERROR else bool(result),
                "blocked_by": blocked_by,
                "blocked_detail": blocked_detail,
                "repairs": repairs,
                "ctl_status": ev.get("status"),
                "initial_violations": initial_violations,
                "code": code,
                "pllm_tokens_input": _usage.pllm.input_tokens,
                "pllm_tokens_output": _usage.pllm.output_tokens,
                "pllm_tokens_cache_read": _usage.pllm.cache_read_input_tokens,
                "pllm_tokens_cache_write": _usage.pllm.cache_creation_input_tokens,
                "qllm_tokens_input": _usage.qllm.input_tokens,
                "qllm_tokens_output": _usage.qllm.output_tokens,
                "qllm_tokens_cache_read": _usage.qllm.cache_read_input_tokens,
                "qllm_tokens_cache_write": _usage.qllm.cache_creation_input_tokens,
                "pllm_tokens_input": _usage.pllm.input_tokens,
                "pllm_tokens_output": _usage.pllm.output_tokens,
                "qllm_tokens_input": _usage.qllm.input_tokens,
                "qllm_tokens_output": _usage.qllm.output_tokens,
            }
            all_records.append(rec)
            by_pair.setdefault((task_id, injection_id), {})[config] = rec

    if not all_records:
        return

    # Write timestamped run directory (only output location).
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = _RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    results_path = run_dir / "results.jsonl"
    with open(results_path, "w") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")
    print(f"\nResults  -> {results_path}")

    summary = _compute_summary(all_records, by_pair, configs)
    summary["meta"] = {
        "timestamp": run_id,
        "name": name,
        "model": model,
        "suite": suite_name,
        "ctl_suite": ctl_suite,
        "configs": configs,
        "with_injections": with_injections,
        "attack": attack_name if with_injections else None,
        "max_repairs": max_repairs,
        "user_tasks": user_tasks,
        "injection_tasks": injection_tasks,
        "n_pairs": n_pairs,
    }
    summary_path = run_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary  -> {summary_path}")
    _print_summary(summary, configs)

    # Write only this run's CTL events (the lines appended since run start).
    if _CTL_LOG.exists():
        new_lines = _CTL_LOG.read_text().splitlines()[ctl_log_lines_before:]
        if new_lines:
            (run_dir / "ctl_events.jsonl").write_text("\n".join(new_lines) + "\n")


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


def _compute_summary(
    records: list[dict],
    by_pair: dict[tuple[str, str | None], dict[str, dict]],
    configs: list[str],
) -> dict:
    per_config: dict[str, dict] = {
        c: {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "blocked_secpol": 0,
            "blocked_ctl": 0,
        }
        for c in configs
    }

    for rec in records:
        d = per_config[rec["config"]]
        d["total"] += 1
        if rec["passed"] is True:
            d["passed"] += 1
        elif rec["passed"] == _TASK_ERROR:
            d["errors"] += 1
        else:
            d["failed"] += 1
        if rec["blocked_by"] == "secpol":
            d["blocked_secpol"] += 1
        elif rec["blocked_by"] == "ctl":
            d["blocked_ctl"] += 1

    # Cross-config agreement (only when both ran)
    agreement = {
        "agree_pass": 0,
        "agree_fail": 0,
        "camel_only_pass": 0,
        "ctl_only_pass": 0,
        "incomplete": 0,
    }
    if CONFIG_CAMEL in configs and CONFIG_CAMEL_CTL in configs:
        for pair_results in by_pair.values():
            a = pair_results.get(CONFIG_CAMEL)
            b = pair_results.get(CONFIG_CAMEL_CTL)
            if a is None or b is None:
                agreement["incomplete"] += 1
                continue
            ap = a["passed"] is True
            bp = b["passed"] is True
            if ap and bp:
                agreement["agree_pass"] += 1
            elif not ap and not bp:
                agreement["agree_fail"] += 1
            elif ap and not bp:
                agreement["camel_only_pass"] += 1
            else:
                agreement["ctl_only_pass"] += 1

    return {"per_config": per_config, "agreement": agreement}


def _print_summary(summary: dict, configs: list[str]) -> None:
    print("\n" + "=" * 80)
    print("PURE OVERLAP — pure CaMeL vs CaMeL+CTL")
    print("=" * 80)
    print(
        f"{'Config':<12} {'Total':>6} {'Pass':>6} {'Fail':>6} {'Err':>4} "
        f"{'BlkSecpol':>10} {'BlkCTL':>7}"
    )
    print("-" * 80)
    for c in configs:
        d = summary["per_config"][c]
        print(
            f"{c:<12} {d['total']:>6} {d['passed']:>6} {d['failed']:>6} "
            f"{d['errors']:>4} {d['blocked_secpol']:>10} {d['blocked_ctl']:>7}"
        )
    print("-" * 80)

    if CONFIG_CAMEL in configs and CONFIG_CAMEL_CTL in configs:
        a = summary["agreement"]
        print()
        print("Agreement (per (task, injection) pair, both configs ran)")
        print(f"  agree_pass       : {a['agree_pass']}")
        print(f"  agree_fail       : {a['agree_fail']}")
        print(
            f"  camel_only_pass  : {a['camel_only_pass']}  (CTL blocked/repaired worse)"
        )
        print(
            f"  ctl_only_pass    : {a['ctl_only_pass']}    (CTL passed where CaMeL failed)"
        )
        if a["incomplete"]:
            print(f"  incomplete       : {a['incomplete']}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--model", required=True, help="e.g. openai:gpt-4o")
    p.add_argument(
        "--suite", default="slack", help="AgentDojo suite name (default: slack)"
    )
    p.add_argument(
        "--ctl-suite",
        default=None,
        help="CTL policy module to use via CAMEL_CTL_SUITE env var. "
        "Default: same as --suite. Set to 'slack_overlap' to use "
        "only the policies that overlap with CaMeL.",
    )
    p.add_argument(
        "--config",
        choices=_VALID_CONFIGS,
        default=CONFIG_BOTH,
        help="Which configs to run (default: both)",
    )
    p.add_argument(
        "--user-tasks", nargs="*", default=None, help="Restrict to these user task IDs"
    )
    p.add_argument(
        "--with-injections",
        action="store_true",
        help="Run benchmark_suite_with_injections instead of "
        "without_injections. Required to observe pure CaMeL "
        "detecting tainted inputs.",
    )
    p.add_argument(
        "--attack",
        default="important_instructions",
        help="Attack name (only used with --with-injections)",
    )
    p.add_argument(
        "--injection-tasks",
        nargs="*",
        default=None,
        help="Restrict to these injection task IDs "
        "(only used with --with-injections)",
    )
    p.add_argument(
        "--max-repairs",
        type=int,
        default=10,
        help="Max CTL repair attempts in the CaMeL+CTL config. "
        "Set to 0 to fail closed on first violation (no repair). Default 10.",
    )
    p.add_argument(
        "--name",
        default=None,
        help="Optional human-readable label for this run, e.g. 'Partial experiment 1'",
    )
    p.add_argument("--logdir", type=Path, default=_repo / "logs" / "pure_overlap")
    p.add_argument("--force-rerun", action="store_true")
    p.add_argument(
        "--sleep",
        type=int,
        default=0,
        help="Seconds to sleep between tasks (use ~30 for Anthropic Tier 1)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    ctl_suite = args.ctl_suite or args.suite
    configs = (
        [CONFIG_CAMEL, CONFIG_CAMEL_CTL]
        if args.config == CONFIG_BOTH
        else [args.config]
    )

    run(
        model=args.model,
        suite_name=args.suite,
        ctl_suite=ctl_suite,
        configs=configs,
        user_tasks=args.user_tasks,
        with_injections=args.with_injections,
        attack_name=args.attack,
        injection_tasks=args.injection_tasks,
        max_repairs=args.max_repairs,
        logdir=args.logdir,
        force_rerun=args.force_rerun,
        sleep_between_tasks=args.sleep,
        name=args.name,
    )


if __name__ == "__main__":
    main()
