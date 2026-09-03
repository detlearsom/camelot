"""
Phase 2 - Tier 1: prompt-extracted CTL experiment

Single-run methodology
----------------------
Every task runs through Config B (CaMeL + CTL + repair loop) exactly once.
Config A (CaMeL only) runs separately for tasks where CTL intervened.

For all other tasks camel_pass is derived directly from ctl_pass:
  1. CTL found no violations → same plan was executed → camel_pass = ctl_pass
    (zero non-determinism: the comparison is provably exact)
  2. CTL did not intervene → no repair changed the plan

Metrics.
  camel_pass         - utility with CaMeL only (inferred or separate Config A)
  ctl_pass           — utility with CaMeL + CTL + repair
  ctl_fp             — camel_pass=True & ctl_pass=False (CTL blocked a legitimate task)
  repairs            — CTL repair rounds used in Config B
  initial_violations — CTL properties violated before first repair
  camel_run          — "inferred" or "separate"

Output
  evaluation/phase2_benign_tasks/results.jsonl  (one record per task)
  evaluation/phase2_benign_tasks/summary.json   (aggregate table)

Usage
  uv run --env-file .env evaluation/phase2_benign_tasks/run_tier1_extracted.py \\
      --model openai:gpt-4.1-2025-04-14 --suites slack --force-rerun

  uv run --env-file .env evaluation/phase2_benign_tasks/run_tier1_extracted.py \\
      --model openai:gpt-4.1-2025-04-14 --suites slack --force-rerun \\
      --prompt-extracted-ctl
"""

import argparse
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import cast

_repo = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_repo))
sys.path.insert(0, str(_repo / "src"))

import camel.custom_yaml  

from agentdojo import benchmark, logging as ad_logging
from agentdojo.task_suite import get_suite

from pydantic_ai.models import KnownModelName

from camel.models import make_tools_pipeline
from camel.interpreter.interpreter import MetadataEvalMode
from camel.security_policy import SecurityPolicyDeniedError

from camel.ext.verification_integration import CTLVerificationError


_OUT_DIR = Path(__file__).parent
_RUNS_DIR = _OUT_DIR / "runs"
_RESULTS_FILE = _OUT_DIR / "results.jsonl"
_SUMMARY_FILE = _OUT_DIR / "summary.json"
_CTL_LOG = _repo / "src" / "camel" / "ext" / "verification_runs" / "ctl_events.jsonl"

_TASK_ERROR = "error"
_PROMPT_EXTRACTED_CTL: dict[tuple[str, str], list[object]] = {}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_pipeline(model: str, suite_name: str, camel_verify: bool):
    os.environ["CAMEL_VERIFY"] = "true" if camel_verify else "false"
    return make_tools_pipeline(
        cast(KnownModelName, model),
        False, False, "important_instructions", "medium",
        None, suite_name, None, MetadataEvalMode.NORMAL, None,
    )


def _verification_run_dirs(suite_name: str) -> set[Path]:
    if not _CTL_LOG.parent.exists():
        return set()
    return {
        d for d in _CTL_LOG.parent.glob(f"{suite_name}_*")
        if d.is_dir()
    }


def _config_name(camel_verify: bool) -> str:
    return "B_CTL" if camel_verify else "A_NO_CTL"


def _config_label(camel_verify: bool) -> str:
    if camel_verify:
        return "Config B — CaMeL + CTL + repair"
    return "Config A — CaMeL only"


def _policy_names_in_run(run_dir: Path) -> set[str]:
    """Read CTL property names from one generated NuSMV artifact."""
    model_path = run_dir / "model.xmv"
    if not model_path.exists():
        return set()
    names = set()
    for line in model_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("-- Property:"):
            names.add(line.removeprefix("-- Property:").strip())
    return names


def _tag_new_verification_runs(
    run_dirs: set[Path],
    *,
    suite_name: str,
    task_id: str,
    query: str,
    camel_verify: bool,
    result: bool | str,
    preferred_policy_names: list[str] | None = None,
) -> None:
    config = _config_name(camel_verify)
    session_update = {
        "phase": "phase2_tier1_benign",
        "suite": suite_name,
        "user_task_id": task_id,
        "query": query,
        "config": config,
        "config_label": _config_label(camel_verify),
        "camel_verify": camel_verify,
        "outcome": "success" if result is True else "failure",
        "utility": result is True,
    }
    if not run_dirs:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        synth = _CTL_LOG.parent / f"{suite_name}_{ts}"
        synth.mkdir(parents=True, exist_ok=True)
        session_update["synthetic_camel_only"] = True
        (synth / "session.json").write_text(
            json.dumps(session_update, indent=2)
        )

        (synth / "verification_result.json").write_text(
            json.dumps({"success": result is True,
                        "config": "A_NO_CTL",
                        "note": "CaMeL only (no CTL); utility from agentdojo"},
                       indent=2)
        )
        return
 
    preferred = set(preferred_policy_names or [])
    preferred_dirs = [
        d for d in sorted(run_dirs)
        if preferred and (_policy_names_in_run(d) & preferred)
    ]
    run_dir = (preferred_dirs or sorted(run_dirs))[-1]
    session_path = run_dir / "session.json"
    existing = {}
    if session_path.exists():
        try:
            existing = json.loads(session_path.read_text())
        except json.JSONDecodeError:
            existing = {}
    existing.update(session_update)
    if preferred_policy_names:
        existing["preferred_policy_names"] = preferred_policy_names
    session_path.write_text(json.dumps(existing, indent=2))


def _run_task(
    model: str,
    suite_name: str,
    suite,
    task_id: str,
    camel_verify: bool,
    logdir: Path,
    force_rerun: bool,
    preferred_policy_names: list[str] | None = None,
) -> bool | str:
    """Run one task; return True/False/'error'."""
    runs_before = _verification_run_dirs(suite_name)
    result: bool | str = _TASK_ERROR
    previous_user_task_id = os.environ.get("CAMEL_USER_TASK_ID")
    os.environ["CAMEL_USER_TASK_ID"] = task_id
    pipeline = _make_pipeline(model, suite_name, camel_verify)
    try:
        with ad_logging.OutputLogger(str(logdir)):
            results = benchmark.benchmark_suite_without_injections(
                pipeline, suite, logdir,
                force_rerun=force_rerun, user_tasks=[task_id],
            )
        result = bool(list(results["utility_results"].values())[0])
    except CTLVerificationError as exc:
        print(f"    [CTL BLOCK] {task_id}: {exc}")
        result = False
    except RecursionError:
        print(f"    [RECURSION ERROR] {task_id}") #this is based on LLM usually
        result = _TASK_ERROR
    except SecurityPolicyDeniedError:
        print(f"    [POLICY BLOCK] {task_id}: denied by runtime policy")
        result = False
    except Exception as exc:
        print(f"    [ERROR] {type(exc).__name__}: {exc}")
        result = _TASK_ERROR
    if previous_user_task_id is None:
        os.environ.pop("CAMEL_USER_TASK_ID", None)
    else:
        os.environ["CAMEL_USER_TASK_ID"] = previous_user_task_id
    runs_after = _verification_run_dirs(suite_name)
    _tag_new_verification_runs(
        runs_after - runs_before,
        suite_name=suite_name,
        task_id=task_id,
        query=_task_prompt(suite.user_tasks[task_id]),
        camel_verify=camel_verify,
        result=result,
        preferred_policy_names=preferred_policy_names,
    )
    return result


def _ctl_events_for_suite(suite_name: str) -> list[dict]:
    """Read ctl_events.jsonl and return all events for this suite in order."""
    events = []
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


def _summarise_events(events: list[dict]) -> dict:
    """Aggregate ALL CTL events emitted during one task's Config B run.

    One task run emits MANY events (each P-LLM plan attempt + each repair
    cycle). Looking at only the first event under-counts repairs and, worse,
    misses that CTL intervened on a later cycle. If CTL intervened at all the
    executed plan differs from CaMeL-only, so camel_pass MUST NOT be inferred
    from ctl_pass — an explicit Config A run is required.
    """
    if not events:
        return {"initial_violations": [], "repairs": 0,
                "status": "pass", "ctl_intervened": False}

    # Reported repairs/violations/status describe the DECISIVE cycle: the last
    # event = the final verification of the plan that was actually executed.
    # Its repair count respects the per-cycle cap (summing across abandoned
    # P-LLM attempts would exceed the documented max and is meaningless).
    decisive = events[-1]
    # ctl_intervened, however, must consider EVERY cycle: if CTL touched the
    # plan on ANY attempt the executed plan differs from CaMeL-only, so
    # camel_pass cannot be inferred (this drives the explicit Config A run).
    intervened = any(
        (e.get("initial_violations") or [])
        or int(e.get("repairs", 0) or 0) > 0
        or e.get("status") == "fail"
        for e in events
    )
    return {
        "initial_violations": list(decisive.get("initial_violations") or []),
        "repairs": int(decisive.get("repairs", 0) or 0),
        "status": decisive.get("status", "pass"),
        "ctl_intervened": intervened,
    }


def _task_prompt(user_task) -> str:
    """Best-effort extraction of the AgentDojo task prompt."""
    for attr in ("PROMPT", "GOAL", "prompt", "goal"):
        value = getattr(user_task, attr, None)
        if value:
            return str(value)
    return str(user_task)


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_") or "task"


def _build_prompt_extracted_ctl(
    suite_name: str,
    task_id: str,
    prompt: str,
    model: str,
    debug: bool,
) -> list[object]:
    from camel.ext.ctl_policies import CTLProperty
    from camel.ext.ctl_policies import get_properties_for_suite
    from camel.ext.ctl_policies import get_llm_tools_for_suite
    from camel.ext.ctl_policies import get_tool_signatures_for_suite
    from evaluation.phase3_ctl_expressiveness.prompt_extraction.check_reality import (
        check_reality,
        make_atom_resolver,
        make_resolver,
    )
    from evaluation.phase3_ctl_expressiveness.prompt_extraction.proposer import propose
    from evaluation.phase3_ctl_expressiveness.prompt_extraction.run_extraction import (
        _describe,
        _known_atoms_from_properties,
        _norm,
    )
    from evaluation.phase3_ctl_expressiveness.prompt_extraction.run_vocabulary_eval import (
        _side_effect_tools,
    )

    tool_sigs = get_tool_signatures_for_suite(suite_name)
    if not tool_sigs:
        raise ValueError(f"empty tool namespace for suite {suite_name!r}")

    authored = get_properties_for_suite(suite_name, user_task_id=task_id)
    authored_by_formula = {_norm(p.formula): p.name for p in authored}
    known_tools = sorted(tool_sigs)
    known_atoms = _known_atoms_from_properties(authored)
    side_effect_tools = sorted(_side_effect_tools(suite_name, set(known_tools)))

    # Match the validated extraction pipeline (run_vocabulary_eval): give the
    # proposer the side-effect vocabulary, tool signatures, and the review pass.
    candidates = propose(
        prompt,
        known_tools=known_tools,
        known_atoms=known_atoms,
        model=model,
        side_effect_tools=side_effect_tools,
        tool_signatures=tool_sigs,
        review=True,
        llm_tools=set(get_llm_tools_for_suite(suite_name)),
    )
    result = check_reality(
        candidates,
        make_resolver(known_tools),
        make_atom_resolver(known_atoms),
        tool_sigs,
    )

    # Restrict to obligation shapes checkable against the control-flow
    # abstraction. `atom_requirement` references selection predicates the state
    # machine never establishes (guaranteed false positive), and `response`'s
    # nested AF has the same per-branch issue. `side_effect_allowlist` is
    # excluded from benign-plan enforcement only: it over-defends when a correct
    # plan uses a helper side effect, while remaining sound under injection.
    _UNCHECKABLE_KINDS = {"response", "atom_requirement", "side_effect_allowlist"}
    shape_dropped = [k for k in result.kept
                     if getattr(k["candidate"], "kind", None) in _UNCHECKABLE_KINDS]
    result.kept = [k for k in result.kept
                   if getattr(k["candidate"], "kind", None) not in _UNCHECKABLE_KINDS]

    if debug:
        print(
            f"    [prompt-ctl] {len(candidates)} proposed -> "
            f"{len(result.kept) + len(shape_dropped)} grounded "
            f"({result.survival_rate:.0%}) -> {len(result.kept)} checkable"
        )
        for dropped in result.dropped:
            print(f"      DROP   {_describe(dropped['candidate'])}")
            print(f"             {dropped['reason']}")
        for sd in shape_dropped:
            print(f"      SHAPE-DROP {_describe(sd['candidate'])}")
            print(f"             uncheckable shape vs control-flow abstraction "
                  f"(encodes task completion; see camel_pass)")

    task_slug = _slug(task_id)
    properties = []
    for i, kept in enumerate(result.kept, 1):
        formula = kept["formula"]
        name = f"prompt_extracted_{task_slug}_{i:02d}"
        description = (
            f"Prompt-extracted obligation for {task_id}: "
            f"{_describe(kept['candidate'])}"
        )
        properties.append(CTLProperty(
            name=name,
            formula=formula,
            description=description,
            severity="medium",
            applicable_user_tasks=[task_id],
            author="prompt_extraction",
            tags=["prompt_extracted"],
        ))
        if debug:
            match = authored_by_formula.get(_norm(formula))
            tag = f"== authored:{match}" if match else "NEW"
            print(f"      KEEP {name}: {formula}  {tag}")

    return properties


def _prepare_prompt_extracted_ctl(
    suite_name: str,
    suite,
    task_ids: list[str],
    model: str,
    debug: bool,
) -> None:
    from camel.ext.ctl_policies import (
        clear_runtime_properties_for_task,
        set_runtime_properties_for_task,
    )

    print(f"\n[prompt-ctl] extracting task-scoped CTL with {model}")
    for task_id in task_ids:
        _PROMPT_EXTRACTED_CTL[(suite_name, task_id)] = []
        clear_runtime_properties_for_task(suite_name, task_id)
        try:
            prompt = _task_prompt(suite.user_tasks[task_id])
            properties = _build_prompt_extracted_ctl(
                suite_name=suite_name,
                task_id=task_id,
                prompt=prompt,
                model=model,
                debug=debug,
            )
        except Exception as exc:
            properties = []
            print(f"  {task_id:30s} prompt_ctl=ERROR {type(exc).__name__}: {exc}")
        _PROMPT_EXTRACTED_CTL[(suite_name, task_id)] = properties
        set_runtime_properties_for_task(
            suite_name,
            task_id,
            properties, # type: ignore
            replace_authored=True,
        )
        print(f"  {task_id:30s} prompt_ctl={len(properties)}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def run(
    model: str,
    suites: list[str],
    logdir: Path,
    user_tasks: list[str] | None,
    force_rerun: bool,
    sleep_between_tasks: int = 0,
    prompt_extracted_ctl: bool = False,
    prompt_extraction_model: str | None = None,
    prompt_extraction_debug: bool = False,
) -> None:
    all_records: list[dict] = []

    for suite_name in suites:
        print(f"\n{'=' * 60}")
        print(f"Suite: {suite_name}")
        print(f"{'=' * 60}")

        suite = get_suite("v1.2", suite_name)
        task_ids = list(suite.user_tasks.keys())
        if user_tasks:
            task_ids = [t for t in task_ids if t in user_tasks]

        if prompt_extracted_ctl:
            _prepare_prompt_extracted_ctl(
                suite_name=suite_name,
                suite=suite,
                task_ids=task_ids,
                model=prompt_extraction_model or model,
                debug=prompt_extraction_debug,
            )

        # --- Config B: CaMeL + CTL + repair (primary run for every task) ---
        print(f"\n[B] CaMeL + CTL + repair (CAMEL_VERIFY=true) …")
        ctl_results: dict[str, bool | str] = {}
        ctl_events_by_task: dict[str, dict] = {}

        for i, task_id in enumerate(task_ids):
            if i > 0 and sleep_between_tasks > 0:
                print(f"  [sleep {sleep_between_tasks}s …]")
                time.sleep(sleep_between_tasks)
            events_before = len(_ctl_events_for_suite(suite_name))
            preferred_policy_names = [
                p.name for p in _PROMPT_EXTRACTED_CTL.get((suite_name, task_id), []) # type: ignore
            ] if prompt_extracted_ctl else None
            r = _run_task(model, suite_name, suite, task_id, True,
                          logdir / "camel_ctl", force_rerun,
                          preferred_policy_names=preferred_policy_names)
            ctl_results[task_id] = r
            print(f"  {task_id:30s} ctl={str(r):5}")

            slice_ = _ctl_events_for_suite(suite_name)[events_before:]
            # Prefer events tagged with this task id; fall back to the
            # positional slice (sequential runs => the slice is this task's).
            tagged = [e for e in slice_ if e.get("user_task_id") == task_id]
            ctl_events_by_task[task_id] = _summarise_events(tagged or slice_)

        # --- Config A: CaMeL only, for every task where CTL intervened ---
        # camel_pass = ctl_pass is only valid when CTL did not touch the plan
        # (no violations on any cycle, no repairs). If CTL intervened, the
        # executed plan differs from what CaMeL-only would produce, so CaMeL-only
        # must run explicitly or a CTL false positive would be hidden.
        needs_config_a = [
            tid for tid in task_ids
            if ctl_results.get(tid) != _TASK_ERROR
            and ctl_events_by_task.get(tid, {}).get("ctl_intervened")
        ]

        camel_results: dict[str, bool | str] = {}
        if needs_config_a:
            print(f"\n[A] CaMeL only for {len(needs_config_a)} task(s) where CTL intervened …")
            for i, task_id in enumerate(needs_config_a):
                if i > 0 and sleep_between_tasks > 0:
                    print(f"  [sleep {sleep_between_tasks}s …]")
                    time.sleep(sleep_between_tasks)
                r = _run_task(model, suite_name, suite, task_id, False,
                              logdir / "camel_only", force_rerun)
                camel_results[task_id] = r
                print(f"  {task_id:30s} camel={str(r):5}")
        else:
            print(f"\n[A] CTL did not intervene on any task — camel_pass safely inferred.")

        # Build records
        print()
        for task_id in task_ids:
            ctl_raw = ctl_results.get(task_id, _TASK_ERROR)
            ev = ctl_events_by_task.get(task_id, {})

            if task_id in camel_results:
                camel_raw = camel_results[task_id]
                camel_run = "separate"
            else:
                camel_raw = ctl_raw
                camel_run = "inferred"

            has_error = camel_raw == _TASK_ERROR or ctl_raw == _TASK_ERROR
            camel_pass = camel_raw is True
            ctl_pass = ctl_raw is True
            ctl_fp = camel_pass and not ctl_pass and not has_error

            if has_error:
                status = "[ERROR]"
            elif ctl_fp:
                status = "[CTL_FP]"
            elif camel_pass == ctl_pass:
                status = "[AGREE]"
            else:
                status = "[DISAGREE]"

            rec = {
                "suite": suite_name,
                "task_id": task_id,
                "camel_pass": camel_raw,
                "ctl_pass": ctl_raw,
                "ctl_fp": ctl_fp,
                "has_error": has_error,
                "repairs": ev.get("repairs", 0),
                "ctl_status": ev.get("status", "unknown"),
                "initial_violations": ev.get("initial_violations", []),
                "camel_run": camel_run,
                "prompt_extracted_ctl": prompt_extracted_ctl,
                "prompt_extracted_count": len(
                    _PROMPT_EXTRACTED_CTL.get((suite_name, task_id), [])
                ),
                "prompt_extracted_properties": [
                    p.name for p in _PROMPT_EXTRACTED_CTL.get((suite_name, task_id), []) # type: ignore
                ],
            }
            all_records.append(rec)
            pctl = (
                f" pctl={rec['prompt_extracted_count']}"
                if prompt_extracted_ctl else ""
            )
            print(
                f"  {task_id:30s} camel={str(camel_raw):5} "
                f"ctl={str(ctl_raw):5} rep={rec['repairs']} "
                f"run={camel_run:8} {status}{pctl}"
            )

    # Write results — latest (overwritten) + timestamped archive
    _RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_RESULTS_FILE, "w") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")
    print(f"\nResults → {_RESULTS_FILE}")

    if not all_records:
        return

    summary = _compute_summary(all_records)
    with open(_SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary → {_SUMMARY_FILE}")
    _print_summary(summary)

    # Archive this run so reruns never overwrite previous results
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_dir = _RUNS_DIR / run_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(_RESULTS_FILE, archive_dir / "results.jsonl")
    shutil.copy(_SUMMARY_FILE, archive_dir / "summary.json")
    if _CTL_LOG.exists():
        shutil.copy(_CTL_LOG, archive_dir / "ctl_events.jsonl")
    print(f"Archived  → {archive_dir}")


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

def _compute_summary(records: list[dict]) -> dict:
    by_suite: dict[str, dict] = {}
    for rec in records:
        s = rec["suite"]
        if s not in by_suite:
            by_suite[s] = {
                "total": 0, "camel_pass": 0, "ctl_pass": 0,
                "ctl_fp": 0, "errors": 0,
                "total_repairs": 0, "tasks_with_repairs": 0,
                "camel_separate_runs": 0,
            }
        d = by_suite[s]
        d["total"] += 1
        d["camel_pass"] += int(rec["camel_pass"] is True)
        d["ctl_pass"] += int(rec["ctl_pass"] is True)
        d["ctl_fp"] += int(rec["ctl_fp"])
        d["errors"] += int(rec["has_error"])
        d["total_repairs"] += rec["repairs"]
        d["tasks_with_repairs"] += int(rec["repairs"] > 0)
        d["camel_separate_runs"] += int(rec.get("camel_run") == "separate")

    overall = {k: 0 for k in by_suite[next(iter(by_suite))]}
    for d in by_suite.values():
        for k in overall:
            overall[k] += d[k]

    def _pct(n, d):
        return round(n / d * 100, 1) if d else 0.0

    for d in list(by_suite.values()) + [overall]:
        n = d["total"]
        d["camel_utility_pct"] = _pct(d["camel_pass"], n)
        d["ctl_utility_pct"] = _pct(d["ctl_pass"], n)
        d["false_positive_pct"] = _pct(d["ctl_fp"], n)
        d["avg_repairs"] = round(d["total_repairs"] / n, 2) if n else 0.0

    return {"per_suite": by_suite, "overall": overall}


def _print_summary(summary: dict) -> None:
    print("\n" + "=" * 80)
    print("TIER 1 SUMMARY — Safety baseline (no injections), single-run methodology")
    print("=" * 80)
    print(f"{'Suite':<12} {'Tasks':>6} {'CaMeL%':>8} {'CTL%':>8} "
          f"{'FP%':>6} {'Err':>4} {'AvgRep':>7} {'SepRuns':>8}")
    print("-" * 80)
    for suite, d in summary["per_suite"].items():
        print(f"{suite:<12} {d['total']:>6} {d['camel_utility_pct']:>8.1f} "
              f"{d['ctl_utility_pct']:>8.1f} {d['false_positive_pct']:>6.1f} "
              f"{d['errors']:>4} {d['avg_repairs']:>7.2f} {d['camel_separate_runs']:>8}")
    print("-" * 80)
    o = summary["overall"]
    print(f"{'OVERALL':<12} {o['total']:>6} {o['camel_utility_pct']:>8.1f} "
          f"{o['ctl_utility_pct']:>8.1f} {o['false_positive_pct']:>6.1f} "
          f"{o['errors']:>4} {o['avg_repairs']:>7.2f} {o['camel_separate_runs']:>8}")
    print("=" * 80)
    print()
    print("CaMeL%   — utility with CaMeL only")
    print("CTL%     — utility with CaMeL + CTL + repair loop")
    print("FP%      — tasks CaMeL passed but CTL permanently blocked")
    print("Err      — tasks that crashed (e.g. CaMeL RecursionError)")
    print("AvgRep   — average CTL repair rounds per task")
    print("SepRuns  — tasks requiring a separate Config A run (CTL intervened)")
    print()
    print("Methodology: single-run. camel_pass = ctl_pass when CTL did not")
    print("intervene (same plan, same execution — zero non-determinism).")
    print("Config A run only for CTL-intervened tasks (see SepRuns column).")

# added sleep in some cases.
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--model", required=True, help="e.g. openai:gpt-4o")
    p.add_argument("--suites", nargs="+",
                   default=["slack", "banking", "travel", "workspace"])
    p.add_argument("--logdir", type=Path, default=_repo / "logs" / "tier1")
    p.add_argument("--user-tasks", nargs="*", default=None)
    p.add_argument("--force-rerun", action="store_true")
    p.add_argument("--sleep", type=int, default=0,
                   help="Seconds to sleep between tasks (use ~30 for Anthropic Tier 1)")
    p.add_argument(
        "--prompt-extracted-ctl",
        action="store_true",
        help=(
            "Verify with prompt-extracted task-scoped CTL only, replacing "
            "authored universal and authored task-scoped CTL for each task"
        ),
    )
    p.add_argument(
        "--prompt-extraction-model",
        default=None,
        help="LLM for prompt extraction; defaults to --model",
    )
    p.add_argument(
        "--prompt-extraction-debug",
        action="store_true",
        help="Print proposed/grounded prompt CTL and authored exact-match tags",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(
        model=args.model,
        suites=args.suites,
        logdir=args.logdir,
        user_tasks=args.user_tasks,
        force_rerun=args.force_rerun,
        sleep_between_tasks=args.sleep,
        prompt_extracted_ctl=args.prompt_extracted_ctl,
        prompt_extraction_model=args.prompt_extraction_model,
        prompt_extraction_debug=args.prompt_extraction_debug,
    )
