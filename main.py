# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
from pathlib import Path

import cyclopts
from agentdojo import attacks, benchmark, logging
from agentdojo.task_suite import get_suite
from openai.types.chat import ChatCompletionReasoningEffort

import camel.custom_yaml  # noqa
from camel.interpreter.interpreter import MetadataEvalMode
from camel.models import make_tools_pipeline


def _print_suite_table(
    suite_name: str,
    pipeline_name: str,
    results: "benchmark.SuiteResults",
    run_attack: bool,
) -> None:
    """Print a per-task results table and CTL stats after a suite run."""
    from rich import box
    from rich.console import Console
    from rich.table import Table

    console = Console()
    utility_results = results["utility_results"]

    if not run_attack:
        table = Table(
            title=f"[bold]{suite_name}[/bold]  ·  {pipeline_name}  ·  utility",
            box=box.SIMPLE_HEAVY,
            show_lines=False,
        )
        table.add_column("Task", style="dim")
        table.add_column("Utility", justify="center", width=8)

        n_pass = 0
        for (task_id, _), ok in sorted(utility_results.items()):
            table.add_row(task_id, "[green]PASS[/green]" if ok else "[red]FAIL[/red]")
            n_pass += ok
        n_total = len(utility_results)
        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{n_pass}/{n_total}  ({n_pass / n_total * 100:.0f}%)[/bold]",
        )
        console.print()
        console.print(table)
        return

    # Attack run: per-injection-task security / utility breakdown
    security_results = results["security_results"]
    it_ids = sorted({it for (_, it) in security_results.keys() if it})

    table = Table(
        title=f"[bold]{suite_name}[/bold]  ·  {pipeline_name}  ·  with injections",
        box=box.SIMPLE_HEAVY,
        show_lines=True,
    )
    table.add_column("Metric", style="bold", width=16)
    table.add_column("Overall", justify="center", width=9)
    for it_id in it_ids:
        table.add_column(it_id.replace("injection_task_", "IT"), justify="center", width=9)

    def _rate(d: dict, it: str | None = None) -> float:
        vals = [v for (_, iid), v in d.items() if it is None or iid == it]
        return (sum(vals) / len(vals) * 100) if vals else 0.0

    def _colour(r: float) -> str:
        return "green" if r >= 95 else "red" if r <= 5 else "yellow"

    sec_overall = _rate(security_results)
    util_overall = _rate(utility_results)

    sec_cells = [f"[bold]{sec_overall:.0f}%[/bold]"]
    for it in it_ids:
        r = _rate(security_results, it)
        sec_cells.append(f"[{_colour(r)}]{r:.0f}%[/{_colour(r)}]")

    util_cells = [f"[bold]{util_overall:.0f}%[/bold]"]
    for it in it_ids:
        util_cells.append(f"{_rate(utility_results, it):.0f}%")

    table.add_row("Security rate", *sec_cells)
    table.add_row("Utility rate", *util_cells)
    console.print()
    console.print(table)

    # CTL stats from ctl_events.jsonl (if it exists)
    _default_ctl_log = (
        Path(__file__).parent / "src" / "camel" / "ext" / "verification_runs" / "ctl_events.jsonl"
    )
    ctl_log = Path(os.environ.get("CTL_LOG_FILE", str(_default_ctl_log)))
    if not ctl_log.exists():
        return

    events = []
    for line in ctl_log.read_text().splitlines():
        try:
            ev = json.loads(line)
            if ev.get("suite") == suite_name:
                events.append(ev)
        except (json.JSONDecodeError, KeyError):
            pass

    if not events:
        return

    n = len(events)
    n_ok = sum(1 for e in events if e["status"] == "pass")
    n_fail = n - n_ok
    avg_repairs = sum(e["repairs"] for e in events) / n
    n_repaired = sum(1 for e in events if e["repairs"] > 0 and e["status"] == "pass")
    all_viols: list[str] = []
    for e in events:
        all_viols.extend(e.get("initial_violations", []))
    top_viols = sorted(set(all_viols), key=lambda v: -all_viols.count(v))[:3]

    ctl_table = Table(
        title="CTL Verification Stats",
        box=box.SIMPLE_HEAVY,
        show_header=False,
        padding=(0, 2),
    )
    ctl_table.add_column("Key", style="bold cyan")
    ctl_table.add_column("Value")
    ctl_table.add_row("Total events", str(n))
    ctl_table.add_row("Pass / Fail", f"[green]{n_ok}[/green] / [red]{n_fail}[/red]")
    ctl_table.add_row("Avg repairs/plan", f"{avg_repairs:.2f}")
    ctl_table.add_row("Repaired → pass", str(n_repaired))
    if top_viols:
        ctl_table.add_row("Top violations", ", ".join(top_viols))
    console.print(ctl_table)


def main(
    model: str,
    use_original: bool = False,
    reasoning_effort: ChatCompletionReasoningEffort = "medium",
    thinking_budget_tokens: int | None = None,
    ad_defense: str | None = None,
    run_attack: bool = False,
    replay_with_policies: bool = False,
    suites: list[str] | None = None,
    eval_mode: MetadataEvalMode = MetadataEvalMode.NORMAL,
    q_llm: str | None = None,
    user_tasks: list[str] | None = None,
    injection_tasks: list[str] | None = None,
    force_rerun: bool = False,
):
    """Example usage of the defense.


    Other newer models might work as well.

    Args:
        model: the model to use. it should be {provider}:model_name. For example, "google:gemini-2.5-pro-preview-06-05".
        use_original: whether to use the original model with tool calling API instead of CaMeL
        reasoning_effort: for OpenAI reasoning models. How much the model should reason. Can be "low", "medium", "high".
        thinking_budget_tokens: how many tokens Anthropic reasoning models can use. Note that Anthropic reasoning models are not supported yet.
        ad_defense: whether to use a defense from AgentDojo and which one. It must be used in conjunction with `--use-original`.
            Tested defenses are "tool_filter", "repeat_user_prompt", "spotlight_with_delimiting"
        run_attack: whether to run the attack (it uses AgentDojo's `important_instructions` attack)
        replay_with_policies: replay the run with the given model enforcing security policies. Note that the equivalent run (with same model and attack config)
            should have already been run.
        suites: which suites to run AgentDojo on (can be a list from `["workspace", "banking", "travel", "slack"]`)
        eval_mode: which eval mode to use when propagating dependencies.
        q_llm: what model to use as a quarantined llm. If None, the same as `model` is used.
        user_tasks: subset of user tasks to run. If None, all user tasks are run.
        injection_tasks: subset of injection tasks to run (e.g. injection_task_1 injection_task_2). If None, all are run.
    """

    attack_name = "important_instructions"

    suites = suites or ["workspace", "banking", "travel", "slack"]
    total_utility_results = []
    total_security_results = []
    logdir = Path("./logs")
    for suite_name in suites:
        tools_pipeline = make_tools_pipeline(
            model,  # type: ignore
            use_original,
            replay_with_policies,
            attack_name,
            reasoning_effort,
            thinking_budget_tokens,
            suite_name,
            ad_defense,
            eval_mode,
            q_llm,  # type: ignore
        )
        suite = get_suite("v1.2", suite_name)
        attack = attacks.load_attack(attack_name, suite, tools_pipeline)
        with logging.OutputLogger(str(logdir)):
            if run_attack:
                results = benchmark.benchmark_suite_with_injections(
                    tools_pipeline,
                    suite,
                    attack,
                    logdir,
                    force_rerun=force_rerun,
                    user_tasks=user_tasks,
                    injection_tasks=injection_tasks,
                )
            else:
                results = benchmark.benchmark_suite_without_injections(
                    tools_pipeline, suite, logdir, force_rerun=force_rerun, user_tasks=user_tasks
                )

        utility_results = results["utility_results"]
        total_utility_results += utility_results.values()
        if run_attack:
            security_results = results["security_results"]
            total_security_results += security_results.values()

        _print_suite_table(suite_name, tools_pipeline.name or model, results, run_attack)

    from rich.console import Console
    from rich import box
    from rich.table import Table

    console = Console()
    summary = Table(title="Overall Results", box=box.SIMPLE_HEAVY, show_lines=False)
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", justify="right")
    u = sum(total_utility_results) / len(total_utility_results) * 100
    summary.add_row("Utility", f"{u:.1f}%")
    if run_attack:
        s = sum(total_security_results) / len(total_security_results) * 100
        summary.add_row("Security", f"{s:.1f}%")
    console.print()
    console.print(summary)


if __name__ == "__main__":
    cyclopts.run(main)
