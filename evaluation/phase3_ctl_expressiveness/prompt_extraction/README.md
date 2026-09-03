# Evaluation of Experiment 3 extracting temporal properties from prompts

The user prompt is turned into typed obligations by an LLM, which trusted code
then grounds and compiles into CTL. Evaluated three ways: E1 extraction
accuracy, E2 an ablation against asking models to write CTL directly, and E3
enforcement of the extracted formulae against fixed plans.

Needs `nuxmv` on `PATH` and a `.env` at the repo root with `ANTHROPIC_API_KEY`
(plus `OPENAI_API_KEY` to rerun the GPT rows of E2).

## Running:

> E1 — extraction accuracy over all 97 AgentDojo user tasks
```bash
uv run --env-file .env python3 -m \
evaluation.phase3_ctl_expressiveness.prompt_extraction.run_vocabulary_eval \
--model anthropic:claude-haiku-4-5-20251001 \
--source agentdojo-ground-truth \
--review \
--json-out vocabulary_eval_ground_truth_review_claude_haiku45.json
```

> E2 — direct-CTL ablation, one run per model row
```bash
uv run --env-file .env python3 -m \
evaluation.phase3_ctl_expressiveness.prompt_extraction.run_direct_ctl_ablation \
--model anthropic:claude-haiku-4-5-20251001 \
--json-out direct_ctl_ablation_claude_haiku45.json
```

Repeat with `--model anthropic:claude-sonnet-4-5|openai:gpt-4.1-mini|openai:gpt-4.1-nano`

> E3 — controlled enforcement, 20 cases. Exits non-zero if any case fails
```bash
uv run --env-file .env python3 -m \
evaluation.phase3_ctl_expressiveness.prompt_extraction.run_enforcement_eval \
--model anthropic:claude-haiku-4-5-20251001
```

`./run.sh` runs E1, E3, and the Haiku row of E2 in one go.

## Results

The runs reported in the paper are committed under [`results/`](results), all
with `anthropic:claude-haiku-4-5-20251001`. Extraction uses an LLM at
provider-default temperature, so E1 percentages can shift by a point or two
between runs.

### E1 — extraction accuracy

From [`results/vocabulary_eval_ground_truth_review_claude_haiku45.json`](results/vocabulary_eval_ground_truth_review_claude_haiku45.json)
— totals under `summary`, the per-suite rows under `summary.suite_results[]`.

| Suite | Tasks | Exact | Faithful | F1 | Vocab. | Surv. |
|-------|-------|-------|----------|------|--------|-------|
| Banking | 16 | 75.0% | 75.0% | 0.79 | 100% | 100% |
| Slack | 21 | 85.7% | 85.7% | 0.88 | 100% | 100% |
| Travel | 20 | 95.0% | 100.0% | 0.91 | 100% | 100% |
| Workspace | 40 | 90.0% | 95.0% | 0.87 | 100% | 100% |
| **Total** | **97** | **87.6%** | **90.7%** | **0.86** | **100%** | **100%** |

- **Exact** — the extracted required side-effect set matches the task's ground-truth side-effecting tools exactly (`exact_required_action_accuracy`).
- **Faithful** — exact, plus credit for correctly conditional side effects, where the prompt gates an action on a condition and a single label cannot distinguish "always do X" from "do X only if the condition holds" (`faithful_accuracy`, not `required_or_conditional_coverage`).
- **Vocab.** — proposed obligations that are in the tool/atom vocabulary.
- **Surv.** — proposed obligations that survive grounding into CTL.

### E2 — direct CTL generation vs the typed pipeline

One file per model row, each under `summary.total`:
[nano](results/direct_ctl_ablation_gpt41nano_rerun.json),
[mini](results/direct_ctl_ablation_gpt41mini.json),
[haiku](results/direct_ctl_ablation_claude_haiku45.json),
[sonnet](results/direct_ctl_ablation_claude_sonnet45.json).
The typed-pipeline row reuses E1's obligation counts.

| Method | Clean tasks | Valid outputs | Malformed | Ungrounded |
|--------|-------------|---------------|-----------|------------|
| Direct CTL, GPT-4.1 nano | 12/97 | 182/655 | 54 | 419 |
| Direct CTL, GPT-4.1 mini | 79/97 | 574/612 | 16 | 22 |
| Direct CTL, Claude Haiku 4.5 | 96/97 | 493/494 | 0 | 1 |
| Direct CTL, Claude Sonnet 4.5 | 94/97 | 551/554 | 2 | 1 |
| **Typed pipeline (Haiku)** | **97/97** | **182/182** | **0** | **0** |

- **Clean tasks** — every proposed formula is syntactically valid and every identifier is grounded in the vocabulary.
- **Malformed / Ungrounded** — formulae nuXmv rejects, and formulae naming a tool or atom that does not exist.

### E3 — enforcement against fixed plans

From [`results/enforcement_eval.json`](results/enforcement_eval.json) — totals at
the top level, per-case detail under `rows`.

20 controlled cases: 12 grounded in AgentDojo tasks (3 per suite) and 8 from the
SOC workflow. Each has one correct and one violating plan, both fixed by hand so
the measurement isolates extraction and enforcement from planner variability.

| | Cases |
|---|---|
| Violating plans blocked by the extracted CTL | 20/20 |
| Correct plans verified | 20/20 |
| Verdicts matching equivalent hand-written CTL | 20/20 |
