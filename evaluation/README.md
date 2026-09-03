# Evaluation

Everything needed to reproduce the results reported in the CaMeLoT paper.

## Prerequisites

1. `uv` — see the [installation instructions](https://docs.astral.sh/uv/getting-started/installation/).
2. A `.env` file at the repo root with your API keys (copy `.env.example`). Only needed
   for the phases that call an LLM
3. **`nuxmv` on your `PATH`** — the model checker used by every verification step.
   Download it from [nuxmv.fbk.eu](https://nuxmv.fbk.eu/download.html).

All commands below are run from the repository root.

## Layout

| Phase | Directory | What it evaluates | Paper |
|-------|-----------|-------------------|-------|
| 0 | [`phase0_unit_testing/`](phase0_unit_testing) | Unit tests over each layer of the CTL pipeline | — |
| 1 | [`phase1_translation/`](phase1_translation) | Translating CaMeL's AgentDojo policies into CTL, and where the two disagree | §5 (translation tables) |
| 2 | [`phase2_benign_tasks/`](phase2_benign_tasks) | Overlap between CaMeL and CaMeLoT detection capability on benign AgentDojo tasks | Experiment 5.1 |
| 3 | [`phase3_ctl_expressiveness/`](phase3_ctl_expressiveness) | Property classes CTL can express and a runtime monitor cannot, plus extracting those properties from the user prompt | Experiments 5.2 and 5.3 |

Shared helpers live in [`utils_evaluation.py`](utils_evaluation.py) (model construction,
pipeline setup) and are imported by the runner scripts.

---

## Phase 0 — Unit testing

Validates each stage of the pipeline (`cast.py` → `state_machine.py` → `json2nuxmv.py` →
`nuxmv_runner.py` → `verification_integration.py`) in isolation, plus the full
verification path on small synthetic examples.

```bash
uv run pytest -q tests/test_ctl
```

## Phase 1 — CaMeL → CTL translation

A manual, per-policy audit: for every CaMeL security policy in the four AgentDojo suites (Slack, banking, travel, workspace), we attempt to write the equivalent CTL formula and record how faithfully it captures the original. There is nothing to run here;
the results are the tables in the phase README and the per-suite notes.

- [`README.md`](phase1_translation/README.md) — the overlap tables (side-effecting policies and read-only output taint)
- [`slack.md`](phase1_translation/slack.md), [`banking.md`](phase1_translation/banking.md), [`travel.md`](phase1_translation/travel.md), [`workspace.md`](phase1_translation/workspace.md) — per-suite, per-policy translations
- [`gaps.md`](phase1_translation/gaps.md) — cross-suite findings: what CaMeL expresses that CTL cannot, and vice versa
- [`bugs.md`](phase1_translation/bugs.md) — issues in the original CaMeL policies found while translating

## Phase 2 — Benign task overlap (Experiment 5.1)

Runs each AgentDojo suite twice — once under pure CaMeL and
once under CaMeLoT — and classifies every task by how
the two configurations agree. The point is to show CaMeLoT blocks what CaMeL blocks without breaking tasks CaMeL lets through.

```bash
uv run --env-file .env evaluation/phase2_benign_tasks/pure_overlap/run_overlap.py \
  --model anthropic:claude-haiku-4-5-20251001 \
  --suite workspace  \
  --config both \
  --force-rerun \
  --max-repairs 0
```

Repeat with `--suite banking|travel|slack`


## Phase 3 — CTL expressiveness (Experiment 5.2)

### Part 1 — Coverage matrix

34 synthetic plans (8 Slack, 14 SOC, 12 healthcare) hand-written to exercise property
classes beyond simple taint sinks: global safety, forbidden effects, liveness (`AF`),
ordering (`AG`+past), until (`AU`), triggered liveness (`AG→AF`) and next-step (`AX`). The paper only presents the results from the SOC usecase.

```bash
# CaMeLoT: CTL model checking of all 34 plans
uv run --env-file .env python \
  evaluation/phase3_ctl_expressiveness/coverage_matrix/run_coverage_matrix_CaMeLoT.py 
```

```bash
# CaMeL baseline: the same plans through CaMeL's interpreter + SOC security policy engine
uv run --env-file .env python \
  evaluation/phase3_ctl_expressiveness/coverage_matrix/run_coverage_matrix_CaMeL.py
```

The plan definitions and the CTL properties they target are documented in the module
docstrings of [`plans.py`](phase3_ctl_expressiveness/coverage_matrix/plans.py),
[`plans_soc.py`](phase3_ctl_expressiveness/coverage_matrix/plans_soc.py) and
[`plans_healthcare.py`](phase3_ctl_expressiveness/coverage_matrix/plans_healthcare.py).

### Part 2 — Query → plan → dual verification

Closes the loop with a real LLM: a user query is turned into a CaMeL plan, which is then verified both ways (CTL model checking and CaMeL's runtime policy engine).

```bash
uv run --env-file .env python \
  evaluation/phase3_ctl_expressiveness/coverage_matrix/run_query_to_plan_dual_verify.py
```

### Part 3 — Prompt extraction (Experiment 5.3)

Parts 1 and 2 assume the CTL properties are already written. This part asks where they
come from: an LLM turns the user prompt into typed obligations, and trusted code grounds
and compiles them into CTL. The LLM never writes CTL itself.

Three sub-evaluations live in
[`prompt_extraction/`](phase3_ctl_expressiveness/prompt_extraction): **E1** extraction
accuracy over the 97 AgentDojo user tasks, **E2** an ablation against asking models to
write CTL directly, and **E3** enforcement of the extracted formulae against 20 fixed
plan pairs.

```bash
evaluation/phase3_ctl_expressiveness/prompt_extraction/run.sh
```

Commands for individual runs, the paper's tables and the committed result files are in
[`prompt_extraction/README.md`](phase3_ctl_expressiveness/prompt_extraction/README.md).

Optionally,
[`pipeline_extraction_optional/`](phase3_ctl_expressiveness/pipeline_extraction_optional)
runs the same extraction inside the live CaMeL pipeline instead of offline.

---

For the design of the verification pipeline these experiments exercise, see the
[CaMeLoT README](../src/camel/ext/README.md).
