#!/usr/bin/env bash
# Reproduce Experiment 3 (E1 accuracy, E2 ablation, E3 enforcement).
# Run from anywhere; requires .env with API keys at the repo root and nuxmv on PATH.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

MODEL="${MODEL:-anthropic:claude-haiku-4-5-20251001}"

echo "== E1: extraction accuracy =="
uv run --env-file .env python3 -m \
  evaluation.phase3_ctl_expressiveness.prompt_extraction.run_vocabulary_eval \
  --model "$MODEL" --source agentdojo-ground-truth --review \
  --json-out "vocabulary_eval_ground_truth_review_$(echo "${MODEL##*:}" | tr -c 'a-zA-Z0-9' '_').json"

echo "== E2: direct-CTL ablation, one row (see README.md for all models) =="
uv run --env-file .env python3 -m \
  evaluation.phase3_ctl_expressiveness.prompt_extraction.run_direct_ctl_ablation \
  --model "$MODEL" --json-out "direct_ctl_ablation_$(echo "${MODEL##*:}" | tr -c 'a-zA-Z0-9' '_').json"

echo "== E3: controlled enforcement, 20 cases =="
uv run --env-file .env python3 -m \
  evaluation.phase3_ctl_expressiveness.prompt_extraction.run_enforcement_eval \
  --model "$MODEL"

echo "All done. Results in evaluation/phase3_ctl_expressiveness/prompt_extraction/results/"
