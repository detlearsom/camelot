# Prompt Extraction Results

Canonical result artifacts behind the paper's Experiment 3 tables
(see [`../README.md`](../README.md) for the commands and the reported numbers).

- `vocabulary_eval_ground_truth_review_claude_haiku45.json`: E1, paper table
  "Prompt-extraction accuracy and trust-boundary metrics (E1)".
- `direct_ctl_ablation_*.json`: E2, one file per model row of the paper table
  "Direct CTL generation compared with the typed pipeline (E2)".
- `enforcement_eval.json`: E3, 20 cases, paper table "Extracted CTL enforced
  against fixed correct and violating plans (E3)".

All of the above are the `anthropic:claude-haiku-4-5-20251001` runs reported
in the paper, except the three non-Haiku E2 rows, which name their model in
the filename and in `summary.model`.
