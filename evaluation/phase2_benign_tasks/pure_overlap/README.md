# Evaluation of Experiment 2 overlap between CaMeL and CaMeL+CTL

## Running:

> Run the whole slack suite with both CaMeL and CaMeL+CTL
```bash
uv run --env-file .env evaluation/phase2_benign_tasks/pure_overlap/run_overlap.py \
--model anthropic:claude-haiku-4-5-20251001 \
--suite slack \
--ctl-suite slack_overlap \
--config both \
--force-rerun \
--max-repairs 0
```

## Results

| Suite | Tasks | Both pass | Both fail | Both block | CaMeLoT only pass | CaMeL only pass | Invalid plan |
|-------|-------|-----------|-----------|------------|-------------------|-----------------|--------------|
| [Banking](runs/20260615_131921) | 16 | 5 | 2 | 6 | 2 | 1 | 0 |
| [Travel](runs/20260615_140609)  | 20 | 9 | 10 | 0 | 1 | 0 | 0 |
| [Slack](runs/20260615_145106)   | 21 | 6 | 5 | 6 | 4 | 0 | 0 |
| [Workspace](runs/20260704_091929) | 40 | 22 | 5 | 5 | 2 | 6 | 0 |
| **Total** | **97** | **42** | **22** | **17** | **9** | **7** | **0** |

- **Both pass** — both configs achieved the task goal.
- **Both fail** — neither a security block nor a code-validity rejection: agent task-failures (`blocked_by=None`), and mixed cases where one side blocked while the other agent-failed.
- **Both block** — both stopped by a genuine security defense (CaMeL secpol / CTL security property such as `recipient_trusted`).
- **CaMeLoT only pass / CaMeL only pass** — exactly one config passed.
- **Invalid plan** — a CTL code-validity rejection: the generated code is invalid (e.g. unsupported `list.append`, undefined schema class such as `RestaurantList`/`URLExtraction`).
