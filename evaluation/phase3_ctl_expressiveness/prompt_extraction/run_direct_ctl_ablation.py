"""Experiment 3 / Q2 ablation: let the LLM write CTL *directly*.

This is the ablation that justifies the typed-obligation architecture. Instead of
proposing typed obligations that a deterministic compiler renders to CTL, here the
LLM is given the *same* fixed vocabulary and asked to emit CTL formulas directly.
Each formula is judged by nuXMV as an oracle:

  * malformed  - nuXMV cannot parse the formula (bad CTL syntax / operator nesting).
                 We declare every referenced identifier as a free boolean var, so a
                 parse failure can only be a genuine syntax error, never an
                 undefined symbol.
  * ungrounded - the formula parses but references an atom outside the suite's
                 valid atom namespace (call_<tool>, <tool>_called, provenance
                 atoms). In a verification system this silently breaks the policy.
  * valid      - parses AND every atom is in-vocabulary.

A task policy-suite is *clean* only if all of its formulas are valid; a single bad
atom corrupts the whole suite. Compare against the typed-obligation pipeline, which
is clean by construction because deterministic grounding rejects bad obligations
before any CTL is produced (see run_vocabulary_eval.py, vocab/survival ~= 100%).

Usage:
    uv run --env-file .env python -m \
      evaluation.phase3_ctl_expressiveness.prompt_extraction.run_direct_ctl_ablation \
      --model openai:gpt-4.1-mini \
      --json-out direct_ctl_ablation.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REPO_SRC = _REPO_ROOT / "src"
_RESULTS_DIR = _REPO_ROOT / "evaluation/phase3_ctl_expressiveness/prompt_extraction/results"
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_SRC))

from camel.ext.ctl_policies import (  # noqa: E402
    get_properties_for_suite,
    get_tool_signatures_for_suite,
)

from evaluation.phase3_ctl_expressiveness.prompt_extraction.proposer import (  # noqa: E402
    _call_model,
    _strip_json_fence,
)
from evaluation.phase3_ctl_expressiveness.prompt_extraction.run_extraction import (  # noqa: E402
    _known_atoms_from_properties,
)
from evaluation.phase3_ctl_expressiveness.prompt_extraction.run_vocabulary_eval import (  # noqa: E402
    AGENTDOJO_SUITES,
    _agentdojo_cases,
    _load_dotenv,
)

# CTL operator / reserved tokens that are not atoms.
_CTL_KEYWORDS = {
    "A", "E", "G", "F", "X", "U", "R",
    "AG", "AF", "AX", "EG", "EF", "EX", "AU", "EU",
    "TRUE", "FALSE", "true", "false",
}

# Tool names that exist in the FSM vocabulary but are never modelled as a
# call_/_called atom (the quarantined-LLM helper produces values, not a side
# effect). Keep the namespace identical to what the real compiler would accept.
_NONCALL_TOOLS: frozenset[str] = frozenset()


def _valid_atoms_for_suite(suite: str) -> set[str]:
    """The atom namespace a sound compiler would accept for this suite."""
    tools = set(get_tool_signatures_for_suite(suite))
    atoms: set[str] = {"done"}
    for tool in tools:
        if tool in _NONCALL_TOOLS:
            continue
        atoms.add(f"call_{tool}")
        atoms.add(f"{tool}_called")
    for atom in _known_atoms_from_properties(get_properties_for_suite(suite)):
        atoms.add(atom.lstrip("!"))
    return atoms


def _identifiers(formula: str) -> set[str]:
    """Atom-like identifiers referenced by a formula (operators excluded)."""
    idents = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", formula))
    return {ident for ident in idents if ident not in _CTL_KEYWORDS}


def _direct_ctl_prompt(prompt: str, tools: list[str], atoms: list[str]) -> str:
    tool_list = ", ".join(tools)
    atom_list = ", ".join(atoms) if atoms else "(none)"
    return f"""\
Write Computation Tree Logic (CTL) formulas that capture the temporal requirements
of the user task below. Output ONLY a JSON list of CTL formula strings.

You may use ONLY these atomic propositions:
  - call_<tool>   : true exactly in the state where <tool> is called.
  - <tool>_called : true once <tool> has been called (and stays true).
  where <tool> is EXACTLY one of: [{tool_list}]
  - provenance atoms: [{atom_list}]
Never invent or paraphrase a tool name or atom outside these lists.

CTL operators: AG, AF, EF, EX, AX, EG, A[ p U q ], E[ p U q ], and the boolean
connectives ! & | ->. Every temporal modality (G, F, X, U) MUST be immediately
preceded by a path quantifier (A or E).

The examples below are SHAPE ONLY; their tool names are placeholders - do not copy
them, use the real tools above.
  "the task must perform do_action"          -> "EF(call_do_action)"
  "do_action only after approve happened"     -> "AG(call_do_action -> approve_called)"
  "never call forbidden_action"               -> "AG(!call_forbidden_action)"
  "do_action must not happen until checked"    -> "A[!call_do_action U check_called]"

Emit one formula per requirement the task implies. Output JSON only.

User-task prompt:
{prompt}"""


def _parse_formulas(text: str) -> list[str]:
    """Extract CTL formula strings from the model output, leniently.

    We do NOT want JSON strictness to mask malformed CTL: if the JSON parses we
    take the strings; otherwise we recover any line that looks like a CTL formula
    so that genuinely malformed formulas still reach the nuXMV oracle.
    """
    text = _strip_json_fence(text)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            out = []
            for item in data:
                if isinstance(item, str) and item.strip():
                    out.append(item.strip())
                elif isinstance(item, dict):
                    for key in ("formula", "ctl", "spec"):
                        if isinstance(item.get(key), str):
                            out.append(item[key].strip())
                            break
            return out
    except (json.JSONDecodeError, TypeError):
        pass
    # Fallback: lines that contain a temporal operator.
    op = re.compile(r"\b(AG|AF|EF|EX|AX|EG)\b|A\[|E\[")
    return [line.strip().strip('",') for line in text.splitlines() if op.search(line)]


def _nuxmv_parses(formula: str, nuxmv: str, timeout: int) -> bool:
    """True iff nuXMV can parse a model where `formula` is the CTLSPEC.

    Every referenced identifier is declared as a free boolean var, so the only
    remaining cause of a parse failure is malformed CTL syntax.
    """
    idents = sorted(_identifiers(formula))
    if not idents:
        # No atoms at all (e.g. just "AG()" / garbage) -> declare a dummy and let
        # nuXMV decide; an empty/garbage spec will still fail to parse.
        idents = ["dummy_atom"]
    var_block = "\n".join(f"  {ident} : boolean;" for ident in idents)
    model = f"MODULE main\nVAR\n{var_block}\nCTLSPEC {formula}\n"
    with tempfile.NamedTemporaryFile("w", suffix=".smv", delete=False) as fh:
        fh.write(model)
        path = fh.name
    try:
        result = subprocess.run(
            [nuxmv, path],
            capture_output=True, text=True, timeout=timeout, errors="replace",
        )
    except subprocess.TimeoutExpired:
        return False
    finally:
        Path(path).unlink(missing_ok=True)
    out = result.stdout + result.stderr
    # nuXMV prints a specification verdict iff it parsed and checked the spec.
    if "specification" in out and (" is true" in out or " is false" in out):
        return True
    # Otherwise treat parse/type errors as malformed.
    return False


@dataclass
class FormulaRecord:
    formula: str
    verdict: str  # valid | malformed | ungrounded
    ungrounded_atoms: list[str]


@dataclass
class TaskRecord:
    id: str
    suite: str
    prompt: str
    n_formulas: int
    n_valid: int
    n_malformed: int
    n_ungrounded: int
    clean: bool
    formulas: list[FormulaRecord]
    error: str | None = None


def _classify(formula: str, valid_atoms: set[str], nuxmv: str, timeout: int) -> FormulaRecord:
    ungrounded = sorted(_identifiers(formula) - valid_atoms)
    if not _nuxmv_parses(formula, nuxmv, timeout):
        return FormulaRecord(formula, "malformed", ungrounded)
    if ungrounded:
        return FormulaRecord(formula, "ungrounded", ungrounded)
    return FormulaRecord(formula, "valid", [])


def _run_task(case, model: str, nuxmv: str, timeout: int) -> TaskRecord:
    tools = sorted(get_tool_signatures_for_suite(case.suite))
    valid_atoms = _valid_atoms_for_suite(case.suite)
    atom_list = sorted(a.lstrip("!") for a in
                       _known_atoms_from_properties(get_properties_for_suite(case.suite)))
    try:
        text = _call_model(model, _direct_ctl_prompt(case.prompt, tools, atom_list))
        formulas = _parse_formulas(text)
    except Exception as exc:  # network / model error
        return TaskRecord(case.id, case.suite, case.prompt, 0, 0, 0, 0,
                          clean=False, formulas=[], error=f"{type(exc).__name__}: {exc}")
    records = [_classify(f, valid_atoms, nuxmv, timeout) for f in formulas]
    n_valid = sum(r.verdict == "valid" for r in records)
    n_malformed = sum(r.verdict == "malformed" for r in records)
    n_ungrounded = sum(r.verdict == "ungrounded" for r in records)
    return TaskRecord(
        id=case.id, suite=case.suite, prompt=case.prompt,
        n_formulas=len(records), n_valid=n_valid,
        n_malformed=n_malformed, n_ungrounded=n_ungrounded,
        clean=bool(records) and n_valid == len(records),
        formulas=records,
    )


def _summarise(records: list[TaskRecord]) -> dict:
    def block(rows: list[TaskRecord]) -> dict:
        tasks = len(rows)
        clean = sum(r.clean for r in rows)
        formulas = sum(r.n_formulas for r in rows)
        valid = sum(r.n_valid for r in rows)
        malformed = sum(r.n_malformed for r in rows)
        ungrounded = sum(r.n_ungrounded for r in rows)
        errors = sum(1 for r in rows if r.error)
        return {
            "tasks": tasks,
            "clean_tasks": clean,
            "clean_task_rate": round(clean / tasks, 4) if tasks else None,
            "formulas": formulas,
            "valid_formulas": valid,
            "formula_valid_rate": round(valid / formulas, 4) if formulas else None,
            "malformed_formulas": malformed,
            "malformed_rate": round(malformed / formulas, 4) if formulas else None,
            "ungrounded_formulas": ungrounded,
            "ungrounded_rate": round(ungrounded / formulas, 4) if formulas else None,
            "errors": errors,
        }

    suites = {}
    for suite in sorted({r.suite for r in records}):
        suites[suite] = block([r for r in records if r.suite == suite])
    return {"by_suite": suites, "total": block(records)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="provider:model, e.g. openai:gpt-4.1-mini")
    ap.add_argument("--benchmark-version", default="v1")
    ap.add_argument("--suite", choices=AGENTDOJO_SUITES, default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--nuxmv", default="nuxmv", help="path to the nuXMV binary")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    _load_dotenv()

    cases = list(_agentdojo_cases(args.benchmark_version, use_ground_truth=False))
    if args.suite:
        cases = [c for c in cases if c.suite == args.suite]
    if args.limit is not None:
        cases = cases[:args.limit]

    records: list[TaskRecord] = []
    for i, case in enumerate(cases, 1):
        rec = _run_task(case, args.model, args.nuxmv, args.timeout)
        records.append(rec)
        flag = "CLEAN" if rec.clean else ("ERROR" if rec.error else "DIRTY")
        print(
            f"[{i:02d}/{len(cases):02d}] {flag:5s} {rec.id:18s} "
            f"formulas={rec.n_formulas} valid={rec.n_valid} "
            f"malformed={rec.n_malformed} ungrounded={rec.n_ungrounded}"
            + (f"  {rec.error}" if rec.error else ""),
            flush=True,
        )

    summary = _summarise(records)
    summary["model"] = args.model
    summary["benchmark_version"] = args.benchmark_version
    print("\nSUMMARY")
    print(json.dumps(summary, indent=2))

    if args.json_out:
        out_path = Path(args.json_out)
        if not out_path.is_absolute() and out_path.parent == Path("."):
            out_path = _RESULTS_DIR / out_path
        elif not out_path.is_absolute():
            out_path = Path(__file__).resolve().parent / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(
            {"summary": summary, "records": [asdict(r) for r in records]},
            indent=2,
        ))
        print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
