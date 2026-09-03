"""
Utility functions for CaMeL verification and analysis.
"""

import json
import os
import pydantic
from datetime import datetime
from pathlib import Path
from typing import Any, List, Sequence, Tuple

from camel.ext import cast
from camel.ext.state_machine import StateMachineBuilder
from camel.ext.json2nuxmv import NuXMV, NuXMVPrinter


_DEFAULT_CTL_LOG = Path(__file__).parent / "verification_runs" / "ctl_events.jsonl"


def log_ctl_event(
    suite: str,
    query: str,
    initial_violations: List[str],
    repairs: int,
    status: str,
    final_violations: List[str] | None = None,
    log_file: str | Path | None = None,
) -> None:
    """Append one CTL event record to a JSONL log file.

    Each line is a self-contained JSON object so the file can be read
    incrementally and survives partial runs.

    Args:
        suite:              suite name (e.g. 'slack', 'email_agent')
        query:              the user task prompt
        initial_violations: property names violated on the first check
        repairs:            number of repair rounds completed
        status:             'pass'  — verified (0 or more repairs)
                            'fail'  — exhausted repair budget
        final_violations:   property names still violated on 'fail'
        log_file:           path to the JSONL file; defaults to
                            src/camel/ext/verification_runs/ctl_events.jsonl
    """
    path = Path(log_file) if log_file else Path(os.environ.get("CTL_LOG_FILE", str(_DEFAULT_CTL_LOG)))
    path.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "ts": datetime.now().isoformat(),
        "suite": suite,
        "query": (query or "")[:200],
        "initial_violations": initial_violations,
        "repairs": repairs,
        "status": status,
    }
    if status == "fail" and final_violations:
        record["final_violations"] = final_violations

    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


def _serialise_message(msg: Any) -> dict:
    """Convert a ChatMessage (any variant) to a plain dict for JSON output."""
    role = msg.get("role", "unknown") if isinstance(msg, dict) else getattr(msg, "role", "unknown")
    content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)

    if content is None:
        text = ""
    elif isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(block.get("text", repr(block)))
            elif hasattr(block, "text"):
                parts.append(block.text)
            else:
                parts.append(str(block))
        text = "\n".join(parts)
    else:
        text = str(content)

    return {"role": role, "content": text}


def _serialise_tool_call(function: str, args: dict, result: Any) -> dict:
    """Convert a (FunctionCall, result) pair to a plain dict."""
    if isinstance(result, pydantic.BaseModel):
        result_str = result.model_dump_json()
    elif isinstance(result, list) and result and isinstance(result[0], pydantic.BaseModel):
        result_str = json.dumps([r.model_dump(mode="json") for r in result])
    else:
        try:
            result_str = json.dumps(result)
        except TypeError:
            result_str = str(result)

    return {"function": function, "args": args, "result": result_str}


def save_verification_artifacts(
    code: str,
    env: Any,
    allowed_tools: List[str],
    base_dir: str | None = None,
    suite_name: str | None = None,
    query: str | None = None,
    conversation: Sequence[Any] | None = None,
    tool_calls_results: Sequence[Tuple[Any, Any]] | None = None,
) -> str:
    """Save all artifacts for one verified execution to a timestamped directory.

    Directory structure:
        {base_dir}/{suite_name}_{timestamp}/
            code.py                 — final verified P-LLM plan
            ast.json                — abstract syntax tree
            state_machine.json      — FSM used for model checking
            model.xmv               — NuXMV input file
            session.json            — query, full conversation, tool call trace
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    resolved_suite: str = suite_name if suite_name is not None else type(env).__name__.replace("Environment", "").lower()
    resolved_base: str = base_dir if base_dir is not None else os.path.join(os.path.dirname(cast.__file__), "verification_runs")

    verification_dir = os.path.join(resolved_base, f"{resolved_suite}_{timestamp}")
    os.makedirs(verification_dir, exist_ok=True)

    from camel.ext.ctl_policies import get_tool_signatures_for_suite, get_llm_tools_for_suite, get_properties_for_suite

    tool_signatures = get_tool_signatures_for_suite(resolved_suite)
    ast_results = cast.parse_camel_code(code, tool_functions=allowed_tools, tool_signatures=tool_signatures)

    with open(os.path.join(verification_dir, "ast.json"), "w") as f:
        json.dump(ast_results, f, indent=2)

    llm_tools = get_llm_tools_for_suite(resolved_suite)
    state_machine = StateMachineBuilder(ast_results, llm_tools=llm_tools).build_state_machine()

    with open(os.path.join(verification_dir, "state_machine.json"), "w") as f:
        json.dump(state_machine, f, indent=2)

    try:
        ctl_properties = get_properties_for_suite(resolved_suite)
    except ValueError:
        ctl_properties = []

    xmv_filename = os.path.join(verification_dir, "model.xmv")
    NuXMVPrinter(NuXMV(state_machine=state_machine), xmv_filename, ctl_properties=ctl_properties)

    with open(os.path.join(verification_dir, "code.py"), "w") as f:
        f.write(code)

    session: dict = {
        "query": query,
        "outcome": "success",
        "conversation": [_serialise_message(m) for m in conversation] if conversation else [],
        "tool_calls": [
            _serialise_tool_call(tc.function, tc.args, result)
            for tc, result in tool_calls_results
        ] if tool_calls_results else [],
    }
    with open(os.path.join(verification_dir, "session.json"), "w") as f:
        json.dump(session, f, indent=2)

    print(f"Saved verification artifacts to: {verification_dir}/")
    return verification_dir
