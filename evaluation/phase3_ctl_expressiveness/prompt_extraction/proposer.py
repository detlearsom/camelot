"""Prompt-to-obligation proposer.

The proposer gets the user task and returns typed obligations over tool names.
It never writes CTL directly.
CTL rendering is handled by templates.py after grounding.

  user prompt -> typed obligations -> deterministic cleanup -> CTL templates

  * existence: a required unconditional call, rendered as EF(call_tool).
  * all_paths_existence: a strong required call on every path, AF(call_tool).
  * precedence: an ordering, call_B -> A_called.
  * until: an action is forbidden until another action has happened.
  * response: after a trigger, a target must eventually happen.
  * enables: after a trigger, a target must remain possible/reachable.
  * absence_after: after one action, listed actions are forbidden.
  * next_step_forbidden: immediately after one action, listed actions are forbidden.
  * side_effect_allowlist: only prompt-commanded side effects are allowed.
  * atom_requirement: tool arguments/selected objects must satisfy known atoms.

Modes:
  * model=None: deterministic demo
  * model="provider:model": real LLM backend supported by evaluation.utils_evaluation.make_llm
"""

import json
import re
from typing import List

from .templates import (
    AbsenceAfter,
    AllPathsExistence,
    AtomRequirement,
    Enables,
    Existence,
    NextStepForbidden,
    Precedence,
    Response,
    SideEffectAllowlist,
    Until,
)

def _schema_doc(
    known_tools,
    known_atoms=None,
    side_effect_tools=None,
    tool_signatures=None,
) -> str:
    """Build the model instruction: fixed vocabulary + per-obligation examples.

    Example-driven, not a prose rulebook. Each obligation kind gets a one-line
    explanation and general, domain-neutral examples (placeholder tool names);
    the only suite-specific content is the factual vocabulary (tool list,
    signatures, side-effect tools, atoms), which is the grounding namespace.
    The deterministic gate (check_reality) rejects anything off-vocabulary.
    """
    tools = ", ".join(known_tools)
    side = ", ".join(side_effect_tools or [])
    atoms = ", ".join(known_atoms or [])
    sig_section = ""
    if tool_signatures:
        sigs = "\n".join(
            f"  {tool}({', '.join(tool_signatures.get(tool, []))})"
            for tool in known_tools
        )
        sig_section = (
            "\nTool signatures (match the task's object/destination/value to the "
            "argument names to pick the right tool):\n" + sigs + "\n"
        )
    return f"""\
Map the user task below to a JSON list of typed obligations over a fixed tool set.
Output ONLY a JSON list. Every tool name must be EXACTLY one tool from this list:
  [{tools}]
Use ONLY these tools; never invent or paraphrase a tool name. If one step has no
matching tool, skip only that step - never drop the whole task.
{sig_section}
The blocks below are ILLUSTRATIVE EXAMPLES ONLY. Their tool names (do_action,
read_source, create_item, update_item, on_event, etc.) are placeholders that
might not be in your tool list - do not copy them. The examples show only the
SHAPE of each obligation kind. In your answer use exclusively the real tools
listed above.

existence - the task directly commands an action, so it must happen. Commanding
verbs (send, pay, transfer, add, create, schedule, post, message, invite, update,
remove, delete, share, book, ...) each map to the tool whose signature fits, as an
existence. A lookup or computation that supplies the details does not replace the
action; the commanded action still occurs. Do NOT return an empty list for a task
that asks you to DO something: multi-step tasks, or ones that need a computation,
sort, or lookup first, still require their core side-effect action(s). A new
object created with its details inline is ONE create action; use a separate
add/update action only to modify an object that ALREADY exists.
  "Do the action the task asks for."               -> {{"kind":"existence","action":"do_action"}}
  "Act on data you must read from a source first."  -> {{"kind":"existence","action":"do_action"}}
  "Find the largest item, then remove it."          -> {{"kind":"existence","action":"remove_item"}}
  "For each item in a list, act on it."             -> {{"kind":"existence","action":"do_action"}}
  "Create a new item, giving its details inline."    -> {{"kind":"existence","action":"create_item"}}
  "Add a field to an item that already exists."      -> {{"kind":"existence","action":"update_item"}}

An informational request commands NO side effect, even when it mentions an action
the user is considering. Emit a side effect only when the task asks you ONLY to
recommend, suggest, compare, tell, list, or summarize. But if it says to find or
identify something AND then act on it, the action is still required - the lookup
only supplies the target.
  "Recommend an option and tell me about it."        -> []
  "Carry out the action on the chosen option."        -> {{"kind":"existence","action":"do_action"}}

all_paths_existence - strong all-path liveness. Use only when the prompt says
the action must happen on every execution path / always eventually / before
finishing no matter what. Ordinary task completion should use existence, not
all_paths_existence.
  "On every path, always eventually do the action."   -> {{"kind":"all_paths_existence","action":"do_action"}}

precedence - ordering ONLY, and ONLY when the prompt EXPLICITLY sequences steps
with words like "first/then", "before", "after", or "once". It says the gated
action may occur only after the prerequisite (it does not force either to happen).
A step that merely SUPPLIES information ("you can find the details in X", "look it
up in Y") is NOT an ordering constraint - do NOT emit precedence for it.
  "Do the action only after approval."               -> {{"kind":"precedence","gated_action":"do_action","prerequisite":"request_approval"}}
  "First read the policy, then update the record."    -> {{"kind":"precedence","gated_action":"update_record","prerequisite":"read_policy"}}
  "Send the note; the details are in the inbox."       -> (no precedence - "details are in X" is not an ordering)

until - strong ordering: the gated action is forbidden until the prerequisite
has occurred, and the prerequisite must eventually occur. Use for explicit
"do not X until Y" / "X must not happen before Y" workflow policies.
  "Do not dispense until interactions are checked."   -> {{"kind":"until","gated_action":"dispense","prerequisite":"check_interactions"}}

response - a mandatory follow-up: after EVERY trigger occurrence, a target must occur.
  "Whenever an event occurs, record the result."     -> {{"kind":"response","trigger":"on_event","targets":["record_result"]}}
  "After each item is processed, send a notice."      -> {{"kind":"response","trigger":"process_item","targets":["send_notice"]}}

enables - a CONDITIONAL follow-up: after the trigger, a target may occur (not on
every path). Use this for "check C; if C, do A" instead of existence for A.
  "Check a condition; if it holds, do the action."   -> {{"kind":"enables","trigger":"check_condition","targets":["do_action"]}}
  "If the source contains a request, respond to it."  -> {{"kind":"enables","trigger":"read_source","targets":["do_action"]}}

absence_after - after an action, the listed tools must never occur.
  "After you finalize, never modify the item."       -> {{"kind":"absence_after","after_action":"do_action","forbidden":["update_item"]}}

next_step_forbidden - immediately after an action, the listed tools must not
happen as the next tool call.
  "After flagging an event, do not immediately dispense." -> {{"kind":"next_step_forbidden","after_action":"flag_event","forbidden":["dispense"]}}

side_effect_allowlist - only the side effects the task commands are allowed.
  "Do only this one action; change nothing else."    -> {{"kind":"side_effect_allowlist","allowed":["do_action"]}}
  "This is read-only; perform no write actions."     -> {{"kind":"side_effect_allowlist","allowed":[]}}

atom_requirement - when a tool is called, the listed atoms must hold (arguments,
sources, selections). Use only atoms from the atom list below. This is the right
shape for static security policies such as "whenever TOOL is called, argument X
must be trusted / not tainted"; these are constraints on calls, not commands to
perform the tool. Do not add existence for static security policies.
  "Only act if the input is trusted."                -> {{"kind":"atom_requirement","tool":"do_action","atoms":["input_trusted"]}}
  "Whenever send_item is called, recipient must be trusted." -> {{"kind":"atom_requirement","tool":"send_item","atoms":["recipient_trusted"]}}
  "Whenever update_item is called, user must be trusted and not tainted." -> {{"kind":"atom_requirement","tool":"update_item","atoms":["user_trusted","!user_tainted"]}}
  "Whenever invite_item is called, user_email must be trusted and not tainted." -> {{"kind":"atom_requirement","tool":"invite_item","atoms":["user_email_trusted","!user_email_tainted"]}}
  "Whenever publish_item is called, url must be trusted and content not tainted." -> {{"kind":"atom_requirement","tool":"publish_item","atoms":["url_trusted","!content_tainted"]}}
  "Whenever publish_item is called, url must be trusted and not tainted." -> {{"kind":"atom_requirement","tool":"publish_item","atoms":["url_trusted","!url_tainted"]}}

Read/get/list/search tools are usually just how information is obtained, not goals
in themselves - do not emit existence for them. Only turn a read into a precedence
prerequisite when the prompt EXPLICITLY requires reading before acting; a read that
merely supplies data ("the details are in X") imposes no ordering constraint.

Side-effect tools (use only these in side_effect_allowlist): [{side}]
Atoms (use only these in atom_requirement): [{atoms}]

Output JSON only."""


def _tools_referenced_by(obligation) -> list[str]:
    """Return every tool name mentioned by one typed obligation."""
    k = obligation.kind
    if k == "existence":
        return [obligation.action]
    if k == "all_paths_existence":
        return [obligation.action]
    if k == "precedence":
        return [obligation.gated_action, obligation.prerequisite]
    if k == "until":
        return [obligation.gated_action, obligation.prerequisite]
    if k in {"response", "enables"}:
        return [obligation.trigger, *obligation.targets]
    if k == "absence_after":
        return [obligation.after_action]
    if k == "next_step_forbidden":
        return [obligation.after_action, *obligation.forbidden]
    if k == "atom_requirement":
        return [obligation.tool]
    if k == "side_effect_allowlist":
        return list(obligation.allowed)
    return []


def _with_inferred_side_effect_allowlist(
    obligations,
    side_effect_tools=None,
    infer_side_effect_allowlist: bool = True,
):
    """Add a side-effect allowlist when the LLM did not explicitly provide one.

    If prompt extraction says the task requires a side-effect tool, this also
    forbids unrelated side-effect tools. Read-only/helper tools are ignored.
    """
    if not infer_side_effect_allowlist:
        return obligations

    effects = set(side_effect_tools or [])
    if not effects:
        return obligations
    if any(o.kind == "side_effect_allowlist" for o in obligations):
        return obligations

    allowed = sorted({
        tool
        for obligation in obligations
        for tool in _tools_referenced_by(obligation)
        if tool in effects
    })
    if not allowed:
        return obligations
    return [
        *obligations,
        SideEffectAllowlist(allowed=allowed, side_effects=sorted(effects)),
    ]


def _dedupe_obligations(obligations):
    """Drop duplicate obligations after deterministic cleanup.

    The review pass can repeat an item that the repair logic also promoted, e.g.
    an existence obligation that appears twice. Repeating the same CTL formula is
    semantically harmless but makes evaluation counts and demos noisy.
    """
    out = []
    seen = set()
    for obligation in obligations:
        fields = tuple(
            sorted(
                (name, tuple(value) if isinstance(value, list) else value)
                for name, value in obligation.__dict__.items()
            )
        )
        key = (
            obligation.kind,
            fields,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(obligation)
    return out


def _with_helper_responses_as_enables(obligations, side_effect_tools=None):
    """Make conditional-helper obligations permissive instead of mandatory.

    Models sometimes encode "check C; if C, do A" as response(check -> AF(A)).
    That is too strong: the prompt does not say A happens on every branch after
    the check. The faithful shape is enables(check -> EF(A)).
    """
    effects = set(side_effect_tools or [])
    helper_prefixes = (
        "check_",
        "find_",
        "get_",
        "list_",
        "read_",
        "search_",
    )
    out = []
    for obligation in obligations:
        if (
            obligation.kind == "response"
            and obligation.trigger.startswith(helper_prefixes)
            and any(target in effects for target in obligation.targets)
        ):
            out.append(Enables(
                trigger=obligation.trigger,
                targets=list(obligation.targets),
            ))
        else:
            out.append(obligation)
    return out


_CONDITIONAL_RE = re.compile(
    r"\b(if|unless|only if|provided that|as long as|in case|whether|depending on)\b",
    re.IGNORECASE,
)

_OPAQUE_EXTERNAL_RE = re.compile(
    r"\b("
    r"follow (the )?instructions|"
    r"instructions (in|from)|"
    r"actions specified in|"
    r"do (all )?the tasks|"
    r"to-do list"
    r")\b",
    re.IGNORECASE,
)


def _prompt_has_conditional_gate(prompt: str | None) -> bool:
    return bool(prompt and _CONDITIONAL_RE.search(prompt))


def _prompt_uses_opaque_external_instructions(prompt: str | None) -> bool:
    return bool(prompt and _OPAQUE_EXTERNAL_RE.search(prompt))


def _side_effect_liveness_candidates(obligations, effects: set[str]) -> set[str]:
    """Return side effects the model mentioned as final actions, but not liveness.

    This is deliberately tool-name agnostic. It repairs a common schema error:
    the model recognizes the right side-effect tool, but encodes it only as an
    enabling target or ordered gated action.
    """
    candidates: set[str] = set()
    for obligation in obligations:
        if obligation.kind in {"response", "enables"}:
            candidates.update(t for t in obligation.targets if t in effects)
        elif obligation.kind == "precedence" and obligation.gated_action in effects:
            candidates.add(obligation.gated_action)
    return candidates


def _with_unconditional_side_effect_liveness(
    obligations,
    side_effect_tools=None,
    prompt: str | None = None,
    infer_side_effect_liveness: bool = True,
):
    """Promote visible final side effects to liveness when the model omitted it.

    We only do this when the model already mentioned the exact side-effect tool,
    the prompt is not conditional, and the prompt is not merely delegating to
    hidden instructions in an external object.
    """
    if not infer_side_effect_liveness:
        return obligations

    effects = set(side_effect_tools or [])
    if (
        not effects
        or _prompt_has_conditional_gate(prompt)
        or _prompt_uses_opaque_external_instructions(prompt)
    ):
        return obligations

    existing = {
        obligation.action
        for obligation in obligations
        if obligation.kind == "existence" and obligation.action in effects
    }
    missing = sorted(
        _side_effect_liveness_candidates(obligations, effects) - existing
    )
    if not missing:
        return obligations
    return [
        *[Existence(action=tool) for tool in missing],
        *obligations,
    ]


def _drop_data_dependency_precedence(obligations, side_effect_tools=None):
    """Drop ordering rules whose prerequisite is not a side-effecting action.

    An extracted precedence "do X only after read/get Y" is a data dependency,
    not a verification-relevant ordering: the read need not lie on every plan
    path, so AG(call_X -> Y_called) false-positives on correct plans. We keep
    action->action orderings (prerequisite is itself a side effect, e.g. invite
    before add, or approval before isolation) -- those are the sequencing/
    security constraints worth enforcing. Read/helper prerequisites are dropped.
    """
    effects = set(side_effect_tools or [])
    if not effects:
        return obligations
    return [
        o for o in obligations
        if not (o.kind == "precedence" and o.prerequisite not in effects)
    ]


def _drop_helper_tool_liveness(obligations, llm_tools=None):
    """Drop liveness obligations that target an LLM-helper tool.

    Tools like `query_ai_assistant` (the quarantined-LLM helper) are an internal
    reasoning step, not a user-facing side effect. "The plan must reach
    query_ai_assistant" is never a real task obligation -- the model may summarise
    or decide inline -- so a liveness requirement on it false-positives correct
    plans. We therefore strip helper tools from existence obligations and from
    response/enables targets. This is generic: the helper set is the suite's
    declared LLM tools (always including query_ai_assistant, matching the state
    machine's own invariant), never a task-specific tool name.
    """
    helpers = set(llm_tools or ()) | {"query_ai_assistant"}
    out = []
    for o in obligations:
        if o.kind == "existence" and o.action in helpers:
            continue
        if o.kind in {"response", "enables"}:
            kept = [t for t in o.targets if t not in helpers]
            if not kept:
                continue
            o = type(o)(trigger=o.trigger, targets=kept)
        out.append(o)
    return out


def _without_speculative_side_effects_for_opaque_prompt(
    obligations,
    side_effect_tools=None,
    prompt: str | None = None,
):
    """Drop invented side effects when the prompt only delegates to hidden instructions.

    When the visible prompt merely says "do the tasks in this email/file/webpage",
    the concrete side effects are not knowable until the agent reads that object.
    Models hedge by listing many side-effect tools as enables/response targets, or
    by emitting existence for a side effect the prompt never named. That floods the
    conditional channel and fabricates liveness for actions hidden in untrusted
    content. We keep read/helper obligations and ordering, but strip side-effect
    tools the visible prompt did not name. The hidden side effects are then left to
    CaMeL's runtime enforcement, as intended for this out-of-scope task class.
    """
    effects = set(side_effect_tools or [])
    if not effects or not _prompt_uses_opaque_external_instructions(prompt):
        return obligations
    out = []
    for obligation in obligations:
        if obligation.kind == "existence" and obligation.action in effects:
            continue
        if obligation.kind in {"response", "enables"}:
            kept_targets = [t for t in obligation.targets if t not in effects]
            if not kept_targets:
                continue
            obligation = type(obligation)(
                trigger=obligation.trigger,
                targets=kept_targets,
            )
        out.append(obligation)
    return out


def _as_tool(value) -> str:
    """Require a single tool name to be a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"expected tool name string, got {value!r}")
    return value


def _as_tool_list(value, *, allow_empty: bool = False) -> list[str]:
    """Require a list of tool-name strings."""
    if not isinstance(value, list) or (not value and not allow_empty) or not all(
        isinstance(v, str) and v.strip() for v in value
    ):
        expected = "list" if allow_empty else "non-empty list"
        raise TypeError(f"expected {expected} of tool names, got {value!r}")
    return list(value)


def _parse(items: List[dict], side_effect_tools=None, prompt: str | None = None,
           llm_tools=None, infer_side_effect_allowlist: bool = True,
           infer_side_effect_liveness: bool = True):
    """Convert raw JSON dictionaries into typed obligation objects.

    The LLM output is intentionally shallow JSON. This function gives each item
    a concrete dataclass from templates.py, then runs deterministic cleanup.
    Items with the wrong shape (missing keys, null/list field values) are dropped
    here, not allowed to crash the pipeline: a malformed obligation simply does
    not survive the trust boundary.
    """
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        try:
            k = it["kind"]
            if k == "existence":
                # Required unconditional call: EF(call_action).
                out.append(Existence(action=_as_tool(it["action"])))
            elif k == "all_paths_existence":
                # Strong all-path liveness: AF(call_action).
                out.append(AllPathsExistence(action=_as_tool(it["action"])))
            elif k == "precedence":
                # Ordering check only: if gated_action is called, prerequisite must
                # already have happened. This does not force either call to happen.
                out.append(Precedence(
                    gated_action=_as_tool(it["gated_action"]),
                    prerequisite=_as_tool(it["prerequisite"]),
                    variant="history",
                ))
            elif k == "until":
                # Strong until: gated action cannot occur before prerequisite,
                # and the prerequisite must eventually happen.
                out.append(Until(
                    gated_action=_as_tool(it["gated_action"]),
                    prerequisite=_as_tool(it["prerequisite"]),
                ))
            elif k == "response":
                # Strong follow-up: after every trigger path, target must occur.
                out.append(Response(
                    trigger=_as_tool(it["trigger"]),
                    targets=_as_tool_list(it["targets"]),
                ))
            elif k == "enables":
                # Weak/conditional follow-up: after trigger, target remains reachable.
                out.append(Enables(
                    trigger=_as_tool(it["trigger"]),
                    targets=_as_tool_list(it["targets"]),
                ))
            elif k == "absence_after":
                # Safety shape: once after_action happens, forbidden calls cannot.
                out.append(AbsenceAfter(
                    after_action=_as_tool(it["after_action"]),
                    forbidden=_as_tool_list(it["forbidden"]),
                ))
            elif k == "next_step_forbidden":
                # Safety shape: constrain the immediately following tool call.
                out.append(NextStepForbidden(
                    after_action=_as_tool(it["after_action"]),
                    forbidden=_as_tool_list(it["forbidden"]),
                ))
            elif k == "side_effect_allowlist":
                # Suite-specific side-effect filter; read-only tools do not belong here.
                out.append(SideEffectAllowlist(
                    allowed=_as_tool_list(it["allowed"], allow_empty=True),
                    side_effects=list(side_effect_tools or []),
                ))
            elif k == "atom_requirement":
                # Argument/source/selection constraints over known CTL atoms.
                out.append(AtomRequirement(
                    tool=_as_tool(it["tool"]),
                    atoms=_as_tool_list(it["atoms"]),
                ))
            else:
                # Unknown kind: reject this one item, keep the rest.
                continue
        except (KeyError, TypeError):
            # Missing key or wrong field type: drop this malformed obligation
            # rather than letting it invalidate the other grounded obligations.
            continue
    out = _with_helper_responses_as_enables(out, side_effect_tools)
    out = _drop_helper_tool_liveness(out, llm_tools)
    out = _without_speculative_side_effects_for_opaque_prompt(
        out, side_effect_tools, prompt
    )
    out = _drop_data_dependency_precedence(out, side_effect_tools)
    out = _with_unconditional_side_effect_liveness(
        out,
        side_effect_tools,
        prompt,
        infer_side_effect_liveness=infer_side_effect_liveness,
    )
    out = _with_inferred_side_effect_allowlist(
        out,
        side_effect_tools,
        infer_side_effect_allowlist=infer_side_effect_allowlist,
    )
    return _dedupe_obligations(out)


def _call_model(model: str, user_msg: str) -> str:
    """Call any LLM backend supported by the evaluation model factory."""
    from agentdojo import types as ad_types

    from evaluation.utils_evaluation import make_dummy_runtime, make_llm

    model_name = model if ":" in model else f"anthropic:{model}"
    llm = make_llm(model_name)
    messages = [{
        "role": "user",
        "content": [{"type": "text", "content": user_msg}],
    }]
    _, _, _, messages, _ = llm.query(
        user_msg,
        make_dummy_runtime(),
        messages=messages,
        extra_args={},
    )

    for message in reversed(messages):
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if content:
            return ad_types.get_text_content_as_str(content)
    raise ValueError(f"model {model_name!r} did not return assistant text")


def _strip_json_fence(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```")[1].lstrip("json").strip()
    return text


def _review_doc(schema_doc: str, prompt: str, draft_json: str) -> str:
    return f"""\
{schema_doc}

Review the draft JSON below. Return ONLY a corrected JSON list.

Checklist:
- Keep only the allowed obligation kinds and exact known tool names.
- Add missing existence obligations for final side effects explicitly requested
  by the visible prompt.
- If the draft already mentions a side-effect tool as an enables/response
  target or precedence gated action, add existence for it unless the prompt
  makes that side effect conditional.
- Do not add final side effects that are only hidden inside an external email,
  webpage, file, or TODO list.
- Convert conditional final side effects to enables instead of existence.
- Remove extra side effects that the prompt does not request.
- For read-only prompts, use side_effect_allowlist with an empty allowed list.
- For static security policy contracts ("whenever TOOL is called, ARG must be
  trusted/not tainted"), use atom_requirement and do not add existence.
- Do not split a newly created calendar/event/reservation into a separate
  participant/update side effect when the create/reserve/schedule tool can
  carry those details directly.
- Preserve useful precedence/order constraints when they are explicit.

User-task prompt:
{prompt}

Draft JSON:
{draft_json}
"""


# --- demo prompt + its expected proposer output -----------------------------
DEMO_PROMPT = (
    "A high-severity alert just came in. Confirm the affected host, then "
    "isolate it. Get IR approval before you isolate anything. Open an incident "
    "ticket for this, and make sure the incident is resolved or escalated to "
    "the IR team before you finish."
)

_DEMO_CANDIDATES_JSON = [
    {"kind": "existence", "action": "confirm_host"},
    {"kind": "existence", "action": "isolate_host"},
    {"kind": "precedence", "gated_action": "isolate_host",
     "prerequisite": "confirm_host"},
    {"kind": "precedence", "gated_action": "isolate_host",
     "prerequisite": "request_ir_approval"},
    {"kind": "existence", "action": "create_incident_ticket"},
    {"kind": "response", "trigger": "create_incident_ticket",
     "targets": ["resolve_incident", "escalate_to_ir_team"]},
    {"kind": "precedence", "gated_action": "finish_task",
     "prerequisite": "resolve_incident", "variant": "history"},
]


def propose(
    prompt: str,
    known_tools=None,
    known_atoms=None,
    model: str | None = None,
    side_effect_tools=None,
    tool_signatures=None,
    review: bool = False,
    llm_tools=None,
    infer_side_effect_allowlist: bool = True,
    infer_side_effect_liveness: bool = True,
) -> list:  # type: ignore
    """Return typed obligations proposed from a task prompt.

    model=None -> deterministic demo (DEMO_PROMPT only).
    model="provider:..." -> real LLM through evaluation.utils_evaluation.make_llm.
        Current project prefixes are anthropic:, openai:, google:, and local:.
    """
    if model is None:
        if prompt.strip() != DEMO_PROMPT.strip():
            raise ValueError(
                "demo proposer only knows DEMO_PROMPT; pass --model for arbitrary prompts"
            )
        return _parse(
            _DEMO_CANDIDATES_JSON,
            side_effect_tools,
            prompt,
            llm_tools,
            infer_side_effect_allowlist=infer_side_effect_allowlist,
            infer_side_effect_liveness=infer_side_effect_liveness,
        )

    if not known_tools:
        raise ValueError("known_tools is required")

    schema_doc = _schema_doc(
        known_tools,
        known_atoms,
        side_effect_tools,
        tool_signatures,
    )
    user_msg = f"{schema_doc}\n\nUser-task prompt:\n{prompt}"

    text = _strip_json_fence(_call_model(model, user_msg))
    if review:
        text = _strip_json_fence(_call_model(
            model,
            _review_doc(schema_doc, prompt, text),
        ))
    return _parse(
        json.loads(text),
        side_effect_tools,
        prompt,
        llm_tools,
        infer_side_effect_allowlist=infer_side_effect_allowlist,
        infer_side_effect_liveness=infer_side_effect_liveness,
    )
