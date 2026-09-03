"""Deterministic CTL templates for prompt-extracted obligations.

The LLM proposes typed obligations, but it never writes CTL. 

"""

from dataclasses import dataclass
from typing import List, Literal


@dataclass
class Existence:
    """The plan must be able to reach the required action.

    CTL: EF(call_action)  -- reachability, not AF. The over-approximating
    control-flow abstraction makes AF (all paths) false-positive on correct
    plans that guard/loop the action; EF still catches do-nothing / wrong-action
    plans (no path reaches the call) without flagging guarded/looped ones.
    """
    action: str
    kind: Literal["existence"] = "existence"


@dataclass
class AllPathsExistence:
    """The action must occur on every possible plan path.

    CTL: AF(call_action). Use sparingly: normal prompt task liveness is rendered
    as EF to avoid false positives on over-approximated branches. This stronger
    shape is for explicit workflow policies such as "on every path, always
    eventually do X".
    """
    action: str
    kind: Literal["all_paths_existence"] = "all_paths_existence"


@dataclass
class Precedence:
    """action may not occur until prerequisite has occurred.

    variant="until"   -> prerequisite must also eventually happen.
    variant="history" -> if action occurs, prerequisite must
                          have happened earlier

    CTL history: AG(call_action -> prerequisite_called)
    CTL until:   A[!call_action U prerequisite_called]
    """
    gated_action: str
    prerequisite: str
    variant: Literal["until", "history"] = "history"
    kind: Literal["precedence"] = "precedence"


@dataclass
class Until:
    """gated_action is forbidden until prerequisite has occurred.

    CTL: A[!call_gated_action U prerequisite_called]
    """
    gated_action: str
    prerequisite: str
    kind: Literal["until"] = "until"


@dataclass
class Response:
    """After trigger, some target in `targets` must eventually occur.

    CTL: AG(call_trigger -> AF(call_target_1 | ... | call_target_n))
    """
    trigger: str
    targets: List[str]
    kind: Literal["response"] = "response"


@dataclass
class Enables:
    """After trigger, some target in `targets` must remain reachable.

    CTL: AG(call_trigger -> EF(call_target_1 | ... | call_target_n))
    """
    trigger: str
    targets: List[str]
    kind: Literal["enables"] = "enables"


@dataclass
class AbsenceAfter:
    """After after_action, none of `forbidden` may ever occur.

    CTL: AG(call_after_action -> AG !(call_forbidden_1 | ... | call_forbidden_n))
    """
    after_action: str
    forbidden: List[str]
    kind: Literal["absence_after"] = "absence_after"


@dataclass
class NextStepForbidden:
    """Immediately after after_action, the forbidden actions may not occur.

    CTL: AG(call_after_action -> AX(!(call_forbidden_1 | ... | call_forbidden_n)))
    """
    after_action: str
    forbidden: List[str]
    kind: Literal["next_step_forbidden"] = "next_step_forbidden"


@dataclass
class SideEffectAllowlist:
    """Only the listed side-effect tools may occur in the plan.

    CTL: AG(!(call_forbidden_1 | ... | call_forbidden_n))
    """
    allowed: List[str]
    side_effects: List[str]
    kind: Literal["side_effect_allowlist"] = "side_effect_allowlist"


@dataclass
class AtomRequirement:
    """When tool is called, each CTL atom in `atoms` must hold.

    This covers prompt requirements about arguments, selected objects, and
    source constraints, but only when those requirements can be grounded to
    existing suite atoms.

    CTL: AG(call_tool -> (atom_1 & ... & atom_n))
    """
    tool: str
    atoms: List[str]
    kind: Literal["atom_requirement"] = "atom_requirement"


Obligation = object


def _call(t: str) -> str:
    return f"call_{t}"


def _hist(t: str) -> str:
    return f"{t}_called"


def render(obligation, resolve, resolve_atom=None) -> str:
    """Render an obligation to CTL, using `resolve(phrase) -> tool_name`.

    Raises KeyError if any referenced tool or atom is not grounded. The caller
    converts that failure into a dropped obligation.
    """
    kind = obligation.kind

    if kind == "existence":
        # Existence: EF(call_action) -- "the plan can reach a state that calls
        # the action," i.e. the required action is reachable on some path.
        # We use EF, not AF, on purpose: against the over-approximating
        # control-flow abstraction, AF (all paths) raises false positives for
        # correct plans that wrap the action in a loop or conditional (the
        # abstraction explores a branch/zero-iteration path with no call). EF
        # still rejects a do-nothing or wrong-action plan (no path reaches the
        # call) -- the suppression we want to catch -- without flagging guarded
        # or looped correct plans.
        t = resolve(obligation.action)
        return f"EF({_call(t)})"

    if kind == "all_paths_existence":
        # Strong all-path liveness: AF(call_action).
        t = resolve(obligation.action)
        return f"AF({_call(t)})"

    if kind == "precedence":
        # Precedence/history: AG(call_gated_action -> prerequisite_called)
        # Precedence/until:   A[!call_gated_action U prerequisite_called]
        g = resolve(obligation.gated_action)
        p = resolve(obligation.prerequisite)
        if obligation.variant == "until":
            return f"A[!{_call(g)} U {_hist(p)}]"
        return f"AG({_call(g)} -> {_hist(p)})"

    if kind == "until":
        # Until: A[!call_gated_action U prerequisite_called]
        g = resolve(obligation.gated_action)
        p = resolve(obligation.prerequisite)
        return f"A[!{_call(g)} U {_hist(p)}]"

    if kind == "response":
        # Response: AG(call_trigger -> AF(call_target_1 | ... | call_target_n))
        trig = resolve(obligation.trigger)
        ts = [resolve(x) for x in obligation.targets]
        disj = " | ".join(_call(t) for t in ts)
        return f"AG({_call(trig)} -> AF({disj}))"

    if kind == "enables":
        # Enables: AG(call_trigger -> EF(call_target_1 | ... | call_target_n))
        trig = resolve(obligation.trigger)
        ts = [resolve(x) for x in obligation.targets]
        disj = " | ".join(_call(t) for t in ts)
        return f"AG({_call(trig)} -> EF({disj}))"

    if kind == "absence_after":
        # Absence-after: AG(call_after_action -> AG !(call_forbidden_1 | ...))
        a = resolve(obligation.after_action)
        fs = [resolve(x) for x in obligation.forbidden]
        disj = " | ".join(_call(t) for t in fs)
        return f"AG({_call(a)} -> AG !({disj}))"

    if kind == "next_step_forbidden":
        # Next-step forbidden: AG(call_after_action -> AX(!(call_forbidden_1 | ...)))
        a = resolve(obligation.after_action)
        fs = [resolve(x) for x in obligation.forbidden]
        disj = " | ".join(_call(t) for t in fs)
        return f"AG({_call(a)} -> AX(!({disj})))"

    if kind == "side_effect_allowlist":
        # Side-effect allowlist: AG(!(call_forbidden_1 | ... | call_forbidden_n))
        allowed = {resolve(x) for x in obligation.allowed}
        side_effects = {resolve(x) for x in obligation.side_effects}
        forbidden = sorted(side_effects - allowed)
        if not forbidden:
            return "AG(TRUE)"
        disj = " | ".join(_call(t) for t in forbidden)
        return f"AG(!({disj}))"

    if kind == "atom_requirement":
        # Atom requirement: AG(call_tool -> (atom_1 & ... & atom_n))
        t = resolve(obligation.tool)
        if resolve_atom is None:
            raise KeyError("atom resolver unavailable")
        atoms = [resolve_atom(x) for x in obligation.atoms]
        conj = " & ".join(atoms)
        return f"AG({_call(t)} -> ({conj}))"

    raise ValueError(f"unknown obligation kind: {kind!r}")
