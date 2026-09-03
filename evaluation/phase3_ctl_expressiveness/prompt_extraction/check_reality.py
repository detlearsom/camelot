"""Grounding gate for prompt-extracted obligations.

An obligation is kept only when every tool and atom it names belongs to the
suite namespace. Tool matching follows CaMeL's policy convention:
`fnmatch.fnmatch(tool_name, pattern)`.
"""

import fnmatch
from dataclasses import dataclass
from typing import List

from .templates import render


def make_resolver(known_tools):
    """Admit a tool name iff it matches the suite's tool namespace."""
    patterns = list(known_tools)

    def resolve(name: str) -> str:
        n = name.strip()
        for pattern in patterns:
            if fnmatch.fnmatch(n, pattern):
                return n
        raise KeyError(name)

    return resolve


def make_atom_resolver(known_atoms):
    """Admit a CTL atom iff it is in the suite/task atom namespace.

    Negated atoms are represented with a leading !, e.g. !channel_tainted.
    """
    atoms = set(known_atoms or [])

    def resolve_atom(name: str) -> str:
        n = name.strip()
        if n in atoms:
            return n
        raise KeyError(f"unknown atom: {name!r}")

    return resolve_atom


@dataclass
class CheckRealityResult:
    kept: List[dict]      # [{"candidate": ..., "formula": ...}]
    dropped: List[dict]   # [{"candidate": ..., "reason": ...}]

    @property
    def survival_rate(self) -> float:
        total = len(self.kept) + len(self.dropped)
        return len(self.kept) / total if total else 0.0


def check_reality(
    candidates: List[object],
    resolver,
    atom_resolver=None,
    tool_signatures=None,
) -> CheckRealityResult:
    kept, dropped = [], []
    for candidate in candidates:
        try:
            _check_atom_tool_compatibility(candidate, tool_signatures)
            formula = render(candidate, resolver, atom_resolver)
        except KeyError as e:
            dropped.append({
                "candidate": candidate,
                "reason": f"ungrounded symbol: {e.args[0]!r} matches no suite namespace entry",
            })
            continue
        kept.append({"candidate": candidate, "formula": formula})
    return CheckRealityResult(kept=kept, dropped=dropped)


def _check_atom_tool_compatibility(candidate, tool_signatures) -> None:
    """Drop atom requirements whose atoms cannot belong to the chosen tool.

    This is still a deterministic reality check: the LLM may only attach
    channel_* atoms to tools with a channel argument, url_* atoms to tools with
    a url argument, etc. It catches errors such as
    post_webpage -> channel_is_random.
    """
    if not tool_signatures or getattr(candidate, "kind", None) != "atom_requirement":
        return

    tool = candidate.tool
    args = set(tool_signatures.get(tool, []))
    if not args:
        raise KeyError(f"tool {tool!r} has no arguments for atom requirement")

    for atom in candidate.atoms:
        stem = atom.lstrip("!")
        if not any(stem == arg or stem.startswith(f"{arg}_") for arg in args):
            raise KeyError(
                f"atom {atom!r} is incompatible with {tool}({', '.join(sorted(args))})"
            )
