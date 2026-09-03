"""
CTL security policies for CaMeL.

This module provides CTL (Computation Tree Logic) properties for verifying
temporal security properties of agent plans. These policies run in parallel
with the standard CaMeL security policies.
"""

from dataclasses import dataclass, field
from types import ModuleType
from typing import List, Dict, Optional, Tuple


@dataclass
class CTLProperty:
    """A CTL property with metadata.

    applicable_user_tasks scopes the property to a subset of user tasks (matched
    by user_task ID, e.g. "user_task_13"). When None (default), the property is
    universal. 
    """
    name: str
    formula: str
    description: str
    severity: Optional[str] = None  # "critical", "high", "medium", "low"
    applicable_user_tasks: Optional[List[str]] = None
    id: Optional[str] = None
    status: str = "experimental"
    author: Optional[str] = None
    date: Optional[str] = None
    level: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = self.level or "medium"
        if self.level is None:
            self.level = self.severity


# Registry of all CTL policies by suite.
# Each registered module defines (at module level):
#   - TOOL_SIGNATURES:        Dict[str, List[str]]
#   - <SUITE>_CTL_PROPERTIES: List[CTLProperty]
#   - GENERIC_PROPERTIES:     List[CTLProperty]
#   - LLM_TOOLS (optional):   Set[str]
CTL_POLICY_REGISTRY: Dict[str, ModuleType] = {}
RUNTIME_PROPERTIES_BY_TASK: Dict[Tuple[str, str], List[CTLProperty]] = {}
RUNTIME_REPLACE_AUTHORED: set[Tuple[str, str]] = set()


def register_policy_module(suite_name: str, module: ModuleType):
    """Register a CTL policy module for a given suite"""
    CTL_POLICY_REGISTRY[suite_name] = module


def set_runtime_properties_for_task(
    suite_name: str,
    user_task_id: str,
    properties: List[CTLProperty],
    replace_authored: bool = False,
) -> None:
    """Install extra task-scoped CTL properties for the current process.
    """
    key = (suite_name, user_task_id)
    RUNTIME_PROPERTIES_BY_TASK[key] = list(properties)
    if replace_authored:
        RUNTIME_REPLACE_AUTHORED.add(key)
    else:
        RUNTIME_REPLACE_AUTHORED.discard(key)


def clear_runtime_properties_for_task(suite_name: str, user_task_id: str) -> None:
    """Remove process-local extra properties for one task."""
    key = (suite_name, user_task_id)
    RUNTIME_PROPERTIES_BY_TASK.pop(key, None)
    RUNTIME_REPLACE_AUTHORED.discard(key)


def get_properties_for_suite(
    suite_name: str,
    include_generic: bool = True,
    user_task_id: Optional[str] = None,
) -> List[CTLProperty]:
    """Return CTL properties for a suite, optionally filtered by user_task_id.

    A property is included when its applicable_user_tasks is None (universal)
    or when user_task_id is in applicable_user_tasks. When user_task_id is
    None, all scoped properties are included as well.
    """
    if suite_name not in CTL_POLICY_REGISTRY:
        raise ValueError(
            f"No CTL policy module registered for suite '{suite_name}'. "
            f"Registered suites: {sorted(CTL_POLICY_REGISTRY.keys())}"
        )

    module = CTL_POLICY_REGISTRY[suite_name]
    properties = getattr(module, f"{suite_name.upper()}_CTL_PROPERTIES", [])

    if include_generic:
        generic_props = getattr(module, "GENERIC_PROPERTIES", [])
        properties = properties + generic_props

    if user_task_id is not None:
        # Eval-time path: include universal properties + properties scoped to this task.
        if (suite_name, user_task_id) in RUNTIME_REPLACE_AUTHORED:
            properties = []
        else:
            properties = [
                p for p in properties
                if p.applicable_user_tasks is None or user_task_id in p.applicable_user_tasks
            ]
    else:
        properties = [p for p in properties if p.applicable_user_tasks is None]

    if user_task_id is not None:
        properties = properties + RUNTIME_PROPERTIES_BY_TASK.get(
            (suite_name, user_task_id),
            [],
        )

    deduped: List[CTLProperty] = []
    seen = set()
    for prop in properties:
        key = (prop.name, prop.formula)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(prop)

    return deduped
    
def get_tool_signatures_for_suite(suite_name: str) -> Dict[str, List[str]]:
    """Get tool signatures for a given suite"""
    if suite_name in CTL_POLICY_REGISTRY:
        module = CTL_POLICY_REGISTRY[suite_name]
        return getattr(module, "TOOL_SIGNATURES", {})
    return {}


def get_llm_tools_for_suite(suite_name: str) -> set:
    """Get the set of LLM tools (always qllm provenance) for a given suite."""
    if suite_name in CTL_POLICY_REGISTRY:
        module = CTL_POLICY_REGISTRY[suite_name]
        return getattr(module, "LLM_TOOLS", set())
    return set()


def get_read_only_tools_for_suite(suite_name: str) -> set:
    """Get the set of read-only tools (always untrusted provenance) for a given suite."""
    if suite_name in CTL_POLICY_REGISTRY:
        module = CTL_POLICY_REGISTRY[suite_name]
        return getattr(module, "READ_ONLY_TOOLS", set())
    return set()


def get_trusted_read_tools_for_suite(suite_name: str) -> set:
    """Get the set of read-only tools whose outputs are always trusted for a given suite."""
    if suite_name in CTL_POLICY_REGISTRY:
        module = CTL_POLICY_REGISTRY[suite_name]
        return getattr(module, "TRUSTED_READ_TOOLS", set())
    return set()

def get_side_effect_tools_for_suite(suite_name: str) -> set:
    """Get the suite's externally visible side-effect tools, when declared."""
    if suite_name in CTL_POLICY_REGISTRY:
        module = CTL_POLICY_REGISTRY[suite_name]
        return getattr(module, "SIDE_EFFECT_TOOLS", set())
    return set()


# Import all policy modules to register them
try:
    from . import slack
except ImportError:
    pass

try:
    from . import email_agent
except ImportError:
    pass

try:
    from . import banking
except ImportError:
    pass

try:
    from . import travel
except ImportError:
    pass

try:
    from . import workspace
except ImportError:
    pass

try:
    from . import soc
except ImportError:
    pass

try:
    from . import healthcare
except ImportError:
    pass


try:
    from . import toy
except ImportError:
    pass
