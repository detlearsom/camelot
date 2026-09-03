import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass


@dataclass
class State:
    state_id: str
    state_type: str  # INIT, TOOL_CALL, LOOP_ENTRY, LOOP_BODY, LOOP_EXIT, CONDITIONAL, DONE
    metadata: Dict

    provenance: Dict[str, str] | None = None
    tainted_vars: Set[str] | None = None

    def __post_init__(self):
        if self.provenance is None:
            self.provenance = {}
        if self.tainted_vars is None:
            self.tainted_vars = set()


@dataclass
class Transition:
    from_state: str
    to_state: str
    guard: str  # Condition for transition
    effect: List[str]  # State variable updates


class StateMachineBuilder:
    def __init__(
        self,
        parsed_result: Dict,
        llm_tools: Set[str] | None = None,
        nonempty_tools: Set[str] | None = None,
        read_only_tools: Set[str] | None = None,
        trusted_read_tools: Set[str] | None = None,
    ):
        self.parsed_result = parsed_result
        self.states: List[State] = []
        self.transitions: List[Transition] = []
        self.state_counter = 0

        # Tools whose outputs are always "qllm" (quarantined LLM), regardless of inputs.
        # query_ai_assistant is always included, allowing suites to add more (e.g. llm_extract_field).
        self.llm_tools: Set[str] = {"query_ai_assistant"} | (llm_tools or set())

        # Tools whose outputs are always "untrusted" (environment-sourced data).
        # Suite-specific read-only tools are merged with the built-in defaults below.
        self._suite_read_only_tools: Set[str] = read_only_tools or set()

        # Tools whose outputs are stamped "trusted" regardless of input args.
        # Mirrors CaMeL's TrustedToolSource / User-sourced capability for read-only
        # tools that cannot carry prompt injections (e.g. get_iban, get_balance,
        # get_user_info in banking).
        self._trusted_read_tools: Set[str] = trusted_read_tools or set()

        self.provenance_map: Dict[str, str] = {}
        self.tainted_vars: Set[str] = set()

        # Variables known to hold non-empty collections.
        self.nonempty_vars: Set[str] = set()

        # Add initial and done states
        self.init_state = self.create_state("INITIAL", "INITIAL", {})
        self.done_state = self.create_state("DONE", "DONE", {})

    def create_state(
        self,
        state_id: str,
        state_type: str,
        metadata: Dict,
        provenance: Dict[str, str] | None = None,
        tainted_vars: Set[str] | None = None,
    ) -> State:
        state = State(state_id, state_type, metadata, provenance, tainted_vars)
        self.states.append(state)
        return state

    def create_state_id(self, prefix: str) -> str:
        state_id = f"{prefix}_{self.state_counter}"
        self.state_counter += 1
        return state_id

    def add_transition(self, from_state: str, to_state: str, guard: str = "true", effect: Optional[List[str]] = None):
        if effect is None:
            effect = []
        transition = Transition(from_state, to_state, guard, effect)
        self.transitions.append(transition)

    def build_from_regions(self) -> Tuple[List[State], List[Transition]]:
        regions = self.parsed_result["regions"]

        if not regions:
            # Empty program
            self.add_transition(self.init_state.state_id, self.done_state.state_id)
            return self.states, self.transitions

        # Process regions sequentially
        prev_state = self.init_state.state_id

        for region in regions:
            region_type = region["region_type"]

            if region_type == "tool_call":
                state = self.process_tool_call(region, prev_state)
                prev_state = state.state_id

            elif region_type == "assignment":
                state = self.process_assignment(region, prev_state)
                prev_state = state.state_id

            elif region_type == "loop":
                exit_state = self.process_loop(region, prev_state)
                prev_state = exit_state.state_id

            elif region_type == "conditional":
                merge_state = self.process_conditional(region, prev_state)
                prev_state = merge_state.state_id

        # Connect final region to DONE
        self.add_transition(prev_state, self.done_state.state_id)

        return self.states, self.transitions

    def process_tool_call(self, region: Dict, prev_state: str) -> State:
        tool_name = region["metadata"]["tool_name"]
        targets = region["metadata"]["targets"]
        arguments = region["metadata"]["arguments"]
        arg_variables = region["metadata"].get("arg_variables", None)  # NEW: Get var tracking

        state_id = self.create_state_id(f"CALL_{tool_name}")

        if tool_name in self.llm_tools:
            for target in targets:
                self.provenance_map[target] = "qllm"
                self.tainted_vars.add(target)
        elif tool_name in self._trusted_read_tools:
            for target in targets:
                self.provenance_map[target] = "trusted"
        elif self._is_read_tool(tool_name):
            for target in targets:
                self.provenance_map[target] = "untrusted"
                self.tainted_vars.add(target)
        else:
            input_provenance = self._get_max_provenance(self._extract_arg_variables(arguments))
            for target in targets:
                self.provenance_map[target] = input_provenance
                if input_provenance in {"untrusted", "qllm"}:
                    self.tainted_vars.add(target)

        state = self.create_state(
            state_id,
            "TOOL_CALL",
            {
                "tool": tool_name,
                "region_id": region["region_id"],
                "targets": region["metadata"]["targets"],
                "arguments": region["metadata"]["arguments"],
                "arg_provenance": self._get_argument_provenance(arguments, arg_variables),  # UPDATED
            },
            provenance=dict(self.provenance_map),
            tainted_vars=set(self.tainted_vars),
        )

        # Add transition from previous state
        effects = [f"{target}_defined = true" for target in targets]
        effects.append(f"{tool_name}_called = true")

        # Track provenance of output variables
        for target in targets:
            prov = self.provenance_map.get(target, "trusted")
            if prov in {"untrusted","qllm"}:
                effects.append(f"{target}_tainted = true")
            else:
                effects.append(f"{target}_trusted = true")
            # qllm: schema-constrained, but content is attacker-influenced.

        # Track provenance of arguments (for CTL property checking)
        arg_provenance = self._get_argument_provenance(arguments, arg_variables) # UPDATED
        for arg_name, prov in arg_provenance.items():
            if prov in {"untrusted","qllm"}:
                effects.append(f"{arg_name}_tainted = true")
                effects.append(f"{arg_name}_trusted = false")
            else:
                effects.append(f"{arg_name}_trusted = true")
                effects.append(f"{arg_name}_tainted = false")

        self.add_transition(prev_state, state_id, "true", effects)

        return state

    def process_assignment(self, region: Dict, prev_state: str) -> State:
        state_id = self.create_state_id("ASSIGN")

        targets = region["metadata"]["targets"]
        value_expr = region["metadata"]["value"]

        # Track provenance through assignments
        # Extract variables used in the RHS
        vars_in_value = self._extract_variables(value_expr)
        if vars_in_value:
            # Assignment inherits max provenance of variables it uses
            max_prov = self._get_max_provenance(vars_in_value)
            for target in targets:
                self.provenance_map[target] = max_prov
                if max_prov in {"untrusted", "qllm"}:
                    self.tainted_vars.add(target)
            # Non-emptiness propagates through concatenation: if any source var
            # is non-empty, the result is non-empty.
            if any(v in self.nonempty_vars for v in vars_in_value):
                for target in targets:
                    self.nonempty_vars.add(target)
        else:
            # Literal assignment - trusted
            for target in targets:
                self.provenance_map[target] = "trusted"

        state = self.create_state(
            state_id,
            "ASSIGNMENT",
            {
                "region_id": region["region_id"],
                "targets": region["metadata"]["targets"],
                "value": region["metadata"]["value"],
            },
        )

        effects = [f"{target}_assigned = true" for target in region["metadata"]["targets"]]
        self.add_transition(prev_state, state_id, "true", effects)

        return state

    def process_loop(self, region: Dict, prev_state: str) -> State:
        loop_var = region["metadata"]["loop_var"]
        iterable = region["metadata"]["iterable"]
        body_regions = region["metadata"].get("body_regions", [])

        # FIX #2: Track loop variable provenance
        # The loop variable inherits provenance from the iterable
        if iterable in self.provenance_map:
            self.provenance_map[loop_var] = self.provenance_map[iterable]
            if self.provenance_map[iterable] in {"untrusted", "qllm"}:
                self.tainted_vars.add(loop_var)
        else:
            # Unknown iterable - conservatively mark as trusted # I am not sure about this now....
            self.provenance_map[loop_var] = "trusted"

        # Create loop states
        entry_id = self.create_state_id("LOOP_ENTRY")
        body_id = self.create_state_id("LOOP_BODY")
        exit_id = self.create_state_id("LOOP_EXIT")

        entry_state = self.create_state(
            entry_id,
            "LOOP_ENTRY",
            {
                "region_id": region["region_id"],
                "loop_var": loop_var,
                "iterable": iterable,
            },
        )

        # Process the loop body regions sequentially
        body_entry_state = body_id  # Where the body starts
        body_exit_state = body_id  # Where the body ends (initially the same)

        if body_regions:
            # Process each region in the loop body
            current_state = body_id

            for body_region in body_regions:
                region_type = body_region["region_type"]

                if region_type == "tool_call":
                    state = self.process_tool_call(body_region, current_state)
                    current_state = state.state_id

                elif region_type == "assignment":
                    state = self.process_assignment(body_region, current_state)
                    current_state = state.state_id

                elif region_type == "loop":
                    # Nested loop!
                    exit_state_inner = self.process_loop(body_region, current_state)
                    current_state = exit_state_inner.state_id

                elif region_type == "conditional":
                    # Nested conditional!
                    merge_state = self.process_conditional(body_region, current_state)
                    current_state = merge_state.state_id

            body_exit_state = current_state

        # Create the LOOP_BODY state (serves as entry point for body)
        body_state = self.create_state(
            body_id,
            "LOOP_BODY",
            {
                "region_id": region["region_id"],
                "loop_var": loop_var,
                "body_regions": body_regions,  # Keep metadata for reference
                "body_expanded": len(body_regions) > 0,  # Flag to indicate expansion
            },
        )

        exit_state = self.create_state(
            exit_id,
            "LOOP_EXIT",
            {
                "region_id": region["region_id"],
            },
        )

        # Transitions:
        # prev -> entry
        self.add_transition(prev_state, entry_id)

        if iterable in self.nonempty_vars:
            # Force the loop body to execute at least once. Afterward, the loop
            # can exit normally. 

            visited_var = f"{entry_id}_visited"
            # entry -> body: take this on the first visit (regardless of nonempty),
            # OR on later visits if iterable is non-empty.
            self.add_transition(
                entry_id, body_id,
                f"(!{visited_var} | {iterable}_nonempty)",
                [f"{loop_var}_bound = true", f"{visited_var} = true"],
            )
            # entry -> exit: only after the body has been visited at least once.
            self.add_transition(
                entry_id, exit_id,
                f"({visited_var} & {iterable}_empty_or_done)",
                [f"{loop_var}_loop_complete = true"],
            )
        else:
            # entry -> body (collection non-empty)
            self.add_transition(entry_id, body_id, f"{iterable}_nonempty", [f"{loop_var}_bound = true"])

            # entry -> exit (collection empty / done iterating)
            self.add_transition(entry_id, exit_id, f"{iterable}_empty_or_done", [f"{loop_var}_loop_complete = true"])

        # body_exit -> entry (loop back, unconditional)
        # Nondeterminism lives at LOOP_ENTRY (nonempty vs empty_or_done);
        # the back-edge is always taken so the body state is never a sink.
        self.add_transition(body_exit_state, entry_id, "true")

        return exit_state

    def process_conditional(self, region: Dict, prev_state: str) -> State:
        condition = region["metadata"]["condition"]
        true_branch_regions = region["metadata"].get("true_branch_regions", [])
        false_branch_regions = region["metadata"].get("false_branch_regions", [])

        # Create branch states
        branch_id = self.create_state_id("BRANCH")
        true_id = self.create_state_id("TRUE_BRANCH")
        false_id = self.create_state_id("FALSE_BRANCH")
        merge_id = self.create_state_id("MERGE")

        branch_state = self.create_state(
            branch_id,
            "CONDITIONAL",
            {
                "region_id": region["region_id"],
                "condition": condition,
            },
        )

        # Process true branch regions
        true_exit_state = true_id
        if true_branch_regions:
            current_state = true_id
            for branch_region in true_branch_regions:
                region_type = branch_region["region_type"]

                if region_type == "tool_call":
                    state = self.process_tool_call(branch_region, current_state)
                    current_state = state.state_id
                elif region_type == "assignment":
                    state = self.process_assignment(branch_region, current_state)
                    current_state = state.state_id
                elif region_type == "loop":
                    exit_state = self.process_loop(branch_region, current_state)
                    current_state = exit_state.state_id
                elif region_type == "conditional":
                    merge_state = self.process_conditional(branch_region, current_state)
                    current_state = merge_state.state_id

            true_exit_state = current_state

        true_state = self.create_state(
            true_id,
            "TRUE_BRANCH",
            {
                "region_id": region["region_id"],
                "branch_expanded": len(true_branch_regions) > 0,
            },
        )

        # Process false branch regions
        false_exit_state = false_id
        if false_branch_regions:
            current_state = false_id
            for branch_region in false_branch_regions:
                region_type = branch_region["region_type"]

                if region_type == "tool_call":
                    state = self.process_tool_call(branch_region, current_state)
                    current_state = state.state_id
                elif region_type == "assignment":
                    state = self.process_assignment(branch_region, current_state)
                    current_state = state.state_id
                elif region_type == "loop":
                    exit_state = self.process_loop(branch_region, current_state)
                    current_state = exit_state.state_id
                elif region_type == "conditional":
                    merge_state = self.process_conditional(branch_region, current_state)
                    current_state = merge_state.state_id

            false_exit_state = current_state

        false_state = self.create_state(
            false_id,
            "FALSE_BRANCH",
            {
                "region_id": region["region_id"],
                "branch_expanded": len(false_branch_regions) > 0,
            },
        )

        merge_state = self.create_state(
            merge_id,
            "MERGE",
            {
                "region_id": region["region_id"],
            },
        )

        # Transitions
        self.add_transition(prev_state, branch_id)
        self.add_transition(branch_id, true_id, condition)
        self.add_transition(branch_id, false_id, f"!({condition})")
        self.add_transition(true_exit_state, merge_id)
        self.add_transition(false_exit_state, merge_id)

        return merge_state

    def _is_read_tool(self, tool_name: str) -> bool:
        _builtin_read_tools = {
            "get_webpage",
            "read_inbox",
            "read_channel_messages",
            "get_channels",
            "get_users_in_channel",
            "read_file",
        }
        return tool_name in _builtin_read_tools or tool_name in self._suite_read_only_tools

    def _extract_variables(self, expr: str) -> Set[str]:
        """
        Extract variable names from an expression string.
        This is extremely hacky and if there is a better way to do it directly from the AST
        we should do that instead.
        """
        import re

        potential_vars = set(re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", expr))
        python_keywords = {"True", "False", "None", "and", "or", "not", "if", "else", "for", "in", "range", "assert"}
        return potential_vars - python_keywords

    def _extract_arg_variables(self, arguments: Dict[str, str]) -> Set[str]:
        all_vars = set()
        for arg_expr in arguments.values():
            all_vars.update(self._extract_variables(arg_expr))
        return all_vars

    def _get_max_provenance(self, var_names: Set[str]) -> str:
        provenance_order = ["trusted", "user", "untrusted", "qllm"]
        max_level = 0
        for var in var_names:
            if var in self.provenance_map:
                level = provenance_order.index(self.provenance_map[var])
                max_level = max(max_level, level)
        return provenance_order[max_level]

    def _get_argument_provenance(
        self, arguments: Dict[str, str], arg_variables: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, str]:
        """
        Determine provenance level for each argument.

        Args:
            arguments: Dict mapping arg names to their string representations
            arg_variables: Optional dict from AST mapping arg names to lists of variables they reference

        Returns:
            Dict mapping argument names to provenance levels
        """
        result = {}

        for arg_name, arg_expr in arguments.items():
            # If we have explicit variable tracking from AST, use it
            if arg_variables and arg_name in arg_variables:
                var_list = arg_variables[arg_name]
                if var_list:
                    # Convert list to set for _get_max_provenance
                    result[arg_name] = self._get_max_provenance(set(var_list))
                else:
                    # No variables referenced - must be a literal
                    result[arg_name] = "trusted"
            else:
                # Fallback: try to extract variables from the string representation
                vars_in_expr = self._extract_variables(arg_expr)
                if not vars_in_expr:
                    result[arg_name] = "trusted"
                else:
                    result[arg_name] = self._get_max_provenance(vars_in_expr)

        return result

    def normalise_guard(self, guard_str: str) -> str:
        """
        Normalise Python-style guards to NuXMV-compatible boolean expressions.

        This function converts Python conditional expressions into simpler boolean
        guard names suitable for NuXMV input variables.
        """
        import re

        guard = guard_str.strip()

        # 0. Special case: "true" literal -> "TRUE" (no IVAR needed)
        if guard.lower() == "true":
            return "TRUE"

        #  Pass-through for guards already in NuXMV-compatible compound form.
        # The state-machine builder constructs some guards directly with NuXMV
        if guard.startswith("(") and guard.endswith(")") and (
            "|" in guard or "&" in guard
        ):
            return guard

        # 1. Handle "X is not None" FIRST (before normalizing "not" to "!")
        match = re.match(r"^(.+?)\s+is\s+not\s+None\s*$", guard)
        if match:
            var = match.group(1).strip()
            var = self._sanitise_identifier(var)
            if "_empty_or_done" in var or "_nonempty" in var:
                return var
            return f"{var}_is_defined"

        # 2. Handle "X is None"
        match = re.match(r"^(.+?)\s+is\s+None\s*$", guard)
        if match:
            var = match.group(1).strip()
            var = self._sanitise_identifier(var)
            if "_empty_or_done" in var or "_nonempty" in var:
                return var
            return f"!{var}_is_defined"

        # 3. Clean up whitespace and normalize negation operators
        # Convert "not " to "!" for consistency
        guard = re.sub(r"\bnot\s+\(", "!(", guard)
        guard = re.sub(r"\bnot\s+", "!", guard)

        # 4. Handle double negation iteratively until resolved
        while True:
            # Pattern: !!(expr) or !!var
            if guard.startswith("!!"):
                # Remove double negation
                guard = guard[2:].strip()
                # Remove outer parens if they exist
                if guard.startswith("(") and guard.endswith(")"):
                    guard = guard[1:-1].strip()
                continue

            # Pattern: !(!(expr))
            match = re.match(r"!\(!(.+)\)", guard)
            if match:
                guard = match.group(1).strip()
                continue

            break

        # 5. Handle "!X" (truthiness check)
        if guard.startswith("!"):
            inner = guard[1:].strip()
            # Remove parens if they wrap the entire expression
            if inner.startswith("(") and inner.endswith(")"):
                inner = inner[1:-1].strip()
            # Recursively normalize the inner part
            normalised_inner = self.normalise_guard(inner)
            # If the result already has negation, simplify
            if normalised_inner.startswith("!"):
                return normalised_inner[1:]  # Remove the !
            elif normalised_inner == "TRUE":
                return "FALSE"
            elif normalised_inner == "FALSE":
                return "TRUE"
            else:
                return f"!{normalised_inner}"

        # 6. Handle bare identifier "X" (truthiness check)
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", guard):
            # Simple identifier - treat as "is defined" checking
            if "_empty_or_done" in guard or "_nonempty" in guard:
                return guard
            return f"{guard}_is_defined"

        # 7. Handle complex conditions with operators
        # For things like "message.sender == 'Bob'", "x > 0", etc.
        # Create a sanitized guard name
        if any(op in guard for op in ["==", "!=", ">", "<", ">=", "<=", " in ", " and ", " or "]):
            sanitised = self._sanitise_identifier(guard)
            return f"cond_{sanitised}"

        # 8. Handle attribute access (e.g., "message.sender")
        if "." in guard:
            sanitised = self._sanitise_identifier(guard)
            if "_empty_or_done" in sanitised or "_nonempty" in sanitised:
                return sanitised
            return f"{sanitised}_is_defined"

        # 9. Fallback - sanitize and use as-is
        return self._sanitise_identifier(guard)

    def _sanitise_identifier(self, expr: str) -> str:
        """
        Convert an arbitrary expression into a valid NuXMV identifier.

        Rules:
        - Replace operators and special chars with underscores
        - Remove quotes and parentheses
        - Ensure it starts with a letter
        """
        import re

        # Remove quotes
        expr = expr.replace('"', "").replace("'", "")

        # Replace operators and special chars with underscores
        expr = re.sub(r"[^\w]", "_", expr)

        # Collapse multiple underscores
        expr = re.sub(r"_+", "_", expr)

        # Remove leading/trailing underscores
        expr = expr.strip("_")

        # Ensure it starts with a letter (prepend 'v_' if needed)
        if expr and not expr[0].isalpha():
            expr = f"v_{expr}"

        # Truncate if too long (NuXMV might have limits)
        if len(expr) > 64:
            expr = expr[:64]

        return expr

    def build_state_machine(self) -> Dict:
        """
        Build the complete state machine and return as a JSON-serialisable dictionary.

        Returns:
            Dict containing states, transitions, atomic_propositions, and ctl_properties
        """
        # Build state machine from regions
        states, transitions = self.build_from_regions()

        # Generate atomic propositions
        atomic_props = generate_atomic_propositions(states)

        # Generate CTL properties
        ctl_props = generate_ctl_properties(self.parsed_result, states)

        # Create output structure
        output = {
            "states": [{"id": s.state_id, "type": s.state_type, "metadata": s.metadata} for s in states],
            "transitions": [
                {
                    "from": t.from_state,
                    "to": t.to_state,
                    "guard": self.normalise_guard(t.guard),
                    "effect": t.effect,
                }
                for t in transitions
            ],
            "atomic_propositions": atomic_props,
            "ctl_properties": ctl_props,
        }

        return output

    def save_state_machine(self, output_path: str) -> None:
        output = self.build_state_machine()

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)


def visualise_state_machine(states: List[State], transitions: List[Transition]) -> str:
    output = []
    output.append("=" * 80)
    output.append("FINITE STATE MACHINE")
    output.append("=" * 80)

    output.append("\nSTATES:")
    output.append("-" * 80)
    for state in states:
        output.append(f"  {state.state_id} ({state.state_type})")
        if state.metadata:
            for key, value in state.metadata.items():
                if key not in ["body_regions", "true_branch_regions", "false_branch_regions"]:
                    output.append(f"    {key}: {value}")

    output.append("\nTRANSITIONS:")
    output.append("-" * 80)
    for trans in transitions:
        output.append(f"  {trans.from_state} -> {trans.to_state}")
        output.append(f"    Guard: {trans.guard}")
        if trans.effect:
            output.append(f"    Effects: {', '.join(trans.effect)}")

    return "\n".join(output)


def generate_atomic_propositions(states: List[State]) -> Dict[str, str]:
    """Generate atomic propositions for CTL formulas"""
    props = {
        "init": "current_state = INITIAL",
        "done": "current_state = DONE",
    }

    for state in states:
        if state.state_type == "TOOL_CALL":
            tool = state.metadata["tool"]
            props[f"call_{tool}"] = f"current_state = {state.state_id}"
            props[f"{tool}_called"] = f"{tool}_called = true"

        elif state.state_type == "LOOP_ENTRY":
            props[f"loop_{state.state_id}"] = f"current_state = {state.state_id}"

    return props


def generate_ctl_properties(parsed_result: Dict, states: List[State]) -> List[str]:
    """Generate CTL properties based on the parsed code structure"""
    properties = []

    # Global liveness: program eventually completes
    properties.append("AF(done)")

    # Extract tool call order
    tool_calls = [s for s in states if s.state_type == "TOOL_CALL"]

    if len(tool_calls) >= 2:
        # Ordering constraint: second tool must only be called after first has been called
        first = tool_calls[0].metadata["tool"]
        second = tool_calls[1].metadata["tool"]
        properties.append(f"AG(call_{second} -> {first}_called)")

    # Safety: No tool calls after done
    for tool_state in tool_calls:
        tool = tool_state.metadata["tool"]
        properties.append(f"AG(done -> AG(!call_{tool}))")

    # Loop properties
    loop_states = [s for s in states if s.state_type == "LOOP_ENTRY"]
    for loop_state in loop_states:
        properties.append(f"AG(loop_{loop_state.state_id} -> AF(done))")

    return properties
