# Convert my state machine JSON to NuXMV Convert
import json
from typing import Dict
from contextlib import redirect_stdout


class NuXMV:
    def __init__(self, state_machine: Dict | None = None, filename: str | None = None):
        """
        Given the filename of a JSON file describing a state machine,
        extract the variables, guards, transitions, etc. for later use.
        Can either write our own model checker or export to NuXMV (trying
        this second option first)
        """
        assert not ((state_machine is None) and (filename is None)), "Must provide one of state_machine or filename"
        assert state_machine is None or filename is None, "One of state_machine or filename must be None"
        self.filename = filename
        if state_machine is not None:
            self.json_machine = state_machine
        else:
            assert filename is not None  # guaranteed by the assertions above
            self.json_machine = self.read_json_machine(filename=filename)
        self.states = set()
        self.variables = set()
        self.transitions = dict()
        self.guards = dict()
        self.effects = dict()

        self.loop_states()
        self.loop_transitions()

    def read_json_machine(self, filename: str):
        with open(filename, "r") as f:
            state_machine_dict = json.load(f)
        return state_machine_dict

    def loop_states(self):
        for state in self.json_machine["states"]:
            self.add_states(state)
            self.add_variables(state)

    def loop_transitions(self):
        for transition in self.json_machine["transitions"]:
            self.add_transitions(transition)
            self.add_guards(transition)
            self.add_effects(transition)

    def add_states(self, state: Dict):
        self.states.add(state["id"])

    def add_variables(self, state):
        if state["type"] == "TOOL_CALL":
            self.variables.add(f"call_{state['metadata']['tool']}")
        elif state["type"] == "ASSIGNMENT":
            for target in state["metadata"]["targets"]:
                self.variables.add(f"assign_{target}")
        elif state["type"] == "LOOP_ENTRY" or state["type"] == "LOOP_BODY":
            self.variables.add(f"bound_{state['metadata']['loop_var']}")
            self.variables.add(f"complete_{state['metadata']['loop_var']}")

    def add_transitions(self, transition: Dict):
        """
        Map each from state to one or more to states
        """
        key = transition["from"]
        self.transitions.setdefault(key, []).append(transition["to"])

    def add_guards(self, transition: Dict):
        """
        Store guard conditions for transitions.
        Guards should already be normalised by StateMachineBuilder.
        """
        self.guards[(transition["from"], transition["to"])] = transition["guard"]

    def add_effects(self, transition: Dict):
        split_list = [trans.split("=", 1) for trans in transition["effect"]]
        split_list = [(trans[0].strip(), trans[1].strip()) for trans in split_list]
        self.effects[(transition["from"], transition["to"])] = [(_tup[0], _tup[1]) for _tup in split_list]

    def debug_print(self):
        print(f"[*] States - Len: {len(self.states)}")

        def sort_states(states):
            split_list = []
            for state in states:
                if "_" in state:
                    split_state = state.rsplit("_", 1)
                    split_list.append((split_state[0], split_state[1], state))
                else:
                    split_list.append((state, "", state))
            sorted_tuples = sorted(split_list, key=lambda tup: tup[1])
            return [tup[2] for tup in sorted_tuples]

        for state in sort_states(self.states):
            print(f"\t{state}")

        print(f"[*] Variables - Len: {len(self.variables)}")
        for variable in self.variables:
            print(f"\t{variable}")

        print(f"[*] Tranistions - Len: {len(self.transitions)}")
        for _from, _to in self.transitions.items():
            for __to in _to:
                print(
                    f"\t{_from} -> {__to};\n\t\tGuard: {self.guards[(_from, __to)]};\n\t\tEffects: {self.effects[(_from, __to)]}"
                )


class NuXMVPrinter:
    def __init__(self, nuxmv: NuXMV, output_file=None, ctl_properties=None):
        self.machine = nuxmv
        self.ctl_properties = ctl_properties or []  # CHANGED
        self.states = sorted(self.machine.states)
        self.effects = set()

        for eff in self.machine.effects.values():
            for e in eff:
                self.effects.add(e[0])
        self.bool_vars = set()
        self.bool_vars |= self.effects

        # Extract provenance variables from states
        self.provenance_vars = set()

        # 1. From state provenance maps (output variables)
        for state in self.machine.json_machine["states"]:
            if "provenance" in state and state["provenance"]:
                for var in state["provenance"].keys():
                    self.provenance_vars.add(f"{var}_trusted")
                    self.provenance_vars.add(f"{var}_tainted")

            # 2. From argument provenance in tool call states
            if state["type"] == "TOOL_CALL" and "metadata" in state:
                metadata = state["metadata"]
                if "arg_provenance" in metadata:
                    for arg_name in metadata["arg_provenance"].keys():
                        self.provenance_vars.add(f"{arg_name}_trusted")
                        self.provenance_vars.add(f"{arg_name}_tainted")

        self.bool_vars |= self.provenance_vars

        # Add boolean variables referenced by CTL properties, even if they
        # do not appear in the current trace. Missing tools/flags should
        # evaluate as FALSE in the model, not cause the property to vanish.
        import re  # CHANGED

        ctl_keywords = {  # CHANGED
            # Multi-char CTL operators
            "AG", "AF", "EG", "EF", "AX", "EX", "AU", "EU",
            # Single-char CTL operators / quantifiers (reserved in NuXMV)
            "A", "E", "U", "W", "X", "F", "G",
            "TRUE", "FALSE", "done", "at_initial"
        }

        referenced_bool_vars = set()  # CHANGED

        for prop in self.ctl_properties:  # CHANGED
            identifiers = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", prop.formula)
            for identifier in identifiers:
                if identifier in ctl_keywords:
                    continue
                if identifier.startswith("call_"):
                    continue
                referenced_bool_vars.add(identifier)

        self.bool_vars |= referenced_bool_vars  # CHANGED

        # Extract unique guard variables for IVAR section
        # We need to be careful to:
        # 1. Exclude TRUE/FALSE constants
        # 2. Only include base variables (not their negations)
        # 3. Avoid duplicates
        self.guards = set()
        for guard in self.machine.guards.values():
            if guard not in ("TRUE", "FALSE"):
                self.guards.add(guard)

        # Build IVAR variables - extract identifiers from each guard.
        # Guards may now be compound boolean expressions like
        #   "(!LOOP_ENTRY_2_visited | channels_nonempty)"
        identifier_re = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")
        guard_keywords = {"TRUE", "FALSE"}
        self.bool_ivars = set()
        for guard in self.guards:
            for ident in identifier_re.findall(guard):
                if ident in guard_keywords:
                    continue
                self.bool_ivars.add(ident)

        # Effect-target variables (e.g. LOOP_ENTRY_2_visited) are regular VARs
        # driven by transition effects. They must not be re-declared as IVARs,
        # even though they appear inside guard expressions.
        self.bool_ivars -= self.effects

        self.invars = list()
        self.guard_defines = {}  # _empty_or_done guards expressed as DEFINE
        self.build_invars()

        self.transitions = self.machine.transitions

        if output_file is None:
            self.complete_print(ctl_properties=ctl_properties)
        else:
            with open(output_file, "w") as f:
                with redirect_stdout(f):
                    self.complete_print(ctl_properties=ctl_properties)

    def format_states(self):
        return ", ".join(list(self.states))

    def build_invars(self):
        # Pair each <root>_nonempty IVAR with its <root>_empty_or_done
        # counterpart and express 
        for ivar in list(self.bool_ivars):
            if ivar.endswith("_nonempty"):
                root = ivar[: -len("_nonempty")]
                other = f"{root}_empty_or_done"
                if other in self.bool_ivars:
                    self.guard_defines[other] = f"!{ivar}"
                    self.bool_ivars.discard(other)

    def _print_boolean_vars(self, bool_vars):

        if not bool_vars:
            return
        # Compute widest variable name
        max_len = max(len(v) for v in bool_vars)
        for v in bool_vars:
            # left-align name in a field of width max_len
            print(f"  {v.ljust(max_len)} : boolean;")

    def var_print(self):
        print("VAR")
        print("  -- all possible states, vaguely ordered for legibility")
        print(f"  current_state : {{{self.format_states()}}};\n")
        print("  -- all internal booleans")
        self._print_boolean_vars(self.bool_vars)
        print()

    def ivar_print(self):
        print("IVAR")
        print("  -- define our input variables")
        self._print_boolean_vars(self.bool_ivars)
        print()

    def invar_print(self):
        print("-- invariables that can't both be true")
        for invar in self.invars:
            print(f"INVAR !({invar[0]} & {invar[1]});")
        print()

    def trans_print(self):
        print("  -- define our transition system. quite messy, might need to clean up.")
        print("ASSIGN")
        print("  init(current_state) := INITIAL;")
        print("  next(current_state) := case")

        for from_state, to_list in self.machine.transitions.items():
            for to_state in to_list:
                guard = self.machine.guards[(from_state, to_state)]
                if guard == "TRUE":
                    cond = f"current_state = {from_state}"
                else:
                    cond = f"current_state = {from_state} & {guard}"
                print(f"    {cond} : {to_state};")

        if "DONE" in self.machine.states:
            print("    current_state = DONE : DONE;")

        print("    TRUE : current_state;")
        print("  esac;")

    def effects_print(self):
        """
        Print init(...) and next(...) assignments for all boolean state variables
        that appear on the LHS of any effect, using the effects recorded in
        self.machine.effects.

        For each var:
          init(var) := FALSE;
          next(var) := case
            <on any transition that sets var = true> : TRUE;
            <on any transition that sets var = false> : FALSE;
            TRUE : var;
          esac;
        """
        # Nothing to do if there are no effect variables
        if not self.effects:
            return

        print()
        # We assume trans_print already printed:
        #   ASSIGN
        #   init(current_state) := INIT;
        #   next(current_state) := case ...
        # so here we only print the per-variable init/next.
        # If you want them in the same ASSIGN block, call this
        # right after trans_print without printing a new "ASSIGN".

        for var in sorted(self.effects):
            print(f"  init({var}) := FALSE;")
            print(f"  next({var}) := case")
            true_conditions = []
            false_conditions = []
            max_len = 0

            for from_state, to_data in self.machine.transitions.items():
                if isinstance(to_data, list):
                    to_states = to_data
                else:
                    to_states = [to_data]

                for to_state in to_states:
                    effects = self.machine.effects.get((from_state, to_state), [])
                    for lhs, rhs in effects:
                        if lhs == var:
                            guard = self.machine.guards[(from_state, to_state)]
                            if guard == "TRUE":
                                cond = f"current_state = {from_state} & next(current_state) = {to_state}"
                            else:
                                cond = f"current_state = {from_state} & {guard} & next(current_state) = {to_state}"

                            if rhs.lower() == "true":
                                true_conditions.append(cond)
                            elif rhs.lower() == "false":
                                false_conditions.append(cond)

            # Print conditions that set to TRUE
            if true_conditions:
                max_len = max(len(c) for c in true_conditions)
                for cond in true_conditions:
                    print(f"    {cond.ljust(max_len)} : TRUE;")

            # Print conditions that set to FALSE
            if false_conditions:
                max_len = max(max_len, max(len(c) for c in false_conditions))
                for cond in false_conditions:
                    print(f"    {cond.ljust(max_len)} : FALSE;")

            # Default: keep current value
            if true_conditions or false_conditions:
                max_len = max(len(c) for c in (true_conditions + false_conditions))
                print(f"    {'TRUE'.ljust(max_len)} : {var};")
            else:
                print(f"    TRUE : {var};")

            print("  esac;")

    def extra_bool_vars_print(self):
        """
        Ensure boolean vars referenced by CTL properties exist even if they
        never appear as transition effects.

        Variables ending in '_called' are treated as monotonic flags: they become
        TRUE when the corresponding CALL_<tool> state is entered and stay TRUE.
        All other extra vars default to FALSE and remain unchanged.
        """
        extra_vars = sorted(self.bool_vars - self.effects)
        if not extra_vars:
            return

        print()
        for var in extra_vars:
            print(f"  init({var}) := FALSE;")
            if var.endswith("_called"):
                tool_name = var[:-7]  # strip "_called" suffix
                call_states = [
                    st["id"] for st in self.machine.json_machine["states"]
                    if st["type"] == "TOOL_CALL" and st["metadata"].get("tool") == tool_name
                ]
                if call_states:
                    cond = " | ".join(f"current_state = {sid}" for sid in call_states)
                    print(f"  next({var}) := case")
                    print(f"    ({cond}) : TRUE;")
                    print(f"    TRUE : {var};")
                    print(f"  esac;")
                    continue
            print(f"  next({var}) := {var};")

    def define_print(self):
        """
        Emit DEFINE section with atomic propositions:

          - at_initial := current_state = INITIAL;
          - done := current_state = DONE;
          - call_<toolname> := current_state = CALL_<toolname>_<id>;
          - loop_<state_id> := current_state = <state_id>;  for all LOOP_ENTRY_* states.
        """
        import re  # CHANGED

        print()
        print("DEFINE")

        if "INITIAL" in self.machine.states:
            print("  at_initial := current_state = INITIAL;")
        if "DONE" in self.machine.states:
            print("  done := current_state = DONE;")

        tool_call_aps = {}  # name -> state_id
        for st in self.machine.json_machine["states"]:
            if st["type"] == "TOOL_CALL":
                tool_name = st["metadata"]["tool"]
                state_id = st["id"]
                ap_name = f"call_{tool_name}"
                if ap_name in tool_call_aps:
                    tool_call_aps[ap_name].append(state_id)
                else:
                    tool_call_aps[ap_name] = [state_id]

        referenced_call_aps = set()  # CHANGED
        for prop in self.ctl_properties:  # CHANGED
            referenced_call_aps.update(re.findall(r"\bcall_[a-zA-Z_][a-zA-Z0-9_]*\b", prop.formula))

        all_call_aps = sorted(set(tool_call_aps.keys()) | referenced_call_aps)  # CHANGED

        for ap_name in all_call_aps:  # CHANGED
            state_ids = tool_call_aps.get(ap_name, [])  # CHANGED
            if len(state_ids) == 1:
                sid = state_ids[0]
                print(f"  {ap_name} := current_state = {sid};")
            elif len(state_ids) > 1:  # CHANGED
                cond = " | ".join(f"current_state = {sid}" for sid in state_ids)
                print(f"  {ap_name} := {cond};")
            else:
                print(f"  {ap_name} := FALSE;")  # CHANGED

        loop_entries = [st["id"] for st in self.machine.json_machine["states"] if st["type"] == "LOOP_ENTRY"]
        for sid in sorted(loop_entries):
            ap_name = f"loop_{sid}"
            print(f"  {ap_name} := current_state = {sid};")

        # Paired loop guards: _empty_or_done is defined as !_nonempty
        # (avoids declaring them both as free IVARs with an INVAR constraint,
        # which NuXMV rejects)
        for var, expr in sorted(self.guard_defines.items()):
            print(f"  {var} := {expr};")

    def _property_is_applicable(self, prop) -> bool:
        return True  # CHANGED

    def ctl_spec_print(self, properties):
        if not properties:
            return

        print()
        print("-- ============================================================================")
        print("-- CTL SECURITY PROPERTIES")
        print("-- Auto-generated from ctl_policies module")
        print("-- ============================================================================")
        print()

        for prop in properties:  # CHANGED
            print(f"-- Property: {prop.name}")
            print(f"-- Description: {prop.description}")
            print(f"-- Severity: {prop.severity}")
            print(f"CTLSPEC {prop.formula};")
            print()

    def complete_print(self, ctl_properties=None):
        """
        Print the NuXMV file
        Either to standard output or to a file, if
        provided.

        Args:
            ctl_properties: Optional list of CTLProperty objects to include in the model
        """
        print("MODULE main")
        self.var_print()
        # if self.bool_vars != set():
        #     self.var_print()
        if self.bool_ivars != set():
            self.ivar_print()
        self.trans_print()
        self.effects_print()
        self.extra_bool_vars_print()  # CHANGED
        self.define_print()
        if ctl_properties:
            self.ctl_spec_print(ctl_properties)