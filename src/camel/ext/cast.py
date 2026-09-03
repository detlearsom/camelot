import ast
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Union
from enum import Enum
from pathlib import Path
import os
from datetime import datetime


class RegionType(Enum):
    INIT = "init"
    TOOL_CALL = "tool_call"
    ASSIGNMENT = "assignment"
    LOOP = "loop"
    CONDITIONAL = "conditional"
    DONE = "done"


@dataclass
class Region:
    region_id: int
    region_type: RegionType
    line_start: int
    line_end: int
    metadata: Dict[str, Any]

    def to_dict(self):
        result = asdict(self)
        result["region_type"] = self.region_type.value
        return result


class RegionExtractor(ast.NodeVisitor):
    """
    Extracts control flow regions from CaMeL code (which is a restricted version of Python).

    This parser identifies:
    - Tool calls (calls to CaMeL tools like get_channels, add_user_to_channel)
    - Assignments (variable definitions)
    - Loops (for/while constructs)
    - Conditionals (if/else branches)
    """

    def __init__(self, tool_functions: List[str], tool_signatures: Optional[Dict[str, List[str]]] = None):
        """
        Args:
            tool_functions: List of known CaMeL tool function names
            tool_signatures: Optional mapping of tool names to parameter names
        """
        self.regions: List[Region] = []
        self.region_counter = 0
        self.tool_functions = set(tool_functions)
        self.tool_signatures = tool_signatures or {}
        self.variable_assignments = {}  # Track what each variable is assigned to

    def get_region_id(self) -> int:
        region_id = self.region_counter
        self.region_counter += 1
        return region_id

    def get_function_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def is_tool_call(self, node: ast.Call) -> bool:
        func_name = self.get_function_name(node)
        return func_name in self.tool_functions

    def check_tool_call(self, node: ast.Assign | ast.Expr) -> bool:
        if isinstance(node.value, ast.Call) and self.is_tool_call(node.value):
            return True
        return False

    def find_nested_tool_calls(self, node: ast.AST) -> List[ast.Call]:
        """

        Addition:  this is to be able to see prerequisite reads and to match them.

        Return Call nodes that target a known tool, excluding
        the top-level Call itself when it is a tool call (that case is handled
        by check_tool_call). 

        """
        results: List[ast.Call] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self.is_tool_call(child):
                if child is node:
                    continue
                results.append(child)
        return results

    def _emit_nested_tool_call_regions(self, node: ast.AST, parent_lineno: int, parent_end_lineno: int) -> None:
        """
        
        TOOL_CALL region for every nested call to a
        known tool. The regions are emitted with no assignment target, they
        exist so the state machine knows the call happened (sets the
        `<tool>_called` flag) and so taint flows through arg provenance.
        
        """
        for call in self.find_nested_tool_calls(node):
            func_name = self.get_function_name(call)
            args = self.extract_call_args(call)
            arg_vars = self.extract_arg_variables(call)

            region = Region(
                region_id=self.get_region_id(),
                region_type=RegionType.TOOL_CALL,
                line_start=getattr(call, "lineno", parent_lineno),
                line_end=getattr(call, "end_lineno", parent_end_lineno) or parent_end_lineno,
                metadata={
                    "tool_name": func_name,
                    "targets": [],
                    "arguments": args,
                    "arg_variables": arg_vars,
                    "nested": True,
                },
            )
            self.regions.append(region)

    def extract_vars_from_node(self, node: ast.expr) -> List[str]:
        """
        Extract all variable names referenced in an AST node.
        Handles f-strings, attribute access, and nested expressions.
        
        Returns: List of base variable names (e.g., 'message' from 'message.body')
        """
        vars_found = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                # Simple variable reference: x
                vars_found.append(child.id)
            elif isinstance(child, ast.Attribute):
                # Attribute access: message.body
                # Extract the base variable name
                base = child.value
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    vars_found.append(base.id)
        
        # Remove duplicates while preserving order
        seen = set()
        result = []
        for var in vars_found:
            if var not in seen:
                seen.add(var)
                result.append(var)
        
        return result

    def extract_call_args(self, node: ast.Call) -> Dict[str, str]:
        args = {}

        # Get the function name to look up signatures
        func_name = self.get_function_name(node)
        param_names = self.tool_signatures.get(func_name, []) if func_name else []

        # Positional arguments - use parameter names from signatures if available
        for i, arg in enumerate(node.args):
            if i < len(param_names):
                # Use the parameter name from the signature
                arg_name = param_names[i]
            else:
                # Fall back to generic name if no signature available
                arg_name = f"arg_{i}"
            args[arg_name] = ast.unparse(arg)

        # Keyword arguments
        for keyword in node.keywords:
            if keyword.arg:
                args[keyword.arg] = ast.unparse(keyword.value)
        return args
    
    def extract_arg_variables(self, node: ast.Call) -> Dict[str, List[str]]:
        """
        For each argument, extract the variables it references.
        This is needed for taint tracking through f-strings and expressions.
        
        Returns: Dict mapping argument name to list of variable names used
        """
        arg_vars = {}

        # Get the function name to look up signatures
        func_name = self.get_function_name(node)
        param_names = self.tool_signatures.get(func_name, []) if func_name else []

        # Positional arguments
        for i, arg in enumerate(node.args):
            if i < len(param_names):
                arg_name = param_names[i]
            else:
                arg_name = f"arg_{i}"
            
            arg_vars[arg_name] = self.extract_vars_from_node(arg)

        # Keyword arguments
        for keyword in node.keywords:
            if keyword.arg:
                arg_vars[keyword.arg] = self.extract_vars_from_node(keyword.value)
        
        return arg_vars

    def visit_Assign(self, node: ast.Assign) -> None:
        # Get the target variable(s)
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
            elif isinstance(target, ast.Tuple):
                targets.extend([elt.id for elt in target.elts if isinstance(elt, ast.Name)])

        # Check if the right-hand side is a tool call
        if self.check_tool_call(node):
            assert isinstance(node.value, ast.Call)
            # Arguments are evaluated before the outer tool call. Emit nested
            # tool calls first so CTL sees inline prerequisite/context reads.
            self._emit_nested_tool_call_regions(
                node.value, node.lineno, node.end_lineno or node.lineno
            )
            func_name = self.get_function_name(node.value)
            args = self.extract_call_args(node.value)
            arg_vars = self.extract_arg_variables(node.value)

            region = Region(
                region_id=self.get_region_id(),
                region_type=RegionType.TOOL_CALL,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                metadata={
                    "tool_name": func_name,
                    "targets": targets,
                    "arguments": args,
                    "arg_variables": arg_vars,  # NEW: Track which vars each arg uses
                },
            )
            self.regions.append(region)

            # Track variable assignment
            for target in targets:
                self.variable_assignments[target] = {
                    "source": "tool_call",
                    "tool": func_name,
                    "region_id": region.region_id,
                }
        else:

            # Emit a TOOL_CALL region for every nested call to a known tool
            # inside the RHS expression (e.g. `len(get_users_in_channel(c))`),
            # so the state machine sets <tool>_called and tracks taint flow.
          
            self._emit_nested_tool_call_regions(
                node.value, node.lineno, node.end_lineno or node.lineno
            )

            # Regular assignment
            region = Region(
                region_id=self.get_region_id(),
                region_type=RegionType.ASSIGNMENT,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                metadata={
                    "targets": targets,
                    "value": ast.unparse(node.value),
                },
            )
            self.regions.append(region)

            # Track variable assignment
            for target in targets:
                self.variable_assignments[target] = {
                    "source": "expression",
                    "expression": ast.unparse(node.value),
                    "region_id": region.region_id,
                }

        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        # Extract loop variable
        loop_var = None
        if isinstance(node.target, ast.Name):
            loop_var = node.target.id

        # Extract iterable
        iterable = ast.unparse(node.iter)

        # Check if iterable is a variable we've seen
        iterable_source = None
        if isinstance(node.iter, ast.Name) and node.iter.id in self.variable_assignments:
            iterable_source = self.variable_assignments[node.iter.id]

        # Extract loop body regions (we'll process these recursively)
        body_extractor = RegionExtractor(list(self.tool_functions), self.tool_signatures)
        for stmt in node.body:
            body_extractor.visit(stmt)

        region = Region(
            region_id=self.get_region_id(),
            region_type=RegionType.LOOP,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            metadata={
                "loop_var": loop_var,
                "iterable": iterable,
                "iterable_source": iterable_source,
                "body_regions": [r.to_dict() for r in body_extractor.regions],
                "num_body_regions": len(body_extractor.regions),
            },
        )
        self.regions.append(region)

        # Don't call generic_visit here! We already processed the body

    def visit_Expr(self, node: ast.Expr) -> None:
        # In this case, expression statements are calls without assignment
        # Check if this is a standalone tool call
        if self.check_tool_call(node):
            assert isinstance(node.value, ast.Call)

            # Arguments are evaluated before the outer tool call. Emit nested
            # tool calls first so CTL sees inline prerequisite/context reads.
            self._emit_nested_tool_call_regions(
                node.value, node.lineno, node.end_lineno or node.lineno
            )
            func_name = self.get_function_name(node.value)
            args = self.extract_call_args(node.value)
            arg_vars = self.extract_arg_variables(node.value)

            region = Region(
                region_id=self.get_region_id(),
                region_type=RegionType.TOOL_CALL,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                metadata={
                    "tool_name": func_name,
                    "targets": [],  # No assignment
                    "arguments": args,
                    "arg_variables": arg_vars,  # NEW: Track which vars each arg uses
                    "standalone": True,  # Mark as standalone call
                },
            )
            self.regions.append(region)
        else:
            # Statement is an expression that isn't a direct tool call
            self._emit_nested_tool_call_regions(
                node.value, node.lineno, node.end_lineno or node.lineno
            )

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        # Extract condition
        condition = ast.unparse(node.test)

        # Extract variables used in condition
        condition_vars = []
        for child_node in ast.walk(node.test):
            if isinstance(child_node, ast.Name):
                condition_vars.append(child_node.id)

        # Extract true branch regions
        true_extractor = RegionExtractor(list(self.tool_functions), self.tool_signatures)
        for stmt in node.body:
            true_extractor.visit(stmt)

        # Extract false branch regions (if exists)
        false_extractor = RegionExtractor(list(self.tool_functions), self.tool_signatures)
        if node.orelse:
            for stmt in node.orelse:
                false_extractor.visit(stmt)

        region = Region(
            region_id=self.get_region_id(),
            region_type=RegionType.CONDITIONAL,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            metadata={
                "condition": condition,
                "condition_vars": condition_vars,
                "true_branch_regions": [r.to_dict() for r in true_extractor.regions],
                "false_branch_regions": [r.to_dict() for r in false_extractor.regions],
                "num_true_regions": len(true_extractor.regions),
                "num_false_regions": len(false_extractor.regions),
            },
        )
        self.regions.append(region)


def parse_camel_code(
    code: str,
    tool_functions: List[str],
    tool_signatures: Optional[Dict[str, List[str]]] = None
) -> Dict[str, Any]:
    """
    Parse CaMeL Python code and extract control flow regions.

    Args:
        code: CaMeL Python code as a string
        tool_functions: List of known CaMeL tool function names
        tool_signatures: Optional mapping of tool names to parameter names

    Returns:
        Dictionary containing parsed regions and metadata
    """
    # Parse the code into an AST
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {"success": False, "error": f"Syntax error: {e}", "regions": []}

    # Extract regions
    extractor = RegionExtractor(tool_functions, tool_signatures)
    extractor.visit(tree)

    return {
        "success": True,
        "num_regions": len(extractor.regions),
        "regions": [r.to_dict() for r in extractor.regions],
        "variable_assignments": extractor.variable_assignments,
    }


def save_region_summary(result: Dict[str, Any], filename: str) -> None:
    if not result["success"]:
        print(f"[!] Parsing failed: {result['error']}")
        return
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)


def save_code(code: str, filename: str) -> None:
    with open(filename, "w") as f:
        f.write(code)


def save_summary_from_camel(
    result: Dict[str, Any], env, attempt: int, code: Optional[str] = None
) -> None:
    """Disabled - requires CaMeL import"""
    pass
    # timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # env_name = env.env_name
    # this_file_directory, _ = os.path.split(__file__)
    # output_path = Path(this_file_directory, "asts", f"ast_{env_name}_{timestamp}_{attempt}")
    # save_region_summary(result, str(output_path) + ".json")
    # if code is not None:
    #     save_code(code, str(output_path) + "_raw_code")