"""
This test is for testing the AST in cast.py,

The AST module (cast.py) parses P-LLM generated Python code into 
a structured representation of control flow regions. It uses 
Python's built-in ast module to traverse the syntax tree and identifies four types of regions:

Tool calls: Function calls to available tools, extracting the tool name, target variables, and argument expressions
Assignments: Variable assignments, tracking which variables are defined and what expressions they depend on
Loops: For-loops over iterables, identifying the loop variable, iterable, and body regions
Conditionals: If-else branches, extracting the condition and regions for each branch

For each region, the parser tracks variable dependencies at argument granularity. This means that for a tool 
call like send_message(recipient, body), we record not just that the tool was called, 
but which specific variables appear in the recipient and body arguments.

The output is a JSON structure with a list of regions, where each region includes its type, 
metadata (e.g., tool name, variables), and for compound regions (loops, conditionals), nested sub-regions. 

This structured representation is then fed into the state machine builder for provenance analysis.

Note: The state machine builder is check in a different file. This is true for the provencane propagation as well.

Last Checked: 06.05.2026

Run:
 pytest -q tests/test_ctl/test_cast.py

Evaluation: 18/18. 

"""
import pytest

from camel.ext.cast import parse_camel_code


# ----- Tools for testing ----- #

# any function should be treated as a tool.
TOOL_FUNCTIONS = [
    "read_channel_messages",
    "query_ai_assistant",
    "send_direct_message",
    "confirm_host",
    "isolate_host",
    "scan_host",
    "create_ticket",
    "resolve_ip",
    "block_ip",
]

# positional arguments should be mapped with signatures
TOOL_SIGNATURES = {
    "read_channel_messages": ["channel"],
    "query_ai_assistant": ["prompt", "schema"], # important one
    "send_direct_message": ["recipient", "body"],
    "confirm_host": ["host"],
    "isolate_host": ["host"],
    "scan_host": ["host"],
    "create_ticket": ["summary"],
    "resolve_ip": ["ip"],
    "block_ip": ["ip"],
}


def parse(code: str):
    return parse_camel_code(
        code,
        tool_functions=TOOL_FUNCTIONS,
        tool_signatures=TOOL_SIGNATURES,
    )


def assert_success(result):
    assert result["success"] is True, result.get("error")

# ========================================
# Test 0: We are expecting that empty code should not have regions.
# ========================================
def test_empty_code_has_no_regions():
    result = parse("")
    assert_success(result)

    assert result["num_regions"] == 0
    assert result["regions"] == []

# ========================================
# Test 1: Produce an assignemnt region (1)
# ========================================

def test_regular_assignment_region():
    code = """
x = 1
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 1

    region = result["regions"][0]
    assert region["region_type"] == "assignment"
    assert region["metadata"]["targets"] == ["x"]
    assert region["metadata"]["value"] == "1"

    assert result["variable_assignments"]["x"]["source"] == "expression"

# ========================================
# Test 2: A tool call that does not have an assignemtn should be a tool call.
# ========================================
def test_single_standalone_tool_call():
    code = """
send_direct_message("bob@example.com", "hello")
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 1

    region = result["regions"][0]
    assert region["region_type"] == "tool_call"
    assert region["metadata"]["tool_name"] == "send_direct_message"
    assert region["metadata"]["targets"] == []
    assert region["metadata"]["standalone"] is True

    assert region["metadata"]["arguments"] == {
        "recipient": "'bob@example.com'",
        "body": "'hello'",
    }

    assert region["metadata"]["arg_variables"] == {
        "recipient": [],
        "body": [],
    }

# ========================================
# Test 3: Gets it the target contained the assigned variable (general)
# ========================================
def test_assigned_tool_call_region():
    code = """
messages = read_channel_messages("general")
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 1

    region = result["regions"][0]
    assert region["region_type"] == "tool_call"
    assert region["metadata"]["tool_name"] == "read_channel_messages"
    assert region["metadata"]["targets"] == ["messages"]
    assert region["metadata"]["arguments"] == {
        "channel": "'general'",
    }
    assert region["metadata"]["arg_variables"] == {
        "channel": [],
    }

    assert result["variable_assignments"]["messages"]["source"] == "tool_call"
    assert result["variable_assignments"]["messages"]["tool"] == "read_channel_messages"

# Test 5: Multiple tool calls preserve source order
def test_multiple_tool_calls_preserve_order():
    code = """
messages = read_channel_messages("general")
email = query_ai_assistant(messages, EmailAddress)
send_direct_message(email, "hello")
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 3

    tool_names = [
        region["metadata"]["tool_name"]
        for region in result["regions"]
    ]

    assert tool_names == [
        "read_channel_messages",
        "query_ai_assistant",
        "send_direct_message",
    ]

# ========================================
# Test 6: Positional arguments use tool signature names
# ========================================

def test_positional_arguments_resolved_using_signature():
    code = """
send_direct_message(email, "hello")
"""

    result = parse(code)
    assert_success(result)

    region = result["regions"][0]

    assert region["metadata"]["arguments"] == {
        "recipient": "email",
        "body": "'hello'",
    }

    assert region["metadata"]["arg_variables"] == {
        "recipient": ["email"],
        "body": [],
    }

# ========================================
# Test 7: Keyword arguments are extracted correctly
# ========================================

def test_keyword_arguments_are_extracted():
    code = """
send_direct_message(recipient=email, body="hello")
"""

    result = parse(code)
    assert_success(result)

    region = result["regions"][0]

    assert region["metadata"]["arguments"] == {
        "recipient": "email",
        "body": "'hello'",
    }

    assert region["metadata"]["arg_variables"] == {
        "recipient": ["email"],
        "body": [],
    }


def test_mixed_positional_and_keyword_arguments():
    code = """
send_direct_message(email, body="hello")
"""

    result = parse(code)
    assert_success(result)

    region = result["regions"][0]

    assert region["metadata"]["arguments"] == {
        "recipient": "email",
        "body": "'hello'",
    }

    assert region["metadata"]["arg_variables"] == {
        "recipient": ["email"],
        "body": [],
    }

# ========================================
# Test 9: F-string assignment is stored as assignment
# ========================================

def test_f_string_assignment_extracts_dependencies():
    code = """
body = f"Here are the messages: {messages}"
"""

    result = parse(code)
    assert_success(result)

    region = result["regions"][0]

    assert region["region_type"] == "assignment"
    assert region["metadata"]["targets"] == ["body"]
    assert region["metadata"]["value"] == "f'Here are the messages: {messages}'"

    assert result["variable_assignments"]["body"]["source"] == "expression"

# ========================================
# Test 10: F-string tool argument records variable dependency
# ========================================

def test_tool_argument_f_string_extracts_variables():
    code = """
send_direct_message("bob@example.com", f"Here are the messages: {messages}")
"""

    result = parse(code)
    assert_success(result)

    region = result["regions"][0]

    assert region["metadata"]["arguments"]["recipient"] == "'bob@example.com'"
    assert region["metadata"]["arguments"]["body"] == "f'Here are the messages: {messages}'"

    assert region["metadata"]["arg_variables"] == {
        "recipient": [],
        "body": ["messages"],
    }

# ========================================
# Test 12: If/else creates conditional region
# ========================================

def test_if_else_region_extraction():
    code = """
if suspicious:
    isolate_host(host)
else:
    create_ticket("benign")
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 1

    region = result["regions"][0]
    assert region["region_type"] == "conditional"

    metadata = region["metadata"]

    assert metadata["condition"] == "suspicious"
    assert metadata["condition_vars"] == ["suspicious"]

    assert metadata["num_true_regions"] == 1
    assert metadata["num_false_regions"] == 1

    true_region = metadata["true_branch_regions"][0]
    false_region = metadata["false_branch_regions"][0]

    assert true_region["region_type"] == "tool_call"
    assert true_region["metadata"]["tool_name"] == "isolate_host"

    assert false_region["region_type"] == "tool_call"
    assert false_region["metadata"]["tool_name"] == "create_ticket"

# ========================================
# Test 13: If without else has empty false branch
# ========================================

def test_if_without_else_region_extraction():
    code = """
if suspicious:
    isolate_host(host)
"""

    result = parse(code)
    assert_success(result)

    region = result["regions"][0]
    metadata = region["metadata"]

    assert region["region_type"] == "conditional"
    assert metadata["condition"] == "suspicious"
    assert metadata["num_true_regions"] == 1
    assert metadata["num_false_regions"] == 0

# ========================================
# Test 14: Nested if keeps nested structure
# ========================================
def test_nested_if_extraction():
    code = """
if suspicious:
    if confirmed:
        isolate_host(host)
else:
    create_ticket("benign")
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 1

    outer = result["regions"][0]
    assert outer["region_type"] == "conditional"

    true_branch = outer["metadata"]["true_branch_regions"]
    false_branch = outer["metadata"]["false_branch_regions"]

    assert len(true_branch) == 1
    assert len(false_branch) == 1

    inner = true_branch[0]
    assert inner["region_type"] == "conditional"
    assert inner["metadata"]["condition"] == "confirmed"

    inner_true = inner["metadata"]["true_branch_regions"]
    assert len(inner_true) == 1
    assert inner_true[0]["metadata"]["tool_name"] == "isolate_host"

    assert false_branch[0]["metadata"]["tool_name"] == "create_ticket"

# ========================================
# Test 15: For loop creates loop region
# ========================================

def test_for_loop_region_extraction():
    code = """
for ip in ips:
    block_ip(ip)
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 1

    region = result["regions"][0]
    assert region["region_type"] == "loop"

    metadata = region["metadata"]

    assert metadata["loop_var"] == "ip"
    assert metadata["iterable"] == "ips"
    assert metadata["num_body_regions"] == 1

    body_region = metadata["body_regions"][0]
    assert body_region["region_type"] == "tool_call"
    assert body_region["metadata"]["tool_name"] == "block_ip"
    assert body_region["metadata"]["arguments"] == {
        "ip": "ip",
    }
    assert body_region["metadata"]["arg_variables"] == {
        "ip": ["ip"],
    }

# ========================================
# Test 16: Loop iterable source is recorded
# ========================================
def test_loop_iterable_source_is_recorded_if_known():
    code = """
ips = read_channel_messages("alerts")
for ip in ips:
    block_ip(ip)
"""

    result = parse(code)
    assert_success(result)

    assert result["num_regions"] == 2

    loop_region = result["regions"][1]
    assert loop_region["region_type"] == "loop"

    iterable_source = loop_region["metadata"]["iterable_source"]

    assert iterable_source is not None
    assert iterable_source["source"] == "tool_call"
    assert iterable_source["tool"] == "read_channel_messages"


# ========================================
# Test 18: Unknown functions are not treated as tools
# ========================================
def test_unknown_function_call_is_not_treated_as_tool_call():
    code = """
x = helper_function(a)
unknown_tool(x)
"""

    result = parse(code)
    assert_success(result)

    # Current behavior:
    # x = helper_function(a) is treated as assignment.
    # unknown_tool(x) is ignored because it is not in TOOL_FUNCTIONS.
    assert result["num_regions"] == 1

    region = result["regions"][0]
    assert region["region_type"] == "assignment"
    assert region["metadata"]["targets"] == ["x"]
    assert region["metadata"]["value"] == "helper_function(a)"

# ========================================
# Test 19: Tuple assignment records all target variables
# ========================================
def test_tuple_assignment_targets():
    code = """
x, y = pair
"""

    result = parse(code)
    assert_success(result)

    region = result["regions"][0]

    assert region["region_type"] == "assignment"
    assert region["metadata"]["targets"] == ["x", "y"]
    assert region["metadata"]["value"] == "pair"

    assert "x" in result["variable_assignments"]
    assert "y" in result["variable_assignments"]

# ========================================
# Test 20: Source line numbers are recorded
# ========================================
def test_line_numbers_are_recorded():
    code = """
messages = read_channel_messages("general")
email = query_ai_assistant(messages, EmailAddress)
send_direct_message(email, "hello")
"""

    result = parse(code)
    assert_success(result)

    regions = result["regions"]

    assert regions[0]["line_start"] == 2
    assert regions[1]["line_start"] == 3
    assert regions[2]["line_start"] == 4