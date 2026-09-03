# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module containing the implementation for the PrivilegedLLM."""

import dataclasses
import os
import time
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Optional, TypeVar

import pydantic
import yaml
from agentdojo import agent_pipeline, functions_runtime
from agentdojo import types as ad_types
from agentdojo.agent_pipeline import tool_execution
from agentdojo.default_suites.v1.banking.task_suite import BankingEnvironment
from agentdojo.default_suites.v1.travel.task_suite import TravelEnvironment
from agentdojo.default_suites.v1.workspace.task_suite import (
    WorkspaceEnvironment,
)
from pydantic_ai.models import KnownModelName

from camel import quarantined_llm, system_prompt_generator
from camel.capabilities import is_trusted
from camel.interpreter import interpreter, result
from camel.interpreter import namespace as ns
from camel.interpreter.value import CaMeLValue
from camel.pipeline_elements.agentdojo_function import (
    make_agentdojo_namespace,
)
from camel.pipeline_elements.security_policies import (
    AgentDojoSecurityPolicyEngine,
)

from camel.ext.ctl_policies import get_tool_signatures_for_suite, get_properties_for_suite, get_llm_tools_for_suite
from camel.ext.utils import save_verification_artifacts, log_ctl_event
from camel.ext.verification_integration import (
    CTLVerificationError,
    DEFAULT_MAX_REPAIR_ATTEMPTS,
    make_repair_messages,
    verification_enabled,
    verify_and_repair_code,
    verify_code,
)

# === VISUALISER HELPERS ===== 

_LAST_MODEL_OUTPUT: list[str] = [""]
_LAST_CODE: list[str] = [""]        # Python source of the final plan (after CTL repair if any)
_LAST_CTL_VIOLATIONS: list[list] = [[]]  # initial_violations from last CTL run ([] if CTL didn't fire)
_LAST_CTL_REPAIRS: list[int] = [0]      # number of repair rounds in last CTL run
_LAST_CTL_USER_TASK_ID: list[str | None] = [None]
_LAST_CTL_POLICY_NAMES: list[list[str]] = [[]]
_LAST_PLLM_INPUT_CHARS: list[int] = [0]
_LAST_PLLM_OUTPUT_CHARS: list[int] = [0]


def _msg_chars(msgs: Sequence) -> int:
    """Sum of text character lengths across a sequence of chat messages.

    AgentDojo text blocks use {"type": "text", "content": "..."} — the inner
    key is "content", not "text".  We check both to be safe.
    """
    total = 0
    for m in msgs:
        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("content") or block.get("text") or ""
                else:
                    text = getattr(block, "content", None) or getattr(block, "text", None) or ""
                total += len(text)
    return total


# Now yaml.safe_dump will work with datetime objects
# But you'd need to use yaml.dump instead of yaml.safe_dump
def custom_yaml_dump(obj: dict | list) -> str:
    return yaml.dump(obj, default_flow_style=False)


_T = TypeVar("_T", bound=str | int | float | pydantic.BaseModel)
_E = TypeVar("_E", bound=functions_runtime.TaskEnvironment)


def extract_print_output(tool_calls: Sequence[interpreter.FunctionCall]) -> str:
    """Extracts and concatenates arguments from print calls."""

    printed_output = ""
    print_calls = [tc for tc in tool_calls if tc.function == "print"]
    for print_call in print_calls:
        for arg_value in print_call.args.values():
            printed_output += str(arg_value)
    return printed_output


def function_call_from_ad_function_call(function_call: interpreter.FunctionCall) -> functions_runtime.FunctionCall:
    args = {k: (v if not isinstance(v, type) else repr(v)) for k, v in function_call.args.items()}
    return functions_runtime.FunctionCall(function=function_call.function, args=args)


def make_ad_tool_calls(
    tool_calls: Sequence[interpreter.FunctionCall],
) -> list[tuple[functions_runtime.FunctionCall, Any]]:
    return [
        (
            function_call_from_ad_function_call(tool_call),
            tool_call.output,
        )
        for tool_call in tool_calls
        if not isinstance(tool_call.output, Exception) and not tool_call.is_builtin
    ]


def _safe_extract_code(code: str) -> str:
    try:
        return interpreter.extract_code_block(code)
    except interpreter.InvalidOutputError:
        return code


def _indent(code: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in code.strip().splitlines())


def format_camel_exception(camel_exception: interpreter.CaMeLException, code: str) -> str:
    exception = camel_exception.exception
    node = camel_exception.nodes[-1]
    extracted_code = _safe_extract_code(code)
    formatted_code = _highlight_exception_code(
        extracted_code,
        camel_exception.exception,
        node.lineno,
        node.col_offset if hasattr(node, "col_offset") else 0,
        node.end_lineno if hasattr(node, "end_lineno") else None,
        node.end_col_offset if hasattr(node, "end_col_offset") else None,
    )
    if is_trusted(camel_exception):
        exception_text = str(exception)
    else:
        exception_text = "<The exception was redacted because it came from an untrusted source. Try to infer what the problem was from the context provided.>"
    return f"""
Traceback (most recent call last):
File "<stdin>", line {camel_exception.nodes[-1].lineno}, in <module>
{formatted_code}

{type(exception).__name__}: {exception_text}
"""


def make_error_messages(code: str, interpretation_error: interpreter.CaMeLException) -> list[ad_types.ChatMessage]:
    return [
        ad_types.ChatAssistantMessage(
            role="assistant",
            content=[ad_types.text_content_block_from_string(code)],
            tool_calls=None,
        ),
        ad_types.ChatUserMessage(
            role="user",
            content=[
                ad_types.text_content_block_from_string(f"""\
Running the code gave the following error:
{format_camel_exception(interpretation_error, code)}
Provide the new code with the error fixed. Provide *all the code* so that I \
can directly run it. If the error comes from a search query that did not \
return any results, then try the query with different parameters. The code \
up to the line before the one where the exception was thrown has already been \
executed and the variables and defined classes will \
still be accessible to you. It's very important that you do not re-write code to run \
functions that have side-effects (e.g., functions that send an email).
""")
            ],
        ),
    ]


def _highlight_exception_code(
    code: str,
    exception: Exception,
    lineno: int,
    col_offset: int,
    end_lineno: int | None,
    end_col_offset: int | None,
) -> str:
    """Highlights the affected code in a multi-line Python code string.

    Args:
        code: The multi-line Python code.
        exception: The exception that occurred.
        lineno: The line number where the exception occurred (1-based).
        col_offset: The column offset where the exception occurred (0-based).
        end_lineno: The end line number of the affected code (1-based), or None if it's a single line.
        end_col_offset: The end column offset of the affected code (0-based), or None if it's a single line.

    Returns:
        A string with the affected code highlighted, or an error message if there's an issue.
    """

    lines = code.splitlines(keepends=True)

    if not 1 <= lineno <= len(lines):
        return f"Error: lineno {lineno} is out of range (1-{len(lines)})."

    highlighted_code = ""

    if end_lineno is None or end_lineno == lineno:  # Single line error
        line = lines[lineno - 1]
        highlighted_code += line
        highlighted_code += (
            " " * col_offset + "^" * (1 if end_col_offset is None else max(1, end_col_offset - col_offset)) + "\n"
        )
    elif 1 <= end_lineno <= len(lines) and end_lineno > lineno:  # Multiline error
        for i in range(lineno - 1, end_lineno):
            current_line = lines[i]
            highlighted_code += current_line
            if i == lineno - 1:
                highlighted_code += " " * col_offset + "^" * (len(current_line) - 1 - col_offset) + "\n"
            elif i == end_lineno - 1:
                highlighted_code += (
                    "^" * (len(current_line) - 1 if end_col_offset is None else end_col_offset) + "\n"
                )  # Fixed here
            else:
                highlighted_code += "^" * (len(current_line) - 1) + "\n"

    else:
        return f"Error: end_lineno {end_lineno} is out of range or not after lineno."

    return highlighted_code


def _get_quarantined_llm(model: KnownModelName) -> KnownModelName:
    if "openai" in model and "o1" in model:
        return "openai:gpt-4o"
    return model


class PrivilegedLLM(agent_pipeline.BasePipelineElement):
    """A pipeline element that generates and interprets code expressing the user query.

    Args:
        llm: the LLM to use to generate the code.
        system_prompt_generator: a function which takes as argument the functions available
          to the LLM and returns the system prompt to use.
        security_policies: a list of security policy tuples, where the first element is the tool name and the second one is the security policy to apply.
        eval_mode: the evaluation mode for the interpreter.
        quarantined_llm_retries: the number of retries for the quarantined LLM.
    """

    def __init__(
        self,
        llm: agent_pipeline.BasePipelineElement,
        security_policy_engine: type[AgentDojoSecurityPolicyEngine],
        quarantined_llm_model: KnownModelName,
        system_prompt_generator: Callable[
            [Iterable[functions_runtime.Function], set[str]], str
        ] = system_prompt_generator.default_system_prompt_generator,
        eval_mode: interpreter.MetadataEvalMode = interpreter.MetadataEvalMode.NORMAL,
        quarantined_llm_retries: int = 10,
        max_attempts: int = 3,
        suite_name: str | None = None,
    ) -> None:
        """Initializes the PrivilegedLLM."""
        self.llm = llm
        self.system_prompt_generator = system_prompt_generator
        self.security_policy_engine = security_policy_engine
        self.eval_mode = eval_mode
        self.quarantined_llm_retries = quarantined_llm_retries
        self.dummy_runtime = functions_runtime.FunctionsRuntime()
        self.max_attempts = max_attempts
        self.suite_name = os.environ.get("CAMEL_CTL_SUITE") or suite_name
        # Gemini thinking and o1-* do not support JSON mode, so we fall back to base base Gemini/4o
        self.quarantined_llm_model: KnownModelName = _get_quarantined_llm(quarantined_llm_model)

    def get_side_effect_tools(self) -> list[str]:
        return [policy[0] for policy in self.security_policy_engine.policies]

    def run_code(
        self,
        code: str,
        env: functions_runtime.TaskEnvironment,
        namespace: ns.Namespace,
        dependencies: Iterable[CaMeLValue],
    ) -> tuple[
        str,
        Sequence[tuple[functions_runtime.FunctionCall, functions_runtime.FunctionReturnType]],
        interpreter.CaMeLException | None,  # Add optional error return
        ns.Namespace,
        Iterable[CaMeLValue],
    ]:
        """Interprets the code in `code` by calling the provided functions.

        Args:
            code: a string with the code to interpret
            env: the task environment.
            ad_functions_runtime: the functions runtime.

        Returns:
            A tuple containing the final model output, a list of tuples where the first
            element is the function call that was done and the second one is the result,
            and an optional Exception if one occurred during interpretation.
        """

        # print("=" * 40)
        # print("CODE GENERATED BY P-LLM")
        # print("=" * 40)

        eval_args = interpreter.EvalArgs(self.security_policy_engine(env), self.eval_mode)

        # print(_safe_extract_code(code))

        interpreter_res, updated_namespace, tool_calls, dependencies = interpreter.parse_and_interpret_code(
            code, namespace, [], dependencies, eval_args
        )

        printed_output = extract_print_output(tool_calls)
        ad_tool_calls = make_ad_tool_calls(tool_calls)

        match interpreter_res:
            case result.Error(error):
                return (printed_output, ad_tool_calls, error, updated_namespace, dependencies)  # Return the exception
            case result.Ok(v):
                res = v

        return (
            f"{printed_output}\n{res.raw if res.raw is not None else ''}",
            ad_tool_calls,
            None,
            updated_namespace,
            dependencies,
        )  # No error

    def _generate_and_interpret_code(
        self,
        query: str,
        runtime: functions_runtime.FunctionsRuntime,
        namespace: ns.Namespace,
        env: functions_runtime.TaskEnvironment,
        messages: Sequence[ad_types.ChatMessage],
        privileged_llm_messages: Sequence[ad_types.ChatMessage],
        system_prompt: str,
        previous_printed_output: str,
        dependencies: Iterable[CaMeLValue], 
        user_task_id: Optional[str] = None, #for us to iterate through the loop
        repair_system_prompt: str = "", # beginning-empty
    ) -> tuple[
        str,
        Sequence[tuple[functions_runtime.FunctionCall, functions_runtime.FunctionReturnType]],
        interpreter.CaMeLException | Exception | None,
        list[ad_types.ChatMessage],
        list[ad_types.ChatMessage],
        ns.Namespace,
        Iterable[CaMeLValue],
    ]:
        if len(privileged_llm_messages) == 0:
            privileged_llm_messages = [
                ad_types.ChatSystemMessage(
                    role="system", content=[ad_types.text_content_block_from_string(system_prompt)]
                ),
                ad_types.ChatUserMessage(role="user", content=[ad_types.text_content_block_from_string(query)]),
            ]

        code = None
        attempts = 5
        while (code is None or code == "") and attempts > 0:

            _LAST_PLLM_INPUT_CHARS[0] += _msg_chars(privileged_llm_messages) #count

            _, _, _, [*_, code_message], _ = self.llm.query(
                query=query,
                runtime=self.dummy_runtime,
                messages=privileged_llm_messages,
            )
            _LAST_PLLM_OUTPUT_CHARS[0] += _msg_chars([code_message]) # count output
            if self.llm.name is not None and "gemini" in self.llm.name and "exp" in self.llm.name:
                time.sleep(6)
            assert code_message["role"] == "assistant"
            if code_message["content"]:
                code = ad_types.get_text_content_as_str(code_message["content"])
            attempts -= 1

        if code is None or code == "":
            empty_message = ad_types.ChatAssistantMessage(
                role="assistant",
                content=[
                    ad_types.text_content_block_from_string(
                        "The generated code was `None`. This message is added by the system does not come from the assistant."
                    )
                ],
                tool_calls=None,
            )
            return (
                previous_printed_output,
                [],
                None,
                [*messages, empty_message],
                list(privileged_llm_messages),
                namespace,
                dependencies,
            )
        
        # phase1: generation - plan text and no execution

        extracted_code = _safe_extract_code(code)

        from camel.ext.delamda import delamda
        extracted_code = delamda(extracted_code)
        code = f"```python\n{extracted_code}\n```"


        _LAST_CODE[0] = extracted_code # this is the raw python plan.

        effective_user_task_id = user_task_id or os.getenv("CAMEL_USER_TASK_ID") or None #evaluation purposes.

        # ======= REPAIR LOOP BEGINS ======= CTL here #
        if verification_enabled() and self.suite_name:
            tool_signatures = dict(get_tool_signatures_for_suite(self.suite_name))

            for llm_tool in get_llm_tools_for_suite(self.suite_name):
                if llm_tool == "query_ai_assistant":
                    tool_signatures.setdefault(llm_tool, ["query", "output_schema"])
                else:
                    tool_signatures.setdefault(llm_tool, ["query"])

            tool_functions = list(tool_signatures.keys())
            ctl_properties = get_properties_for_suite(
                self.suite_name,
                user_task_id=effective_user_task_id,
            )

            _LAST_CTL_USER_TASK_ID[0] = effective_user_task_id
            _LAST_CTL_POLICY_NAMES[0] = [prop.name for prop in ctl_properties]

            initial_feedback = verify_code(
                extracted_code,
                tool_functions,
                tool_signatures,
                self.suite_name,
                save_artifacts=False,
                user_task_id=effective_user_task_id,
            )

            initial_violations = (
                initial_feedback.verification_result.properties_violated
                if initial_feedback.verification_result
                else []
            )

            _LAST_CTL_VIOLATIONS[0] = initial_violations
            _LAST_CTL_REPAIRS[0] = 0

            _repair_system_msg = (
                ad_types.ChatSystemMessage(
                    role="system",
                    content=[ad_types.text_content_block_from_string(repair_system_prompt)],
                )
                if repair_system_prompt
                else privileged_llm_messages[0]
            )

            def _llm_generate_repair(
                repair_messages: list[ad_types.ChatMessage],
            ) -> str:
                full_msgs = [_repair_system_msg, *repair_messages]
                _LAST_PLLM_INPUT_CHARS[0] += _msg_chars(full_msgs)
                _, _, _, [*_, repair_msg], _ = self.llm.query(
                    query=query,
                    runtime=self.dummy_runtime,
                    messages=full_msgs,
                )
                _LAST_PLLM_OUTPUT_CHARS[0] += _msg_chars([repair_msg])

                repaired_raw = (
                    ad_types.get_text_content_as_str(repair_msg["content"])
                    if repair_msg["content"]
                    else ""
                )

                if not repaired_raw:
                    return extracted_code

                return _safe_extract_code(repaired_raw)

            try:
                repaired_code, final_feedback = verify_and_repair_code(
                    generated_code=extracted_code,
                    tool_functions=tool_functions,
                    tool_signatures=tool_signatures,
                    suite_name=self.suite_name,
                    max_repair_attempts=int(os.environ.get("CAMEL_MAX_REPAIRS", DEFAULT_MAX_REPAIR_ATTEMPTS)),
                    llm_generate_fn=_llm_generate_repair,
                    save_artifacts=True,
                    user_query=query,
                    user_task_id=effective_user_task_id,
                )

                repairs = final_feedback.repairs

                extracted_code = repaired_code # the last
                _LAST_CODE[0] = extracted_code # visualiser addition
                code = f"```python\n{repaired_code}\n```"

                _LAST_CTL_REPAIRS[0] = repairs # visualiser addition - repair rounds needed

                log_ctl_event(
                    suite=self.suite_name,
                    query=query,
                    initial_violations=initial_violations,
                    repairs=repairs,
                    status="pass",
                )

                if initial_violations or repairs:
                    print("\n[CTL] Verification/rewrite completed.")
                    print(f"[CTL] Initial violations: {initial_violations}")
                    print(f"[CTL] Repairs: {repairs}")

                privileged_llm_messages = [
                    *list(privileged_llm_messages)[:2],
                    ad_types.ChatAssistantMessage(
                        role="assistant",
                        content=[ad_types.text_content_block_from_string(code)],
                        tool_calls=None,
                    ),
                ]

            except CTLVerificationError as exc:
                final_violations = []
                if exc.feedback.verification_result:
                    final_violations = exc.feedback.verification_result.properties_violated
                elif exc.feedback.counterexamples:
                    final_violations = exc.feedback.counterexamples

                # banner = (
                #     f"[CTL-BLOCKED] Plan rejected after {exc.repairs} repair attempt(s). "
                #     f"Violated properties: {final_violations}. No tool calls were executed."
                # )

                # print(f"\n{'!' * 60}\n{banner}\n{'!' * 60}")

                log_ctl_event(
                    suite=self.suite_name,
                    query=query,
                    initial_violations=initial_violations,
                    repairs=exc.repairs,
                    status="fail",
                    final_violations=final_violations,
                )

                _LAST_CODE[0] = extracted_code # visualiser addition
                _LAST_CTL_REPAIRS[0] = exc.repairs # visualiser addition
                raise
        model_output, tool_calls_results, interpretation_error, namespace, dependencies = self.run_code(
            code, env, namespace, dependencies
        )

        # last phase if repair works fine or not.

        tool_calls: list[functions_runtime.FunctionCall] = []
        tool_call_messages: list[ad_types.ChatMessage] = []

        for tool_call, tool_result in tool_calls_results:
            tool_call_messages.append(
                ad_types.ChatToolResultMessage(
                    role="tool",
                    tool_call=tool_call,
                    content=[
                        ad_types.text_content_block_from_string(
                            tool_execution.tool_result_to_str(tool_result, dump_fn=custom_yaml_dump)
                        )
                    ],
                    tool_call_id=None,
                    error=None,
                )
            )
            tool_calls.append(tool_call)

        if interpretation_error:
            error_messages = make_error_messages(code, interpretation_error)
            updated_messages = [*messages, *tool_call_messages, *error_messages]
            privileged_llm_messages = [*privileged_llm_messages, *error_messages]
        else:
            updated_messages = [
                *messages,
                ad_types.ChatAssistantMessage(
                    role="assistant",
                    content=[ad_types.text_content_block_from_string(code)],
                    tool_calls=tool_calls,
                ),
                *tool_call_messages,
                ad_types.ChatAssistantMessage(
                    role="assistant",
                    content=[ad_types.text_content_block_from_string(previous_printed_output + model_output)],
                    tool_calls=None,
                ),
            ]
            print("~" * 40)
            print("Code accepted!")
            policy_engine_instance = self.security_policy_engine(env)
            allowed_tools = policy_engine_instance.get_allowed_tools()
            if os.getenv("CAMEL_SKIP_EXECUTION_ARTIFACTS", "false").lower() not in (
                "true",
                "1",
                "yes",
            ):
                save_verification_artifacts(
                    code=extracted_code,
                    env=env,
                    allowed_tools=allowed_tools,
                    suite_name=self.suite_name,
                    query=query,
                    conversation=privileged_llm_messages,
                    tool_calls_results=tool_calls_results,
                )
            print("~" * 40)

        return (
            previous_printed_output + model_output,
            tool_calls_results,
            interpretation_error,
            updated_messages,
            list(privileged_llm_messages),
            namespace,
            dependencies,
        )

    def query(
        self,
        query: str,
        runtime: functions_runtime.FunctionsRuntime,
        env: _E = functions_runtime.EmptyEnv(),
        messages: Sequence[ad_types.ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[
        str,
        functions_runtime.FunctionsRuntime,
        _E,
        Sequence[ad_types.ChatMessage],
        dict,
    ]:
        """Generates and interprets code which expresses the user query."""
        _LAST_PLLM_INPUT_CHARS[0] = 0 #counting the tokens for evaluation.
        _LAST_PLLM_OUTPUT_CHARS[0] = 0 #counting the tokens for evaluation.

        privileged_llm_messages = []

        def query_ai_assistant(query: str, output_schema: type[_T]) -> _T:
            return quarantined_llm.query_quarantined_llm(
                llm=(self.quarantined_llm_model),
                query=query,
                output_schema=output_schema,
                retries=self.quarantined_llm_retries,
            )

        query_ai_assistant.__doc__ = quarantined_llm.query_quarantined_llm.__doc__
        runtime.register_function(query_ai_assistant)

        builtins_namespace = ns.Namespace.with_builtins()
        # Models get confused in the other suites and should not use datetime stuff
        classes_to_exclude = (
            {
                "datetime",
                "timedelta",
                "date",
                "time",
                "NaiveDatetime",
                "timezone",
            }
            if not isinstance(env, WorkspaceEnvironment | TravelEnvironment)
            else set()
        )

        system_prompt = self.system_prompt_generator(runtime.functions.values(), classes_to_exclude)
        repair_system_prompt = system_prompt_generator.make_repair_system_prompt(runtime.functions.values()) # we  still want in our repair prompt to have the function values. 

        if isinstance(env, BankingEnvironment):
            system_prompt += "\n\nNote that, in the transaction history, the transactions from the user have 'me' as sender, and still habe positive amounts."

        if not isinstance(env, WorkspaceEnvironment):
            new_variables = {k: v for k, v in builtins_namespace.variables.items() if k not in classes_to_exclude}
            builtins_namespace = dataclasses.replace(builtins_namespace, variables=new_variables)

        namespace = builtins_namespace.add_variables(make_agentdojo_namespace(builtins_namespace, runtime, env))

        model_output = ""
        dependencies = ()

        for _ in range(self.max_attempts):
            (model_output, _, interpretation_error, messages, privileged_llm_messages, namespace, dependencies) = (
                self._generate_and_interpret_code(
                    query,
                    runtime,
                    namespace,
                    env,
                    messages,
                    privileged_llm_messages,
                    system_prompt,
                    model_output,
                    dependencies,
                    user_task_id=extra_args.get("user_task_id"),
                    repair_system_prompt=repair_system_prompt,
                )
            )

            if not interpretation_error:
                break

        extra_args["camel_namespace"] = namespace
        _LAST_MODEL_OUTPUT[0] = model_output or ""
        if messages[-1]["role"] == "user" and "\n\nTraceback" in ad_types.get_text_content_as_str(
            messages[-1]["content"]
        ):
            messages = [*messages, ad_types.ChatAssistantMessage(role="assistant", content=None, tool_calls=None)]

        return query, runtime, env, messages, extra_args
