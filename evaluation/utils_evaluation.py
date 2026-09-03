"""
Shared utilities for evaluation scripts.
"""

from __future__ import annotations

import os
from agentdojo import agent_pipeline, functions_runtime


def make_llm(model: str) -> agent_pipeline.BasePipelineElement:
    """Construct an LLM pipeline element for any supported model prefix.

    Handles anthropic:, openai:, google:, local: prefixes — same logic as
    make_tools_pipeline but without building a full pipeline or loading a suite.

    Usage:
        llm = make_llm("anthropic:claude-sonnet-4-20250514")
        _, _, _, messages, _ = llm.query(query, dummy_runtime, messages=history)
    """
    if "google" in model:
        from google import genai
        client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
        max_tokens = 8192 if "lite" in model else 65535
        llm = agent_pipeline.GoogleLLM(model.split(":")[1], client, max_tokens=max_tokens)

    elif "openai" in model:
        import openai as _openai
        client = _openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        _reasoning = any(x in model for x in ("o4", "o3", "o1", "codex"))
        if _reasoning:
            llm = agent_pipeline.OpenAILLM(client, model.split(":")[1], "medium", None)
        else:
            llm = agent_pipeline.OpenAILLM(client, model.split(":")[1], None)

    elif "anthropic" in model:
        import anthropic as _anthropic
        client = _anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        llm = agent_pipeline.AnthropicLLM(client, model.split(":")[1], max_tokens=8192)

    elif "local" in model:
        import openai as _openai
        base_url = os.getenv("LOCAL_MODEL_URL", "http://localhost:11434/v1")
        client = _openai.OpenAI(api_key="not-needed", base_url=base_url)
        llm = agent_pipeline.OpenAILLM(client, model.split(":")[1], None)

    else:
        raise ValueError(f"Unknown model prefix: {model!r}. Expected anthropic:, openai:, google:, or local:")

    llm.name = model.split(":")[1]
    return llm


def make_dummy_runtime() -> functions_runtime.FunctionsRuntime:
    return functions_runtime.FunctionsRuntime()
