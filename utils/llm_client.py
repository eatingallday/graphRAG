"""
Unified OpenAI-compatible LLM client (Qwen / any OSS endpoint).
"""
import json
import httpx
from openai import OpenAI
from config import QWEN_MODEL, QWEN_BASE_URL, QWEN_API_KEY

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        # Use system proxy (SOCKS proxy needed to reach the Qwen endpoint).
        # socksio must be installed: pip install "httpx[socks]"
        _client = OpenAI(base_url=QWEN_BASE_URL, api_key=QWEN_API_KEY)
    return _client


def llm_call(system: str, user: str, json_mode: bool = True) -> dict | str:
    """
    Call the LLM and return parsed JSON (or raw string if json_mode=False).
    Strips <think>...</think> blocks that Qwen3 inserts in reasoning mode.
    """
    client = _get_client()
    messages = [
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ]
    kwargs = {"model": QWEN_MODEL, "messages": messages}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    response = client.chat.completions.create(**kwargs)
    content = response.choices[0].message.content

    # Strip Qwen3 reasoning/thinking blocks
    import re
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    if json_mode:
        # Be resilient: extract first JSON object if model wraps it in text
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            content = match.group(0)
        return json.loads(content)
    return content


def llm_call_raw(system: str, user: str) -> str:
    """Return raw text without JSON parsing."""
    return llm_call(system, user, json_mode=False)
