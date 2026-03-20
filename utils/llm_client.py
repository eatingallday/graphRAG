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


def llm_call(
    system: str,
    user: str,
    json_mode: bool = True,
    agent_name: str = "",
    trace_label: str = "",
) -> dict | str:
    """
    Call the LLM and return parsed JSON (or raw string if json_mode=False).
    Strips <think>...</think> blocks that Qwen3 inserts in reasoning mode.
    """
    from utils.debug_logger import trace_event

    trace_event(
        "llm_request",
        {
            "trace_label": trace_label,
            "json_mode": json_mode,
            "system_prompt": system,
            "user_prompt": user,
        },
        agent=agent_name or None,
    )

    client = _get_client()
    messages = [
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ]
    kwargs = {"model": QWEN_MODEL, "messages": messages}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    response = client.chat.completions.create(**kwargs)
    raw_content = response.choices[0].message.content
    trace_event(
        "llm_response_raw",
        {"trace_label": trace_label, "content": raw_content},
        agent=agent_name or None,
    )
    content = raw_content

    # Strip Qwen3 reasoning/thinking blocks
    import re
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    if json_mode:
        # Be resilient: extract first valid JSON object from LLM output
        # Use bracket-counting to handle nested braces correctly
        start = content.find("{")
        if start != -1:
            depth, end = 0, start
            for i in range(start, len(content)):
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            content = content[start:end]
        try:
            parsed = json.loads(content)
            trace_event(
                "llm_response_parsed",
                {"trace_label": trace_label, "parsed": parsed},
                agent=agent_name or None,
            )
            return parsed
        except json.JSONDecodeError:
            # Fix common LLM JSON issues: invalid \escapes
            content = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r'\\\\', content)
            parsed = json.loads(content)
            trace_event(
                "llm_response_parsed",
                {"trace_label": trace_label, "parsed": parsed},
                agent=agent_name or None,
            )
            return parsed
    trace_event(
        "llm_response_text",
        {"trace_label": trace_label, "content": content},
        agent=agent_name or None,
    )
    return content


def llm_call_raw(system: str, user: str, agent_name: str = "", trace_label: str = "") -> str:
    """Return raw text without JSON parsing."""
    return llm_call(
        system,
        user,
        json_mode=False,
        agent_name=agent_name,
        trace_label=trace_label,
    )


def llm_tool_call(
    messages: list[dict],
    tools: list[dict],
    tool_choice: str | dict | None = None,
    agent_name: str = "",
    trace_label: str = "",
):
    """
    支持工具调用的 LLM 请求。返回原始 message 对象（含 tool_calls）。
    不做 JSON 解析，由 agent_loop 负责处理。

    tool_choice=None 时不传该参数（让服务端使用默认行为）。
    强制收尾时传 {"type":"function","function":{"name":"finish"}}。
    """
    from utils.debug_logger import trace_event

    trace_event(
        "llm_tool_request",
        {
            "trace_label": trace_label,
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice,
        },
        agent=agent_name or None,
    )

    client = _get_client()
    kwargs: dict = {
        "model":    QWEN_MODEL,
        "messages": messages,
        "tools":    tools,
    }
    if tool_choice is not None:
        kwargs["tool_choice"] = tool_choice
    response = client.chat.completions.create(**kwargs)
    msg = response.choices[0].message
    trace_event(
        "llm_tool_response",
        {"trace_label": trace_label, "message": msg.model_dump()},
        agent=agent_name or None,
    )
    return msg
