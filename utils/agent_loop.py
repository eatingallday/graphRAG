"""
通用 Budget-Aware ReAct 循环引擎（JSON 模拟工具调用版）。

由于 Qwen vLLM 后端不支持原生 function calling，
改用 JSON 模式模拟：LLM 每轮输出 {"tool": "名称", "args": {...}}，
引擎解析后调用对应的 Python 函数，把结果拼入下一轮的历史记录。

与 Android / Neo4j 完全解耦，只负责：
  1. 循环调用 LLM（json_mode=True）
  2. 每轮把操作历史 + 预算提示拼入 user 消息
  3. 解析 {"tool", "args"} 并执行
  4. 检测 finish 退出（早退）
  5. 超出 max_loops 时强制收尾
"""
import json
from utils.llm_client import llm_call


# ── 内部辅助 ──────────────────────────────────────────────────────────────────

def _budget_hint(remaining: int, is_last: bool) -> str:
    if is_last:
        return "[⚠️ 最后一轮] 请勿再查询新信息，直接调用 finish 输出当前最佳结论。"
    if remaining == 2:
        return f"[预算] 还剩 {remaining} 轮（含本轮）。建议本轮做最后补充，下轮直接收尾。"
    return f"[预算] 还剩 {remaining} 轮（含本轮）。请合理规划，优先查询影响最大的信息。"


def _build_user_msg(original_task: str, history: list[dict],
                    remaining: int, is_last: bool) -> str:
    """把原始任务 + 历史记录 + 预算提示拼成本轮 user 消息。"""
    parts = [original_task]

    if history:
        parts.append("\n=== 已执行的操作记录 ===")
        for i, step in enumerate(history, 1):
            args_str = json.dumps(step["args"], ensure_ascii=False)
            result_preview = str(step["result"])[:400].replace("\n", " ")
            parts.append(f"第{i}轮：{step['tool']}({args_str})\n  → {result_preview}")

    parts.append(f"\n{_budget_hint(remaining, is_last)}")
    parts.append(
        "\n请输出下一步操作（严格 JSON，只输出 JSON，不要其他文字）：\n"
        '{"tool": "工具名", "args": {"参数名": 值}}'
    )
    return "\n".join(parts)


# ── 公共入口 ──────────────────────────────────────────────────────────────────

def run_agent_loop(
    agent_name: str,
    system_prompt: str,
    first_user_msg: str,
    tool_executors: dict,
    max_loops: int,
) -> dict:
    """
    运行 Budget-Aware ReAct 循环。

    参数：
        agent_name    : 用于日志标记，如 "taint_agent"
        system_prompt : 描述任务目标 + 可用工具（含 finish 格式）的 system 消息
        first_user_msg: 任务详情（首轮 user 消息主体，后续每轮复用）
        tool_executors: {tool_name: callable(**kwargs) -> str}
                        finish 无需注册，由引擎特殊处理
        max_loops     : 最大循环轮数

    返回：
        finish 工具的 args 字典，附加：
          - conclude_reason : "early_finish" | "forced"
          - loops_used      : int
    """
    history: list[dict] = []

    for loop_idx in range(max_loops):
        remaining = max_loops - loop_idx
        is_last   = (remaining == 1)

        user_msg  = _build_user_msg(first_user_msg, history, remaining, is_last)
        response  = llm_call(system_prompt, user_msg, json_mode=True)

        tool_name = response.get("tool", "")
        args      = response.get("args", {})
        if not isinstance(args, dict):
            args = {}

        # finish → 提前退出
        if tool_name == "finish":
            args["conclude_reason"] = "early_finish"
            args["loops_used"]      = loop_idx + 1
            print(f"[{agent_name}] 主动完成（第 {loop_idx+1}/{max_loops} 轮）")
            return args

        # 执行普通工具
        executor = tool_executors.get(tool_name)
        if executor is None:
            result = f"[错误] 未知工具: {tool_name!r}，请从可用工具列表中选择"
        else:
            try:
                result = str(executor(**args))
            except Exception as e:
                result = f"[工具执行错误] {tool_name}: {e}"

        preview = str(result)[:120].replace("\n", " ")
        print(f"[{agent_name}] 第 {loop_idx+1} 轮 → {tool_name}() → {preview}...")
        history.append({"tool": tool_name, "args": args, "result": result})

    # ── 强制收尾 ──────────────────────────────────────────────────────────────
    print(f"[{agent_name}] 达到最大轮数 {max_loops}，强制收尾")
    force_msg = _build_user_msg(first_user_msg, history, 1, is_last=True)
    force_msg += (
        "\n\n必须立即调用 finish，即使信息不完整也要给出判断。"
        "\n输出格式：{\"tool\": \"finish\", \"args\": {...}}"
    )
    response = llm_call(system_prompt, force_msg, json_mode=True)

    tool_name = response.get("tool", "")
    args      = response.get("args", {})
    if not isinstance(args, dict):
        args = {}

    if tool_name == "finish" or args:
        args["conclude_reason"] = "forced"
        args["loops_used"]      = max_loops
        return args

    # 终极兜底
    print(f"[{agent_name}] 强制收尾失败，返回空结构")
    return {"conclude_reason": "forced", "loops_used": max_loops}
