from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .agent_client import AgentConfig, chat_completion, extract_message
from .agent_schemas import TOOLS

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "desktop" / "agent_cli.py"

# 白名单：合法工具名（由 schema 派生，执行前再校验一次，杜绝任意命令）
VALID_TOOLS = {t["function"]["name"] for t in TOOLS}

SYSTEM_PROMPT = """你是运行在密码学实验系统内部的「密码学应用编排器」。用户用自然语言描述一个加密、签名或校验需求，你调用系统提供的密码原语工具，把它们编排成完整的高层应用流程（如混合加密、数字签名、加密保险箱）。

你可以调用这些工具（输出均为 JSON）：
- make_key / sym_encrypt / sym_decrypt：对称密码的生成密钥、加密、解密
- pubkey_keygen / pubkey_encrypt / pubkey_decrypt：公钥密码的生成密钥对、公钥加密、私钥解密
- sign / verify：SM2 数字签名与验签
- hash：MD5/SM3 散列
- hmac：HMAC-SHA256 完整性校验

编排规则：
1. 动手前先在脑中规划完整步骤，再逐条调用工具。
2. 只调用给定的工具，不虚构工具或结果；工具返回的是真实算法输出。
3. 中间值（密钥、密文、签名、摘要）按工具返回的原样传递，不要改动或编造。
4. 每一步根据真实结果决定下一步；工具报错时分析原因、调整参数重试。
5. 数据格式：对称密钥与密文是 hex；公钥/私钥是十进制（冒号分隔）；签名是十进制 "r:s"。
6. 最终用中文输出：先概述执行的步骤，再给出最终产物（如数字信封、密文、验签结论）。

编排范例（供参考，不必照搬）：
- 混合加密（数字信封）：make_key(aes) 得会话密钥 K → sym_encrypt(aes, 消息, K) 得密文 C1 → pubkey_keygen(rsa) 得公钥 P/私钥 S → pubkey_encrypt(rsa, K, P) 得 C2 → 数字信封 = {C2, C1}。解密：pubkey_decrypt(rsa, C2, S) 还原 K → sym_decrypt(aes, C1, K) 还原消息。（会话密钥 K 是 hex 字符串，可直接作为 pubkey_encrypt 的 text 参数。）
- 数字签名：hash(md5, 消息) 得摘要 H → sign(sm2, H, 私钥, 公钥) 得签名 σ → verify(sm2, H, σ, 公钥) 验签。
- 加密保险箱：make_key(aes, seed=口令) 得密钥 K → sym_encrypt(aes, 秘密, K) 存密文 → 取回时 sym_decrypt(aes, 密文, K)。"""


def execute_tool(name: str, args: dict) -> tuple[str, bool]:
    """执行一个工具：spawn agent_cli.py 对应子命令，返回 (结果文本, 是否成功)。"""
    if name not in VALID_TOOLS:
        return f"未知工具: {name}", False
    cmd = [sys.executable, str(CLI), name]
    for key, value in args.items():
        if value is None:
            continue
        cmd += [f"--{key}", str(value)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return "工具执行超时", False
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    if p.returncode == 0:
        return out, True
    return (err + ("\n" + out if out else "")).strip(), False


def run_agent(config: AgentConfig, user_request: str, on_step=None, max_steps: int = 12):
    """ReAct 循环：think → act → observe，直到模型给出最终结论或达到步数上限。

    返回 (final_answer: str, steps: list)。steps 供 UI 展示编排过程：
    [{"type":"thought","content":...}, {"type":"tool_call","name":..., "args":..., "result":..., "ok":...}]
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_request},
    ]
    steps: list[dict] = []

    for _ in range(max_steps):
        resp = chat_completion(config, messages, TOOLS)
        msg = extract_message(resp)
        tool_calls = msg.get("tool_calls")

        if not tool_calls:
            return msg.get("content") or "（无输出）", steps

        if msg.get("content"):
            steps.append({"type": "thought", "content": msg["content"]})

        messages.append(msg)  # assistant 消息（含 tool_calls）入历史

        for tc in tool_calls:
            fn = tc["function"]
            name = fn["name"]
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            result, ok = execute_tool(name, args)
            step = {"type": "tool_call", "name": name, "args": args, "result": result, "ok": ok}
            steps.append(step)
            if on_step:
                on_step(step)
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})

    return "已达到最大执行步数，请缩小任务范围重试。", steps
