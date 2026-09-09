from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def collect_context() -> str:
    parts = []
    readme = ROOT / "README.md"
    todo = ROOT / "TODO.md"
    if readme.exists():
        parts.append("=== 项目 README ===\n" + readme.read_text(encoding="utf-8", errors="replace")[:12000])
    if todo.exists():
        parts.append("=== 项目 TODO ===\n" + todo.read_text(encoding="utf-8", errors="replace"))
    try:
        status = subprocess.run(["git", "status", "--short", "--branch"], cwd=ROOT, text=True, capture_output=True, timeout=10)
        parts.append("=== Git 状态 ===\n" + status.stdout)
    except Exception as exc:
        parts.append(f"=== Git 状态读取失败 ===\n{exc}")
    return "\n\n".join(parts)


def compose_prompt(action: str, user_text: str, context: str) -> str:
    task = {
        "explain": "请用中文解释当前实验，按‘现象、关键步骤、结果含义、安全边界’组织，避免空话。",
        "diagnose": "请诊断当前双机通信或测试日志，明确指出通过项、失败原因和下一步修复动作；不要臆造日志中没有的数据。",
        "conclusion": "请根据当前真实项目资料生成一段适合写入实验记录的中文结论，包含已验证内容、局限和可复现实验命令。",
    }.get(action, "请分析当前实验。")
    return f"{task}\n\n用户补充：{user_text or '无'}\n\n以下是本地项目上下文：\n{context[:30000]}"
