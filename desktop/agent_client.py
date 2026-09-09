from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class AgentConfig:
    base_url: str
    api_key: str
    model: str
    auth_mode: str = "bearer"
    auth_header: str = "Authorization"
    timeout: int = 60


class AgentError(RuntimeError):
    pass


def chat(config: AgentConfig, system_prompt: str, user_prompt: str | list[dict[str, str]]) -> str:
    base = config.base_url.strip().rstrip("/")
    if not base:
        raise AgentError("请先填写 API 地址")
    if not config.model.strip():
        raise AgentError("请先填写模型名称")
    if base.endswith("/chat/completions"):
        url = base
    elif base.endswith("/v1"):
        url = base + "/chat/completions"
    else:
        url = base + "/v1/chat/completions"
    messages = user_prompt if isinstance(user_prompt, list) else [{"role": "user", "content": user_prompt}]
    payload = json.dumps({
        "model": config.model.strip(),
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "temperature": 0.2,
        "stream": False,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = config.api_key.strip()
    if key:
        if config.auth_mode == "raw":
            headers[config.auth_header.strip() or "Authorization"] = key
        elif config.auth_mode == "x-api-key":
            headers["x-api-key"] = key
        else:
            if key.lower().startswith("bearer "):
                key = key[7:].strip()
            headers["Authorization"] = "Bearer " + key
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=config.timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        if exc.code == 401:
            raise AgentError(f"API 认证失败（HTTP 401）：{detail}\n请检查：API 地址是否为 OpenAI 兼容接口、Key 是否重复填写 Bearer、认证方式是否应改为 x-api-key。请求地址：{url}") from exc
        raise AgentError(f"API 请求失败（HTTP {exc.code}）：{detail}") from exc
    except urllib.error.URLError as exc:
        raise AgentError(f"无法连接 API：{exc.reason}") from exc
    except TimeoutError as exc:
        raise AgentError("API 请求超时，请检查地址或网络") from exc
    try:
        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise AgentError("API 返回格式不是 OpenAI Chat Completions 格式") from exc
    if not isinstance(content, str) or not content.strip():
        raise AgentError("API 返回了空答案")
    return content.strip()
