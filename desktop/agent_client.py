from __future__ import annotations

import json
import os
import ssl
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


def _ssl_context() -> ssl.SSLContext:
    """显式使用 macOS 系统 CA，避免 Finder 启动环境污染 SSL_CERT_FILE。"""
    system_ca = "/private/etc/ssl/cert.pem"
    if os.path.isfile(system_ca):
        return ssl.create_default_context(cafile=system_ca)
    return ssl.create_default_context()


def _resolve_url(config: AgentConfig) -> str:
    base = config.base_url.strip().rstrip("/")
    if not base:
        raise AgentError("请先填写 API 地址")
    if not config.model.strip():
        raise AgentError("请先填写模型名称")
    if base.endswith("/chat/completions"):
        return base
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


def _auth_headers(config: AgentConfig) -> dict:
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
    return headers


def _post_json(config: AgentConfig, payload: dict) -> dict:
    url = _resolve_url(config)
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=_auth_headers(config), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=config.timeout, context=_ssl_context()) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        if exc.code == 401:
            raise AgentError(f"API 认证失败（HTTP 401）：{detail}\n请检查 API 地址/Key/认证方式。请求地址：{url}") from exc
        raise AgentError(f"API 请求失败（HTTP {exc.code}）：{detail}") from exc
    except urllib.error.URLError as exc:
        raise AgentError(
            f"无法连接 API：{exc.reason}\n请求地址：{url}\nPython：{__import__('sys').executable}"
        ) from exc
    except TimeoutError as exc:
        raise AgentError("API 请求超时，请检查地址或网络") from exc
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise AgentError("API 返回不是合法 JSON") from exc


def chat_completion(config: AgentConfig, messages: list[dict], tools: list[dict] | None = None) -> dict:
    """单次 Chat Completions 请求，返回完整响应 JSON。

    返回值里 `choices[0].message` 可能是普通文本（content），也可能带
    `tool_calls`（content 为 None）。由调用方（agent_loop）决定下一步。
    """
    payload: dict = {
        "model": config.model.strip(),
        "messages": messages,
        "temperature": 0.2,
        "stream": False,
    }
    if tools:
        payload["tools"] = tools
    return _post_json(config, payload)


def extract_message(resp: dict) -> dict:
    """从响应里取出 choices[0].message，失败抛 AgentError。"""
    try:
        return resp["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AgentError("API 返回不是 OpenAI Chat Completions 格式") from exc


def chat(config: AgentConfig, system_prompt: str, user_prompt: str | list[dict[str, str]]) -> str:
    """兼容旧接口：单轮文本问答，返回纯文本内容。"""
    messages = user_prompt if isinstance(user_prompt, list) else [{"role": "user", "content": user_prompt}]
    full = [{"role": "system", "content": system_prompt}] + messages
    resp = chat_completion(config, full)
    msg = extract_message(resp)
    content = msg.get("content")
    if not isinstance(content, str) or not content.strip():
        raise AgentError("API 返回了空答案")
    return content.strip()
