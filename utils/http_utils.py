#!/usr/bin/env python3
"""
响应处理工具函数
"""

import json
import os
import re
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from curl_cffi import requests as curl_requests


SENSITIVE_KEY_PATTERN = re.compile(
    r"(authorization|access[_-]?token|api[_-]?key|code|cookie|password|passwd|secret|session|state|token)",
    re.IGNORECASE,
)


def _debug_enabled() -> bool:
    return os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")


def _redact_debug_value(value):
    """递归脱敏调试响应中的凭据字段，避免日志变成凭据副本。"""
    if isinstance(value, dict):
        return {
            key: "***REDACTED***" if SENSITIVE_KEY_PATTERN.search(str(key)) else _redact_debug_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_debug_value(item) for item in value]
    return value


def _redact_debug_url(url: str) -> str:
    """保留调试 URL 结构，但隐藏 OAuth code/state 等敏感查询参数。"""
    parsed = urlparse(url)
    query = [
        (key, "***REDACTED***" if SENSITIVE_KEY_PATTERN.search(key) else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse(parsed._replace(query=urlencode(query)))


def _save_debug_response(response: curl_requests.Response, context: str, account_name: str, body):
    safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
    safe_context = "".join(c if c.isalnum() else "_" for c in context)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)
    filepath = os.path.join(logs_dir, f"{safe_account_name}_{timestamp}_{safe_context}_response.json")
    debug_record = {
        "context": context,
        "status_code": response.status_code,
        "url": _redact_debug_url(response.url),
        "content_type": response.headers.get("content-type", ""),
        "body": _redact_debug_value(body),
    }
    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(debug_record, file, ensure_ascii=False, indent=2)
    print(f"📝 {account_name}: Debug response saved to: {filepath}")


def proxy_resolve(proxy_config: dict | None = None) -> str | None:
    """将 proxy_config 转换为代理 URL 字符串

    Args:
        proxy_config: 代理配置字典

    Returns:
        代理 URL 字符串，如果没有配置代理则返回 None
    """
    if not proxy_config:
        return None

    proxy_url = proxy_config.get("server")
    if not proxy_url:
        return None

    username = proxy_config.get("username")
    password = proxy_config.get("password")

    if username and password:
        # 解析 URL 并添加认证信息
        parsed = urlparse(proxy_url)
        # 构建带认证的 URL
        netloc = f"{username}:{password}@{parsed.hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

    return proxy_url


def response_resolve(
    response: curl_requests.Response,
    context: str,
    account_name: str,
) -> dict | None:
    """检查响应类型，如果是 HTML 则保存为文件，否则返回 JSON 数据

    Args:
        response: curl_cffi Response 对象
        context: 上下文描述，用于生成文件名
        account_name: 账号名称（用于日志和文件名）

    Returns:
        JSON 数据字典，如果响应是 HTML 则返回 None
    """
    safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)

    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    try:
        json_data = response.json()
        if _debug_enabled():
            _save_debug_response(response, context, account_name, json_data)
        return json_data
    except json.JSONDecodeError as e:
        print(f"❌ {account_name}: Failed to parse JSON response: {e}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_context = "".join(c if c.isalnum() else "_" for c in context)

        content_type = response.headers.get("content-type", "").lower()

        if "text/html" in content_type or "text/plain" in content_type:
            filename = f"{safe_account_name}_{timestamp}_{safe_context}.html"
            filepath = os.path.join(logs_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(response.text)

            print(f"⚠️ {account_name}: Received HTML response, saved to: {filepath}")
        else:
            filename = f"{safe_account_name}_{timestamp}_{safe_context}_invalid.txt"
            filepath = os.path.join(logs_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(response.text)

            print(f"⚠️ {account_name}: Invalid response saved to: {filepath}")
        return None
    except Exception as e:
        print(f"❌ {account_name}: Error occurred while checking and handling response: {e}")
        return None