#!/usr/bin/env python3
"""
响应处理工具函数
"""

import json
import os
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from curl_cffi import requests as curl_requests


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
        return response.json()
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