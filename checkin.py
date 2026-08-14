#!/usr/bin/env python3
"""
CheckIn 类
"""

import asyncio
import json
import inspect
import hashlib
import os
import tempfile
from urllib.parse import urlparse, urlencode

from curl_cffi import requests as curl_requests
from camoufox.async_api import AsyncCamoufox
from utils.config import AccountConfig, ProviderConfig
from utils.browser_utils import parse_cookies, filter_cookies, get_random_user_agent, take_screenshot, aliyun_captcha_check
from utils.get_cf_clearance import get_cf_clearance
from utils.http_utils import proxy_resolve, response_resolve
from utils.topup import topup
from utils.get_headers import get_browser_headers, get_curl_cffi_impersonate, print_browser_headers
from utils.mask_utils import mask_username

class CheckIn:
    """newapi.ai 签到管理类"""

    def __init__(
        self,
        account_name: str,
        account_config: AccountConfig,
        provider_config: ProviderConfig,
        global_proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
    ):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
                proxy_config: 全局代理配置(可选)
        """
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.account_config = account_config
        self.provider_config = provider_config

        # 将全局代理存入 account_config.extra，供 get_cdk 和 check_in_status 等函数使用
        if global_proxy:
            self.account_config.extra["global_proxy"] = global_proxy

        # 代理优先级: 账号配置 > 全局配置
        self.camoufox_proxy_config = account_config.proxy if account_config.proxy else global_proxy
        # curl_cffi proxy 转换
        self.http_proxy_config = proxy_resolve(self.camoufox_proxy_config)

        # storage-states 目录
        self.storage_state_dir = storage_state_dir

        os.makedirs(self.storage_state_dir, exist_ok=True)

    async def get_waf_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取 WAF cookies（隐私模式）"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get WAF cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_waf_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    cookies = await browser.cookies()

                    waf_cookies = {}
                    print(f"ℹ️ {self.account_name}: WAF cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"] and cookie_value is not None:
                            waf_cookies[cookie_name] = cookie_value

                    print(f"ℹ️ {self.account_name}: Got {len(waf_cookies)} WAF cookies after step 1")

                    # 检查是否至少获取到一个 WAF cookie
                    if not waf_cookies:
                        print(f"❌ {self.account_name}: No WAF cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(waf_cookies.keys())
                    print(f"✅ {self.account_name}: Successfully got WAF cookies: {cookie_names}")

                    return waf_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting WAF cookies: {e}")
                    return None
                finally:
                    await page.close()

    async def get_aliyun_captcha_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取阿里云验证 cookies"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get Aliyun captcha cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_aliyun_captcha_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                        # # 提取验证码相关数据
                        # captcha_data = await page.evaluate(
                        #     """() => {
                        #     const data = {};

                        #     // 获取 traceid
                        #     const traceElement = document.getElementById('traceid');
                        #     if (traceElement) {
                        #         const text = traceElement.innerText || traceElement.textContent;
                        #         const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                        #         data.traceid = match ? match[1] : null;
                        #     }

                        #     // 获取 window.aliyun_captcha 相关字段
                        #     for (const key in window) {
                        #         if (key.startsWith('aliyun_captcha')) {
                        #             data[key] = window[key];
                        #         }
                        #     }

                        #     // 获取 requestInfo
                        #     if (window.requestInfo) {
                        #         data.requestInfo = window.requestInfo;
                        #     }

                        #     // 获取当前 URL
                        #     data.currentUrl = window.location.href;

                        #     return data;
                        # }"""
                        # )

                        # print(
                        #     f"📋 {self.account_name}: Captcha data extracted: " f"\n{json.dumps(captcha_data, indent=2)}"
                        # )

                        # # 通过 WaitForSecrets 发送验证码数据并等待用户手动验证
                        # from utils.wait_for_secrets import WaitForSecrets

                        # wait_for_secrets = WaitForSecrets()
                        # secret_obj = {
                        #     "CAPTCHA_NEXT_URL": {
                        #         "name": f"{self.account_name} - Aliyun Captcha Verification",
                        #         "description": (
                        #             f"Aliyun captcha verification required.\n"
                        #             f"TraceID: {captcha_data.get('traceid', 'N/A')}\n"
                        #             f"Current URL: {captcha_data.get('currentUrl', 'N/A')}\n"
                        #             f"Please complete the captcha manually in the browser, "
                        #             f"then provide the next URL after verification."
                        #         ),
                        #     }
                        # }

                        # secrets = wait_for_secrets.get(
                        #     secret_obj,
                        #     timeout=300,
                        #     notification={
                        #         "title": "阿里云验证",
                        #         "content": "请在浏览器中完成验证，并提供下一步的 URL。\n"
                        #         f"{json.dumps(captcha_data, indent=2)}\n"
                        #         "📋 操作说明：https://github.com/aceHubert/newapi-ai-check-in/docs/aliyun_captcha/README.md",
                        #     },
                        # )
                        # if not secrets or "CAPTCHA_NEXT_URL" not in secrets:
                        #     print(f"❌ {self.account_name}: No next URL provided " f"for captcha verification")
                        #     return None

                        # next_url = secrets["CAPTCHA_NEXT_URL"]
                        # print(f"🔄 {self.account_name}: Navigating to next URL " f"after captcha: {next_url}")

                        # # 导航到新的 URL
                        # await page.goto(next_url, wait_until="networkidle")

                        try:
                            await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 再次检查是否还有 traceid
                        traceid_after = None
                        try:
                            traceid_after = await page.evaluate(
                                """() => {
                                const traceElement = document.getElementById('traceid');
                                if (traceElement) {
                                    const text = traceElement.innerText || traceElement.textContent;
                                    const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                                    return match ? match[1] : null;
                                }
                                return null;
                            }"""
                            )
                        except Exception:
                            traceid_after = None

                        if traceid_after:
                            print(
                                f"❌ {self.account_name}: Captcha verification failed, "
                                f"traceid still present: {traceid_after}"
                            )
                            return None

                        print(f"✅ {self.account_name}: Captcha verification successful, " f"traceid cleared")

                    cookies = await browser.cookies()

                    aliyun_captcha_cookies = {}
                    print(f"ℹ️ {self.account_name}: Aliyun Captcha cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        # if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]
                        # and cookie_value is not None:
                        aliyun_captcha_cookies[cookie_name] = cookie_value

                    print(
                        f"ℹ️ {self.account_name}: "
                        f"Got {len(aliyun_captcha_cookies)} "
                        f"Aliyun Captcha cookies after step 1"
                    )

                    # 检查是否至少获取到一个 Aliyun Captcha cookie
                    if not aliyun_captcha_cookies:
                        print(f"❌ {self.account_name}: " f"No Aliyun Captcha cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(aliyun_captcha_cookies.keys())
                    print(f"✅ {self.account_name}: " f"Successfully got Aliyun Captcha cookies: {cookie_names}")

                    return aliyun_captcha_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: " f"Error occurred while getting Aliyun Captcha cookies, {e}")
                    return None
                finally:
                    await page.close()

    async def get_status_with_browser(self) -> dict | None:
        """使用 Camoufox 获取状态信息并缓存
        Returns:
            状态数据字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get status (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_status_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access status page to get status from localStorage")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 从 localStorage 获取 status
                    status_data = None
                    try:
                        status_str = await page.evaluate("() => localStorage.getItem('status')")
                        if status_str:
                            status_data = json.loads(status_str)
                            print(f"✅ {self.account_name}: Got status from localStorage")
                        else:
                            print(f"⚠️ {self.account_name}: No status found in localStorage")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Error reading status from localStorage: {e}")

                    return status_data

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting status: {e}")
                    return None
                finally:
                    await page.close()

    async def get_auth_client_id(self, session: curl_requests.Session, headers: dict, provider: str) -> dict:
        """获取状态信息

        Args:
            session: curl_cffi Session 客户端
            headers: 请求头
            provider: 提供商类型 (github/linuxdo)

        Returns:
            包含 success 和 client_id 或 error 的字典
        """
        try:
            response = session.get(self.provider_config.get_status_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response_resolve(response, f"get_auth_client_id_{provider}", self.account_name)
                if data is None:

                    # 尝试从浏览器 localStorage 获取状态
                    # print(f"ℹ️ {self.account_name}: Getting status from browser")
                    # try:
                    #     status_data = await self.get_status_with_browser()
                    #     if status_data:
                    #         oauth = status_data.get(f"{provider}_oauth", False)
                    #         if not oauth:
                    #             return {
                    #                 "success": False,
                    #                 "error": f"{provider} OAuth is not enabled.",
                    #             }

                    #         client_id = status_data.get(f"{provider}_client_id", "")
                    #         if client_id:
                    #             print(f"✅ {self.account_name}: Got client ID from localStorage: " f"{client_id}")
                    #             return {
                    #                 "success": True,
                    #                 "client_id": client_id,
                    #             }
                    # except Exception as browser_err:
                    #     print(f"⚠️ {self.account_name}: Failed to get status from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": "Failed to get client id: Invalid response type (saved to logs)",
                    }

                if data.get("success"):
                    status_data = data.get("data", {})
                    oauth = status_data.get(f"{provider}_oauth", False)
                    if not oauth:
                        return {
                            "success": False,
                            "error": f"{provider} OAuth is not enabled.",
                        }

                    client_id = status_data.get(f"{provider}_client_id", "")
                    return {
                        "success": True,
                        "client_id": client_id,
                    }
                else:
                    error_msg = data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get client id: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get client id: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get client id, {e}",
            }

    async def get_auth_state_with_browser(self) -> dict:
        """使用 Camoufox 获取认证 URL 和 cookies

        Args:
            status: 要存储到 localStorage 的状态数据
            wait_for_url: 要等待的 URL 模式

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get auth state (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_auth_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    # 1. Open the login page first
                    print(f"ℹ️ {self.account_name}: Opening login page")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    # Wait for page to be fully loaded
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    response = await page.evaluate(
                        f"""async () => {{
                            try{{
                                const response = await fetch('{self.provider_config.get_auth_state_url()}');
                                const data = await response.json();
                                return data;
                            }}catch(e){{
                                return {{
                                    success: false,
                                    message: e.message
                                }};
                            }}
                        }}"""
                    )

                    if response and "data" in response:
                        cookies = await browser.cookies()
                        return {
                            "success": True,
                            "state": response.get("data"),
                            "cookies": cookies,
                        }

                    return {"success": False, "error": f"Failed to get state, \n{json.dumps(response, indent=2)}"}

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get state, {e}")
                    await take_screenshot(page, "auth_url_error", self.account_name)
                    return {"success": False, "error": "Failed to get state"}
                finally:
                    await page.close()

    async def get_auth_state(
        self,
        session: curl_requests.Session,
        headers: dict,
    ) -> dict:
        """获取认证状态
        
        使用 curl_cffi Session 发送请求。Session 可在创建时设置全局 impersonate。
        
        Args:
            session: curl_cffi Session 客户端（已包含 cookies，可能已设置 impersonate）
            headers: 请求头
        """
        try:
            response = session.get(
                self.provider_config.get_auth_state_url(),
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                json_data = response_resolve(response, "get_auth_state", self.account_name)
                if json_data is None:
                    return {
                        "success": False,
                        "error": "Failed to get auth state: Invalid response type (saved to logs)",
                    }

                # 检查响应是否成功
                if json_data.get("success"):
                    auth_data = json_data.get("data")

                    # 将 curl_cffi Cookies 转换为 Camoufox 格式
                    result_cookies = []
                    parsed_domain = urlparse(self.provider_config.origin).netloc

                    print(f"ℹ️ {self.account_name}: Got {len(response.cookies)} cookies from auth state request")
                    for cookie in response.cookies.jar:
                        # 从 _rest 中获取 HttpOnly 和 SameSite，确保类型正确
                        http_only_raw = cookie._rest.get("HttpOnly", False)
                        http_only = bool(http_only_raw) if http_only_raw is not None else False
                        
                        same_site_raw = cookie._rest.get("SameSite", "Lax")
                        same_site = str(same_site_raw) if same_site_raw else "Lax"
                        
                        # secure 也需要确保是布尔值
                        secure = bool(cookie.secure) if cookie.secure is not None else False
                        
                        print(
                            f"  📚 Cookie: {cookie.name} (Domain: {cookie.domain}, "
                            f"Path: {cookie.path}, Expires: {cookie.expires}, "
                            f"HttpOnly: {http_only}, Secure: {secure}, "
                            f"SameSite: {same_site})"
                        )
                        # 构建 cookie 字典，Camoufox 要求字段类型严格
                        cookie_dict = {
                            "name": cookie.name,
                            "domain": cookie.domain if cookie.domain else parsed_domain,
                            "value": cookie.value,
                            "path": cookie.path if cookie.path else "/",
                            "secure": secure,
                            "httpOnly": http_only,
                            "sameSite": same_site,
                        }
                        # 只有当 expires 是有效的数值时才添加
                        if cookie.expires is not None:
                            cookie_dict["expires"] = float(cookie.expires)
                        result_cookies.append(cookie_dict)

                    return {
                        "success": True,
                        "state": auth_data,
                        "cookies": result_cookies,
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get auth state: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get auth state: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get auth state, {e}",
            }

    async def get_user_info_with_browser(self, auth_cookies: list[dict]) -> dict:
        """使用 Camoufox 获取用户信息

        Returns:
            包含 success、quota、used_quota 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get user info (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_user_info_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                browser.add_cookies(auth_cookies)

                try:
                    # 1. 打开登录页面
                    print(f"ℹ️ {self.account_name}: Opening main page")
                    await page.goto(self.provider_config.origin, wait_until="networkidle")

                    # 等待页面完全加载
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 获取用户信息
                    response = await page.evaluate(
                        f"""async () => {{
                           const response = await fetch(
                               '{self.provider_config.get_user_info_url()}'
                           );
                           const data = await response.json();
                           return data;
                        }}"""
                    )

                    if response and "data" in response:
                        user_data = response.get("data", {})
                        quota = round(user_data.get("quota", 0) / 500000, 2)
                        used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                        bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                        print(
                            f"✅ {self.account_name}: "
                            f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}"
                        )
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "bonus_quota": bonus_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                        }

                    return {
                        "success": False,
                        "error": f"Failed to get user info, \n{json.dumps(response, indent=2)}",
                    }

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get user info, {e}")
                    await take_screenshot(page, "user_info_error", self.account_name)
                    return {"success": False, "error": "Failed to get user info"}
                finally:
                    await page.close()

    async def get_user_info(self, session: curl_requests.Session, headers: dict) -> dict:
        """获取用户信息"""
        try:
            response = session.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = response_resolve(response, "get_user_info", self.account_name)
                if json_data is None:
                    # 尝试从浏览器获取用户信息
                    # print(f"ℹ️ {self.account_name}: Getting user info from browser")
                    # try:
                    #     user_info_result = await self.get_user_info_with_browser()
                    #     if user_info_result.get("success"):
                    #         return user_info_result
                    #     else:
                    #         error_msg = user_info_result.get("error", "Unknown error")
                    #         print(f"⚠️ {self.account_name}: {error_msg}")
                    # except Exception as browser_err:
                    #     print(
                    #         f"⚠️ {self.account_name}: "
                    #         f"Failed to get user info from browser: {browser_err}"
                    #     )

                    return {
                        "success": False,
                        "error": "Failed to get user info: Invalid response type (saved to logs)",
                    }

                if json_data.get("success"):
                    user_data = json_data.get("data", {})
                    quota = round(user_data.get("quota", 0) / 500000, 2)
                    used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                    bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "bonus_quota": bonus_quota,
                        "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get user info: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get user info: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get user info, {e}",
            }

    def execute_check_in(
        self,
        session: curl_requests.Session,
        headers: dict,
        api_user: str | int,
    ) -> dict:
        """执行签到请求
        
        Returns:
            包含 success, message, data 等信息的字典
        """
        print(f"🌐 {self.account_name}: Executing check-in")

        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})

        check_in_url = self.provider_config.get_check_in_url(api_user)
        if not check_in_url:
            print(f"❌ {self.account_name}: No check-in URL configured")
            return {"success": False, "error": "No check-in URL configured"}

        response = session.post(check_in_url, headers=checkin_headers, timeout=30)

        print(f"📨 {self.account_name}: Response status code {response.status_code}")

        # 尝试解析响应（200 或 400 都可能包含有效的 JSON）
        if response.status_code in [200, 400]:
            json_data = response_resolve(response, "execute_check_in", self.account_name)
            if json_data is None:
                # 如果不是 JSON 响应（可能是 HTML），检查是否包含成功标识
                if "success" in response.text.lower():
                    print(f"✅ {self.account_name}: Check-in successful!")
                    return {"success": True, "message": "Check-in successful"}
                else:
                    print(f"❌ {self.account_name}: Check-in failed - Invalid response format")
                    return {"success": False, "error": "Invalid response format"}

            # 检查签到结果
            message = json_data.get("message", json_data.get("msg", ""))

            if (
                json_data.get("ret") == 1
                or json_data.get("code") == 0
                or json_data.get("success")
                or "已经签到" in message
                or "签到成功" in message
            ):
                # 提取签到数据
                check_in_data = json_data.get("data", {})
                checkin_date = check_in_data.get("checkin_date", "")
                quota_awarded = check_in_data.get("quota_awarded", 0)
                
                if quota_awarded:
                    quota_display = round(quota_awarded / 500000, 2)
                    print(f"✅ {self.account_name}: Check-in successful! Date: {checkin_date}, Quota awarded: ${quota_display}")
                else:
                    print(f"✅ {self.account_name}: Check-in successful! {message}")
                
                return {
                    "success": True,
                    "message": message or "Check-in successful",
                    "data": check_in_data,
                }
            else:
                error_msg = json_data.get("msg", json_data.get("message", "Unknown error"))
                print(f"❌ {self.account_name}: Check-in failed - {error_msg}")
                return {"success": False, "error": error_msg}
        else:
            print(f"❌ {self.account_name}: Check-in failed - HTTP {response.status_code}")
            return {"success": False, "error": f"HTTP {response.status_code}"}

    async def execute_topup(
        self,
        headers: dict,
        cookies: dict,
        api_user: str | int,
        topup_interval: int = 60,
    ) -> dict:
        """执行完整的 CDK 获取和充值流程

        直接调用 get_cdk 生成器函数，每次 yield 一个 CDK 字符串并执行 topup
        每次 topup 之间保持间隔时间，如果 topup 失败则停止
        
        支持同步生成器和异步生成器两种类型的 get_cdk 函数

        Args:
            headers: 请求头
            cookies: cookies 字典
            api_user: API 用户 ID（通过参数传递，因为登录方式可能不同）
            topup_interval: 多次 topup 之间的间隔时间（秒），默认 60 秒

        Returns:
            包含 success, topup_count, errors 等信息的字典
        """
        # 检查是否配置了 get_cdk 函数
        if not self.provider_config.get_cdk:
            print(f"ℹ️ {self.account_name}: No get_cdk function configured for provider {self.provider_config.name}")
            return {
                "success": True,
                "topup_count": 0,
                "topup_success_count": 0,
                "error": "",
            }

        # 构建 topup 请求头
        topup_headers = headers.copy()
        topup_headers.update({
            "Referer": f"{self.provider_config.origin}/console/topup",
            "Origin": self.provider_config.origin,
            self.provider_config.api_user_key: f"{api_user}",
        })

        results = {
            "success": True,
            "topup_count": 0,
            "topup_success_count": 0,
            "error": "",
        }

        # 调用 get_cdk 函数，返回同步生成器或异步生成器
        cdk_generator = self.provider_config.get_cdk(self.account_config)
        
        topup_count = 0
        error_msg = ""

        # 内部函数：处理单个 CDK 结果
        async def process_cdk_result(success: bool, data: dict) -> bool:
            """处理单个 CDK 结果，返回是否应该继续
            
            Args:
                success: 是否成功获取 CDK
                data: 包含 code 或 error 的字典
                
            Returns:
                bool: True 继续处理下一个，False 停止处理
            """
            nonlocal topup_count, error_msg
            
            # 如果获取 CDK 失败，停止处理
            if not success:
                error_msg = data.get("error", "Failed to get CDK")
                results["success"] = False
                results["error"] = error_msg
                print(f"❌ {self.account_name}: Failed to get CDK - {error_msg}, stopping topup process")
                return False
            
            # 获取 code
            cdk = data.get("code", "")
            
            # 如果 code 为空，表示不需要充值，继续处理下一个
            if not cdk:
                print(f"ℹ️ {self.account_name}: No CDK to topup (code is empty), continuing...")
                return True
            
            # 如果不是第一个 CDK，等待间隔时间
            if topup_count > 0 and topup_interval > 0:
                print(f"⏳ {self.account_name}: Waiting {topup_interval} seconds before next topup...")
                await asyncio.sleep(topup_interval)

            topup_count += 1
            print(f"💰 {self.account_name}: Executing topup #{topup_count} with CDK: {cdk}")

            topup_result = topup(
                provider_config=self.provider_config,
                account_config=self.account_config,
                headers=topup_headers,
                cookies=cookies,
                key=cdk,
            )

            results["topup_count"] += 1

            if topup_result.get("success"):
                results["topup_success_count"] += 1
                if not topup_result.get("already_used"):
                    print(f"✅ {self.account_name}: Topup #{topup_count} successful")
                return True  # 继续处理下一个
            else:
                # topup 失败，记录错误并停止
                error_msg = topup_result.get("error", "Topup failed")
                results["success"] = False
                results["error"] = error_msg
                print(f"❌ {self.account_name}: Topup #{topup_count} failed, stopping topup process")
                return False  # 停止处理

        # 检查是否是异步生成器
        if inspect.isasyncgen(cdk_generator):
            # 异步生成器，使用 async for
            async for success, data in cdk_generator:
                should_continue = await process_cdk_result(success, data)
                if not should_continue:
                    break
        else:
            # 同步生成器，使用普通 for
            for success, data in cdk_generator:
                should_continue = await process_cdk_result(success, data)
                if not should_continue:
                    break

        if topup_count == 0:
            print(f"ℹ️ {self.account_name}: No CDK available for topup")
        elif results["topup_success_count"] > 0:
            print(f"✅ {self.account_name}: Total {results['topup_success_count']}/{results['topup_count']} topup(s) successful")

        return results

    async def check_in_with_cookies(
        self,
        cookies: dict,
        common_headers: dict,
        api_user: str | int,
    ) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作
        
        Args:
            cookies: cookies 字典
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
            api_user: API 用户 ID
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with existing cookies (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent) if user_agent else "firefox135"
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}")
        
        try:
            # 打印 cookies 的键和值
            print(f"ℹ️ {self.account_name}: Cookies to be used:")
            for key, value in cookies.items():
                print(f"  📚 {key}: {value[:50] if len(value) > 50 else value}{'...' if len(value) > 50 else ''}")
            session.cookies.update(cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = f"{api_user}"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 检查是否需要手动签到
            if self.provider_config.needs_manual_check_in():
                # 如果配置了签到状态查询，先检查是否已签到
                check_in_status_func = self.provider_config.get_check_in_status_func()
                if check_in_status_func:
                    checked_in_today = check_in_status_func(
                        provider_config=self.provider_config,
                        account_config=self.account_config,
                        cookies=cookies,
                        headers=headers,
                    )
                    if checked_in_today:
                        print(f"ℹ️ {self.account_name}: Already checked in today, skipping check-in")
                    else:
                        # 未签到，执行签到
                        check_in_result = self.execute_check_in(session, headers, api_user)
                        if not check_in_result.get("success"):
                            return False, {"error": check_in_result.get("error", "Check-in failed")}
                        # 签到成功后再次查询状态（显示最新状态）
                        check_in_status_func(
                            provider_config=self.provider_config,
                            account_config=self.account_config,
                            cookies=cookies,
                            headers=headers,
                        )
                else:
                    # 没有配置签到状态查询函数，直接执行签到
                    check_in_result = self.execute_check_in(session, headers, api_user)
                    if not check_in_result.get("success"):
                        return False, {"error": check_in_result.get("error", "Check-in failed")}
            else:
                print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")

            # 如果需要手动 topup（配置了 topup_path 和 get_cdk），执行 topup
            if self.provider_config.needs_manual_topup():
                print(f"ℹ️ {self.account_name}: Provider requires manual topup, executing...")
                topup_result = await self.execute_topup(headers, cookies, api_user)
                if topup_result.get("topup_count", 0) > 0:
                    print(
                        f"ℹ️ {self.account_name}: Topup completed - "
                        f"{topup_result.get('topup_success_count', 0)}/{topup_result.get('topup_count', 0)} successful"
                    )
                if not topup_result.get("success"):
                    error_msg = topup_result.get("error") or "Topup failed"
                    print(f"❌ {self.account_name}: Topup failed, stopping check-in process")
                    return False, {"error": error_msg}

            user_info = await self.get_user_info(session, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "User info retrieved successfully")
                print(f"✅ {self.account_name}: {success_msg}")
                return True, user_info
            elif user_info:
                error_msg = user_info.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get user info"}
            else:
                return False, {"error": "No user info available"}

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Error occurred during check-in process"}
        finally:
            session.close()

    async def check_in_with_system_access_token(
        self,
        access_token: str,
        bypass_cookies: dict,
        common_headers: dict,
        api_user: str | int,
    ) -> tuple[bool, dict]:
        """使用 system access token 执行签到操作
        
        Args:
            access_token: 系统访问令牌
            bypass_cookies: 绕过 cookies（WAF/CF）
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
            api_user: API 用户 ID
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with system access token (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent) if user_agent else "firefox135"
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}")
        
        try:
            # 设置 bypass cookies
            if bypass_cookies:
                session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers["Authorization"] = f"Bearer {access_token}"
            headers[self.provider_config.api_user_key] = f"{api_user}"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 检查是否需要手动签到
            if self.provider_config.needs_manual_check_in():
                # 如果配置了签到状态查询，先检查是否已签到
                check_in_status_func = self.provider_config.get_check_in_status_func()
                if check_in_status_func:
                    checked_in_today = check_in_status_func(
                        provider_config=self.provider_config,
                        account_config=self.account_config,
                        cookies=session.cookies.get_dict(),
                        headers=headers,
                    )
                    if checked_in_today:
                        print(f"ℹ️ {self.account_name}: Already checked in today, skipping check-in")
                    else:
                        # 未签到，执行签到
                        check_in_result = self.execute_check_in(session, headers, api_user)
                        if not check_in_result.get("success"):
                            return False, {"error": check_in_result.get("error", "Check-in failed")}
                        # 签到成功后再次查询状态（显示最新状态）
                        check_in_status_func(
                            provider_config=self.provider_config,
                            account_config=self.account_config,
                            cookies=session.cookies.get_dict(),
                            headers=headers,
                        )
                else:
                    # 没有配置签到状态查询函数，直接执行签到
                    check_in_result = self.execute_check_in(session, headers, api_user)
                    if not check_in_result.get("success"):
                        return False, {"error": check_in_result.get("error", "Check-in failed")}
            else:
                print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")

            # 如果需要手动 topup（配置了 topup_path 和 get_cdk），执行 topup
            if self.provider_config.needs_manual_topup():
                print(f"ℹ️ {self.account_name}: Provider requires manual topup, executing...")
                topup_result = await self.execute_topup(headers, session.cookies.get_dict(), api_user)
                if topup_result.get("topup_count", 0) > 0:
                    print(
                        f"ℹ️ {self.account_name}: Topup completed - "
                        f"{topup_result.get('topup_success_count', 0)}/{topup_result.get('topup_count', 0)} successful"
                    )
                if not topup_result.get("success"):
                    error_msg = topup_result.get("error") or "Topup failed"
                    print(f"❌ {self.account_name}: Topup failed, stopping check-in process")
                    return False, {"error": error_msg}

            user_info = await self.get_user_info(session, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "User info retrieved successfully")
                print(f"✅ {self.account_name}: {success_msg}")
                return True, user_info
            elif user_info:
                error_msg = user_info.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get user info"}
            else:
                return False, {"error": "No user info available"}

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": f"Error occurred during check-in process - {e}"}
        finally:
            session.close()

    async def check_in_with_github(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作
        
        Args:
            username: GitHub 用户名
            password: GitHub 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with GitHub account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值，在 Session 上设置全局 impersonate
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}")
        
        try:
            session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.github_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.github_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using GitHub client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(session, headers, "github")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for GitHub: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get GitHub client ID"}

            # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                session=session,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for GitHub: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/github_{username_hash}_storage_state.json"

            from sign_in_with_github import GitHubSignIn

            github = GitHubSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data, oauth_browser_headers = await github.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result.get("state"),
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path
            )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = {**bypass_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                # 构建带参数的回调 URL
                base_url = self.provider_config.get_github_auth_url()
                callback_url = f"{base_url}?{urlencode(result_data, doseq=True)}"
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 curl_cffi 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        session.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                        updated_headers.update(oauth_browser_headers)

                    response = session.get(callback_url, headers=updated_headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "github_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**bypass_cookies, **user_cookies}
                                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "GitHub check-in process error"}
        finally:
            session.close()

    async def check_in_with_linuxdo(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with Linux.do account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值，在 Session 上设置全局 impersonate
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}")
        
        try:
            session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.linuxdo_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.linuxdo_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using Linux.do client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(session, headers, "linuxdo")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for Linux.do: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get Linux.do client ID"}

            # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                session=session,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get Linux.do auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/linuxdo_{username_hash}_storage_state.json"

            from sign_in_with_linuxdo import LinuxDoSignIn

            linuxdo = LinuxDoSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data, oauth_browser_headers = await linuxdo.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result["state"],
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path
            )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = {**bypass_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                # 构建带参数的回调 URL
                base_url = self.provider_config.get_linuxdo_auth_url()
                callback_url = f"{base_url}?{urlencode(result_data, doseq=True)}"
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 curl_cffi 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        session.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                        updated_headers.update(oauth_browser_headers)

                    response = session.get(callback_url, headers=updated_headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "linuxdo_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**bypass_cookies, **user_cookies}
                                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Linux.do check-in process error"}
        finally:
            session.close()

    async def check_in_with_site(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
        mode: str = "auto",
    ) -> tuple[bool, dict]:
        """使用站点账号密码执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: Executing check-in with site account, mode={mode} (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        if mode == "browser":
            return await self.check_in_with_site_browser(username, password, bypass_cookies, common_headers)

        success, result = await self.check_in_with_site_api(username, password, bypass_cookies, common_headers)
        if success or mode == "api":
            return success, result

        print(f"⚠️ {self.account_name}: Site API login failed, falling back to browser login")
        return await self.check_in_with_site_browser(username, password, bypass_cookies, common_headers)

    async def check_in_with_site_api(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用站点登录接口执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: Executing site API login (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)

        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}")

        try:
            session.cookies.update(bypass_cookies)

            headers = common_headers.copy()
            headers["Content-Type"] = "application/json"
            headers["X-Requested-With"] = "XMLHttpRequest"
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            login_url = f"{self.provider_config.origin}/api/user/login?turnstile="
            payload = {"username": username, "password": password}
            response = session.post(login_url, headers=headers, json=payload, timeout=30)

            if response.status_code != 200:
                print(f"❌ {self.account_name}: Site login failed - HTTP {response.status_code}")
                return False, {"error": f"Site login HTTP {response.status_code}"}

            json_data = response_resolve(response, "site_login", self.account_name)
            if json_data is None:
                return False, {"error": "Site login returned invalid response"}

            if not json_data.get("success"):
                error_msg = json_data.get("message", "Site login failed")
                print(f"❌ {self.account_name}: Site login failed - {error_msg}")
                return False, {"error": error_msg}

            user_data = json_data.get("data", {})
            api_user = user_data.get("id")
            if api_user is None:
                print(f"❌ {self.account_name}: No user ID in site login response")
                return False, {"error": "No user ID in site login response"}

            user_cookies = {}
            for cookie in session.cookies.jar:
                user_cookies[cookie.name] = cookie.value

            print(f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} site login cookies: {list(user_cookies.keys())}")

            merged_cookies = {**bypass_cookies, **user_cookies}
            return await self.check_in_with_cookies(merged_cookies, common_headers, api_user, impersonate)

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during site login process - {e}")
            return False, {"error": "Site login process error"}
        finally:
            session.close()

    async def _click_site_password_login_switch(self, page) -> bool:
        """切换到站点账号密码登录表单，尽量使用稳定选择器和文本匹配。"""
        selectors = [
            'button:has-text("使用 邮箱或用户名 登录")',
            'button:has-text("邮箱或用户名")',
            'button:has-text("用户名")',
            'button.semi-button:nth-child(4)',
        ]

        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if element:
                    print(f"ℹ️ {self.account_name}: Clicking site password-login switch by selector: {selector}")
                    await element.click()
                    await page.wait_for_timeout(1000)
                    return True
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed password-login switch selector {selector}: {e}")

        try:
            clicked = await page.evaluate(
                """() => {
                    const candidates = Array.from(document.querySelectorAll('button'));
                    const button = candidates.find((item) => {
                        const text = (item.innerText || item.textContent || '').replace(/\s+/g, ' ').trim();
                        return text.includes('邮箱或用户名') || text.includes('用户名') || text.includes('密码登录');
                    });
                    if (button) {
                        button.click();
                        return true;
                    }
                    return false;
                }"""
            )
            if clicked:
                print(f"ℹ️ {self.account_name}: Clicking site password-login switch by text scan")
                await page.wait_for_timeout(1000)
                return True
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed password-login switch text scan: {e}")

        return False

    async def _fill_site_login_form(self, page, username: str, password: str) -> bool:
        """填写站点登录表单，使用 fill + 事件触发，兼容前端校验。"""
        username_selectors = [
            '#username',
            'input[name="username"]',
            'input[placeholder*="用户名"]',
            'input[placeholder*="邮箱"]',
            'input[type="text"]',
        ]
        password_selectors = [
            '#password',
            'input[name="password"]',
            'input[type="password"]',
        ]

        username_selector = None
        for selector in username_selectors:
            try:
                await page.wait_for_selector(selector, timeout=3000)
                username_selector = selector
                break
            except Exception:
                continue

        password_selector = None
        for selector in password_selectors:
            try:
                await page.wait_for_selector(selector, timeout=3000)
                password_selector = selector
                break
            except Exception:
                continue

        if not username_selector or not password_selector:
            print(f"❌ {self.account_name}: Site login form inputs not found")
            return False

        await page.fill(username_selector, username)
        await page.dispatch_event(username_selector, "input")
        await page.dispatch_event(username_selector, "change")
        await page.wait_for_timeout(500)

        await page.fill(password_selector, password)
        await page.dispatch_event(password_selector, "input")
        await page.dispatch_event(password_selector, "change")
        await page.wait_for_timeout(500)
        return True

    async def _submit_site_login_form(self, page) -> bool:
        """提交站点登录表单，优先使用表单内 submit 按钮。"""
        selectors = [
            'form button[type="submit"]',
            'button[type="submit"]:has-text("继续")',
            'button.semi-button-primary:has-text("继续")',
            'button.semi-button-primary',
        ]

        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if element:
                    print(f"ℹ️ {self.account_name}: Submitting site login form by selector: {selector}")
                    await element.click()
                    return True
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed submit selector {selector}: {e}")

        try:
            submitted = await page.evaluate(
                """() => {
                    const buttons = Array.from(document.querySelectorAll('button'));
                    const button = buttons.find((item) => {
                        const text = (item.innerText || item.textContent || '').replace(/\s+/g, ' ').trim();
                        return text.includes('继续') || text.includes('登录') || text.includes('登入');
                    });
                    if (button) {
                        button.click();
                        return true;
                    }
                    const form = document.querySelector('form');
                    if (form) {
                        form.requestSubmit ? form.requestSubmit() : form.submit();
                        return true;
                    }
                    return false;
                }"""
            )
            if submitted:
                print(f"ℹ️ {self.account_name}: Submitting site login form by text/form scan")
                return True
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed submit text/form scan: {e}")

        return False

    async def _read_site_api_user_from_browser(self, page, cookies: dict, common_headers: dict) -> str | int | None:
        """从浏览器 localStorage 或 /api/user/self 获取用户 ID。"""
        try:
            user_data = await page.evaluate("() => localStorage.getItem('user')")
            if user_data:
                user_obj = json.loads(user_data)
                api_user = user_obj.get("id")
                if api_user is not None:
                    print(f"✅ {self.account_name}: Got api user from localStorage: {api_user}")
                    return api_user
        except Exception as e:
            print(f"⚠️ {self.account_name}: Error reading user from localStorage: {e}")

        session = None
        try:
            user_agent = common_headers.get("User-Agent", "")
            impersonate = get_curl_cffi_impersonate(user_agent)
            session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
            session.cookies.update(cookies)

            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.origin
            headers["Origin"] = self.provider_config.origin

            response = session.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)
            if response.status_code == 200:
                json_data = response_resolve(response, "site_user_self", self.account_name)
                if json_data and json_data.get("success"):
                    user_data = json_data.get("data", {})
                    api_user = user_data.get("id")
                    if api_user is not None:
                        print(f"✅ {self.account_name}: Got api user from user-info API: {api_user}")
                        return api_user
            print(f"⚠️ {self.account_name}: Unable to get api user from user-info API, HTTP {response.status_code}")
        except Exception as e:
            print(f"⚠️ {self.account_name}: Error getting api user from user-info API: {e}")
        finally:
            if session:
                session.close()

        return None

    async def check_in_with_site_browser(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用浏览器打开登录页并完成站点账号密码登录。"""
        print(
            f"ℹ️ {self.account_name}: Executing site browser login (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        async with AsyncCamoufox(
            headless=False,
            humanize=True,
            locale="en-US",
            geoip=True if self.camoufox_proxy_config else False,
            proxy=self.camoufox_proxy_config,
            os="macos",
            config={
                "forceScopeAccess": True,
            },
        ) as browser:
            context = await browser.new_context()
            if bypass_cookies:
                parsed_origin = urlparse(self.provider_config.origin)
                await context.add_cookies([
                    {
                        "name": name,
                        "value": value,
                        "domain": parsed_origin.hostname,
                        "path": "/",
                        "secure": parsed_origin.scheme == "https",
                    }
                    for name, value in bypass_cookies.items()
                ])
                print(f"ℹ️ {self.account_name}: Set {len(bypass_cookies)} bypass cookies before browser login")

            page = await context.new_page()
            try:
                await page.goto(self.provider_config.get_login_url(), wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    await page.wait_for_timeout(3000)

                if self.provider_config.aliyun_captcha:
                    await aliyun_captcha_check(page, self.account_name)

                await self._click_site_password_login_switch(page)

                if not await self._fill_site_login_form(page, username, password):
                    await take_screenshot(page, "site_login_form_not_found", self.account_name)
                    return False, {"error": "Site browser login form not found"}

                current_url = page.url
                if not await self._submit_site_login_form(page):
                    await take_screenshot(page, "site_login_submit_not_found", self.account_name)
                    return False, {"error": "Site browser login submit not found"}

                try:
                    await page.wait_for_function('localStorage.getItem("user") !== null', timeout=15000)
                except Exception:
                    try:
                        await page.wait_for_url(lambda url: url != current_url, timeout=15000)
                    except Exception:
                        await page.wait_for_timeout(5000)

                restore_cookies = await context.cookies()
                user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)
                merged_cookies = {**bypass_cookies, **user_cookies}

                api_user = await self._read_site_api_user_from_browser(page, merged_cookies, common_headers)
                if api_user is None:
                    await take_screenshot(page, "site_browser_login_no_user_id", self.account_name)
                    return False, {"error": "Site browser login succeeded but no user ID found"}

                browser_headers = await get_browser_headers(page)
                updated_headers = common_headers.copy()
                if browser_headers:
                    print_browser_headers(self.account_name, browser_headers)
                    updated_headers.update(browser_headers)

                impersonate = get_curl_cffi_impersonate(updated_headers.get("User-Agent", ""))
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user, impersonate)

            except Exception as e:
                print(f"❌ {self.account_name}: Error occurred during site browser login process - {e}")
                await take_screenshot(page, "site_browser_login_error", self.account_name)
                return False, {"error": "Site browser login process error"}
            finally:
                await page.close()
                await context.close()

    async def execute(self) -> list[tuple[str, bool, dict | None]]:
        """为单个账号执行签到操作，支持多种认证方式"""
        print(f"\n\n⏳ Starting to process {self.account_name}")

        bypass_cookies = {}
        browser_headers = None  # 浏览器指纹头部信息
        
        if self.provider_config.needs_waf_cookies():
            waf_cookies = await self.get_waf_cookies_with_browser()
            if waf_cookies:
                bypass_cookies = waf_cookies
                print(f"✅ {self.account_name}: WAF cookies obtained")
            else:
                print(f"⚠️ {self.account_name}: Unable to get WAF cookies, continuing with empty cookies")

        elif self.provider_config.needs_cf_clearance():
            # 直接调用公共模块的 get_cf_clearance 函数
            try:
                cf_result = await get_cf_clearance(
                    url=self.provider_config.get_login_url(),
                    account_name=self.account_name,
                    proxy_config=self.camoufox_proxy_config,
                )
                
                if cf_result[0]:
                    bypass_cookies = cf_result[0]
                    print(f"✅ {self.account_name}: Cloudflare cookies obtained")
                else:
                    print(f"⚠️ {self.account_name}: Unable to get Cloudflare cookies, continuing with empty cookies")

                # 因为 Cloudflare 验证需要一致的浏览器指纹
                if cf_result[1]:
                    browser_headers = cf_result[1]
                    print(f"✅ {self.account_name}: Cloudflare fingerprint headers obtained")
            except Exception as e:
                print(f"❌ {self.account_name}: Error occurred while getting cf_clearance cookie: {e}")
                print(f"⚠️ {self.account_name}: Continuing with empty cookies")
        else:
            print(f"ℹ️ {self.account_name}: Bypass not required, using user cookies directly")

        # 生成公用请求头（只生成一次 User-Agent，整个签到流程保持一致）
        # 注意：Referer 和 Origin 不在这里设置，由各个签到方法根据实际请求动态设置
        if browser_headers:
            # 如果有浏览器指纹头部（来自 cf_clearance 获取），使用它
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": browser_headers.get("User-Agent", get_random_user_agent()),
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            
            # 只有当 browser_headers 中包含 sec-ch-ua 时才添加 Client Hints 头部
            # Firefox 浏览器不支持 Client Hints，所以 browser_headers 中不会有这些头部
            # 如果强行添加会导致 Cloudflare 检测到指纹不一致而返回 403
            if "sec-ch-ua" in browser_headers:
                common_headers.update({
                    "sec-ch-ua": browser_headers.get("sec-ch-ua", ""),
                    "sec-ch-ua-mobile": browser_headers.get("sec-ch-ua-mobile", "?0"),
                    "sec-ch-ua-platform": browser_headers.get("sec-ch-ua-platform", ""),
                    "sec-ch-ua-platform-version": browser_headers.get("sec-ch-ua-platform-version", ""),
                    "sec-ch-ua-arch": browser_headers.get("sec-ch-ua-arch", ""),
                    "sec-ch-ua-bitness": browser_headers.get("sec-ch-ua-bitness", ""),
                    "sec-ch-ua-full-version": browser_headers.get("sec-ch-ua-full-version", ""),
                    "sec-ch-ua-full-version-list": browser_headers.get("sec-ch-ua-full-version-list", ""),
                    "sec-ch-ua-model": browser_headers.get("sec-ch-ua-model", '""'),
                })
                print(f"ℹ️ {self.account_name}: Using browser fingerprint headers (with Client Hints)")
            else:
                print(f"ℹ️ {self.account_name}: Using browser fingerprint headers (Firefox, no Client Hints)")
        else:
            # 没有浏览器指纹，生成一次随机 User-Agent 并在整个流程中使用
            random_ua = get_random_user_agent()
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": random_ua,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            print(f"ℹ️ {self.account_name}: Using random User-Agent (generated once)")

        # 解析账号配置
        cookies_data = self.account_config.cookies
        system_access_token_data = self.account_config.system_access_token
        github_accounts = self.account_config.github  # 现在是 List[OAuthAccountConfig] 类型
        linuxdo_accounts = self.account_config.linux_do  # 现在是 List[OAuthAccountConfig] 类型
        site_accounts = self.account_config.site
        results = []

        # 尝试 cookies 认证
        if cookies_data:
            print(f"\nℹ️ {self.account_name}: Trying cookies authentication")
            try:
                user_cookies = parse_cookies(cookies_data)
                if not user_cookies:
                    print(f"❌ {self.account_name}: Invalid cookies format")
                    results.append(("cookies", False, {"error": "Invalid cookies format"}))
                else:
                    api_user = self.account_config.api_user
                    if not api_user:
                        print(f"❌ {self.account_name}: API user identifier not found for cookies")
                        results.append(("cookies", False, {"error": "API user identifier not found"}))
                    else:
                        # 使用已有 cookies 执行签到，传入公用请求头
                        all_cookies = {**bypass_cookies, **user_cookies}
                        success, user_info = await self.check_in_with_cookies(all_cookies, common_headers, api_user)
                        if success:
                            print(f"✅ {self.account_name}: Cookies authentication successful")
                            results.append(("cookies", True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Cookies authentication failed")
                            results.append(("cookies", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: Cookies authentication error: {e}")
                results.append(("cookies", False, {"error": str(e)}))

        # 尝试 system access token 认证
        if system_access_token_data:
            print(f"\nℹ️ {self.account_name}: Trying system access token authentication")
            try:
                api_user = self.account_config.api_user
                if not api_user:
                    print(f"❌ {self.account_name}: API user identifier not found for system access token")
                    results.append(("system_access_token", False, {"error": "API user identifier not found"}))
                else:
                    # 使用 system access token 执行签到，传入公用请求头
                    success, user_info = await self.check_in_with_system_access_token(
                        system_access_token_data, bypass_cookies, common_headers, api_user
                    )
                    if success:
                        print(f"✅ {self.account_name}: System access token authentication successful")
                        results.append(("system_access_token", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: System access token authentication failed")
                        results.append(("system_access_token", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: System access token authentication error: {e}")
                results.append(("system_access_token", False, {"error": str(e)}))

        # 尝试 GitHub 认证（支持多个账号）
        if github_accounts:
            for idx, github_account in enumerate(github_accounts):
                account_label = f"github[{idx}]" if len(github_accounts) > 1 else "github"
                print(f"\nℹ️ {self.account_name}: Trying GitHub authentication ({mask_username(github_account.username)})")
                try:
                    username = github_account.username
                    password = github_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: Incomplete GitHub account information")
                        results.append((account_label, False, {"error": "Incomplete GitHub account information"}))
                    else:
                        # 使用 GitHub 账号执行签到，传入公用请求头
                        success, user_info = await self.check_in_with_github(
                            username, password, bypass_cookies, common_headers
                        )
                        if success:
                            print(f"✅ {self.account_name}: GitHub authentication successful ({mask_username(github_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: GitHub authentication failed ({mask_username(github_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: GitHub authentication error ({mask_username(github_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        if site_accounts:
            for idx, site_account in enumerate(site_accounts):
                account_label = f"site[{idx}]" if len(site_accounts) > 1 else "site"
                print(f"\nℹ️ {self.account_name}: Trying site authentication ({mask_username(site_account.username)})")
                try:
                    username = site_account.username
                    password = site_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: Incomplete site account information")
                        results.append((account_label, False, {"error": "Incomplete site account information"}))
                    else:
                        success, user_info = await self.check_in_with_site(
                            username,
                            password,
                            bypass_cookies,
                            common_headers,
                            site_account.mode,
                        )
                        if success:
                            print(f"✅ {self.account_name}: Site authentication successful ({mask_username(site_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Site authentication failed ({mask_username(site_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: Site authentication error ({mask_username(site_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        # 尝试 Linux.do 认证（支持多个账号）
        if linuxdo_accounts:
            for idx, linuxdo_account in enumerate(linuxdo_accounts):
                account_label = f"linux.do[{idx}]" if len(linuxdo_accounts) > 1 else "linux.do"
                print(f"\nℹ️ {self.account_name}: Trying Linux.do authentication ({mask_username(linuxdo_account.username)})")
                try:
                    username = linuxdo_account.username
                    password = linuxdo_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: Incomplete Linux.do account information")
                        results.append((account_label, False, {"error": "Incomplete Linux.do account information"}))
                    else:
                        # 使用 Linux.do 账号执行签到，传入公用请求头
                        success, user_info = await self.check_in_with_linuxdo(
                            username,
                            password,
                            bypass_cookies,
                            common_headers,
                        )
                        if success:
                            print(f"✅ {self.account_name}: Linux.do authentication successful ({mask_username(linuxdo_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Linux.do authentication failed ({mask_username(linuxdo_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: Linux.do authentication error ({mask_username(linuxdo_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        if not results:
            print(f"❌ {self.account_name}: No valid authentication method found in configuration")
            return []

        # 输出最终结果
        print(f"\n📋 {self.account_name} authentication results:")
        successful_count = 0
        for auth_method, success, user_info in results:
            status = "✅" if success else "❌"
            print(f"  {status} {auth_method} authentication")
            if success:
                successful_count += 1

        print(f"\n🎯 {self.account_name}: {successful_count}/{len(results)} authentication methods successful")

        return results

   