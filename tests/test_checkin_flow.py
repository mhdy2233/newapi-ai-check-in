import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from checkin import CheckIn
from utils.config import AccountConfig, OAuthAccountConfig, ProviderConfig


@pytest.mark.asyncio
async def test_authentication_stops_after_first_success():
    account = AccountConfig(
        provider="test",
        cookies={"session": "session-value"},
        api_user="123",
        system_access_token="system-token",
        github=[OAuthAccountConfig(username="github-user", password="github-pass")],
        linux_do=[OAuthAccountConfig(username="linux-user", password="linux-pass")],
        site=None,
    )
    provider = ProviderConfig(
        name="test",
        origin="https://example.test",
        check_in_path="/api/user/checkin",
        check_in_status=False,
    )
    checkin = CheckIn("test account", account, provider)
    checkin.check_in_with_cookies = AsyncMock(
        return_value=(
            True,
            {
                "success": True,
                "quota": 1,
                "used_quota": 0,
                "bonus_quota": 0,
                "display": "Current balance: $1",
            },
        )
    )
    checkin.check_in_with_system_access_token = AsyncMock()
    checkin.check_in_with_github = AsyncMock()
    checkin.check_in_with_linuxdo = AsyncMock()

    results = await checkin.execute()

    assert results == [
        (
            "cookies",
            True,
            {
                "success": True,
                "quota": 1,
                "used_quota": 0,
                "bonus_quota": 0,
                "display": "Current balance: $1",
            },
        )
    ]
    checkin.check_in_with_cookies.assert_awaited_once()
    checkin.check_in_with_system_access_token.assert_not_awaited()
    checkin.check_in_with_github.assert_not_awaited()
    checkin.check_in_with_linuxdo.assert_not_awaited()


@pytest.mark.asyncio
async def test_authentication_continues_after_failure_until_one_succeeds():
    account = AccountConfig(
        provider="test",
        system_access_token="system-token",
        api_user="123",
        github=[OAuthAccountConfig(username="github-user", password="github-pass")],
    )
    provider = ProviderConfig(
        name="test",
        origin="https://example.test",
        check_in_path="/api/user/checkin",
        check_in_status=False,
    )
    checkin = CheckIn("test account", account, provider)
    checkin.check_in_with_system_access_token = AsyncMock(return_value=(False, {"error": "failed"}))
    checkin.check_in_with_github = AsyncMock(
        return_value=(
            True,
            {
                "success": True,
                "quota": 1,
                "used_quota": 0,
                "bonus_quota": 0,
                "display": "Current balance: $1",
            },
        )
    )
    checkin.check_in_with_linuxdo = AsyncMock()

    results = await checkin.execute()

    assert [result[0:2] for result in results] == [
        ("system_access_token", False),
        ("github", True),
    ]
    checkin.check_in_with_system_access_token.assert_awaited_once()
    checkin.check_in_with_github.assert_awaited_once()
    checkin.check_in_with_linuxdo.assert_not_awaited()


class FakeResponse:
    status_code = 200
    url = "https://example.test/api/user/checkin?code=secret-code&month=2026-08"
    headers = {"content-type": "application/json"}
    text = '{"success":true,"message":"签到成功","token":"secret-token"}'

    def json(self):
        return {"success": True, "message": "签到成功", "token": "secret-token"}


def test_debug_logs_response_and_redacts_sensitive_fields(tmp_path, monkeypatch):
    from utils.http_utils import response_resolve

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEBUG", "true")

    result = response_resolve(FakeResponse(), "execute_check_in", "test account")

    assert result["success"] is True
    log_files = list((tmp_path / "logs").glob("*.json"))
    assert len(log_files) == 1
    content = log_files[0].read_text(encoding="utf-8")
    assert "签到成功" in content
    assert "secret-token" not in content
    assert "secret-code" not in content
    assert "month=2026-08" in content
    assert "***REDACTED***" in content
