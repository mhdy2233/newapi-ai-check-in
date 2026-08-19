import json

from utils.config import AppConfig


def _account(name: str) -> dict:
    return {
        "name": name,
        "provider": "anyrouter",
        "api_user": name,
        "system_access_token": f"token-{name}",
    }


def test_load_accounts_merges_numbered_environment_variables(monkeypatch):
    monkeypatch.setenv("TEST_ACCOUNTS", json.dumps([_account("base")]))
    monkeypatch.setenv("TEST_ACCOUNTS_10", json.dumps([_account("ten")]))
    monkeypatch.setenv("TEST_ACCOUNTS_2", json.dumps(_account("two")))
    monkeypatch.setenv("TEST_ACCOUNTS_LINUX_DO", json.dumps([_account("ignored")]))

    accounts = AppConfig._load_accounts("TEST_ACCOUNTS", [], [])

    assert [account.name for account in accounts] == ["base", "two", "ten"]


def test_load_accounts_works_with_only_numbered_environment_variables(monkeypatch):
    monkeypatch.delenv("TEST_ACCOUNTS", raising=False)
    monkeypatch.setenv("TEST_ACCOUNTS_1", json.dumps(_account("one")))

    accounts = AppConfig._load_accounts("TEST_ACCOUNTS", [], [])

    assert len(accounts) == 1
    assert accounts[0].name == "one"


def test_invalid_numbered_environment_variable_does_not_hide_valid_accounts(monkeypatch):
    monkeypatch.setenv("TEST_ACCOUNTS", json.dumps([_account("base")]))
    monkeypatch.setenv("TEST_ACCOUNTS_1", "not-json")

    accounts = AppConfig._load_accounts("TEST_ACCOUNTS", [], [])

    assert [account.name for account in accounts] == ["base"]
