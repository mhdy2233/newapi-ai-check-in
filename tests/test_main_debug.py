import sys
from pathlib import Path
from unittest.mock import patch

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from main import (
    get_accounts_debug_payload,
    get_accounts_env_names,
    is_debug_enabled,
    send_debug_accounts,
    split_debug_payload,
)


def test_get_accounts_env_names_orders_numbered_variables(monkeypatch):
    monkeypatch.setenv("ACCOUNTS_10", "ten")
    monkeypatch.setenv("ACCOUNTS_2", "two")
    monkeypatch.setenv("ACCOUNTS_1", "one")
    monkeypatch.setenv("ACCOUNTS_LINUX_DO", "ignored")

    assert get_accounts_env_names()[:4] == ["ACCOUNTS", "ACCOUNTS_1", "ACCOUNTS_2", "ACCOUNTS_10"]


def test_get_accounts_debug_payload_exports_raw_account_values(monkeypatch):
    monkeypatch.setenv("ACCOUNTS", '[{"provider":"demo","site":{"password":"secret"}}]')
    monkeypatch.setenv("ACCOUNTS_2", '{"provider":"second","site":{"password":"secret-2"}}')

    payload = get_accounts_debug_payload()

    assert "===== ACCOUNTS =====" in payload
    assert '"password":"secret"' in payload
    assert "===== ACCOUNTS_2 =====" in payload
    assert '"password":"secret-2"' in payload


def test_debug_helpers(monkeypatch):
    monkeypatch.setenv("DEBUG", "true")

    assert is_debug_enabled() is True
    assert split_debug_payload("123456", chunk_size=3) == ["123", "456"]


def test_send_debug_accounts_sends_plain_text_chunks(monkeypatch):
    monkeypatch.setenv("ACCOUNTS", '{"provider":"demo","site":{"password":"secret_value"}}')

    with patch("main.notify.push_message") as push_message:
        send_debug_accounts()

    push_message.assert_called_once()
    args, kwargs = push_message.call_args
    assert args[0] == "DEBUG ACCOUNTS"
    assert '"password":"secret_value"' in args[1]
    assert kwargs == {"msg_type": "text", "telegram_parse_mode": None}
