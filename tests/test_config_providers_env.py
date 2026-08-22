import json

from utils.config import AppConfig


def test_load_providers_merges_numbered_environment_variables(monkeypatch):
    monkeypatch.delenv("TEST_PROVIDERS", raising=False)
    monkeypatch.setenv(
        "TEST_PROVIDERS",
        json.dumps({"base": {"origin": "https://base.example"}, "shared": {"origin": "https://base-shared.example"}}),
    )
    monkeypatch.setenv("TEST_PROVIDERS_10", json.dumps({"ten": {"origin": "https://ten.example"}}))
    monkeypatch.setenv(
        "TEST_PROVIDERS_2",
        json.dumps({"two": {"origin": "https://two.example"}, "shared": {"origin": "https://numbered-shared.example"}}),
    )
    monkeypatch.setenv("TEST_PROVIDERS_OTHER", json.dumps({"ignored": {"origin": "https://ignored.example"}}))

    providers = AppConfig._load_providers("TEST_PROVIDERS")

    assert providers["base"].origin == "https://base.example"
    assert providers["two"].origin == "https://two.example"
    assert providers["ten"].origin == "https://ten.example"
    assert providers["shared"].origin == "https://numbered-shared.example"
    assert "ignored" not in providers


def test_load_providers_works_with_only_numbered_environment_variables(monkeypatch):
    monkeypatch.delenv("TEST_PROVIDERS", raising=False)
    monkeypatch.setenv("TEST_PROVIDERS_1", json.dumps({"numbered": {"origin": "https://numbered.example"}}))

    providers = AppConfig._load_providers("TEST_PROVIDERS")

    assert providers["numbered"].origin == "https://numbered.example"
    assert providers["numbered"].isCustomize is True


def test_invalid_numbered_provider_environment_does_not_hide_valid_providers(monkeypatch):
    monkeypatch.delenv("TEST_PROVIDERS", raising=False)
    monkeypatch.setenv("TEST_PROVIDERS", json.dumps({"base": {"origin": "https://base.example"}}))
    monkeypatch.setenv("TEST_PROVIDERS_1", "not-json")

    providers = AppConfig._load_providers("TEST_PROVIDERS")

    assert providers["base"].origin == "https://base.example"
