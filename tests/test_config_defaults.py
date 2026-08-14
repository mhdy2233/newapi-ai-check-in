import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.config import ProviderConfig


def test_custom_provider_uses_newapi_checkin_defaults_when_omitted():
    provider = ProviderConfig.from_dict(
        "shellten",
        {"origin": "https://api.shellten.top"},
        is_customize=True,
    )

    assert provider.check_in_path == "/api/user/checkin"
    assert provider.user_info_path == "/api/user/self"
    assert provider.check_in_status is True
    assert provider.get_check_in_url("23") == "https://api.shellten.top/api/user/checkin"
    assert provider.needs_manual_check_in() is True
    assert provider.get_check_in_status_func() is not None


def test_explicit_null_checkin_path_can_disable_standard_checkin():
    provider = ProviderConfig.from_dict(
        "special",
        {
            "origin": "https://example.test",
            "check_in_path": None,
            "check_in_status": False,
        },
        is_customize=True,
    )

    assert provider.check_in_path is None
    assert provider.check_in_status is False
    assert provider.needs_manual_check_in() is False
    assert provider.get_check_in_url("23") is None
