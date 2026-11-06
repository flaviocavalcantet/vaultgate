"""Credentials from files in VAULTGATE_SECRETS_DIR (vaultgate_gateway.settings._secret)."""

from vaultgate_gateway.settings import _secret


def test_the_file_when_no_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("VAULTGATE_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("VAULTGATE_SECRETS_DIR", str(tmp_path))
    (tmp_path / "vaultgate_internal_token").write_text("from-openbao\n")
    assert _secret("INTERNAL_TOKEN") == "from-openbao"


def test_the_variable_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTGATE_INTERNAL_TOKEN", "from-env")
    monkeypatch.setenv("VAULTGATE_SECRETS_DIR", str(tmp_path))
    (tmp_path / "vaultgate_internal_token").write_text("from-openbao")
    assert _secret("INTERNAL_TOKEN") == "from-env"


def test_nothing_without_either(tmp_path, monkeypatch):
    monkeypatch.delenv("VAULTGATE_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("VAULTGATE_SECRETS_DIR", str(tmp_path))
    assert _secret("INTERNAL_TOKEN") is None
    monkeypatch.delenv("VAULTGATE_SECRETS_DIR")
    assert _secret("INTERNAL_TOKEN") is None
