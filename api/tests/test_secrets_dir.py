"""Settings from files in VAULTGATE_SECRETS_DIR: how credentials arrive from OpenBao."""

from vaultgate_api.config import Settings


def test_a_setting_comes_from_its_file(tmp_path, monkeypatch):
    monkeypatch.delenv("VAULTGATE_INTERNAL_TOKEN", raising=False)
    (tmp_path / "vaultgate_internal_token").write_text("from-openbao")
    (tmp_path / "vaultgate_database_url").write_text("postgresql+asyncpg://u:p@db/x")
    settings = Settings(_secrets_dir=tmp_path)
    assert settings.internal_token.get_secret_value() == "from-openbao"
    assert settings.database_url == "postgresql+asyncpg://u:p@db/x"
    assert settings.scanner_token is None  # no file, no variable


def test_a_variable_wins_over_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTGATE_INTERNAL_TOKEN", "from-env")
    (tmp_path / "vaultgate_internal_token").write_text("from-openbao")
    assert Settings(_secrets_dir=tmp_path).internal_token.get_secret_value() == "from-env"
