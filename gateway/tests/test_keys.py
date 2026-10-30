import uuid

import boto3
import pytest
from moto import mock_aws

from vaultgate_gateway.keys import KMS_CLIENT_CONFIG, KeyUnavailable, KmsKeyProvider


@pytest.fixture
def kms():
    with mock_aws():
        client = boto3.client("kms", region_name="ap-northeast-1")
        key_id = client.create_key(Description="vaultgate test")["KeyMetadata"]["KeyId"]
        yield client, key_id


async def test_generate_and_unwrap(kms) -> None:
    client, key_id = kms
    provider = KmsKeyProvider(client, key_id)
    file_id = uuid.uuid4()
    key = await provider.generate(file_id)
    assert len(key.plaintext) == 32
    assert key.wrapped != key.plaintext
    assert key_id in key.kms_key_id
    assert await provider.unwrap(file_id, key.wrapped) == key.plaintext


async def test_wrapped_key_only_unwraps_for_its_file(kms) -> None:
    client, key_id = kms
    provider = KmsKeyProvider(client, key_id)
    key = await provider.generate(uuid.uuid4())
    with pytest.raises(KeyUnavailable):
        await provider.unwrap(uuid.uuid4(), key.wrapped)


async def test_kms_errors_become_key_unavailable(kms) -> None:
    client, _ = kms
    provider = KmsKeyProvider(client, "alias/does-not-exist")
    with pytest.raises(KeyUnavailable):
        await provider.generate(uuid.uuid4())


async def test_key_material_is_not_in_repr(kms) -> None:
    client, key_id = kms
    key = await KmsKeyProvider(client, key_id).generate(uuid.uuid4())
    assert key.plaintext.hex() not in repr(key)
    assert repr(key.plaintext) not in repr(key)


def test_client_from_settings_fails_fast() -> None:
    provider = KmsKeyProvider.from_settings(
        kms_key_id="alias/x", region="ap-northeast-1", endpoint_url="http://localhost:4566"
    )
    config = provider._client.meta.config
    assert config.connect_timeout == KMS_CLIENT_CONFIG.connect_timeout == 2
    assert config.read_timeout == 5
    assert config.retries == {"total_max_attempts": 3, "mode": "standard"}
