import json
import re
import pytest
import pytest_asyncio
from outline_vpn.outline_vpn_async import AsyncOutlineVPN

@pytest_asyncio.fixture
async def client():
    """This generates a client from the credentials provided in the environment"""
    install_log = open("outline-install.log", "r").read()
    json_text = re.findall("({[^}]+})", install_log)[0]
    api_data = json.loads(json_text)
    api_url = re.sub("https://[^:]+:", "https://127.0.0.1:", api_data.get("apiUrl"))

    client = AsyncOutlineVPN(api_url=api_url + '/', cert_sha256=api_data.get("certSha256"))
    return client


@pytest.mark.asyncio
async def test_crud(client: AsyncOutlineVPN):
    try:
        key = await client.create_key(name="new_test_key")
        assert key.name == 'new_test_key'
        assert (await client.get_key(key.key_id)).key_id == key.key_id
        assert await client.rename_key(key_id=key.key_id, name="update_test_key")
        assert (await client.get_key(key.key_id)).name == "update_test_key"
        assert await client.delete_key(key_id=key.key_id)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_create_with_attrs(client: AsyncOutlineVPN):
    """Test creating a key with attributes"""
    key = await client.create_key(
        name="Another test key",
        data_limit=1024 * 1024 * 20,
        method="aes-192-gcm",
        password="test",
        port=4545,
    )
    assert key.name == "Another test key"
    assert key.method == "aes-192-gcm"
    assert key.password == "test"
    assert key.data_limit == 1024 * 1024 * 20
    assert key.port == 4545
    assert await client.delete_key(key_id=key.key_id)


@pytest.mark.asyncio
async def test_limits(client: AsyncOutlineVPN):  # pylint: disable=W0621
    """Test setting, retrieving and removing custom limits"""

    new_limit = 1024 * 1024 * 20
    key = await client.create_key()

    assert await client.add_data_limit(key_id=key.key_id, limit_bytes=new_limit)
    assert (await client.get_key(key_id=key.key_id)).data_limit == new_limit
    assert await client.delete_data_limit(key.key_id)


@pytest.mark.asyncio
async def test_data_limit_for_all_keys(client: AsyncOutlineVPN):
    try:
        assert client.set_data_limit_for_all_keys(1024 * 1024 * 20)
        assert client.delete_data_limit_for_all_keys()
    finally:
        await client.close()

@pytest.mark.asyncio
async def test_get_transferred_data(client: AsyncOutlineVPN):
    """Call the method and assert it responds something"""
    data = await client.get_transferred_data()
    assert data is not None
    assert "bytesTransferredByUserId" in data



@pytest.mark.asyncio
async def test_metrics_status(client: AsyncOutlineVPN):
    metrics_status = await client.get_metrics_status()
    assert await client.set_metrics_status(not metrics_status)
    assert await client.get_metrics_status() != metrics_status
    await client.set_metrics_status(metrics_status)
