"""
Integration tests for the API wrapper
"""

import json
import random
import re

import pytest

from outline_vpn.outline_vpn import OutlineVPN, OutlineLibraryException


@pytest.fixture
def client() -> OutlineVPN:
    """This generates a client from the credentials provided in the environment"""
    install_log = open("outline-install.log", "r").read()
    json_text = re.findall("({[^}]+})", install_log)[0]
    api_data = json.loads(json_text)
    api_url = re.sub("https://[^:]+:", "https://127.0.0.1:", api_data.get("apiUrl"))

    client = OutlineVPN(api_url=api_url, cert_sha256=api_data.get("certSha256"))

    return client


def test_no_cert_sha256_raises_exception():
    """Test that the client raises an exception if the cert sha256 is not provided"""
    with pytest.raises(OutlineLibraryException):
        OutlineVPN(api_url="https://aaa", cert_sha256="")


def test_get_keys(client: OutlineVPN):  # pylint: disable=W0621
    """Test for the get keys method"""
    assert len(client.get_keys()) >= 1


def test_crud_key(client: OutlineVPN):  # pylint: disable=W0621
    """Test creating/updating the name/deleting a key"""
    new_key = client.create_key()
    assert new_key is not None
    assert int(new_key.key_id) > 0

    read_key = client.get_key(new_key.key_id)
    assert read_key is not None
    assert read_key.key_id == new_key.key_id

    named_key = client.create_key(name="Test Key")
    assert named_key.name == "Test Key"

    assert client.rename_key(new_key.key_id, "a_name")

    assert client.delete_key(new_key.key_id)


def test_create_key_with_attributes(client: OutlineVPN):
    """Test creating a key with attributes"""
    key = client.create_key(
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
    assert client.delete_key(key.key_id)


def test_create_key_with_attributes_and_id(client: OutlineVPN):
    """Test creating a key with attributes and id"""
    key_id = f"test-id-{random.random()}"
    key = client.create_key(
        key_id=key_id,
        name="Yet another test key",
        data_limit=1024 * 1024 * 20,
        method="aes-192-gcm",
        password="test",
        port=2323,
    )
    assert key.key_id == key_id
    assert key.name == "Yet another test key"
    assert key.method == "aes-192-gcm"
    assert key.password == "test"
    assert key.data_limit == 1024 * 1024 * 20
    assert key.port == 2323
    assert client.delete_key(key.key_id)


def test_limits(client: OutlineVPN):  # pylint: disable=W0621
    """Test setting, retrieving and removing custom limits"""
    new_limit = 1024 * 1024 * 20
    target_key_id = 0

    assert client.add_data_limit(target_key_id, new_limit)

    keys = client.get_keys()
    for key in keys:
        if key.key_id == target_key_id:
            assert key.data_limit == new_limit

    assert client.delete_data_limit(target_key_id)


def test_server_methods(client: OutlineVPN):
    server_info = client.get_server_information()
    assert server_info is not None
    new_server_name = "Test Server name"
    assert client.set_server_name(new_server_name)
    new_hostname = "example.com"
    assert client.set_hostname(new_hostname)
    new_port_for_access_keys = 11233
    assert client.set_port_new_for_access_keys(new_port_for_access_keys)
    updated_server_info = client.get_server_information()
    assert updated_server_info.get("name") == new_server_name
    assert updated_server_info.get("hostnameForAccessKeys") == new_hostname
    assert updated_server_info.get("portForNewAccessKeys") == new_port_for_access_keys

    assert client.set_server_name(server_info.get("name"))
    assert client.set_hostname(server_info.get("hostnameForAccessKeys"))
    assert client.set_port_new_for_access_keys(server_info.get("portForNewAccessKeys"))


def test_metrics_status(client: OutlineVPN):
    metrics_status = client.get_metrics_status()
    assert client.set_metrics_status(not metrics_status)
    assert client.get_metrics_status() != metrics_status
    client.set_metrics_status(metrics_status)


def test_data_limit_for_all_keys(client: OutlineVPN):
    assert client.set_data_limit_for_all_keys(1024 * 1024 * 20)
    assert client.delete_data_limit_for_all_keys()


def test_get_transferred_data(client: OutlineVPN):
    """Call the method and assert it responds something"""
    data = client.get_transferred_data()
    assert data is not None
    assert "bytesTransferredByUserId" in data
