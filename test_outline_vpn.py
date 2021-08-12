"""
Integration tests for the API wrapper
"""

import os

import pytest

from outline_vpn.outline_vpn import OutlineVPN


@pytest.fixture
def client() -> OutlineVPN:
    """This generates a client from the credentials provided in the environment"""
    assert os.getenv("OUTLINE_CREDENTIALS")
    client = OutlineVPN(api_url=os.getenv("OUTLINE_CREDENTIALS"))  # pylint: disable=W0621
    yield client


def test_get_keys(client: OutlineVPN):  # pylint: disable=W0621
    """Test for the get keys method"""
    assert len(client.get_keys()) >= 1


def test_cud_key(client: OutlineVPN):  # pylint: disable=W0621
    """Test creating/updating the name/deleting a key"""
    new_key = client.create_key()
    assert new_key is not None
    assert int(new_key.key_id) > 0

    assert client.rename_key(new_key.key_id, "a_name")

    assert client.delete_key(new_key.key_id)


def test_limits(client: OutlineVPN):  # pylint: disable=W0621
    """Test setting and removing limits"""
    assert client.add_data_limit(0, 1024 * 1024 * 20)
    assert client.delete_data_limit(0)
