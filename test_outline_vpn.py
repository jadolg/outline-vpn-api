"""
Integration tests for the API wrapper
"""

import os

from outline_vpn import OutlineVPN


def test_get_keys():
    """Test for the get keys method"""
    assert os.getenv("OUTLINE_CREDENTIALS")
    api_url = f'https://127.0.0.1:{os.getenv("OUTLINE_CREDENTIALS")}'
    print(api_url)
    client = OutlineVPN(api_url)
    assert len(client.get_keys()) == 1
