"""
Integration tests for the API wrapper
"""

import os

from outline_vpn import OutlineVPN


def test_get_keys():
    """Test for the get keys method"""
    assert os.getenv("OUTLINE_CREDENTIALS")
    client = OutlineVPN(api_url=os.getenv("OUTLINE_CREDENTIALS"))
    assert len(client.get_keys()) == 1
