import os

from outline_vpn import OutlineVPN


def test_get_keys():
    assert os.getenv("OUTLINE_CREDENTIALS")
    api_url = f'https://127.0.0.1:{os.getenv("OUTLINE_CREDENTIALS")}'
    print(api_url)
    client = OutlineVPN(api_url)
    assert len(client.get_keys()) == 1
