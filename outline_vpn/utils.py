import base64

import aiohttp


def get_aiohttp_fingerprint(ssl_assert_fingerprint: str) -> aiohttp.Fingerprint:
    return aiohttp.Fingerprint(
        base64.b16decode(ssl_assert_fingerprint.replace(":", ""), casefold=True)
    )
