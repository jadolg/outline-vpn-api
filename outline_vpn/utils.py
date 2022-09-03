import ssl
import socket
import hashlib
from urllib.parse import urlparse


class OutlineConnectionError(Exception):
    pass


class OutlineInvalidFingerprintError(Exception):
    pass


def check_ssl_fingerprint(api_url: str, cert_sha256: str) -> bool:
    url = urlparse(api_url)
    address = url.hostname
    port = url.port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrapped_socket = ssl.wrap_socket(sock)
    try:
        wrapped_socket.connect((address, port))
    except Exception as e:
        raise OutlineConnectionError(f"Connection Error: {e}")
    else:
        der_cert = wrapped_socket.getpeercert(True)
        thumb_sha256 = hashlib.sha256(der_cert).hexdigest()
        if thumb_sha256.upper() != cert_sha256.upper():
            raise OutlineInvalidFingerprintError("Invalid fingerprint!")
    return True
