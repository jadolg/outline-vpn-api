import ssl
import socket
import hashlib
from urllib.parse import urlparse


def check_ssl_fingerprint(api_url: str, cert_sha256: str) -> bool:
    url = urlparse(api_url)
    address = url.hostname
    port = url.port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((address, port))
    except Exception as e:
        raise Exception(f"Connection Error: {e}")
    else:
        der_cert = wrappedSocket.getpeercert(True)
        thumb_sha256 = hashlib.sha256(der_cert).hexdigest()
        if thumb_sha256.upper() != cert_sha256.upper():
            raise Exception("Invalid fingerprint!")
    return True
