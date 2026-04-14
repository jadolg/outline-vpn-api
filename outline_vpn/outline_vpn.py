"""
API wrapper for Outline VPN
"""

import typing
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager

UNABLE_TO_GET_METRICS_ERROR = "Unable to get metrics"


@dataclass(init=False)
class OutlineKey:
    """
    Describes a key in the Outline server
    """

    key_id: str
    name: str
    password: str
    port: int
    method: str
    access_url: str
    used_bytes: int
    data_limit: typing.Optional[int]

    def __init__(self, response: dict, metrics: dict = None):
        self.key_id = response["id"]
        self.name = response["name"]
        self.password = response["password"]
        self.port = response["port"]
        self.method = response["method"]
        self.access_url = response["accessUrl"]
        transferred = (metrics or {}).get("bytesTransferredByUserId") or {}
        self.used_bytes = transferred.get(self.key_id) or 0
        data_limit = response.get("dataLimit")
        self.data_limit = data_limit.get("bytes") if isinstance(data_limit, dict) else None


class OutlineServerErrorException(Exception):
    pass


class OutlineLibraryException(Exception):
    pass


class _FingerprintAdapter(HTTPAdapter):
    """
    This adapter injected into the `requests` session will check that the
    fingerprint for the certificate matches for every request
    """

    def __init__(self, fingerprint=None, **kwargs):
        self.fingerprint = str(fingerprint)
        super(_FingerprintAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            assert_fingerprint=self.fingerprint,
        )


class OutlineVPN:
    """
    An Outline VPN connection
    """

    def __init__(self, api_url: str, cert_sha256: str, cert_path: typing.Optional[str] = None):
        self.api_url = api_url

        if cert_sha256:
            session = requests.Session()
            session.mount("https://", _FingerprintAdapter(cert_sha256))
            session.verify = cert_path if cert_path else False
            self.session = session
        else:
            raise OutlineLibraryException(
                "No certificate SHA256 provided. Running without certificate is no longer supported."
            )

    def get_keys(self, timeout: typing.Optional[int] = None) -> list[OutlineKey]:
        """Get all keys in the outline server"""
        response = self.session.get(
            f"{self.api_url}/access-keys/", timeout=timeout
        )
        if response.status_code == 200 and "accessKeys" in response.json():
            response_metrics = self.session.get(
                f"{self.api_url}/metrics/transfer", timeout=timeout
            )
            if (
                response_metrics.status_code >= 400
                or "bytesTransferredByUserId" not in response_metrics.json()
            ):
                raise OutlineServerErrorException(UNABLE_TO_GET_METRICS_ERROR)

            response_json = response.json()
            result: list[OutlineKey] = []
            for key in response_json.get("accessKeys"):
                result.append(OutlineKey(key, response_metrics.json()))
            return result
        raise OutlineServerErrorException("Unable to retrieve keys")

    def get_key(self, key_id: str, timeout: typing.Optional[int] = None) -> OutlineKey:
        response = self.session.get(
            f"{self.api_url}/access-keys/{key_id}", timeout=timeout
        )
        if response.status_code == 200:
            key = response.json()

            response_metrics = self.session.get(
                f"{self.api_url}/metrics/transfer", timeout=timeout
            )
            if (
                response_metrics.status_code >= 400
                or "bytesTransferredByUserId" not in response_metrics.json()
            ):
                raise OutlineServerErrorException(UNABLE_TO_GET_METRICS_ERROR)

            return OutlineKey(key, response_metrics.json())
        else:
            raise OutlineServerErrorException("Unable to get key")

    def create_key(
        self,
        key_id: typing.Optional[str] = None,
        name: typing.Optional[str] = None,
        method: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        data_limit: typing.Optional[int] = None,
        port: typing.Optional[int] = None,
        timeout: typing.Optional[int] = None,
    ) -> OutlineKey:
        """Create a new key"""

        payload = {}
        if name:
            payload["name"] = name
        if method:
            payload["method"] = method
        if password:
            payload["password"] = password
        if data_limit:
            payload["limit"] = {"bytes": data_limit}
        if port:
            payload["port"] = port
        if key_id:
            payload["id"] = key_id
            response = self.session.put(
                f"{self.api_url}/access-keys/{key_id}",
                json=payload,
                timeout=timeout,
            )
        else:
            response = self.session.post(
                f"{self.api_url}/access-keys",
                json=payload,
                timeout=timeout,
            )

        if response.status_code == 201:
            key = response.json()
            outline_key = OutlineKey(key)
            return outline_key

        raise OutlineServerErrorException(f"Unable to create key. {response.text}")

    def delete_key(self, key_id: str, timeout: typing.Optional[int] = None) -> bool:
        """Delete a key"""
        response = self.session.delete(
            f"{self.api_url}/access-keys/{key_id}", timeout=timeout
        )
        return response.status_code == 204

    def rename_key(self, key_id: str, name: str, timeout: typing.Optional[int] = None):
        """Rename a key"""
        files = {
            "name": (None, name),
        }

        response = self.session.put(
            f"{self.api_url}/access-keys/{key_id}/name",
            files=files,
            timeout=timeout,
        )
        return response.status_code == 204

    def add_data_limit(
        self, key_id: str, limit_bytes: int, timeout: typing.Optional[int] = None
    ) -> bool:
        """Set data limit for a key (in bytes)"""
        data = {"limit": {"bytes": limit_bytes}}

        response = self.session.put(
            f"{self.api_url}/access-keys/{key_id}/data-limit",
            json=data,
            timeout=timeout,
        )
        return response.status_code == 204

    def delete_data_limit(self, key_id: str, timeout: typing.Optional[int] = None) -> bool:
        """Removes data limit for a key"""
        response = self.session.delete(
            f"{self.api_url}/access-keys/{key_id}/data-limit",
            timeout=timeout,
        )
        return response.status_code == 204

    def get_transferred_data(self, timeout: typing.Optional[int] = None):
        """Gets how much data all keys have used
        {
            "bytesTransferredByUserId": {
                "1":1008040941,
                "2":5958113497,
                "3":752221577
            }
        }"""
        response = self.session.get(
            f"{self.api_url}/metrics/transfer", timeout=timeout
        )
        if (
            response.status_code >= 400
            or "bytesTransferredByUserId" not in response.json()
        ):
            raise OutlineServerErrorException(UNABLE_TO_GET_METRICS_ERROR)
        return response.json()

    def get_server_information(self, timeout: typing.Optional[int] = None):
        """Get information about the server
        {
            "name":"My Server",
            "serverId":"7fda0079-5317-4e5a-bb41-5a431dddae21",
            "metricsEnabled":true,
            "createdTimestampMs":1536613192052,
            "version":"1.0.0",
            "accessKeyDataLimit":{"bytes":8589934592},
            "portForNewAccessKeys":1234,
            "hostnameForAccessKeys":"example.com"
        }
        """
        response = self.session.get(
            f"{self.api_url}/server", timeout=timeout
        )
        if response.status_code != 200:
            raise OutlineServerErrorException(
                "Unable to get information about the server"
            )
        return response.json()

    def set_server_name(self, name: str, timeout: typing.Optional[int] = None) -> bool:
        """Renames the server"""
        data = {"name": name}
        response = self.session.put(
            f"{self.api_url}/name", json=data, timeout=timeout
        )
        return response.status_code == 204

    def set_hostname(self, hostname: str, timeout: typing.Optional[int] = None) -> bool:
        """Changes the hostname for access keys.
        Must be a valid hostname or IP address."""
        data = {"hostname": hostname}
        response = self.session.put(
            f"{self.api_url}/server/hostname-for-access-keys",
            json=data,
            timeout=timeout,
        )
        return response.status_code == 204

    def get_metrics_status(self, timeout: typing.Optional[int] = None) -> bool:
        """Returns whether metrics is being shared"""
        response = self.session.get(
            f"{self.api_url}/metrics/enabled", timeout=timeout
        )
        return response.json().get("metricsEnabled")

    def set_metrics_status(self, status: bool, timeout: typing.Optional[int] = None) -> bool:
        """Enables or disables sharing of metrics"""
        data = {"metricsEnabled": status}
        response = self.session.put(
            f"{self.api_url}/metrics/enabled", json=data, timeout=timeout
        )
        return response.status_code == 204

    def set_port_new_for_access_keys(self, port: int, timeout: typing.Optional[int] = None) -> bool:
        """Changes the default port for newly created access keys.
        This can be a port already used for access keys."""
        data = {"port": port}
        response = self.session.put(
            f"{self.api_url}/server/port-for-new-access-keys",
            json=data,
            timeout=timeout,
        )
        if response.status_code == 400:
            raise OutlineServerErrorException(
                "The requested port wasn't an integer from 1 through 65535, or the request had no port parameter."
            )
        elif response.status_code == 409:
            raise OutlineServerErrorException(
                "The requested port was already in use by another service."
            )
        return response.status_code == 204

    def set_data_limit_for_all_keys(
        self, limit_bytes: int, timeout: typing.Optional[int] = None
    ) -> bool:
        """Sets a data transfer limit for all access keys."""
        data = {"limit": {"bytes": limit_bytes}}
        response = self.session.put(
            f"{self.api_url}/server/access-key-data-limit",
            json=data,
            timeout=timeout,
        )
        return response.status_code == 204

    def delete_data_limit_for_all_keys(self, timeout: typing.Optional[int] = None) -> bool:
        """Removes the access key data limit, lifting data transfer restrictions on all access keys."""
        response = self.session.delete(
            f"{self.api_url}/server/access-key-data-limit",
            timeout=timeout,
        )
        return response.status_code == 204
