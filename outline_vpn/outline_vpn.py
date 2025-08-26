"""
API wrapper for Outline VPN
"""

import typing
from dataclasses import dataclass

import requests
from urllib3 import PoolManager

UNABLE_TO_GET_METRICS_ERROR = "Unable to get metrics"


@dataclass
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
        self.key_id = response.get("id")
        self.name = response.get("name")
        self.password = response.get("password")
        self.port = response.get("port")
        self.method = response.get("method")
        self.access_url = response.get("accessUrl")
        self.used_bytes = (
            metrics.get("bytesTransferredByUserId").get(response.get("id"))
            if metrics
            else 0
        )
        self.data_limit = response.get("dataLimit", {}).get("bytes")


class OutlineServerErrorException(Exception):
    pass


class OutlineLibraryException(Exception):
    pass


class _FingerprintAdapter(requests.adapters.HTTPAdapter):
    """
    This adapter injected into the requests session will check that the
    fingerprint for the certificate matches for every request
    """

    def __init__(self, fingerprint=None, **kwargs):
        self.fingerprint = str(fingerprint)
        super(_FingerprintAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
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

    def __init__(self, api_url: str, cert_sha256: str):
        self.api_url = api_url

        if cert_sha256:
            session = requests.Session()
            session.mount("https://", _FingerprintAdapter(cert_sha256))
            self.session = session
        else:
            raise OutlineLibraryException(
                "No certificate SHA256 provided. Running without certificate is no longer supported."
            )

    def get_keys(self, timeout: int = None) -> list[OutlineKey]:
        """Get all keys in the outline server"""
        response = self.session.get(
            f"{self.api_url}/access-keys/", verify=False, timeout=timeout
        )
        if response.status_code == 200 and "accessKeys" in response.json():
            response_metrics = self.session.get(
                f"{self.api_url}/metrics/transfer", verify=False
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

    def get_key(self, key_id: str, timeout: int = None) -> OutlineKey:
        response = self.session.get(
            f"{self.api_url}/access-keys/{key_id}", verify=False, timeout=timeout
        )
        if response.status_code == 200:
            key = response.json()

            response_metrics = self.session.get(
                f"{self.api_url}/metrics/transfer", verify=False, timeout=timeout
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
        key_id: str = None,
        name: str = None,
        method: str = None,
        password: str = None,
        data_limit: int = None,
        port: int = None,
        timeout: int = None,
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
                verify=False,
                json=payload,
                timeout=timeout,
            )
        else:
            response = self.session.post(
                f"{self.api_url}/access-keys",
                verify=False,
                json=payload,
                timeout=timeout,
            )

        if response.status_code == 201:
            key = response.json()
            outline_key = OutlineKey(key)
            return outline_key

        raise OutlineServerErrorException(f"Unable to create key. {response.text}")

    def delete_key(self, key_id: str, timeout: int = None) -> bool:
        """Delete a key"""
        response = self.session.delete(
            f"{self.api_url}/access-keys/{key_id}", verify=False, timeout=timeout
        )
        return response.status_code == 204

    def rename_key(self, key_id: str, name: str, timeout: int = None):
        """Rename a key"""
        files = {
            "name": (None, name),
        }

        response = self.session.put(
            f"{self.api_url}/access-keys/{key_id}/name",
            files=files,
            verify=False,
            timeout=timeout,
        )
        return response.status_code == 204

    def add_data_limit(
        self, key_id: str, limit_bytes: int, timeout: int = None
    ) -> bool:
        """Set data limit for a key (in bytes)"""
        data = {"limit": {"bytes": limit_bytes}}

        response = self.session.put(
            f"{self.api_url}/access-keys/{key_id}/data-limit",
            json=data,
            verify=False,
            timeout=timeout,
        )
        return response.status_code == 204

    def delete_data_limit(self, key_id: str, timeout: int = None) -> bool:
        """Removes data limit for a key"""
        response = self.session.delete(
            f"{self.api_url}/access-keys/{key_id}/data-limit",
            verify=False,
            timeout=timeout,
        )
        return response.status_code == 204

    def get_transferred_data(self, timeout: int = None):
        """Gets how much data all keys have used
        {
            "bytesTransferredByUserId": {
                "1":1008040941,
                "2":5958113497,
                "3":752221577
            }
        }"""
        response = self.session.get(
            f"{self.api_url}/metrics/transfer", verify=False, timeout=timeout
        )
        if (
            response.status_code >= 400
            or "bytesTransferredByUserId" not in response.json()
        ):
            raise OutlineServerErrorException(UNABLE_TO_GET_METRICS_ERROR)
        return response.json()

    def get_server_information(self, timeout: int = None):
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
            f"{self.api_url}/server", verify=False, timeout=timeout
        )
        if response.status_code != 200:
            raise OutlineServerErrorException(
                "Unable to get information about the server"
            )
        return response.json()

    def set_server_name(self, name: str, timeout: int = None) -> bool:
        """Renames the server"""
        data = {"name": name}
        response = self.session.put(
            f"{self.api_url}/name", verify=False, json=data, timeout=timeout
        )
        return response.status_code == 204

    def set_hostname(self, hostname: str, timeout: int = None) -> bool:
        """Changes the hostname for access keys.
        Must be a valid hostname or IP address."""
        data = {"hostname": hostname}
        response = self.session.put(
            f"{self.api_url}/server/hostname-for-access-keys",
            verify=False,
            json=data,
            timeout=timeout,
        )
        return response.status_code == 204

    def get_metrics_status(self, timeout: int = None) -> bool:
        """Returns whether metrics is being shared"""
        response = self.session.get(
            f"{self.api_url}/metrics/enabled", verify=False, timeout=timeout
        )
        return response.json().get("metricsEnabled")

    def set_metrics_status(self, status: bool, timeout: int = None) -> bool:
        """Enables or disables sharing of metrics"""
        data = {"metricsEnabled": status}
        response = self.session.put(
            f"{self.api_url}/metrics/enabled", verify=False, json=data, timeout=timeout
        )
        return response.status_code == 204

    def set_port_new_for_access_keys(self, port: int, timeout: int = None) -> bool:
        """Changes the default port for newly created access keys.
        This can be a port already used for access keys."""
        data = {"port": port}
        response = self.session.put(
            f"{self.api_url}/server/port-for-new-access-keys",
            verify=False,
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
        self, limit_bytes: int, timeout: int = None
    ) -> bool:
        """Sets a data transfer limit for all access keys."""
        data = {"limit": {"bytes": limit_bytes}}
        response = self.session.put(
            f"{self.api_url}/server/access-key-data-limit",
            verify=False,
            json=data,
            timeout=timeout,
        )
        return response.status_code == 204

    def delete_data_limit_for_all_keys(self, timeout: int = None) -> bool:
        """Removes the access key data limit, lifting data transfer restrictions on all access keys."""
        response = self.session.delete(
            f"{self.api_url}/server/access-key-data-limit",
            verify=False,
            timeout=timeout,
        )
        return response.status_code == 204
    def get_all_key_usages(self):
        """
        Get usage for all available keys.
        """
        try:
            keys = self.get_keys()
            usage_data = self.get_transferred_data()
            key_usage_list = []

            for key in keys:
                key_id = key.key_id
                used_bytes = usage_data.get("bytesTransferredByUserId", {}).get(key_id, 0)
                key_usage_list.append({
                    "key_id": key_id,
                    "name": key.name,
                    "used_bytes": used_bytes
                })

            return key_usage_list
        except Exception as e:
            raise OutlineServerErrorException(f"Failed to get all key usages: {str(e)}")

    def get_key_usage(self, key_name: str):
        """
        Get usage for a given key by name.
        """
        try:
            keys = self.get_keys()
            usage_data = self.get_transferred_data()

            for key in keys:
                if key.name == key_name:
                    key_id = key.key_id
                    used_bytes = usage_data.get("bytesTransferredByUserId", {}).get(key_id, 0)
                    return {
                        "key_id": key.key_id,
                        "name": key.name,
                        "used_bytes": used_bytes
                    }
            raise OutlineServerErrorException(f"Key with name {key_name} not found")
        except Exception as e:
            raise OutlineServerErrorException(f"Failed to get key usage for '{key_name}': {str(e)}")

    def get_key_info_by_name(self, name: str):
        """
        Get key information by key name.
        """
        try:
            keys = self.get_keys()
            for key in keys:
                if key.name == name:
                    return {
                        "id": key.key_id,
                        "name": name,
                        "url": key.access_url,
                        "used": key.used_bytes,
                        "data_limit": key.data_limit
                    }
            raise OutlineServerErrorException(f"Key with name {name} not found")
        except Exception as e:
            raise OutlineServerErrorException(f"Failed to get key info by name '{name}': {str(e)}")
