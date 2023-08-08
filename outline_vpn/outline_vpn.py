"""
API wrapper for Outline VPN
"""
import asyncio
import typing
from dataclasses import dataclass

import aiohttp

from utils import get_aiohttp_fingerprint


@dataclass
class OutlineKey:
    """
    Describes a key in the Outline server
    """

    key_id: int
    name: str
    password: str
    port: int
    method: str
    access_url: str
    used_bytes: int
    data_limit: typing.Optional[int]


class OutlineServerErrorException(Exception):
    pass


class OutlineVPN:
    """
    An Outline VPN connection
    """

    def __init__(self, api_url: str):
        self.api_url = api_url
        self.session: aiohttp.ClientSession | None = None

    async def init(self, cert_sha256: str = None):
        if cert_sha256:
            connector = aiohttp.TCPConnector(
                ssl=get_aiohttp_fingerprint(ssl_assert_fingerprint=cert_sha256)
            )
            session = aiohttp.ClientSession(connector=connector)
            self.session = session
        else:
            self.session = aiohttp.ClientSession()

    async def _get_metrics(self) -> dict:
        async with self.session.get(
            url=f"{self.api_url}/metrics/transfer"
        ) as resp:
            resp_json = await resp.json()
            if (
                resp.status >= 400
                or "bytesTransferredByUserId" not in resp_json
            ):
                raise OutlineServerErrorException("Unable to get metrics")
            return resp_json

    async def get_keys(self):
        """Get all keys in the outline server"""
        async with self.session.get(
            url=f"{self.api_url}/access-keys/",
        ) as resp:
            resp_json = await resp.json()
            if resp.status != 200 or "accessKeys" not in resp_json:
                raise OutlineServerErrorException("Unable to retrieve keys")

        response_metrics = await self._get_metrics()

        result = []
        for key in resp_json.get("accessKeys"):
            result.append(
                OutlineKey(
                    key_id=key.get("id"),
                    name=key.get("name"),
                    password=key.get("password"),
                    port=key.get("port"),
                    method=key.get("method"),
                    access_url=key.get("accessUrl"),
                    data_limit=key.get("dataLimit", {}).get("bytes"),
                    used_bytes=response_metrics
                    .get("bytesTransferredByUserId")
                    .get(key.get("id")),
                )
            )
        return result

    async def create_key(self, key_name: str = None) -> OutlineKey:
        """Create a new key"""
        async with self.session.post(
            url=f"{self.api_url}/access-keys/"
        ) as resp:

            if resp.status != 201:
                raise OutlineServerErrorException("Unable to create key")

            key = await resp.json()

        outline_key = OutlineKey(
            key_id=key.get("id"),
            name=key.get("name"),
            password=key.get("password"),
            port=key.get("port"),
            method=key.get("method"),
            access_url=key.get("accessUrl"),
            used_bytes=0,
            data_limit=None,
        )
        if key_name is not None:
            is_renamed = await self.rename_key(outline_key.key_id, key_name)
            if is_renamed:
                outline_key.name = key_name
        return outline_key

    async def delete_key(self, key_id: int) -> bool:
        """Delete a key"""
        async with self.session.delete(
            url=f"{self.api_url}/access-keys/{key_id}"
        ) as resp:
            return resp.status == 204

    async def rename_key(self, key_id: int, name: str) -> bool:
        """Rename a key"""
        async with self.session.put(
            url=f"{self.api_url}/access-keys/{key_id}/name",
            data={"name": name}
        ) as resp:
            return resp.status == 204

    def add_data_limit(self, key_id: int, limit_bytes: int) -> bool:
        """Set data limit for a key (in bytes)"""
        data = {"limit": {"bytes": limit_bytes}}

        response = self.session.put(
            f"{self.api_url}/access-keys/{key_id}/data-limit", json=data, verify=False
        )
        return response.status_code == 204

    def delete_data_limit(self, key_id: int) -> bool:
        """Removes data limit for a key"""
        response = self.session.delete(
            f"{self.api_url}/access-keys/{key_id}/data-limit", verify=False
        )
        return response.status_code == 204

    def get_transferred_data(self):
        """Gets how much data all keys have used
        {
            "bytesTransferredByUserId": {
                "1":1008040941,
                "2":5958113497,
                "3":752221577
            }
        }"""
        response = self.session.get(f"{self.api_url}/metrics/transfer", verify=False)
        if (
            response.status_code >= 400
            or "bytesTransferredByUserId" not in response.json()
        ):
            raise OutlineServerErrorException("Unable to get metrics")
        return response.json()

    def get_server_information(self):
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
        response = self.session.get(f"{self.api_url}/server", verify=False)
        if response.status_code != 200:
            raise OutlineServerErrorException(
                "Unable to get information about the server"
            )
        return response.json()

    def set_server_name(self, name: str) -> bool:
        """Renames the server"""
        data = {"name": name}
        response = self.session.put(f"{self.api_url}/name", verify=False, json=data)
        return response.status_code == 204

    def set_hostname(self, hostname: str) -> bool:
        """Changes the hostname for access keys.
        Must be a valid hostname or IP address."""
        data = {"hostname": hostname}
        response = self.session.put(
            f"{self.api_url}/server/hostname-for-access-keys", verify=False, json=data
        )
        return response.status_code == 204

    def get_metrics_status(self) -> bool:
        """Returns whether metrics is being shared"""
        response = self.session.get(f"{self.api_url}/metrics/enabled", verify=False)
        return response.json().get("metricsEnabled")

    def set_metrics_status(self, status: bool) -> bool:
        """Enables or disables sharing of metrics"""
        data = {"metricsEnabled": status}
        response = self.session.put(
            f"{self.api_url}/metrics/enabled", verify=False, json=data
        )
        return response.status_code == 204

    def set_port_new_for_access_keys(self, port: int) -> bool:
        """Changes the default port for newly created access keys.
        This can be a port already used for access keys."""
        data = {"port": port}
        response = self.session.put(
            f"{self.api_url}/server/port-for-new-access-keys", verify=False, json=data
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

    def set_data_limit_for_all_keys(self, limit_bytes: int) -> bool:
        """Sets a data transfer limit for all access keys."""
        data = {"limit": {"bytes": limit_bytes}}
        response = self.session.put(
            f"{self.api_url}/server/access-key-data-limit", verify=False, json=data
        )
        return response.status_code == 204

    def delete_data_limit_for_all_keys(self) -> bool:
        """Removes the access key data limit, lifting data transfer restrictions on all access keys."""
        response = self.session.delete(
            f"{self.api_url}/server/access-key-data-limit", verify=False
        )
        return response.status_code == 204

    def __del__(self):
        if self.session is not None:
            asyncio.create_task(self.session.close())
