"""
API wrapper for Outline VPN
"""
import binascii
import json
from aiohttp import Fingerprint, ClientSession, FormData
from outline_vpn.exceptions import OutlineLibraryException, OutlineServerErrorException
from outline_vpn.models import UNABLE_TO_GET_METRICS_ERROR, OutlineKey
from outline_vpn.utils import create_payload


class AsyncOutlineVPN:
    """
    An Outline VPN connection
    """

    def __init__(self, api_url: str, cert_sha256: str):

        if cert_sha256:
            self.fingerprint = Fingerprint(binascii.unhexlify(cert_sha256.lower()))
            self.session = ClientSession(base_url=api_url)
        else:
            raise OutlineLibraryException(
                "No certificate SHA256 provided. Running without certificate is no longer supported."
            )

    async def get_keys(self, timeout: int = None) -> list[OutlineKey]:
        """Get all keys in the outline server"""

        async with self.session.get("access-keys/", ssl=self.fingerprint, timeout=timeout) as response:
            body = await response.json(loads=json.loads)
            if response.status != 200:
                raise OutlineServerErrorException("Unable to retrieve keys")
            if body.get("accessKeys") == "":
                raise OutlineServerErrorException("Unable to retrieve keys")

        async with self.session.get(f"metrics/transfer", ssl=self.fingerprint, timeout=timeout) as response_metrics:
            metric_body = await response_metrics.json(loads=json.loads)
            if (
                    response_metrics.status >= 400
                    or "bytesTransferredByUserId" not in metric_body
            ):
                raise OutlineServerErrorException(UNABLE_TO_GET_METRICS_ERROR)

        result: list[OutlineKey] = [OutlineKey(key, metrics=metric_body) for key in body.get("accessKeys")]
        return result

    async def get_key(self, key_id: str, timeout: int = None) -> OutlineKey:
        async with self.session.get(url=f"access-keys/{key_id}", ssl=self.fingerprint, timeout=timeout) as response:
            key = await response.json(loads=json.loads)
            if response.status != 200:
                raise OutlineServerErrorException("Unable to get key")
        async with self.session.get(f"metrics/transfer", ssl=self.fingerprint, timeout=timeout) as response_metrics:
            metric_body = await response_metrics.json(loads=json.loads)
            if (
                    response_metrics.status >= 400
                    or "bytesTransferredByUserId" not in metric_body
            ):
                raise OutlineServerErrorException(UNABLE_TO_GET_METRICS_ERROR)
        return OutlineKey(key, metrics=metric_body)

    async def create_key(
            self,
            name: str = None,
            method: str = None,
            password: str = None,
            data_limit: int = None,
            port: int = None,
            timeout: int = None,
    ) -> OutlineKey:
        """Create a new key"""

        async with self.session.post(
                url="access-keys",
                ssl=self.fingerprint,
                json=create_payload(name, method, password, data_limit, port),
                timeout=timeout,
        ) as response:
            if response.status != 201:
                raise OutlineServerErrorException(f"Unable to create key. {response.text}")

            key = await response.json(loads=json.loads)
            return OutlineKey(key)



    async def delete_key(self, key_id: str, timeout: int = None) -> bool:
        """Delete a key"""
        async with self.session.delete(
                url=f"access-keys/{key_id}",
                ssl=self.fingerprint,
                timeout=timeout,
        ) as response:
            return response.status == 204

    async def rename_key(self, key_id: str, name: str, timeout: int = None) -> bool:
        """Rename a key"""
        multipart_data = FormData()
        multipart_data.add_field("name", name)
        async with self.session.put(
                url=f"access-keys/{key_id}/name",
                ssl=self.fingerprint,
                data=multipart_data,
                timeout=timeout,
        ) as response:
            return response.status == 204

    async def add_data_limit(
            self, key_id: str, limit_bytes: int, timeout: int = None
    ) -> bool:
        """Set data limit for a key (in bytes)"""
        data = {"limit": {"bytes": limit_bytes}}

        async with self.session.put(
                url=f"access-keys/{key_id}/data-limit",
                json=data,
                ssl=self.fingerprint,
                timeout=timeout,
        ) as response:
            return response.status == 204

    async def delete_data_limit(self, key_id: str, timeout: int = None) -> bool:
        """Removes data limit for a key"""

        async with self.session.delete(
                url=f"access-keys/{key_id}/data-limit",
                ssl=self.fingerprint,
                timeout=timeout,
        ) as response:
            return response.status == 204

    async def get_transferred_data(self, timeout: int = None) -> dict:
        """Gets how much data all keys have used
        {
            "bytesTransferredByUserId": {
                "1":1008040941,
                "2":5958113497,
                "3":752221577
            }
        }"""

        async with self.session.get(
                url="metrics/transfer",
                ssl=self.fingerprint,
                timeout=timeout,
        ) as response:
            body = await response.json(loads=json.loads)
            if response.status >= 400 or "bytesTransferredByUserId" not in body:
                raise OutlineServerErrorException(UNABLE_TO_GET_METRICS_ERROR)
            return body

    async def get_server_information(self, timeout: int = None) -> dict:
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

        async with self.session.get("server", ssl=self.fingerprint, timeout=timeout) as response:
            if response.status != 200:
                raise OutlineServerErrorException("Unable to get information about the server")
            return await response.json()

    async def set_server_name(self, name: str, timeout: int = None) -> bool:
        """Renames the server"""

        async with self.session.put(
                f"name",
                ssl=self.fingerprint,
                json={"name": name},
                timeout=timeout,
        ) as response:
            return response.status == 204

    async def set_hostname(self, hostname: str, timeout: int = None) -> bool:
        """Changes the hostname for access keys.
        Must be a valid hostname or IP address."""

        async with self.session.put(
                f"name",
                ssl=self.fingerprint,
                json={"hostname": hostname},
                timeout=timeout,
        ) as response:
            return response.status == 204

    async def get_metrics_status(self, timeout: int = None) -> bool:
        """Returns whether metrics is being shared"""

        async with self.session.get(
                "metrics/enabled",
                ssl=self.fingerprint,
                timeout=timeout,
        ) as response:
            if response.status != 200:
                raise OutlineServerErrorException("Unable to get metrics status")
            body = await response.json(loads=json.loads)
            return body.get("metricsEnabled")

    async def set_metrics_status(self, status: bool, timeout: int = None) -> bool:
        """Enables or disables sharing of metrics"""

        async with self.session.put(
                url="metrics/enabled",
                ssl=self.fingerprint,
                json={"metricsEnabled": status},
                timeout=timeout,
        ) as response:
            return response.status == 204

    async def set_port_new_for_access_keys(self, port: int, timeout: int = None) -> bool:
        """Changes the default port for newly created access keys.
        This can be a port already used for access keys."""

        async with self.session.put(
                url="server/port-for-new-access-keys",
                ssl=self.fingerprint,
                json={"port": port},
                timeout=timeout,
        ) as response:
            if response.status == 400:
                raise OutlineServerErrorException(
                    "The requested port wasn't an integer from 1 through 65535, or the request had no port parameter."
                )
            elif response.status == 409:
                raise OutlineServerErrorException(
                    "The requested port was already in use by another service."
                )
            else:
                return response.status == 204

    async def set_data_limit_for_all_keys(
            self, limit_bytes: int, timeout: int = None
    ) -> bool:
        """Sets a data transfer limit for all access keys."""

        async with self.session.put(
            url="server/access-key-data-limit",
            ssl=self.fingerprint,
            json={"limit": {"bytes": limit_bytes}},
            timeout=timeout,
        ) as response:
            return response.status == 204

    async def delete_data_limit_for_all_keys(self, timeout: int = None) -> bool:
        """Removes the access key data limit, lifting data transfer restrictions on all access keys."""

        async with self.session.delete(
            url="server/access-key-data-limit",
            ssl=self.fingerprint,
            timeout=timeout,
        ) as response:
            return response.status == 204

    async def close(self):
        """Closes the session."""

        await self.session.close()
