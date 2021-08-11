from dataclasses import dataclass

import requests


@dataclass
class OutlineKey:
    id: int
    name: str
    password: str
    port: int
    method: str
    access_url: str
    used_bytes: int


class OutlineVPN:
    def __init__(self, api_url: str):
        self.api_url = api_url

    def get_keys(self):
        response = requests.get(f"{self.api_url}/access-keys/", verify=False)
        if response.status_code == 200 and "accessKeys" in response.json():
            response_metrics = requests.get(
                f"{self.api_url}/metrics/transfer", verify=False
            )
            if (
                response_metrics.status_code >= 400
                or "bytesTransferredByUserId" not in response_metrics.json()
            ):
                raise Exception("Unable to get metrics")

            response_json = response.json()
            for key in response_json.get("accessKeys"):
                yield OutlineKey(
                    id=key.get("id"),
                    name=key.get("name"),
                    password=key.get("password"),
                    port=key.get("port"),
                    method=key.get("method"),
                    access_url=key.get("accessUrl"),
                    used_bytes=response_metrics.json()
                    .get("bytesTransferredByUserId")
                    .get(key.get("id")),
                )
        else:
            raise Exception("Unable to retrieve keys")

    def create_key(self) -> OutlineKey:
        response = requests.post(f"{self.api_url}/access-keys/", verify=False)
        if response.status_code == 201:
            key = response.json()
            return OutlineKey(
                id=key.get("id"),
                name=key.get("name"),
                password=key.get("password"),
                port=key.get("port"),
                method=key.get("method"),
                access_url=key.get("accessUrl"),
                used_bytes=0,
            )
        else:
            raise Exception("Unable to create key")

    def delete_key(self, key_id: int) -> bool:
        response = requests.delete(f"{self.api_url}/access-keys/{key_id}", verify=False)
        return response.status_code == 204

    def rename_key(self, key_id: int, name: str):
        files = {
            "name": (None, name),
        }

        response = requests.put(
            f"{self.api_url}/access-keys/{key_id}/name", files=files, verify=False
        )
        return response.status_code == 204

    def add_data_limit(self, key_id: int, limit_bytes: int) -> bool:
        data = {"limit": {"bytes": limit_bytes}}

        response = requests.put(
            f"{self.api_url}/access-keys/{key_id}/data-limit", json=data, verify=False
        )
        return response.status_code == 204

    def delete_data_limit(self, key_id: int) -> bool:
        response = requests.delete(
            f"{self.api_url}/access-keys/{key_id}/data-limit", verify=False
        )
        return response.status_code == 204

    def get_transferred_data(self):
        response = requests.get(f"{self.api_url}/metrics/transfer", verify=False)
        if (
            response.status_code >= 400
            or "bytesTransferredByUserId" not in response.json()
        ):
            raise Exception("Unable to get metrics")
        return response.json()
