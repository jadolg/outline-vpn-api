from dataclasses import dataclass
from typing import Optional


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
    data_limit: Optional[int]
    used_bytes: int = 0

    @classmethod
    def from_key_json(cls, json_data: dict) -> "OutlineKey":
        return cls(
            key_id=int(json_data.get("id")),
            name=json_data.get("name"),
            password=json_data.get("password"),
            port=json_data.get("port"),
            method=json_data.get("method"),
            access_url=json_data.get("accessUrl"),
            data_limit=json_data.get("dataLimit", {}).get("bytes"),
            used_bytes=json_data.get("used_bytes"),
        )
