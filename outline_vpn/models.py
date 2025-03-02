from typing import Optional
from dataclasses import dataclass


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
    data_limit: Optional[int]

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
