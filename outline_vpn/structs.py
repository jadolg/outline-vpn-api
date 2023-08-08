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
    used_bytes: int
    data_limit: Optional[int]
