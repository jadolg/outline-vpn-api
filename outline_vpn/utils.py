from typing import Union


def create_payload(
        name: Union[str, None],
        method: Union[str, None],
        password: Union[str, None],
        data_limit: Union[str, None],
        port: Union[str, None],
):
    payload: dict = {}
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
    return payload
