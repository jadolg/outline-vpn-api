def create_payload(
        name: str | None = None,
        method: str | None = None,
        password: str | None = None,
        data_limit: int | None = None,
        port: int | None = None,
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
