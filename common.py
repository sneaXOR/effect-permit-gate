from __future__ import annotations

import base64
import hashlib
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def arguments_digest(arguments: dict) -> str:
    return hashlib.sha256(canonical_json(arguments)).hexdigest()


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def http_json(method: str, url: str, payload: dict | None = None, timeout: float = 3) -> tuple[int, dict]:
    body = None if payload is None else canonical_json(payload)
    request = Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else {}
