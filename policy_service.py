from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common import arguments_digest, b64url_encode, canonical_json


def serve(port: int, revision: str, audience: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status: int, payload: dict) -> None:
            encoded = canonical_json(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path == "/ready":
                self.send_json(200, {"ready": True})
            elif self.path == "/public-key":
                self.send_json(200, {"public_key": b64url_encode(public_key), "revision": revision})
            else:
                self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/authorize":
                self.send_json(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
            principal = request.get("principal")
            tool = request.get("tool")
            tool_version = request.get("tool_version")
            arguments = request.get("arguments", {})
            allowed = (
                principal == "purchasing-agent"
                and tool == "wire_payment"
                and tool_version == "v1"
                and arguments.get("vendor") == "approved-vendor"
                and arguments.get("currency") == "EUR"
                and isinstance(arguments.get("amount"), int)
                and 0 < arguments["amount"] <= 1000
            )
            if not allowed:
                self.send_json(403, {"decision": "deny"})
                return
            ttl_ms = max(1, min(int(request.get("ttl_ms", 5000)), 5000))
            claims = {
                "version": 1,
                "principal": principal,
                "tool": tool,
                "tool_version": tool_version,
                "audience": audience,
                "arguments_sha256": arguments_digest(arguments),
                "policy_revision": revision,
                "expires_at_ms": int(time.time() * 1000) + ttl_ms,
                "nonce": secrets.token_hex(16),
            }
            encoded_claims = b64url_encode(canonical_json(claims))
            signature = b64url_encode(private_key.sign(encoded_claims.encode()))
            self.send_json(200, {"decision": "allow", "permit": f"{encoded_claims}.{signature}"})

        def log_message(self, format, *args) -> None:
            pass

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--audience", required=True)
    args = parser.parse_args()
    serve(args.port, args.revision, args.audience)
