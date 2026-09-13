from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from common import arguments_digest, b64url_decode, canonical_json


def serve(port: int, database: Path, mode: str, public_key_text: str, revision: str, audience: str) -> None:
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS effects (id INTEGER PRIMARY KEY AUTOINCREMENT, nonce TEXT UNIQUE, principal TEXT, tool TEXT, arguments_json TEXT, committed_at_ms INTEGER)"
        )
    public_key = Ed25519PublicKey.from_public_bytes(b64url_decode(public_key_text))
    lock = threading.Lock()

    def verify_binding(request: dict) -> tuple[dict | None, str]:
        if mode == "trust-adapter":
            return {}, "adapter_trusted"
        permit = request.get("permit", "")
        try:
            encoded_claims, encoded_signature = permit.split(".", 1)
            public_key.verify(b64url_decode(encoded_signature), encoded_claims.encode())
            claims = json.loads(b64url_decode(encoded_claims))
        except (ValueError, json.JSONDecodeError, InvalidSignature):
            return None, "invalid_signature"
        if claims.get("version") != 1:
            return None, "unsupported_permit_version"
        if claims.get("audience") != audience:
            return None, "wrong_audience"
        if claims.get("principal") != request.get("principal"):
            return None, "principal_mismatch"
        if claims.get("tool") != request.get("tool"):
            return None, "tool_mismatch"
        if claims.get("tool_version") != request.get("tool_version"):
            return None, "tool_version_mismatch"
        if claims.get("arguments_sha256") != arguments_digest(request.get("arguments", {})):
            return None, "arguments_mismatch"
        return claims, "valid"

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
                return
            if self.path == "/effects":
                with sqlite3.connect(database) as connection:
                    rows = connection.execute(
                        "SELECT id, principal, tool, arguments_json, committed_at_ms FROM effects ORDER BY id"
                    ).fetchall()
                self.send_json(200, {"effects": [
                    {"id": row[0], "principal": row[1], "tool": row[2], "arguments": json.loads(row[3]), "committed_at_ms": row[4]}
                    for row in rows
                ]})
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/execute":
                self.send_json(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
            claims, reason = verify_binding(request)
            if claims is None:
                self.send_json(403, {"committed": False, "reason": reason})
                return
            nonce = claims.get("nonce")
            if nonce is not None:
                with sqlite3.connect(database) as connection:
                    existing = connection.execute("SELECT id FROM effects WHERE nonce = ?", (nonce,)).fetchone()
                if existing is not None:
                    self.send_json(200, {"committed": True, "replayed": True, "effect_id": existing[0]})
                    return
            if mode == "permit" and claims.get("expires_at_ms", 0) <= int(time.time() * 1000):
                self.send_json(403, {"committed": False, "reason": "expired"})
                return
            if mode == "permit" and claims.get("policy_revision") != revision:
                self.send_json(403, {"committed": False, "reason": "stale_policy"})
                return
            try:
                with lock, sqlite3.connect(database) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if nonce is not None:
                        connection.execute("INSERT INTO used_nonces(nonce) VALUES (?)", (nonce,))
                    cursor = connection.execute(
                        "INSERT INTO effects(nonce, principal, tool, arguments_json, committed_at_ms) VALUES (?, ?, ?, ?, ?)",
                        (nonce, request.get("principal"), request.get("tool"), canonical_json(request.get("arguments", {})).decode(), int(time.time() * 1000)),
                    )
                    effect_id = cursor.lastrowid
                    connection.commit()
            except sqlite3.IntegrityError:
                with sqlite3.connect(database) as connection:
                    existing = connection.execute("SELECT id FROM effects WHERE nonce = ?", (nonce,)).fetchone()
                self.send_json(200, {"committed": True, "replayed": True, "effect_id": existing[0]})
                return
            self.send_json(200, {"committed": True, "replayed": False, "effect_id": effect_id})

        def log_message(self, format, *args) -> None:
            pass

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--mode", choices=("trust-adapter", "permit"), required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--audience", required=True)
    args = parser.parse_args()
    serve(args.port, args.database, args.mode, args.public_key, args.revision, args.audience)
