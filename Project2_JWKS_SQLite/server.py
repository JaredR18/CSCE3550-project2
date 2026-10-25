"""Small JWKS server with SQLite-backed RSA keys."""

import base64
import json
import os
import sqlite3
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_NAME = "totally_not_my_privateKeys.db"


def open_db(db_path):
    return sqlite3.connect(db_path, timeout=10)


def new_private_key():
    """Generate an RSA private key and serialize it for database storage."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def prepare_database(db_path):
    """Create the table and keep one expired and one working key available."""
    with closing(open_db(db_path)) as connection:
        with connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS keys (
                       kid INTEGER PRIMARY KEY AUTOINCREMENT,
                       key BLOB NOT NULL,
                       exp INTEGER NOT NULL
                   )"""
            )

    ensure_keys(db_path)


def ensure_keys(db_path):
    now = int(time.time())
    with closing(open_db(db_path)) as connection:
        with connection:
            expired = connection.execute(
                "SELECT 1 FROM keys WHERE exp <= ? LIMIT 1", (now,)
            ).fetchone()
            valid = connection.execute(
                "SELECT 1 FROM keys WHERE exp > ? LIMIT 1", (now,)
            ).fetchone()

            if expired is None:
                connection.execute(
                    "INSERT INTO keys (key, exp) VALUES (?, ?)",
                    (new_private_key(), now - 3600),
                )
            if valid is None:
                connection.execute(
                    "INSERT INTO keys (key, exp) VALUES (?, ?)",
                    (new_private_key(), now + 7200),
                )


def get_signing_key(db_path, expired=False):
    """Return a (kid, PEM, expiry) row without including user input in SQL."""
    now = int(time.time())
    comparison = "<=" if expired else ">"
    with closing(open_db(db_path)) as connection:
        return connection.execute(
            f"SELECT kid, key, exp FROM keys WHERE exp {comparison} ? ORDER BY exp DESC LIMIT 1",
            (now,),
        ).fetchone()


def b64url_integer(number):
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_jwks(db_path):
    now = int(time.time())
    with closing(open_db(db_path)) as connection:
        rows = connection.execute(
            "SELECT kid, key FROM keys WHERE exp > ? ORDER BY kid", (now,)
        ).fetchall()

    keys = []
    for kid, pem in rows:
        private_key = serialization.load_pem_private_key(pem, password=None)
        public_numbers = private_key.public_key().public_numbers()
        keys.append(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": str(kid),
                "n": b64url_integer(public_numbers.n),
                "e": b64url_integer(public_numbers.e),
            }
        )
    return {"keys": keys}


def username_from_request(headers, body):
    """Accept Basic auth or JSON credentials. Authentication is mocked."""
    authorization = headers.get("Authorization", "")
    if authorization.lower().startswith("basic "):
        try:
            encoded = authorization.split(" ", 1)[1]
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
            return decoded.split(":", 1)[0] or "userABC"
        except (ValueError, UnicodeDecodeError):
            pass

    try:
        data = json.loads(body) if body else {}
        if isinstance(data, dict) and isinstance(data.get("username"), str):
            return data["username"] or "userABC"
    except (ValueError, UnicodeDecodeError):
        pass
    return "userABC"


def sign_token(db_path, username, expired=False):
    row = get_signing_key(db_path, expired=expired)
    if row is None:
        raise RuntimeError("No suitable signing key is available")

    kid, pem, exp = row
    claims = {"sub": username, "iat": int(time.time()), "exp": exp}
    token = jwt.encode(claims, pem, algorithm="RS256", headers={"kid": str(kid)})
    return {"token": token}


class JWKSHandler(BaseHTTPRequestHandler):
    def send_json(self, status, value):
        response = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path != "/.well-known/jwks.json":
            self.send_json(404, {"error": "Not found"})
            return
        ensure_keys(self.server.db_path)
        self.send_json(200, public_jwks(self.server.db_path))

    def do_POST(self):
        url = urlsplit(self.path)
        if url.path != "/auth":
            self.send_json(404, {"error": "Not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        body = self.rfile.read(min(max(length, 0), 65536))

        # Even ?expired by itself counts as requesting an expired signing key.
        expired = any(name == "expired" for name, _ in parse_qsl(url.query, keep_blank_values=True))
        ensure_keys(self.server.db_path)
        username = username_from_request(self.headers, body)
        self.send_json(200, sign_token(self.server.db_path, username, expired))


class JWKSServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, db_path):
        self.db_path = Path(db_path)
        prepare_database(self.db_path)
        super().__init__(address, JWKSHandler)


def main():
    port = int(os.environ.get("PORT", "8080"))
    host = os.environ.get("HOST", "127.0.0.1")
    database = Path.cwd() / DB_NAME
    server = JWKSServer((host, port), database)
    print(f"JWKS server listening at http://{host}:{server.server_port}", flush=True)
    print(f"Database: {database}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
