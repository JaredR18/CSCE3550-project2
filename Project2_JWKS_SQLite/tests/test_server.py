"""Endpoint and database tests for Project 2."""

import base64
import http.client
import json
import sqlite3
import threading
import time
from contextlib import closing

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from server import JWKSServer, get_signing_key, prepare_database, public_jwks


@pytest.fixture
def running_server(tmp_path):
    db_path = tmp_path / "totally_not_my_privateKeys.db"
    server = JWKSServer(("127.0.0.1", 0), db_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, db_path
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def request(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        res = conn.getresponse()
        return res.status, json.loads(res.read())
    finally:
        conn.close()


def test_database_is_created_with_correct_schema_and_two_keys(running_server):
    _, db_path = running_server
    with closing(sqlite3.connect(db_path)) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(keys)")]
        rows = connection.execute("SELECT kid, key, exp FROM keys").fetchall()
    assert columns == ["kid", "key", "exp"]
    assert len(rows) >= 2
    assert len({r[0] for r in rows}) == len(rows)
    assert any(r[2] <= time.time() for r in rows)
    assert any(r[2] > time.time() for r in rows)
    assert all(b"BEGIN RSA PRIVATE KEY" in r[1] for r in rows)


def test_jwks_contains_only_valid_public_keys(running_server):
    server, db_path = running_server
    status, response = request(server, "GET", "/.well-known/jwks.json")
    assert status == 200
    assert len(response["keys"]) >= 1
    with closing(sqlite3.connect(db_path)) as connection:
        valid_ids = {
            str(row[0])
            for row in connection.execute("SELECT kid FROM keys WHERE exp > ?", (int(time.time()),))
        }
    assert {key["kid"] for key in response["keys"]} == valid_ids
    for key in response["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert key["n"] and key["e"]
        assert "key" not in key and "d" not in key


def test_auth_with_json_creates_verifiable_jwt(running_server):
    server, db_path = running_server
    status, result = request(
        server,
        "POST",
        "/auth",
        json.dumps({"username": "userABC", "password": "pass123"}),
        {"Content-Type": "application/json"},
    )
    assert status == 200
    token = result["token"]
    kid = jwt.get_unverified_header(token)["kid"]
    with closing(sqlite3.connect(db_path)) as connection:
        pem = connection.execute("SELECT key FROM keys WHERE kid = ?", (kid,)).fetchone()[0]
    public_key = serialization.load_pem_private_key(pem, None).public_key()
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    assert claims["sub"] == "userABC"
    assert claims["exp"] > time.time()


def test_expired_parameter_returns_expired_signed_jwt(running_server):
    server, db_path = running_server
    for query in ("?expired", "?expired=true"):
        status, result = request(server, "POST", "/auth" + query)
        assert status == 200
        token = result["token"]
        kid = jwt.get_unverified_header(token)["kid"]
        with closing(sqlite3.connect(db_path)) as connection:
            pem, expiry = connection.execute(
                "SELECT key, exp FROM keys WHERE kid = ?", (kid,)
            ).fetchone()
        public_key = serialization.load_pem_private_key(pem, None).public_key()
        assert expiry < time.time()
        claims = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_exp": False})
        assert claims["exp"] == expiry
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token, public_key, algorithms=["RS256"])


def test_basic_auth_is_accepted_without_real_password_check(running_server):
    server, _ = running_server
    basic = base64.b64encode(b"alice:wrong-password").decode("ascii")
    status, result = request(server, "POST", "/auth", headers={"Authorization": "Basic " + basic})
    assert status == 200
    assert jwt.decode(result["token"], options={"verify_signature": False})["sub"] == "alice"


def test_auth_with_empty_and_malformed_payloads(running_server):
    server, _ = running_server
    for body in (None, "bad-json", json.dumps({"username": 123})):
        status, result = request(server, "POST", "/auth", body)
        assert status == 200
        assert jwt.decode(result["token"], options={"verify_signature": False})["sub"] == "userABC"


def test_unknown_routes_return_404(running_server):
    server, _ = running_server
    assert request(server, "GET", "/auth")[0] == 404
    assert request(server, "POST", "/missing")[0] == 404


def test_database_persists_across_restart(tmp_path):
    db_path = tmp_path / "totally_not_my_privateKeys.db"
    prepare_database(db_path)
    before = public_jwks(db_path)
    valid_key = get_signing_key(db_path)
    expired_key = get_signing_key(db_path, expired=True)
    prepare_database(db_path)
    assert public_jwks(db_path) == before
    assert get_signing_key(db_path) == valid_key
    assert get_signing_key(db_path, expired=True) == expired_key


def test_replenishes_valid_key_after_expiration(tmp_path):
    db_path = tmp_path / "totally_not_my_privateKeys.db"
    prepare_database(db_path)
    with closing(sqlite3.connect(db_path)) as connection:
        with connection:
            connection.execute("UPDATE keys SET exp = ?", (int(time.time()) - 20,))
    assert not public_jwks(db_path)["keys"]
    prepare_database(db_path)
    assert public_jwks(db_path)["keys"]
