# Project 2 - JWKS server with SQLite

This extends the basic JWKS server by storing the RSA private keys in SQLite instead of keeping them only in memory.

## Setup

Python 3.10+ is recommended.

```powershell
python -m pip install -r requirements.txt
python server.py
```

The server runs on `http://127.0.0.1:8080` by default. It creates `totally_not_my_privateKeys.db` in the **current working directory**, using the table and column names required by the assignment. The file and keys stay in place when the server is restarted. Keep the database out of public repositories.

You can set the `PORT` and `HOST` environment variables if necessary. Stop the server with Ctrl+C.

## Endpoints

- `GET /.well-known/jwks.json` - Returns the public parts of non-expired RSA keys in JWKS format.
- `POST /auth` - Returns a signed RS256 JWT, using an unexpired private key from SQLite.
- `POST /auth?expired` - Returns a JWT signed with an expired key to test expiry handling.

Authentication is deliberately mocked for this exercise. Both HTTP Basic credentials and JSON bodies such as `{"username":"userABC","password":"pass123"}` are accepted; no real password checking is performed.

Examples in a separate terminal:

```powershell
curl.exe http://127.0.0.1:8080/.well-known/jwks.json
curl.exe -X POST http://127.0.0.1:8080/auth -H "Content-Type: application/json" -d '{"username":"userABC","password":"pass123"}'
curl.exe -X POST http://127.0.0.1:8080/auth?expired
```

On Windows PowerShell, shell quoting for the JSON example may differ. The Basic-auth example is simpler to test with `curl.exe -u userABC:pass123 -X POST http://127.0.0.1:8080/auth`.

## Tests

In another terminal, from the project directory:

```powershell
python -m pytest -v --cov=server --cov-report=term-missing --cov-fail-under=80
```

The tests cover database creation and persistence, RSA JWT signing, expired tokens, JWKS output, both auth styles, and error routes.

