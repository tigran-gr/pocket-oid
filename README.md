# pocket-oid

A minimal OpenID Connect provider in Rust - no bloat, just auth.

## Getting started

1. Ensure you have the Rust toolchain installed (Rust 1.76 or later is recommended).
2. Copy the example configuration under `config/` and adjust the issuer URL, clients, and signing keys as needed.
3. Run the server:
   ```bash
   cargo run
   ```
4. Call the discovery endpoints:
   - `GET /.well-known/openid-configuration`
   - `GET /jwks.json`
5. Exchange client credentials for a token:
   ```bash
   curl -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=svc-alpha&client_secret=supersecret" \
     http://localhost:8080/oauth/token
   ```

Environment variables:

- `POCKET_OID_HOST` – host interface to bind (default `0.0.0.0`).
- `POCKET_OID_PORT` – port to bind (default `8080`).

The default configuration expects an RSA key in `config/keys/signing-key.pem` and exposes a single sample client (`svc-alpha`).
