# Local-dev changes (not for upstream)

This file tracks patches kept in the local `opensecret` checkout for the
agicash rust dev environment. Each change is local-only — do not push to
`fork/` or upstream.

## `src/main.rs` — bind to `127.0.0.1:3999`

Default is `:3000`, which collides with the agicash dev server. The
enclave now binds to `:3999` so both can run on the same host.

```diff
-let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
+let listener = tokio::net::TcpListener::bind("127.0.0.1:3999")
```

## `src/bin/seed-project-secret.rs` — new dev helper

Seeds a per-project HS256 JWT secret into `org_project_secrets` so the
enclave will sign third-party JWTs with the same secret a downstream
verifier (Supabase gotrue, for our case) accepts.

The enclave's third-party-token signer (`src/jwt.rs`) reads
`org_project_secrets.secret_enc`, decrypts with the enclave key, and feeds
the resulting bytes to HS256 via `EncodingKey::from_secret(&decrypted)`.
This helper encrypts the *ASCII bytes* of a chosen plaintext so both
sides agree on the HMAC key.

Usage:

```sh
PROJECT_ID=1 SECRET='super-secret-jwt-token-with-at-least-32-characters-long' \
  cargo run --bin seed-project-secret
```

Omitting `SECRET` generates a random 32-byte hex string and prints it to
stdout (so you can paste it into the downstream service's env). `PROJECT_ID`
is required; confirm with `SELECT id, name FROM org_projects;` first.

Self-contained: declares its own minimal copy of the `org_project_secrets`
table macro and a duplicate of `crate::encrypt::encrypt_with_key`, because
`opensecret` has no `lib.rs` to import from. Keep the table macro and
encryption wrapper in sync with `src/models/schema.rs` and `src/encrypt.rs`
respectively.
