//! Local-dev helper: seed a per-project HS256 JWT secret into
//! `org_project_secrets` so OpenSecret will sign third-party JWTs with the
//! same secret a downstream service (e.g., Supabase gotrue) verifies with.
//!
//! Not for upstream / production. The enclave key here is `ENCLAVE_SECRET_MOCK`,
//! which only exists in `APP_MODE=local`.
//!
//! Usage:
//!     PROJECT_ID=<id> [SECRET=<ascii>] cargo run --bin seed-project-secret
//!
//! `PROJECT_ID` is required. If `SECRET` is omitted, generates a random
//! 32-byte hex string. The plaintext is printed to stdout (last line) so
//! the operator can paste it into the downstream service's JWT secret env.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use rand_core::RngCore;
use secp256k1::rand::rngs::OsRng;
use secp256k1::SecretKey;
use std::env;
use std::process::ExitCode;

// Minimal local copy of just the org_project_secrets table — the main
// `opensecret` crate has no `lib.rs`, so we can't reach its private
// `models::schema`. Keep in sync with `src/models/schema.rs`.
diesel::table! {
    org_project_secrets (id) {
        id -> Int4,
        project_id -> Int4,
        key_name -> Text,
        secret_enc -> Bytea,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

const THIRD_PARTY_JWT_SECRET: &str = "THIRD_PARTY_JWT_SECRET";

#[derive(Insertable)]
#[diesel(table_name = org_project_secrets)]
struct NewSecret<'a> {
    project_id: i32,
    key_name: &'a str,
    secret_enc: &'a [u8],
}

/// Mirror of `crate::encrypt::encrypt_with_key` from `opensecret`. We can't
/// reach the original (binary-only crate, private modules) so we duplicate
/// the AES-256-GCM wrapper. Format on disk:
///     [12-byte nonce][ciphertext]
/// matched by `decrypt_with_key` in the enclave at JWT-sign time.
fn encrypt_with_key(key: &SecretKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.secret_bytes()).expect("32-byte key always valid for AES");
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-GCM encrypt cannot fail with a valid key");
    let mut out = nonce_bytes.to_vec();
    out.extend(ciphertext);
    out
}

fn env_required(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("env var {key} is required"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = dotenv::dotenv();

    let project_id: i32 = match env_required("PROJECT_ID").and_then(|s| {
        s.parse::<i32>()
            .map_err(|e| format!("PROJECT_ID must be i32: {e}"))
    }) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let enclave_hex = match env_required("ENCLAVE_SECRET_MOCK") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let enclave_bytes: [u8; 32] = match hex::decode(&enclave_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    {
        Some(b) => b,
        None => {
            eprintln!("error: ENCLAVE_SECRET_MOCK must decode to exactly 32 bytes of hex");
            return ExitCode::from(2);
        }
    };
    let enclave_key = match SecretKey::from_slice(&enclave_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: enclave bytes not a valid secp256k1 key: {e}");
            return ExitCode::from(2);
        }
    };

    let database_url = match env_required("DATABASE_URL") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // Plaintext: explicit override via SECRET env, else random 32-byte hex.
    // Store the ASCII *string bytes* so OpenSecret (HS256 over decrypted
    // bytes) and downstream verifiers (HS256 over env-string bytes) agree.
    let plaintext = match env::var("SECRET") {
        Ok(s) => s,
        Err(_) => {
            let mut buf = [0u8; 32];
            OsRng.fill_bytes(&mut buf);
            hex::encode(buf)
        }
    };

    let encrypted = encrypt_with_key(&enclave_key, plaintext.as_bytes());

    let mut conn = match PgConnection::establish(&database_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: connect to {database_url}: {e}");
            return ExitCode::from(1);
        }
    };

    let new_secret = NewSecret {
        project_id,
        key_name: THIRD_PARTY_JWT_SECRET,
        secret_enc: &encrypted,
    };

    let result: QueryResult<(i32, i32, String)> = diesel::insert_into(org_project_secrets::table)
        .values(&new_secret)
        .on_conflict((
            org_project_secrets::project_id,
            org_project_secrets::key_name,
        ))
        .do_update()
        .set(org_project_secrets::secret_enc.eq(&encrypted))
        .returning((
            org_project_secrets::id,
            org_project_secrets::project_id,
            org_project_secrets::key_name,
        ))
        .get_result(&mut conn);

    match result {
        Ok((id, project_id, key_name)) => {
            eprintln!("upserted org_project_secrets row id={id} project_id={project_id} key_name={key_name}");
            // stdout: plaintext only, last line, for shell capture.
            println!("{plaintext}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: upsert failed: {e}");
            ExitCode::from(1)
        }
    }
}
