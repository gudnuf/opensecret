//! Local-dev helper: inspect pg_stat_activity, optionally terminate orphaned
//! connections from prior opensecret runs.
//!
//! Usage:
//!     cargo run --bin pg-stat              # read-only stats
//!     KILL=1 cargo run --bin pg-stat       # terminate orphaned conns
//!
//! "Orphaned" = state IN ('idle', 'idle in transaction') AND application_name
//! does not match the current PID (i.e., not this script itself). We use
//! `pg_terminate_backend` on those.

use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::*;
use std::env;
use std::process::ExitCode;

#[derive(QueryableByName, Debug)]
struct Stat {
    #[diesel(sql_type = Text)]
    label: String,
    #[diesel(sql_type = BigInt)]
    n: i64,
}

#[derive(QueryableByName, Debug)]
struct Conn {
    #[diesel(sql_type = Integer)]
    pid: i32,
    #[diesel(sql_type = Nullable<Text>)]
    state: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    application_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    client_addr: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    query_start_age: Option<String>,
}

fn main() -> ExitCode {
    let _ = dotenv::dotenv();
    let url = match env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DATABASE_URL not set");
            return ExitCode::from(2);
        }
    };
    let mut conn = match PgConnection::establish(&url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return ExitCode::from(1);
        }
    };

    // Summary
    let stats: Vec<Stat> = diesel::sql_query(
        r#"
        SELECT 'total'      AS label, count(*)::bigint AS n FROM pg_stat_activity
        UNION ALL
        SELECT 'active'     AS label, count(*)::bigint AS n FROM pg_stat_activity WHERE state = 'active'
        UNION ALL
        SELECT 'idle'       AS label, count(*)::bigint AS n FROM pg_stat_activity WHERE state = 'idle'
        UNION ALL
        SELECT 'idle_in_tx' AS label, count(*)::bigint AS n FROM pg_stat_activity WHERE state = 'idle in transaction'
        UNION ALL
        SELECT 'max_conn'   AS label, current_setting('max_connections')::bigint AS n
        "#,
    )
    .load(&mut conn)
    .unwrap_or_default();

    eprintln!("== pg_stat_activity summary ==");
    for s in &stats {
        eprintln!("  {:12} = {}", s.label, s.n);
    }

    // List opensecret-y connections (datname=opensecret, not this script's pid)
    let conns: Vec<Conn> = diesel::sql_query(
        r#"
        SELECT pid,
               state,
               application_name,
               client_addr::text AS client_addr,
               (now() - query_start)::text AS query_start_age
        FROM pg_stat_activity
        WHERE datname = 'opensecret'
          AND pid <> pg_backend_pid()
        ORDER BY pid
        "#,
    )
    .load(&mut conn)
    .unwrap_or_default();

    eprintln!("\n== connections to db=opensecret (excluding self) ==");
    for c in &conns {
        eprintln!(
            "  pid={:6} state={:?} app={:?} client={:?} age={:?}",
            c.pid, c.state, c.application_name, c.client_addr, c.query_start_age
        );
    }

    if env::var("KILL").ok().as_deref() == Some("1") {
        eprintln!("\n== KILL=1: terminating idle / idle-in-tx backends ==");
        let killed: Vec<Stat> = diesel::sql_query(
            r#"
            SELECT 'killed' AS label, count(*)::bigint AS n
            FROM (
                SELECT pg_terminate_backend(pid) AS ok
                FROM pg_stat_activity
                WHERE datname = 'opensecret'
                  AND pid <> pg_backend_pid()
                  AND state IN ('idle','idle in transaction')
            ) t
            WHERE t.ok
            "#,
        )
        .load(&mut conn)
        .unwrap_or_default();
        for s in &killed {
            eprintln!("  {} = {}", s.label, s.n);
        }
    } else {
        eprintln!(
            "\n(set KILL=1 to terminate idle / idle-in-tx backends owned by db=opensecret)"
        );
    }

    ExitCode::SUCCESS
}
