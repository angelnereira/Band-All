//! Schema guards for the Postgres migrations.
//!
//! Both checks exist because of the same class of bug, found by the first run
//! of the ADR-0017 ticket battery against real Postgres: a timestamp column
//! declared `INTEGER` (Postgres `INT4`, 32-bit) while the store decodes it as
//! `i64`. The inserts succeeded and every read failed with a `ColumnDecode`
//! error, because sqlx refuses to decode `INT4` into `INT8`.
//!
//! What makes this class of bug dangerous is that **SQLite cannot catch it**:
//! SQLite's type system is dynamic, so an `INTEGER` column happily holds 64-bit
//! values and the shared conformance battery passes on both engines. Only
//! Postgres complains. So the guard has to be a check on the migration files
//! themselves, which needs no database and therefore runs everywhere.

use std::fs;
use std::path::PathBuf;

/// The Postgres migrations, resolved from this file's location.
fn migrations_dir() -> PathBuf {
    // crates/store/src/...  ->  crates/store/migrations/postgres
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join("postgres")
}

/// Timestamp columns declared `INTEGER`, which decode wrong.
///
/// Returns `(column, type)` pairs so the failure can name the offending line
/// instead of just counting them.
///
/// The comparison is against the SQL keyword `INTEGER`, case-insensitively, and
/// **not** against Postgres's internal name `int4`: the migration files spell
/// it `INTEGER`. The first version of this guard looked for `int4` and passed
/// on the broken migration, which is worth recording — it is exactly how a
/// guard test can look green while protecting nothing.
fn integer_timestamp_columns(migration: &str) -> Vec<(String, String)> {
    migration
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // A comment, a blank line, or the closing paren of `CREATE TABLE`
            // is not a column definition.
            if trimmed.starts_with("--") || trimmed.is_empty() || trimmed.starts_with(')') {
                return None;
            }
            let (name, rest) = trimmed.split_once(char::is_whitespace)?;
            let column = match name.to_ascii_lowercase().as_str() {
                // Every one of these is read as `i64` by the store.
                //
                // `access_expires_at` is in the list on purpose: the first
                // version of this guard omitted it, so the one column that was
                // actually broken — the connection ceiling ADR-0017 adds — was
                // never checked and the test passed on the broken migration.
                "created_at" | "expires_at" | "access_expires_at" | "used_at" | "revoked_at"
                | "ts" | "last_step" => name.to_string(),
                _ => return None,
            };
            let sql_type = rest.split_whitespace().next()?;
            sql_type
                .eq_ignore_ascii_case("INTEGER")
                .then(|| (column, sql_type.to_string()))
        })
        .collect()
}

#[test]
fn postgres_timestamps_are_bigint_not_integer() {
    let mut offenders = Vec::new();
    for entry in fs::read_dir(migrations_dir()).expect("the migrations directory exists") {
        let path = entry.expect("a readable migration").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".sql") {
            continue;
        }
        let sql = fs::read_to_string(&path).expect("a migration is UTF-8 text");
        offenders.extend(
            integer_timestamp_columns(&sql)
                .into_iter()
                .map(|(column, sql_type)| format!("{name}: `{column} {sql_type}`")),
        );
    }

    assert!(
        offenders.is_empty(),
        "Postgres timestamp columns must be BIGINT: the store decodes them as \
         i64, and sqlx refuses to decode INT4. Each one below passes on SQLite \
         and fails on every read against Postgres:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn every_migration_declares_the_ws_tickets_columns_the_store_reads() {
    // The store reads `WsTicketEntry` with `query_as`, so the column names in
    // the migration are a contract: a rename breaks decoding at runtime rather
    // than at compile time.
    let sql = fs::read_to_string(migrations_dir().join("8_ws_tickets.sql"))
        .expect("migration 8 exists (ADR-0017)");

    for column in [
        "code_hash",
        "session_id",
        "tenant_id",
        "subject_id",
        // The hard ceiling for the connection. It has to survive a rename:
        // without it the API cannot tell a service how long the connection may
        // live, which is the one thing ADR-0017 adds over a bearer token.
        "access_expires_at",
        "created_at",
        "expires_at",
        "used_at",
    ] {
        assert!(
            sql.contains(column),
            "migration 8 is missing `{column}`, which the store reads back with \
             `UPDATE ... RETURNING`"
        );
    }
}
