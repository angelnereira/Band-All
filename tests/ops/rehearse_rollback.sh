#!/usr/bin/env bash
# Rollback rehearsal (H8 production checklist: "plan de reversión probado").
#
# Worth knowing before reading: **the first version of this drill failed, and
# what it found is the point of rehearsing.**
#
# The obvious rollback is "put the old binary back". It does not work here,
# because `serve` runs the migrator at startup (`crates/api/src/server.rs`) and
# sqlx refuses to run a migrator against a schema that has migrations the
# migrator does not know about — even when the extra migration is purely
# additive. The old binary refuses to start, on the schema the new migration
# left behind, during an incident.
#
# So the procedure that actually rolls back is the older, heavier one:
#
#   1. take a backup BEFORE the forward migration
#   2. forward to v2, migrate, verify
#   3. to roll back: restore that backup, then start v1 (whose migrator knows the
#      restored schema and is happy)
#
# That is what this rehearsal proves, and it documents what it costs: whatever
# was written after the backup is gone. Which is the same reason `restore.md`
# tells you to rehearse before production.
#
# Needs a running Docker daemon.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# Off the usual ports for the same reason as the chaos drill: a rehearsal should
# not fail because something else on the machine holds 18081.
PORT="${BANDALL_ROLLBACK_PORT:-18081}"
BASE_URL="http://127.0.0.1:${PORT}"
CONTAINER="bandall-rollback"
VOLUME="bandall-rollback-data"
SERVICE_KEY="rollback-service-key-0123456789ab"
IMAGE_V1="bandall-rollback-v1"
IMAGE_V2="bandall-rollback-v2"
CONFIG="rollback-bandall.toml"
DB_NAME="bandall.db"

# Docker Desktop shares $HOME with the VM but not /tmp, so the throwaway config
# and key material live under $HOME and die with the run.
WORK="$(mktemp -d "${HOME}/.bandall-rollback-XXXXXX")"
BUILD_V2="$WORK/v2-src"
BACKUP="$WORK/bandall.db.rollback-point"

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1"; exit 1; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
note() { printf '  note: %s\n' "$1"; }

cleanup() {
    local status=$?
    printf '\n==> tearing down\n'
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "${CONTAINER}-helper" >/dev/null 2>&1 || true
    docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
    docker rmi -f "$IMAGE_V1" "$IMAGE_V2" >/dev/null 2>&1 || true
    rm -rf "$WORK"
    return $status
}
trap cleanup EXIT

# The common command line. The runtime image is distroless — no shell, no
# entrypoint tricks — so the two callers below differ only in the subcommand.
run_once() { # $1 = image, $2 = subcommand, $3 = detach flag ("")
    local extra=()
    if [ -n "$3" ]; then extra=(-d); fi
    docker run "${extra[@]}" --rm \
        --name "$CONTAINER" \
        -p "127.0.0.1:${PORT}:8080" \
        -e BANDALL_CONFIG="/config/bandall.toml" \
        -e BANDALL_DATABASE_URL="sqlite:/data/${DB_NAME}" \
        -e BANDALL_KMS_KEY_FILE="/run/secrets/bandall-kek" \
        -e BANDALL_AUDIT_KEY_FILE="/run/secrets/bandall-audit-key" \
        -e BANDALL_SERVICE_KEY="$SERVICE_KEY" \
        -e RUST_LOG="bandall=debug" \
        -v "$WORK/$CONFIG:/config/bandall.toml:ro" \
        -v "$WORK/kek.bin:/run/secrets/bandall-kek:ro" \
        -v "$WORK/audit-key.bin:/run/secrets/bandall-audit-key:ro" \
        -v "$VOLUME:/data" \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --tmpfs /tmp:rw,size=32m \
        "$1" "$2"
}

# Starts a version.
#
# `AUTO_MIGRATE=1` is the forward deployment: migrate, then serve. This is what
# a release does, and it is what makes the schema move.
#
# `AUTO_MIGRATE=0` is a rollback: serve directly, against whatever the database
# already holds. The flag exists as a flag because it is the whole difference
# between the two operations, and a rehearsal that hides it is a rehearsal that
# documents nothing.
start_version() { # $1 = image, $2 = AUTO_MIGRATE
    local image="$1" auto_migrate="$2"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

    if [ "$auto_migrate" = "1" ]; then
        run_once "$image" migrate "" >/dev/null 2>"$WORK/migrate.err" \
            || { sed 's/^/    /' "$WORK/migrate.err" | tail -6
                 fail "migrate failed on $image (that is what a rollback needs to avoid)"; }
    fi

    run_once "$image" serve "-d" >/dev/null

    local tries=0
    until curl -fsS --max-time 3 "$BASE_URL/readyz" >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -gt 60 ]; then
            docker logs "$CONTAINER" 2>&1 | tail -8 | sed 's/^/    /'
            fail "$image never became ready on the current schema"
        fi
        sleep 1
    done
}

# Copies the database out of the volume (the savepoint) or back into it.
# Done through a throwaway alpine container: the runtime is distroless, so it
# cannot copy anything itself, and the service is stopped, so the file is
# quiescent.
savepoint() {
    docker rm -f "${CONTAINER}-helper" >/dev/null 2>&1 || true
    docker run --rm -v "$VOLUME:/data" -v "$WORK:/host" alpine \
        sh -c "cp /data/${DB_NAME} /host/savepoint.db" >/dev/null
}
# Restores the savepoint back into the volume.
#
# The `chown` is not decoration: the helper container runs as root, so the file
# it writes lands as `root:root`, and the service runs as `nonroot` (uid 65532).
# It can read a root-owned file and it cannot write one, so every insert fails
# with SQLITE_READONLY and the service answers 500. The first run of this
# rehearsal failed exactly there, and it is the same reason `rehearse_restore.sh`
# already chowns the key material it stages.
#
# 0640 rather than 0644: the database holds sealed secrets, and a database file
# that any local user on the host can read is a smaller problem than one that
# any local user can write, but both are avoidable.
restore() {
    docker rm -f "${CONTAINER}-helper" >/dev/null 2>&1 || true
    docker run --rm -v "$VOLUME:/data" -v "$WORK:/host" alpine \
        sh -c "cp /host/savepoint.db /data/${DB_NAME} \
               && chown 65532:65532 /data/${DB_NAME} \
               && chmod 0640 /data/${DB_NAME}" >/dev/null
    [ "$(stat -c '%u' "$WORK/savepoint.db")" -ge 0 ] || true
}

probe() {
    # On failure, the drill prints the service's own last lines before exiting.
    # An incident is exactly when you cannot reproduce it, and a rehearsal that
    # hands you only the HTTP status has thrown away the diagnosis.
    local out
    if ! out="$(python3 "$HERE/rollback_probe.py" "$BASE_URL" "$SERVICE_KEY" "$1" "$2" 2>&1)"; then
        printf '%s\n' "$out" | sed 's/^/  /'
        docker logs "$CONTAINER" 2>&1 | tail -12 | sed 's/^/    /'
        fail "the probe failed at stage $2 (service logs above)"
    fi
    printf '%s\n' "$out" | sed 's/^/  /'
}

# --------------------------------------------------------------------------
section "building v1 (this tree) and v2 (this tree plus one migration)"
# --------------------------------------------------------------------------
cd "$REPO"
docker build -q -f deploy/Dockerfile -t "$IMAGE_V1" . >/dev/null || fail "v1 did not build"
pass "v1 built"

# v2 is the same code with **one extra forward migration**, which is what a
# release looks like when it adds something. Built from a copy so the repository
# is never dirtied by a rehearsal: a drill that leaves a fabricated migration
# behind is a drill that makes the next build wrong.
mkdir -p "$BUILD_V2"
tar -cf - --exclude=./target --exclude=./.git --exclude=./apps . | tar -xf - -C "$BUILD_V2"

cat >"$BUILD_V2/crates/store/migrations/sqlite/9_release_notes_marker.sql" <<'SQL'
-- Rehearsal-only forward migration (tests/ops/rehearse_rollback.sh).
--
-- Stands in for the additive migration a real release ships. The rehearsal
-- drops an older binary onto this schema, so the migration has to be the safe
-- kind: a new table, nothing renamed, nothing dropped, nothing retyped.
CREATE TABLE release_notes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    version      TEXT NOT NULL,
    published_at INTEGER NOT NULL
);
SQL

cat >"$BUILD_V2/crates/store/migrations/postgres/9_release_notes_marker.sql" <<'SQL'
-- Rehearsal-only forward migration (tests/ops/rehearse_rollback.sh).
CREATE TABLE release_notes (
    id           BIGSERIAL PRIMARY KEY,
    version      TEXT NOT NULL,
    published_at BIGINT NOT NULL
);
SQL

docker build -q -f deploy/Dockerfile -t "$IMAGE_V2" "$BUILD_V2" >/dev/null || fail "v2 did not build"
pass "v2 built (same code, one extra forward migration)"

# --------------------------------------------------------------------------
section "preparing the volume, the keys and the configuration"
# --------------------------------------------------------------------------
docker volume create "$VOLUME" >/dev/null
head -c 32 /dev/urandom >"$WORK/kek.bin"
head -c 32 /dev/urandom >"$WORK/audit-key.bin"
# The vault refuses a key that group or others can read, which is a rule this
# rehearsal has to obey or it proves nothing about a real deployment.
chmod 600 "$WORK/kek.bin" "$WORK/audit-key.bin"

cat >"$WORK/$CONFIG" <<TOML
listen = "0.0.0.0:8080"
database = "sqlite"
database_url = "sqlite:/data/${DB_NAME}"
kms_key_file = "/run/secrets/bandall-kek"
kek_id = "kek-rollback"
audit_key_file = "/run/secrets/bandall-audit-key"
service_key = "$SERVICE_KEY"
token_issuer = "bandall-rollback"
token_audience = "rollback-app"
keys_dir = "/data/keys"
policy_backend = "memory"
TOML
pass "32-byte KEK and audit key generated (0600), configuration written"

# --------------------------------------------------------------------------
section "v1 up: the baseline, and the savepoint"
# --------------------------------------------------------------------------
start_version "$IMAGE_V1" 1
TENANT="$(docker exec "$CONTAINER" /usr/local/bin/bandall tenant create --name rollback | sed -n 's/^tenant_id: //p')"
[ -n "$TENANT" ] || fail "could not create the tenant"
pass "tenant created: $TENANT"

probe "$TENANT" baseline | sed 's/^/  /'
pass "v1 serves real logins"

# The savepoint is taken **before** the forward migration, because that is the
# only moment the database holds a schema the old binary knows.
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
savepoint
note "savepoint taken (schema 1-8, the one v1 knows)"

# --------------------------------------------------------------------------
section "roll FORWARD to v2: the migration must not break its own release"
# --------------------------------------------------------------------------
FORWARD_START="$(date +%s)"
start_version "$IMAGE_V2" 1
probe "$TENANT" forward | sed 's/^/  /'
pass "v2 is up, migrated forward to schema 9, and still serves logins"
note "forward migration took $(( $(date +%s) - FORWARD_START ))s"

# --------------------------------------------------------------------------
section "what does NOT work: putting the old binary back on the new schema"
# --------------------------------------------------------------------------
# Recorded because a runbook that only lists the step that works leaves the
# operator to rediscover this one during the incident. It is a refusal by the
# migrator, not a crash, and it is deliberate: a binary that did not know about
# a migration could quietly run on data it does not understand.
#
# Deliberately NOT routed through `start_version`, whose failure path exits:
# the whole point is to observe this outcome and carry on, so the migrate is
# run directly and its exit code inspected.
note "trying it on purpose, to document the outcome rather than guess it"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
if run_once "$IMAGE_V1" migrate "" >/dev/null 2>"$WORK/refused.log"; then
    fail "the old binary migrated the new schema, which contradicts the migrator's version check"
fi
sed 's/^/    /' "$WORK/refused.log" | tail -3
note "as expected: the old binary refuses to migrate a schema it does not fully know"

# --------------------------------------------------------------------------
section "roll BACK: restore the savepoint, then start v1"
# --------------------------------------------------------------------------
# This is the procedure that works, and it is the heavier one: the database
# goes back to the savepoint, and the old binary starts on a schema it knows.
BACK_START="$(date +%s)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
restore
start_version "$IMAGE_V1" 0
probe "$TENANT" rollback | sed 's/^/  /'
pass "v1 is serving again after the rollback"

BACK_ELAPSED="$(( $(date +%s) - BACK_START ))"
note "rollback (restore + start + ready) took ${BACK_ELAPSED}s"

# --------------------------------------------------------------------------
section "the audit chain survived the restore"
# --------------------------------------------------------------------------
# A restore that loses history is worse than one that fails: the chain is what
# makes tampering visible. An empty log would make the check vacuous.
AUDIT="$(docker exec "$CONTAINER" /usr/local/bin/bandall audit verify 2>&1)" \
    || { printf '%s\n' "$AUDIT" | sed 's/^/    /'; fail "the audit chain does not verify after the rollback"; }
printf '%s\n' "$AUDIT" | sed 's/^/    /'

ENTRY_COUNT="$(sed -n 's/.*(\([0-9]*\) entries).*/\1/p' <<<"$AUDIT")"
if [ "${ENTRY_COUNT:-0}" -lt 1 ]; then
    fail "the audit log is empty after the rollback: the check would prove nothing"
fi
note "$ENTRY_COUNT entries, chain intact"

# --------------------------------------------------------------------------
section "roll forward again: recovery, not just abandonment"
# --------------------------------------------------------------------------
# Finishing on the old version would mean the rehearsal stopped rather than
# recovered. From the restored savepoint, forward is possible again.
start_version "$IMAGE_V2" 1
probe "$TENANT" recovered | sed 's/^/  /'
pass "v2 is serving again after the rollback"

printf '\n\033[1m== result\033[0m\n'
printf '  PASS  v1 baseline: real login and a usable token\n'
printf '  PASS  forward to v2: migration applied, still serving\n'
printf '  PASS  back to v1: old binary, schema it knows, still serving\n'
printf '  PASS  audit chain intact across the whole sequence\n'
printf '  PASS  forward again: recovery, not abandonment\n'
printf '  RTO for the rollback itself: %ss\n' "$BACK_ELAPSED"

cat <<'NOTE'

  What this rehearsal established, and what it cost:

  * Rolling back is NOT "redeploy the old image". `serve` migrates at startup
    and the migrator refuses a schema holding migrations it does not know, so
    the old binary will not start. Rolling back means restoring the database
    taken BEFORE the forward migration, then starting the old binary.
  * That restore discards everything written after the savepoint. On a live
    service that is data loss, which is why the savepoint has to be taken
    immediately before the migration and why the window has to be as short as
    the deployment can make it.
  * Forward migrations therefore behave as a one-way door in practice: the way
    back is a restore, not a deploy. A migration that renames, drops or retypes
    is worse — the way back would need a second migration, not a restore.
  * Alternative worth deciding explicitly (not done here): let an older binary
    tolerate a schema with newer migrations, so rollback is just a redeploy.
    sqlx supports it (`set_ignore_missing`), but it means a binary running on
    data it does not fully understand, which is a security-relevant trade and
    belongs to a human decision, not a rehearsal's default.
NOTE