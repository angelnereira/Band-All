#!/usr/bin/env bash
# Package the project into a container and verify the *container*, not the
# source tree: runtime shape, configuration, the MFA journey, the security
# defences, the audit chain and (optionally) measured load.
#
#   tests/container/verify.sh              # full run against SQLite
#   tests/container/verify.sh --postgres   # same suite against Postgres
#   tests/container/verify.sh --bench      # also run the simulated load
#
# Everything it creates is removed on exit, including the mock clients: the
# containers, the network and the volumes live only for this run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE="bandall:verify"
CONTAINER="bandall-verify"
NETWORK="bandall-verify-net"
PG_CONTAINER="bandall-verify-pg"
VOLUME="bandall-verify-data"
PG_VOLUME="bandall-verify-pgdata"
SECRETS="bandall-verify-secrets"
PORT="${BANDALL_VERIFY_PORT:-18080}"
IMAGE_TAG="bandall-verify"
SUITE="bandall-verify"
AUDIENCE="verify-app"
K6_PORT="${BANDALL_K6_PORT:-18090}"

# Docker Desktop only shares the home directory with the VM, and `/tmp` is not
# one of them, so the throwaway files (config, key material) live under `$HOME`
# and are deleted on the way out.
WORK="$(mktemp -d "${HOME}/.bandall-verify-XXXXXX")"

RUN_POSTGRES=0
RUN_BENCH=0
KEEP=0
SKIP_BUILD=0
for arg in "$@"; do
    case "$arg" in
        --postgres) RUN_POSTGRES=1 ;;
        --bench) RUN_BENCH=1 ;;
        --keep) KEEP=1 ;;
        # Reuse an image that already exists (the CI job builds it with
        # build-push-action and its own cache before calling this script).
        --skip-build) SKIP_BUILD=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

# Cleanup: the mock clients and the throwaway tenant are not reusable state, so
# they die with the run unless --keep asks otherwise (for debugging a failure).
cleanup() {
    local status=$?
    if [ "$KEEP" -eq 1 ]; then
        echo "==> --keep: leaving $CONTAINER, $PG_CONTAINER, their volumes and $WORK up"
        return $status
    fi
    echo
    echo "==> tearing down mock clients and throwaway state"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    docker volume rm "$SECRETS" >/dev/null 2>&1 || true
    docker volume rm "$PG_VOLUME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
    return $status
}
trap cleanup EXIT

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1"; exit 1; }

# --------------------------------------------------------------------------
# 1. Package.
# --------------------------------------------------------------------------
if [ "$SKIP_BUILD" -eq 1 ]; then
    section "reusing the existing $IMAGE image"
    docker image inspect "$IMAGE" >/dev/null 2>&1 \
        || fail "--skip-build was given but $IMAGE does not exist"
else
    section "building $IMAGE from deploy/Dockerfile"
    cd "$ROOT"
    docker build -f deploy/Dockerfile -t "$IMAGE" .
fi
docker image inspect "$IMAGE" --format 'image: {{.Id}} ({{.Size}} bytes, user={{.Config.User}}, entrypoint={{.Config.Entrypoint}})'

# --------------------------------------------------------------------------
# 2. Runtime shape assertions: these are properties of the artifact, checked
#    before anything is trusted to run inside it.
# --------------------------------------------------------------------------
section "runtime shape"
docker image inspect "$IMAGE" --format '{{json .Config.Healthcheck}}' | grep -q 'bandall.*healthcheck' \
    || fail "the image has no HEALTHCHECK using the bandall subcommand"
echo "healthcheck: uses \`bandall healthcheck\`"

test "$(docker image inspect "$IMAGE" --format '{{.Config.User}}')" = "nonroot:nonroot" \
    || fail "the image does not run as nonroot"
echo "user: nonroot:nonroot (uid 65532)"

docker run --rm --entrypoint /usr/local/bin/bandall "$IMAGE" version
echo "binary: present and executable"

# No shell and no curl in a distroless runtime: confirm the hardening rather
# than assuming it.
if docker run --rm --entrypoint /bin/sh "$IMAGE" -c 'echo pwned' >/dev/null 2>&1; then
    fail "the runtime image ships a shell"
fi
echo "runtime: no shell in the image"

# --------------------------------------------------------------------------
# 3. Throwaway secrets: 32 random bytes each, written to a volume that the
#    container mounts read-only. Generated per run, never committed.
# --------------------------------------------------------------------------
section "generating throwaway KEK and audit key"
docker volume create "$SECRETS" >/dev/null
KEK="$WORK/kek.bin"
AUDIT_KEY="$WORK/audit.bin"
openssl rand -out "$KEK" 32
openssl rand -out "$AUDIT_KEY" 32
chmod 600 "$KEK" "$AUDIT_KEY"
# The service runs as uid 65532 (nonroot), so the key files must be owned by
# that uid inside the volume: mode 0400 owned by root would be unreadable to
# the process, which is the correct fail-closed behaviour but not a working
# deployment. Ownership is fixed here, at install time, which is what a real
# orchestrator does with its secrets.
docker run --rm -v "$SECRETS:/secrets" -v "$KEK:/tmp/kek:ro" -v "$AUDIT_KEY:/tmp/audit:ro" \
    alpine:latest sh -c 'cp /tmp/kek /secrets/kek && cp /tmp/audit /secrets/audit \
        && chown 65532:65532 /secrets/kek /secrets/audit \
        && chmod 400 /secrets/kek /secrets/audit'
rm -f "$KEK" "$AUDIT_KEY"
echo "wrote 32-byte KEK and audit key into volume $SECRETS"
echo "  mode 400, owner 65532:65532 (uid nonroot), removed with the volume"
echo "  host copies deleted; the volume holds the only remaining copy"

# --------------------------------------------------------------------------
# 4. Configuration, served through the mounted file the container reads.
# --------------------------------------------------------------------------
section "configuration"
CONFIG="$WORK/bandall.toml"
if [ "$RUN_POSTGRES" -eq 1 ]; then
    # The store refuses a clear-text connection to a non-loopback host
    # (`PgStore::require_tls_for_remote`), and a container hostname is not
    # loopback. So the throwaway Postgres gets a self-signed certificate and
    # the service connects with `sslmode=require`, which is the same posture a
    # real deployment uses. `require` does not verify the chain: the
    # certificate exists here to exercise the TLS path, not to be trusted.
    DB_KIND="postgres"
    DB_URL="postgres://bandall:bandall-dev-only@${PG_CONTAINER}:5432/bandall?sslmode=require"
else
    DB_KIND="sqlite"
    DB_URL="sqlite:/data/bandall.db"
fi

cat > "$CONFIG" <<EOF
listen = "0.0.0.0:8080"
database = "${DB_KIND}"
database_url = "${DB_URL}"
kms_key_file = "/run/secrets/kek"
kek_id = "kek-verify"
audit_key_file = "/run/secrets/audit"
service_key = "${SERVICE_KEY:-verify-service-key-0123456789abcd}"
token_issuer = "${IMAGE_TAG}"
token_audience = "${AUDIENCE}"
keys_dir = "/data/keys"
policy_backend = "memory"
policy_max_attempts = 5
policy_lockout_after = 10
policy_tenant_max_attempts = 1000
# Every mock client shares 127.0.0.1, so the per-IP ceiling would throttle the
# benchmark long before the crypto or the database does. The IP limit is
# exercised by its own test in the verification suite; here it is raised so
# the load numbers measure the verification path rather than the limiter.
policy_ip_max_attempts = 1000000
trusted_proxies = []
body_limit_bytes = 65536
EOF
echo "config: database=${DB_KIND}, issuer=${IMAGE_TAG}, audience=${AUDIENCE}"

# Fail-closed on a broken config: an invalid file must stop the process at
# startup, not degrade into "open".
section "fail-closed configuration"
BROKEN="$WORK/broken-service-key.toml"
sed 's/^service_key = .*/service_key = "too-short"/' "$CONFIG" > "$BROKEN"
docker volume create "$VOLUME" >/dev/null
if docker run --rm \
    -v "$BROKEN:/config/bandall.toml:ro" \
    -v "$SECRETS:/run/secrets:ro" \
    -v "$VOLUME:/data" \
    -e BANDALL_CONFIG=/config/bandall.toml \
    "$IMAGE" serve >/dev/null 2>&1; then
    fail "the service started with an invalid service_key"
fi
echo "invalid service_key: startup refused (exit != 0)"

MISSING="$WORK/no-audit-key.toml"
grep -v '^audit_key_file' "$CONFIG" > "$MISSING"
if docker run --rm \
    -v "$MISSING:/config/bandall.toml:ro" \
    -v "$SECRETS:/run/secrets:ro" \
    -v "$VOLUME:/data" \
    -e BANDALL_CONFIG=/config/bandall.toml \
    "$IMAGE" serve >/dev/null 2>&1; then
    fail "the service started without audit_key_file"
fi
echo "missing audit_key_file: startup refused (exit != 0)"
# --------------------------------------------------------------------------
# 5. Database and the service container.
# --------------------------------------------------------------------------
docker network create "$NETWORK" >/dev/null 2>&1 || true

if [ "$RUN_POSTGRES" -eq 1 ]; then
    section "starting the throwaway Postgres (TLS, because the store demands it)"
    # Self-signed material, generated per run, never reused and never committed.
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj '/CN=bandall-verify-pg' \
        -keyout "$WORK/pg-key.pem" -out "$WORK/pg-cert.pem" >/dev/null 2>&1
    chmod 600 "$WORK/pg-key.pem"

    # The settings go through `-c` on the *command*, not on `docker run`: the
    # postgres image turns trailing arguments into postgresql flags, and `docker
    # run -c` means --cpu-shares.
    # The postgres image declares `VOLUME /var/lib/postgresql/data`, and
    # `docker run --rm` does not delete anonymous volumes, so the data volume is
    # named explicitly and removed by the cleanup trap. Otherwise every run
    # would leave a fresh anonymous volume holding a copy of the database.
    docker volume create "$PG_VOLUME" >/dev/null
    docker run -d --name "$PG_CONTAINER" --network "$NETWORK" \
        -e POSTGRES_USER=bandall -e POSTGRES_PASSWORD=bandall-dev-only \
        -e POSTGRES_DB=bandall \
        -v "$PG_VOLUME:/var/lib/postgresql/data" \
        -v "$WORK/pg-cert.pem:/certs/server.crt:ro" \
        -v "$WORK/pg-key.pem:/certs/server.key:ro" \
        --health-cmd 'pg_isready -U bandall -d bandall' \
        --health-interval 2s --health-retries 30 \
        postgres:16-alpine \
        -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key \
        >/dev/null
    echo "postgres: starting, waiting for readiness"
    for _ in $(seq 1 60); do
        if [ "$(docker inspect -f '{{.State.Health.Status}}' "$PG_CONTAINER" 2>/dev/null)" = healthy ]; then
            break
        fi
        sleep 1
    done
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$PG_CONTAINER")" = healthy ] \
        || fail "postgres did not become healthy"
    echo "postgres: healthy"
fi

section "migrating and starting the service container"
docker run --rm \
    -v "$CONFIG:/config/bandall.toml:ro" \
    -v "$SECRETS:/run/secrets:ro" \
    -v "$VOLUME:/data" \
    --tmpfs /tmp:rw,size=64m \
    -e BANDALL_CONFIG=/config/bandall.toml \
    -e RUST_LOG=bandall=info \
    --network "$NETWORK" \
    "$IMAGE" migrate || fail "migrations failed"

docker run -d --name "$CONTAINER" \
    --network "$NETWORK" \
    -p "127.0.0.1:${PORT}:8080" \
    -v "$CONFIG:/config/bandall.toml:ro" \
    -v "$SECRETS:/run/secrets:ro" \
    -v "$VOLUME:/data" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --ulimit core=0 \
    --memory 512m --cpus 1.0 \
    --tmpfs /tmp:rw,size=64m \
    -e BANDALL_CONFIG=/config/bandall.toml \
    -e RUST_LOG=bandall=info \
    "$IMAGE" >/dev/null

echo "container: started, waiting for /readyz"
BASE_URL="http://127.0.0.1:${PORT}"
for _ in $(seq 1 60); do
    if curl -fsS "${BASE_URL}/readyz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS "${BASE_URL}/readyz" >/dev/null || {
    echo "--- container logs ---"
    docker logs "$CONTAINER"
    fail "the service never became ready"
}
echo "readyz: ok at ${BASE_URL}"

# The image's own HEALTHCHECK must agree with our probe.
for _ in $(seq 1 20); do
    HEALTH="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")"
    [ "$HEALTH" = healthy ] && break
    sleep 1
done
echo "docker HEALTHCHECK: ${HEALTH}"
[ "$HEALTH" = healthy ] || fail "the image healthcheck never went green"

# Hardening actually applied at runtime, not just declared in the compose file.
section "runtime hardening (as started by this script)"
docker inspect "$CONTAINER" --format 'read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} no_new_privs={{.HostConfig.SecurityOpt}} memory={{.HostConfig.Memory}}cpus={{.HostConfig.NanoCpus}}'
docker exec "$CONTAINER" /usr/local/bin/bandall healthcheck && echo "bandall healthcheck: exit 0"
# The process must not be root: the image declares nonroot, and this proves the
# declaration took effect in the running container.
docker exec "$CONTAINER" /usr/local/bin/bandall version
echo "binary runs inside the container as $(docker inspect "$CONTAINER" --format '{{.Config.User}}')"

# --------------------------------------------------------------------------
# 6. Functional / security / audit verification against the container.
# --------------------------------------------------------------------------
section "creating the throwaway tenant"
SERVICE_KEY_VALUE="$(grep '^service_key' "$CONFIG" | cut -d'"' -f2)"
TENANT_ID="$(docker exec "$CONTAINER" /usr/local/bin/bandall tenant create --name "verify-$RANDOM" | sed -n 's/^tenant_id: //p')"
[ -n "$TENANT_ID" ] || fail "could not create the tenant"
echo "tenant: ${TENANT_ID}"

section "running the verification suite against the container"
cd "$HERE"
SUITE_STATUS=0
python3 verify_container.py "$BASE_URL" "$SERVICE_KEY_VALUE" "$TENANT_ID" || SUITE_STATUS=$?

# --------------------------------------------------------------------------
# 7. HMAC request signatures: create a throwaway API client with the CLI that
#    ships in the image, then verify signatures against it.
# --------------------------------------------------------------------------
SIGS_STATUS=0
section "HMAC request signatures (throwaway API client)"
APIKEY_OUTPUT="$(docker exec "$CONTAINER" /usr/local/bin/bandall apikey create --tenant "$TENANT_ID" --scopes verify --prefix mock)"
APIKEY_ID="$(sed -n 's/^key_id: //p' <<<"$APIKEY_OUTPUT")"
APIKEY_SECRET="$(sed -n 's/^key: //p' <<<"$APIKEY_OUTPUT")"
if [ -z "$APIKEY_ID" ] || [ -z "$APIKEY_SECRET" ]; then
    echo "$APIKEY_OUTPUT"
    fail "could not create the throwaway API client"
fi
echo "api client: ${APIKEY_ID} (scope verify)"
python3 verify_sigs.py "$BASE_URL" "$APIKEY_ID" "$APIKEY_SECRET" verify || SIGS_STATUS=$?
unset APIKEY_SECRET

# --------------------------------------------------------------------------
# 8. Logs: the container's own stdout must carry no secret material. Read
#    while the service is still running and its log is complete.
# --------------------------------------------------------------------------
section "no secrets in the container logs"
LOGS="$(docker logs "$CONTAINER" 2>&1)"
if printf '%s' "$LOGS" | grep -qF "$SERVICE_KEY_VALUE"; then
    fail "the service key appears in the logs"
fi
echo "service key: absent from logs"
if printf '%s' "$LOGS" | grep -aiE 'panicked at|RUST_BACKTRACE|stack backtrace' >/dev/null; then
    fail "a panic reached the logs"
fi
echo "panics: none"
echo "log lines: $(printf '%s' "$LOGS" | wc -l)"

# --------------------------------------------------------------------------
# 9. Optional: simulated load with throwaway mock clients.
# --------------------------------------------------------------------------
BENCH_STATUS=0
if [ "$RUN_BENCH" -eq 1 ]; then
    section "simulated load (throwaway mock clients)"
    cd "$HERE"
    python3 bench_container.py "$BASE_URL" "$SERVICE_KEY_VALUE" "$TENANT_ID" || BENCH_STATUS=$?
fi

# --------------------------------------------------------------------------
# 10. Audit chain, last: the tampering check deliberately corrupts the log, so
#     nothing that needs an intact database may run after it.
# --------------------------------------------------------------------------
section "audit chain"
AUDIT_BEFORE="$(docker exec "$CONTAINER" /usr/local/bin/bandall audit verify)" || fail "the audit chain does not verify"
echo "$AUDIT_BEFORE"
# An empty log would make the tampering check below vacuous.
ENTRY_COUNT="$(sed -n 's/.*(\([0-9]*\) entries).*/\1/p' <<<"$AUDIT_BEFORE")"
if [ "${ENTRY_COUNT:-0}" -lt 1 ]; then
    fail "the audit log is empty: the tamper check would prove nothing"
fi

# The H5 gate: altering one row must make the chain fail to verify. The service
# is stopped first so the database is not being written underneath the tamper,
# and the check runs in a one-shot container against the same volume.
docker stop "$CONTAINER" >/dev/null

audit_verify_once() {
    docker run --rm \
        -v "$CONFIG:/config/bandall.toml:ro" \
        -v "$SECRETS:/run/secrets:ro" \
        -v "$VOLUME:/data" \
        --network "$NETWORK" \
        -e BANDALL_CONFIG=/config/bandall.toml \
        "$IMAGE" audit verify
}

if [ "$RUN_POSTGRES" -eq 1 ]; then
    docker exec "$PG_CONTAINER" psql -U bandall -d bandall -q -c \
        "UPDATE audit_log SET event = 'tampered' WHERE seq = 1;" >/dev/null
else
    # Pull the database out, alter it with the host's sqlite3, put it back: the
    # helper image has no sqlite client and installing one would be a network
    # dependency this script should not have. `-wal`/`-shm` come along, because
    # a WAL holds committed pages the main file does not.
    docker run --rm -v "$VOLUME:/data:ro" -v "$WORK:/work" alpine:latest sh -c \
        'cp /data/bandall.db /work/tampered.db
         [ ! -f /data/bandall.db-wal ] || cp /data/bandall.db-wal /work/tampered.db-wal
         [ ! -f /data/bandall.db-shm ] || cp /data/bandall.db-shm /work/tampered.db-shm
         rm -f /work/tampered.db-journal'
    python3 - "$WORK/tampered.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
changed = connection.execute("UPDATE audit_log SET event = 'tampered' WHERE seq = 1").rowcount
connection.commit()
# Fold the WAL back into the main file so the copy that goes back into the
# volume is a single self-contained database. Otherwise the verifier would read
# a stale main file plus a WAL that no longer matches it.
connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
connection.close()
if changed != 1:
    raise SystemExit(f"expected to alter exactly one row, altered {changed}")
print("  altered seq 1 of the audit log")
PY
    # Only the single file goes back: the checkpoint above made it complete,
    # and a stale -wal alongside it would be the thing under test, not the
    # tamper.
    docker run --rm -v "$VOLUME:/data" -v "$WORK:/work:ro" alpine:latest sh -c \
        'cp /work/tampered.db /data/bandall.db && rm -f /data/bandall.db-wal /data/bandall.db-shm'
    rm -f "$WORK"/tampered.db*
fi

if audit_verify_once >/dev/null 2>&1; then
    fail "the audit chain verified after a row was tampered with"
fi
echo "tampered row: audit verify reports BROKEN (exit != 0), as the H5 gate requires"
# `|| true` because a non-zero status here is the expected result, and
# `set -o pipefail` would otherwise turn this diagnostic line into the end of
# the script.
audit_verify_once 2>&1 | tail -1 | sed 's/^/  /' || true

# --------------------------------------------------------------------------
section "result"
declare -A STATUS=(
    [functional/security/audit suite]=$SUITE_STATUS
    [HMAC signatures]=$SIGS_STATUS
)
OVERALL=0
for label in "${!STATUS[@]}"; do
    if [ "${STATUS[$label]}" -eq 0 ]; then
        printf '  PASS  %s\n' "$label"
    else
        printf '  FAIL  %s\n' "$label"
        OVERALL=1
    fi
done
if [ "$RUN_BENCH" -eq 1 ]; then
    if [ "$BENCH_STATUS" -eq 0 ]; then
        printf '  PASS  %s\n' "simulated load"
    else
        printf '  FAIL  %s\n' "simulated load"
        OVERALL=1
    fi
else
    printf '  SKIP  %s\n' "simulated load (pass --bench to run it)"
fi
exit "$OVERALL"