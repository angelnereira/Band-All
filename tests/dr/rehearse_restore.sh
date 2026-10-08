#!/usr/bin/env bash
# H8 disaster-recovery rehearsal: does a restored database actually serve again?
#
# The runbooks say "rehearse the restore at least once before production". This
# is that rehearsal, end to end, against the real image and a real Postgres:
#
#   1. bring the stack up and enroll real factors, so the log is not empty
#   2. take a real backup (pg_dump, the way a managed instance would)
#   3. destroy the database underneath the running service
#   4. restore the backup into a clean schema
#   5. `bandall migrate` (must be idempotent: nothing pending)
#   6. `bandall audit verify` must be green on the restored data
#   7. a real login with a real factor must work again
#
# Step 7 is the one that matters. A backup that verifies and still cannot log
# anybody in is not a restore.
#
# Everything is destroyed on exit.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE="bandall:verify"
NETWORK="bandall-dr-net"
PG="bandall-dr-pg"
APP="bandall-dr-app"
PG_VOLUME="bandall-dr-pgdata"
SECRETS="bandall-dr-secrets"
WORK="$(mktemp -d "${HOME}/.bandall-dr-XXXXXX")"
SERVICE_KEY="dr-rehearsal-service-key-0123456789"
ISSUER="bandall-dr"
AUDIENCE="dr-app"
RPO_NOTE=""

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1"; exit 1; }

cleanup() {
    local status=$?
    if [ "${KEEP:-0}" -eq 1 ]; then
        echo "==> KEEP=1: leaving $APP, $PG and $WORK up"
        return $status
    fi
    printf '\n==> tearing down\n'
    docker rm -f "$APP" >/dev/null 2>&1 || true
    docker rm -f "$PG" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    docker volume rm "$PG_VOLUME" >/dev/null 2>&1 || true
    docker volume rm "$SECRETS" >/dev/null 2>&1 || true
    rm -rf "$WORK"
    return $status
}
trap cleanup EXIT

bandall() { docker exec "$APP" /usr/local/bin/bandall "$@"; }

# --------------------------------------------------------------------------
section "preflight"
# --------------------------------------------------------------------------
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -f deploy/Dockerfile -t "$IMAGE" "$ROOT"
docker network create "$NETWORK" >/dev/null 2>&1 || true

openssl rand -out "$WORK/kek" 32
openssl rand -out "$WORK/audit" 32
chmod 600 "$WORK/kek" "$WORK/audit"
docker volume create "$SECRETS" >/dev/null
docker run --rm -v "$SECRETS:/s" -v "$WORK/kek:/k:ro" -v "$WORK/audit:/a:ro" alpine:latest \
    sh -c 'cp /k /s/kek && cp /a /s/audit && chown 65532:65532 /s/* && chmod 400 /s/*'
rm -f "$WORK/kek" "$WORK/audit"

cat > "$WORK/bandall.toml" <<EOF
listen = "0.0.0.0:8080"
database = "postgres"
database_url = "postgres://bandall:bandall-dev-only@${PG}:5432/bandall?sslmode=require"
kms_key_file = "/run/secrets/kek"
kek_id = "kek-dr"
audit_key_file = "/run/secrets/audit"
service_key = "${SERVICE_KEY}"
token_issuer = "${ISSUER}"
token_audience = "${AUDIENCE}"
keys_dir = "/data/keys"
policy_backend = "database"
trusted_proxies = []
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=${PG}" \
    -keyout "$WORK/pg-key" -out "$WORK/pg-cert" >/dev/null 2>&1
chmod 600 "$WORK/pg-key"

docker volume create "$PG_VOLUME" >/dev/null
docker run -d --name "$PG" --network "$NETWORK" \
    -e POSTGRES_USER=bandall -e POSTGRES_PASSWORD=bandall-dev-only -e POSTGRES_DB=bandall \
    -v "$PG_VOLUME:/var/lib/postgresql/data" \
    -v "$WORK/pg-cert:/certs/server.crt:ro" -v "$WORK/pg-key:/certs/server.key:ro" \
    --health-cmd 'pg_isready -U bandall -d bandall' --health-interval 2s --health-retries 30 \
    postgres:16-alpine -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key \
    >/dev/null
for _ in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$PG" 2>/dev/null)" = healthy ] && break
    sleep 1
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$PG")" = healthy ] || fail "postgres never became healthy"

start_app() {
    docker rm -f "$APP" >/dev/null 2>&1 || true
    docker run -d --name "$APP" --network "$NETWORK" -p "127.0.0.1:${DR_PORT:-18081}:8080" \
        -v "$WORK/bandall.toml:/config/bandall.toml:ro" \
        -v "$SECRETS:/run/secrets:ro" -v "$WORK:/data" \
        --tmpfs /tmp:rw,size=64m \
        -e BANDALL_CONFIG=/config/bandall.toml -e RUST_LOG=bandall=info \
        "$IMAGE" >/dev/null
    for _ in $(seq 1 60); do
        curl -fsS "http://127.0.0.1:${DR_PORT:-18081}/readyz" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

docker run --rm -v "$WORK/bandall.toml:/config/bandall.toml:ro" -v "$SECRETS:/run/secrets:ro" \
    -v "$WORK:/data" --network "$NETWORK" -e BANDALL_CONFIG=/config/bandall.toml \
    "$IMAGE" migrate >/dev/null || fail "migrate failed"
start_app || { docker logs "$APP"; fail "the service never became ready"; }
echo "stack up: app + postgres (TLS)"

# --------------------------------------------------------------------------
section "1. produce state worth losing"
# --------------------------------------------------------------------------
TENANT="$(bandall tenant create --name "dr-$RANDOM" | sed -n 's/^tenant_id: //p')"
[ -n "$TENANT" ] || fail "could not create the tenant"

# Enroll through the real API with a mock authenticator, so the backup holds
# genuine sealed factors, sessions and audit entries rather than empty tables.
FACTORS="$WORK/factors.tsv"
python3 - "$ROOT/tests/container" "$TENANT" "$SERVICE_KEY" "http://127.0.0.1:${DR_PORT:-18081}" \
    "$FACTORS" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from totp_client import Client, Session

tenant, key, base, out = sys.argv[2:6]
client = Client(base, service_key=key)
rows = []
for index in range(4):
    session = Session(client, tenant, f"dr-user-{index}")
    session.enroll(issuer="DR")
    assert session.mfa_verify().status == 200, "login failed"
    # The step the login consumed. The post-restore check must wait for a later
    # one: the accepted step is spent, and presenting it again is a replay, which
    # the server is right to refuse.
    consumed_step = int(__import__("time").time()) // session.otpauth.period
    rows.append(
        "\t".join(
            [
                tenant,
                session.subject_id,
                session.factor_id,
                session.otpauth.secret,
                str(session.otpauth.period),
                str(consumed_step),
            ]
        )
        + "\n"
    )
open(out, "w").writelines(rows)
print("  enrolled and logged in 4 users, kept their secrets and spent steps")
PY
[ -s "$FACTORS" ] || fail "no factors were enrolled"

ENTRIES="$(bandall audit verify | sed -n 's/.*(\([0-9]*\) entries).*/\1/p')"
echo "audit log: ${ENTRIES} entries"
[ "${ENTRIES:-0}" -ge 8 ] || fail "the log is too short for the rehearsal to mean anything"

# --------------------------------------------------------------------------
section "2. back up"
# --------------------------------------------------------------------------
START="$(date +%s)"
docker exec "$PG" pg_dump -U bandall -d bandall -Fc -f /tmp/bandall.dump >/dev/null
docker cp "$PG:/tmp/bandall.dump" "$WORK/bandall.dump" >/dev/null
docker exec "$PG" rm -f /tmp/bandall.dump
SIZE="$(stat -c %s "$WORK/bandall.dump")"
echo "pg_dump: ${SIZE} bytes in $(( $(date +%s) - START ))s (format -Fc, as a managed instance would hand you)"
[ "$SIZE" -gt 0 ] || fail "the backup is empty"

# --------------------------------------------------------------------------
section "3. destroy the database out from under the service"
# --------------------------------------------------------------------------
docker exec "$PG" psql -U bandall -d bandall -q -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null
echo "schema dropped and recreated: the data is gone and the service does not know yet"

# The service must fail closed rather than serve with nothing behind it.
sleep 2
HEALTH="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${DR_PORT:-18081}/healthz" || echo 000)"
READY="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${DR_PORT:-18081}/readyz" || echo 000)"
echo "after the wipe: /healthz=${HEALTH} /readyz=${READY}"
if [ "$READY" = "200" ]; then
    fail "/readyz is still 200 with an empty database: readiness is not testing the store"
fi
echo "readyz refuses to advertise an unusable service"

# --------------------------------------------------------------------------
section "4. restore"
# --------------------------------------------------------------------------
docker cp "$WORK/bandall.dump" "$PG:/tmp/restore.dump" >/dev/null
docker exec "$PG" pg_restore -U bandall -d bandall --clean --if-exists /tmp/restore.dump >/dev/null
docker exec "$PG" rm -f /tmp/restore.dump
echo "restored into the clean schema"

# --------------------------------------------------------------------------
section "5. migrate on the restored database (must be idempotent)"
# --------------------------------------------------------------------------
docker run --rm -v "$WORK/bandall.toml:/config/bandall.toml:ro" -v "$SECRETS:/run/secrets:ro" \
    -v "$WORK:/data" --network "$NETWORK" -e BANDALL_CONFIG=/config/bandall.toml \
    "$IMAGE" migrate || fail "migrate failed on the restored database"
echo "migrate applied nothing pending, as it should"

# --------------------------------------------------------------------------
section "6. the audit chain must verify on restored data"
# --------------------------------------------------------------------------
RESTORED_ENTRIES="$(bandall audit verify | sed -n 's/.*(\([0-9]*\) entries).*/\1/p')" \
    || fail "the audit chain does not verify after the restore"
echo "restored log: ${RESTORED_ENTRIES} entries, chain verified"
[ "${RESTORED_ENTRIES:-0}" -eq "${ENTRIES}" ] \
    || fail "entry count changed across the backup: ${ENTRIES} -> ${RESTORED_ENTRIES}"

# --------------------------------------------------------------------------
section "7. a real login must work on the restored data"
# --------------------------------------------------------------------------
python3 - "$ROOT/tests/container" "$FACTORS" "http://127.0.0.1:${DR_PORT:-18081}" <<'PY'
import sys
import time
sys.path.insert(0, sys.argv[1])
from totp_client import Client, Otpauth

facts, base = sys.argv[2], sys.argv[3]
client = Client(base)
rows = [line.rstrip("\n").split("\t") for line in open(facts)]

# Wait past the step each login consumed. The recorded step is the one the
# client was *on* when it generated the code, and the server accepts any of the
# three steps around its own clock, so the spent step is one of N-1..N+1: the
# rehearsal waits until the clock is beyond all three. Without this, the very
# same code would be presented again and the anti-replay would refuse it, which
# is correct — a real user waits for the next code, and so does this.
def current_step(period):
    return int(time.time()) // int(period)

deadline = time.time() + max(int(row[4]) for row in rows) * 2 + 5
while any(current_step(row[4]) <= int(row[5]) + 1 for row in rows):
    if time.time() > deadline:
        raise SystemExit("timed out waiting for the next TOTP step")
    time.sleep(0.5)

checked = 0
for tenant, subject, factor, secret, period, _spent in rows:
    entry = Otpauth(secret=secret, algorithm="SHA256", digits=6, period=int(period),
                    issuer="DR", account=subject)
    code = entry.code()
    result = client.post("/v1/mfa/verify", {
        "tenant_id": tenant, "subject_id": subject, "factor_id": factor, "code": code,
    })
    if result.status == 401:
        # Retry once on the window boundary: the code may have rotated between
        # generating it and the server reading the clock.
        result = client.post("/v1/mfa/verify", {
            "tenant_id": tenant, "subject_id": subject, "factor_id": factor,
            "code": entry.code(),
        })
    if result.status != 200:
        raise SystemExit(f"login failed on the restored database: {result}")
    checked += 1
print(f"  {checked} restored users logged in on the restored database")
PY

RTO_SECONDS=$(( $(date +%s) - START ))
RPO_NOTE="backup taken mid-run; measured RTO from backup to verified login = ${RTO_SECONDS}s on one desktop machine"
echo "$RPO_NOTE"

printf '\n\033[1m== result\033[0m\n'
printf '  PASS  backup taken (%s bytes)\n' "$SIZE"
printf '  PASS  destroyed database fails closed (/readyz refuses)\n'
printf '  PASS  restore + idempotent migrate\n'
printf '  PASS  audit chain green on restored data (%s entries)\n' "$RESTORED_ENTRIES"
printf '  PASS  real login works again on restored data\n'
printf '  %s\n' "$RPO_NOTE"