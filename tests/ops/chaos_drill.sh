#!/usr/bin/env bash
# Chaos drill for H8: break the service on purpose and confirm the two things
# that are worth confirming.
#
#   1. BandAll **fails closed**. A service that answers HTTP 200 with a code it
#      could not verify is worse than one that is down, and "the DB is broken"
#      is the classic way to get there. The DR rehearsal already found one
#      instance of this exact shape: `/readyz` answering 200 with the schema
#      destroyed, because `health()` was `SELECT 1`.
#
#   2. **Somebody hears about it.** `deploy/compose/alerts.yml` defines rules
#      that never fired, because nothing ever broke them. A rule that has never
#      fired is not a rule, it is a comment in YAML.
#
# Uses the observability stack, so Prometheus, the blackbox exporter and
# Alertmanager are all real. Nothing is mocked: the target is a real BandAll
# container on a real volume, and the failure is a real failure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
COMPOSE="$REPO/deploy/compose/compose.obs.yaml"

# The observability stack binds to non-default ports by default, so it does
# not collide with whatever else the machine already runs on 9090. Compose
# reads these from the environment, so the values here and there have to be
# the same expression.
PROM_PORT="${BANDALL_OBS_PROMETHEUS_PORT:-19090}"
AM_PORT="${BANDALL_OBS_ALERTMANAGER_PORT:-19093}"
PROM="http://127.0.0.1:${PROM_PORT}"
AM="http://127.0.0.1:${AM_PORT}"
BANDALL_PORT="${BANDALL_OBS_BANDALL_PORT:-18080}"
BANDALL="http://127.0.0.1:${BANDALL_PORT}"
SERVICE_KEY="demo-service-key-0123456789abcdef"

# The alert takes 30 s to become `firing` by design (a `for:` of 30 s, so a
# single bad scrape is not a fact). Waiting a bit beyond that covers the scrape
# and evaluation intervals without making the drill slow.
FIRE_TIMEOUT="${BANDALL_CHAOS_FIRE_TIMEOUT:-60}"

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1"; exit 1; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
note() { printf '  note: %s\n' "$1"; }

cleanup() {
    local status=$?
    printf '\n==> restoring the stack\n'
    docker compose -f "$COMPOSE" start bandall >/dev/null 2>&1 || true
    docker compose -f "$COMPOSE" down >/dev/null 2>&1 || true
    return $status
}
trap cleanup EXIT

# --------------------------------------------------------------------------
section "starting the observability stack"
# --------------------------------------------------------------------------
cd "$REPO"
# Built once, with a tag this script owns, so the fail-closed check further down
# can name it. Without an explicit tag the image would be named after the
# Compose project, which is an internal detail worth not depending on.
IMAGE="bandall-chaos"
docker build -q -f deploy/Dockerfile -t "$IMAGE" . || fail "the image did not build"
note "image built: $IMAGE"

docker compose -f "$COMPOSE" up -d --wait || fail "the stack did not come up"
pass "prometheus, blackbox-exporter, alertmanager and bandall are up"

# --------------------------------------------------------------------------
section "baseline: the alert rules are loaded and quiet"
# --------------------------------------------------------------------------
# This is the half of alerting that is usually never checked, and it is the half
# that matters: a rule that fires at baseline is noise, and operators learn to
# ignore noise. So the baseline has to be *verified*, not assumed.
wait_for() { # $1 = url, $2 = description
    local url="$1" what="$2" tries=0
    until curl -fsS "$url" >/dev/null 2>&1; do
        tries=$((tries + 1))
        [ "$tries" -gt 60 ] && fail "$what never became reachable at $url"
        sleep 1
    done
}
wait_for "$PROM/-/ready" "prometheus"
pass "prometheus is ready"

RULES="$(curl -fsS "$PROM/api/v1/rules")"
LOADED="$(printf '%s' "$RULES" | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]["groups"]
names = [r["name"] for g in data for r in g["rules"]]
print("\n".join(names) or "none")')"

printf '  rules loaded:\n'
printf '%s\n' "$LOADED" | sed 's/^/    /'

for want in BandAllNotReady BandAllNoTraffic BandAllHighDenialRate; do
    if ! grep -qx "$want" <<<"$LOADED"; then
        printf '%s\n' "$LOADED" | sed 's/^/    /'
        fail "rule $want is not loaded: alerts.yml and prometheus.yml disagree"
    fi
done
pass "the readiness, traffic and denial rules are loaded"

# Everything must start `inactive`. A rule that is `pending` at baseline means
# the condition is already true, which is not a drill, it is an incident.
BASELINE="$(printf '%s' "$RULES" | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]["groups"]
loud = [(r["name"], r.get("state")) for g in data for r in g["rules"] if r.get("state") != "inactive"]
print("\n".join(f"{n}={s}" for n, s in loud) or "quiet")')"
if [ "$BASELINE" = "quiet" ]; then
    pass "no rule is pending or firing before anything is broken"
else
    printf '%s\n' "$BASELINE" | sed 's/^/    /'
    fail "a rule is not quiet at baseline: the alert would be noise"
fi

# --------------------------------------------------------------------------
section "sanity: the service really answers before it is broken"
# --------------------------------------------------------------------------
# The drill must not be able to "pass" because the service never worked.
READYZ="$(curl -s -o /dev/null -w '%{http_code}' "$BANDALL/readyz")"
[ "$READYZ" = "200" ] || fail "/readyz answered $READYZ before anything was broken"
pass "/readyz answers 200"

# --------------------------------------------------------------------------
section "chaos: stopping bandall"
# --------------------------------------------------------------------------
# `docker compose stop` is the honest simulation of the two failures that
# matter, and it is reversible, which a drill has to be. What cannot be done
# from outside the container is destroying the schema itself: the runtime is
# distroless, with no shell and no sqlite3, so a schema-level failure is a
# *restore* problem and belongs to `tests/dr/rehearse_restore.sh`, which does
# destroy and rebuild the database for real. This drill owns the alerting path.
docker compose -f "$COMPOSE" stop bandall >/dev/null
note "bandall stopped: /readyz now refused, not 200"

# The blackbox exporter probes through Docker DNS. A stopped container has no
# address, so the probe fails rather than timing out, which is the faster and
# clearer signal.
READYZ_DOWN="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BANDALL/readyz" || true)"
[ -z "$READYZ_DOWN" ] || [ "$READYZ_DOWN" = "000" ] || [ "$READYZ_DOWN" = "503" ] || [ "$READYZ_DOWN" = "502" ] \
    || fail "the service still answered $READYZ_DOWN after being stopped"
pass "readiness is refused while the service is down"

# --------------------------------------------------------------------------
section "the alert fires"
# --------------------------------------------------------------------------
# Poll until the rule is `firing`, not just `pending`: `pending` means the
# condition was seen once and the `for:` has not elapsed, which is the state
# that looks like coverage without being it.
FIRED=0
for _ in $(seq 1 "$FIRE_TIMEOUT"); do
    STATE="$(curl -fsS "$PROM/api/v1/rules" | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]["groups"]
print(next((r["state"] for g in data for r in g["rules"] if r["name"] == "BandAllNotReady"), "absent"))')"
    if [ "$STATE" = "firing" ]; then
        FIRED=1
        break
    fi
    sleep 1
done
if [ "$FIRED" -ne 1 ]; then
    curl -fsS "$PROM/api/v1/rules" | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]["groups"]
for g in data:
    for r in g["rules"]:
        print(f"{r[\"name\"]}: {r[\"state\"]}")' | sed 's/^/    /'
    fail "BandAllNotReady never started firing within ${FIRE_TIMEOUT}s"
fi
pass "BandAllNotReady is firing"

# And it has to reach Alertmanager, otherwise it fired into a room nobody was
# in. Alertmanager is configured with an empty receiver on purpose: this checks
# that the alert is *received*, and the delivery target is a deployment
# decision, documented in alertmanager.yml.
DELIVERED=0
for _ in $(seq 1 "$FIRE_TIMEOUT"); do
    if [ "$(curl -fsS "$AM/api/v2/alerts" | python3 -c '
import json, sys
print(len([a for a in json.load(sys.stdin) if a.get("labels", {}).get("alertname") == "BandAllNotReady"]))')" != "0" ]; then
        DELIVERED=1
        break
    fi
    sleep 1
done
if [ "$DELIVERED" -ne 1 ]; then
    printf 'alertmanager sees: '
    curl -fsS "$AM/api/v2/alerts" | python3 -c 'import json,sys; print([a["labels"]["alertname"] for a in json.load(sys.stdin)])'
    fail "BandAllNotReady never reached alertmanager"
fi
pass "BandAllNotReady was delivered to alertmanager"

# --------------------------------------------------------------------------
section "recovery: the alert resolves"
# --------------------------------------------------------------------------
# A drill that leaves the alert firing has proven it can raise, not that it can
# clear. An alert that never clears is the other operators ignore.
docker compose -f "$COMPOSE" start bandall >/dev/null
wait_for "$BANDALL/readyz" "bandall after recovery"
pass "bandall is ready again"

RESOLVED=0
for _ in $(seq 1 "$FIRE_TIMEOUT"); do
    STATE="$(curl -fsS "$PROM/api/v1/rules" | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]["groups"]
print(next((r["state"] for g in data for r in g["rules"] if r["name"] == "BandAllNotReady"), "absent"))')"
    if [ "$STATE" = "inactive" ]; then
        RESOLVED=1
        break
    fi
    sleep 1
done
[ "$RESOLVED" = "1" ] || fail "BandAllNotReady never stopped firing after the service recovered"
pass "BandAllNotReady is inactive again"

# --------------------------------------------------------------------------
section "fail-closed on boot: broken configuration must refuse"
# --------------------------------------------------------------------------
# The other half of H8's fail-closed requirement, and it does not need the
# stack: a service that cannot reach its key material must refuse to start
# rather than serve anyone who asks.
#
# A throwaway tmpfs stands in for the data directory, because the runtime is
# read-only and distroless: this is the same arrangement the service normally
# runs under, and it needs no volume left behind. The key paths point at a file
# that does not exist, which is what a missing secret mount looks like.
set +e
OUT="$(docker run --rm \
    --tmpfs /tmp \
    -e BANDALL_DATABASE_URL="sqlite:/tmp/bandall.db" \
    -e BANDALL_KMS_KEY_FILE="/run/secrets/missing-kek" \
    -e BANDALL_AUDIT_KEY_FILE="/run/secrets/missing-audit-key" \
    -e BANDALL_SERVICE_KEY="$SERVICE_KEY" \
    "$IMAGE" 2>&1)"
RC=$?
set -e

if [ "$RC" -eq "0" ]; then
    printf '%s\n' "$OUT" | sed 's/^/    /'
    fail "bandall started with an unreadable key file: it is not failing closed"
fi
pass "bandall refuses to start when the key file is unreadable (exit $RC)"

printf '\n\033[1m== result\033[0m\n'
printf '  PASS  alert rules loaded and quiet at baseline\n'
printf '  PASS  service refused while stopped\n'
printf '  PASS  BandAllNotReady fired, within its %s s window\n' "$FIRE_TIMEOUT"
printf '  PASS  BandAllNotReady reached alertmanager\n'
printf '  PASS  BandAllNotReady resolved after recovery\n'
printf '  PASS  fail-closed on unreadable key material\n'
