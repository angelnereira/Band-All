"""Rollback probe: proves one thing about a running BandAll.

Enrols a user, verifies the second factor, and prints a single line the driver
reads. The same probe runs at every stage of `rehearse_rollback.sh`, so the
stages are compared on identical criteria rather than on prose.

Exits non-zero with a diagnostic if any step fails, because the drill must fail
loudly: a probe that reports success through a broken service would make the
rollback rehearsal certify the wrong thing.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "container"))

from totp_client import Client, Session, unique  # noqa: E402


def main() -> int:
    base_url = sys.argv[1]
    service_key = sys.argv[2]
    tenant_id = sys.argv[3]
    stage = sys.argv[4]

    client = Client(base_url, service_key)

    # The rollout has to be *usable*, not merely reachable: an authenticator
    # whose factors cannot produce a working code is down no matter what
    # /readyz says.
    ready = client.get("/readyz")
    if ready.status != 200:
        print(f"{stage}: READY_FAIL /readyz={ready.status}")
        return 1

    # A fresh user at every stage. Reusing one across stages would hide a
    # rollback that breaks only *existing* state, which is exactly the case a
    # rollback drill exists to find.
    session = Session(client, tenant_id, unique("rollback"))
    session.enroll()
    result = session.mfa_verify()
    if result.status != 200:
        print(f"{stage}: LOGIN_FAIL status={result.status} body={result}")
        return 1

    if not session.access_token:
        print(f"{stage}: NO_TOKEN")
        return 1

    # And the token it just issued has to be honoured, not merely handed out:
    # a signing key lost on restart would pass the login check and fail every
    # protected request afterwards.
    check = client.get(
        "/v1/authz/check",
        headers={"Authorization": f"Bearer {session.access_token}"},
        with_service_key=False,
    )
    if check.status != 200:
        print(f"{stage}: TOKEN_FAIL /v1/authz/check={check.status}")
        return 1

    print(f"{stage}: OK subject={session.subject_id[:8]} factor={session.factor_id[:8]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())