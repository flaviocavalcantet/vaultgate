"""PostgreSQL over TLS (M9, ADR 0012), from the API's pod: scripts/k3d.sh check runs it with
`kubectl exec deploy/vaultgate-api -- python - < scripts/postgres_tls_check.py`.

With the API's own database URL (from its settings, so from OpenBao's file on the
cluster) and trust store (PGSSLROOTCERT): a connection that verifies the server's name
and chain is TLS, logs in as a login OpenBao issued (v-...) acting as vaultgate_owner,
and one without TLS is refused.
"""

import asyncio

import asyncpg
from vaultgate_api.config import settings

URL = settings.database_url.replace("+asyncpg", "").split("?")[0]


async def main() -> None:
    conn = await asyncpg.connect(URL, ssl="verify-full")
    # From the client's side: pg_stat_ssl hides the row from a session acting as another
    # role than its login.
    tls = conn._transport.get_extra_info("ssl_object")
    version = tls.version() if tls else None
    login, acting = await conn.fetchrow("select session_user, current_user")
    await conn.close()
    if not tls:
        raise SystemExit("FAIL the API's connection to PostgreSQL is not TLS")
    if not login.startswith("v-") or acting != "vaultgate_owner":
        raise SystemExit(f"FAIL the API logs in as {login} acting as {acting}, not OpenBao's")
    try:
        await asyncpg.connect(URL, ssl="disable")
    except asyncpg.InvalidAuthorizationSpecificationError:
        pass
    else:
        raise SystemExit("FAIL PostgreSQL accepted a connection without TLS")
    print(
        f"ok  PostgreSQL over {version}, server verified, as {login[:24]}... (OpenBao's, "
        "acting as vaultgate_owner); a connection without TLS is refused"
    )


asyncio.run(main())
