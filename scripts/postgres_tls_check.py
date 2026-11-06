"""PostgreSQL over TLS (M9, ADR 0012), from the API's pod: scripts/k3d.sh check runs it with
`kubectl exec deploy/vaultgate-api -- python - < scripts/postgres_tls_check.py`.

With the API's own database URL and trust store (PGSSLROOTCERT): a connection that
verifies the server's name and chain is TLS, and one without TLS is refused.
"""

import asyncio
import os

import asyncpg

URL = os.environ["VAULTGATE_DATABASE_URL"].replace("+asyncpg", "").split("?")[0]


async def main() -> None:
    conn = await asyncpg.connect(URL, ssl="verify-full")
    tls, version = await conn.fetchrow(
        "select ssl, version from pg_stat_ssl where pid = pg_backend_pid()"
    )
    await conn.close()
    if not tls:
        raise SystemExit("FAIL the API's connection to PostgreSQL is not TLS")
    try:
        await asyncpg.connect(URL, ssl="disable")
    except asyncpg.InvalidAuthorizationSpecificationError:
        pass
    else:
        raise SystemExit("FAIL PostgreSQL accepted a connection without TLS")
    print(f"ok  PostgreSQL over {version}, server verified; a connection without TLS is refused")


asyncio.run(main())
