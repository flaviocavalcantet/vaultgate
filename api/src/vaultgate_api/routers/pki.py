"""The nodes' CA, published (M11, ADR 0014): its certificate, its revocation lists and
its OCSP responder, from OpenBao's nodes mount (settings.nodes_pki_mount).

External nodes, and whoever checks their certificates, can't reach OpenBao, which
serves the cluster only: the certificates the nodes' CA issues point here instead
(their CA Issuers, CRL distribution point and OCSP URLs). All of it is public by
nature: a CA certificate, signed lists, signed responses. So these routes need no token,
and are limited per client address instead. The certificate and the lists are cached for
a minute, so a flood of them doesn't reach OpenBao; OCSP answers are not, so a
revocation shows at once.
"""

import time

import httpx
from fastapi import APIRouter, HTTPException, Request, Response, status

from vaultgate_api.config import settings

router = APIRouter(prefix="/pki/nodes", tags=["pki"])

CACHE_SECONDS = 60
MAX_OCSP_REQUEST = 4096  # bytes; a request for one certificate is about 100

_cache: dict[str, tuple[float, bytes]] = {}


async def _openbao(
    request: Request, method: str, path: str, body: bytes | None = None
) -> httpx.Response:
    if not settings.openbao_address:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not Found")
    url = f"{settings.openbao_address.rstrip('/')}/v1/{settings.nodes_pki_mount}/{path}"
    headers = {"Content-Type": "application/ocsp-request"} if body is not None else {}
    try:
        response = await request.app.state.openbao.request(
            method, url, content=body, headers=headers
        )
    except httpx.HTTPError:
        raise _unavailable() from None
    return response


def _unavailable() -> HTTPException:
    return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The CA is unavailable")


async def _cached(request: Request, path: str, media_type: str) -> Response:
    now = time.monotonic()
    hit = _cache.get(path)
    if hit is None or hit[0] <= now:
        response = await _openbao(request, "GET", path)
        if response.status_code != 200:
            raise _unavailable()
        hit = (now + CACHE_SECONDS, response.content)
        _cache[path] = hit
    return Response(
        hit[1], media_type=media_type, headers={"Cache-Control": f"max-age={CACHE_SECONDS}"}
    )


@router.get("/ca")
async def ca_der(request: Request) -> Response:
    """The nodes' CA certificate, DER (the certificates' CA Issuers URL)."""
    return await _cached(request, "ca", "application/pkix-cert")


@router.get("/ca/pem")
async def ca_pem(request: Request) -> Response:
    """The nodes' CA certificate, PEM."""
    return await _cached(request, "ca/pem", "application/x-pem-file")


@router.get("/crl")
async def crl(request: Request) -> Response:
    """The full revocation list, DER (the certificates' CRL distribution point)."""
    return await _cached(request, "crl", "application/pkix-crl")


@router.get("/crl/delta")
async def crl_delta(request: Request) -> Response:
    """The revocations since the full list, DER."""
    return await _cached(request, "crl/delta", "application/pkix-crl")


@router.post("/ocsp")
async def ocsp(request: Request) -> Response:
    """OCSP (RFC 6960), the request DER in the body: the certificates' OCSP URL. OCSP's
    own errors (a malformed request, an unknown issuer) are OCSP responses too, and pass
    through as OpenBao answers them."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_OCSP_REQUEST:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "OCSP request too large")
    response = await _openbao(request, "POST", "ocsp", bytes(body))
    if response.headers.get("content-type") != "application/ocsp-response":
        raise _unavailable()
    return Response(
        response.content, status_code=response.status_code, media_type="application/ocsp-response"
    )


def reset() -> None:
    """Forget the cached certificate and lists (tests)."""
    _cache.clear()
