import ipaddress

from fastapi import Header, HTTPException, Request, status
from pydantic import BaseModel

from app.config import settings
from app.logging_config import get_logger

log = get_logger(__name__)


class Principal(BaseModel):
    username: str
    groups: list[str] = []
    source: str = "forward-auth"


def _is_trusted_proxy(client_host: str | None) -> bool:
    """Prüft, ob die Verbindung von einem vertrauenswürdigen Proxy kommt.
    Nur dann dürfen Remote-User/-Groups-Header geglaubt werden — sonst kann
    jeder mit direktem Netzzugang die Header spoofen."""
    if not client_host:
        return False
    try:
        addr = ipaddress.ip_address(client_host)
    except ValueError:
        return False
    for entry in settings.auth_trusted_proxies:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


async def current_user(
    request: Request,
    x_remote_user: str | None = Header(None, alias="Remote-User"),
    x_remote_groups: str | None = Header(None, alias="Remote-Groups"),
) -> Principal:
    """
    Erwartet Authelia/Nginx forward-auth Header (Remote-User, Remote-Groups).
    Wenn auth_required=False: anonymous Principal.
    """
    if not settings.auth_required:
        return Principal(username="anonymous", source="disabled")

    # Forward-Auth-Header nur von vertrauenswürdigem Proxy akzeptieren (Anti-Spoofing).
    client_host = request.client.host if request.client else None
    if not _is_trusted_proxy(client_host):
        log.warning("auth.untrusted_proxy", client=client_host, path=str(request.url.path))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    if not x_remote_user:
        log.warning("auth.missing_header", path=str(request.url.path))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    groups = [g.strip() for g in (x_remote_groups or "").split(",") if g.strip()]
    return Principal(username=x_remote_user, groups=groups)


def require_group(group: str):
    async def _check(principal: Principal) -> Principal:
        if group not in principal.groups:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Group '{group}' required",
            )
        return principal

    return _check
