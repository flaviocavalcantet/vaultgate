"""Who is an administrator: a user in one of settings.admin_groups, by the groups the
identity provider put in their token (synced at each request). One place decides, for
the admin routes' check and for what /me tells a client."""

from vaultgate_api.config import settings
from vaultgate_api.models import User


def is_admin(user: User) -> bool:
    return bool({group.name for group in user.groups} & set(settings.admin_groups))
