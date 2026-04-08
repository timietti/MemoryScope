# backend/core/ldap_auth.py
"""
LDAP / LDAPS authentication helper.

Supports:
  - Plain LDAP (ldap://) with optional StartTLS upgrade
  - LDAPS (ldaps://) — TLS from the start
  - TLS certificate verification toggle
  - Service-account bind for user search
  - User credential verification via re-bind
  - Group membership → role mapping (admin / analyst / viewer)
  - JIT provisioning metadata returned for the caller to persist

Usage::
    from backend.core.ldap_auth import authenticate_ldap, LdapUserInfo, LdapAuthError
    try:
        info = authenticate_ldap(username, password)
    except LdapAuthError as exc:
        # log exc.detail internally; return generic message to client
        ...
"""
from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass

import ldap3
from ldap3 import Connection, Server, Tls, ALL_ATTRIBUTES, SUBTREE
from ldap3.core.exceptions import LDAPException

from backend.config import settings

logger = logging.getLogger(__name__)


# ── Public types ──────────────────────────────────────────────────────────────

@dataclass
class LdapUserInfo:
    dn: str
    email: str
    display_name: str
    role: str   # "admin" | "analyst" | "viewer"


class LdapAuthError(Exception):
    """Raised when LDAP authentication fails for any reason."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


# ── Internal helpers ──────────────────────────────────────────────────────────

def _build_server() -> Server:
    """Build an ldap3 Server object from current settings."""
    url: str = settings.LDAP_URL.strip()
    if not url:
        raise LdapAuthError("LDAP_URL is not configured")

    use_ssl = url.lower().startswith("ldaps://")
    tls_config: Tls | None = None

    if use_ssl or settings.LDAP_USE_STARTTLS:
        tls_config = Tls(
            validate=ssl.CERT_REQUIRED if settings.LDAP_TLS_VERIFY else ssl.CERT_NONE,
        )

    return Server(url, use_ssl=use_ssl, tls=tls_config, get_info=ldap3.ALL)


def _service_bind() -> Connection:
    """Open and bind a service-account connection for user searching."""
    server = _build_server()
    bind_dn: str = settings.LDAP_BIND_DN.strip()
    bind_pw: str = settings.LDAP_BIND_PASSWORD.get_secret_value() if settings.LDAP_BIND_PASSWORD else ""

    conn = Connection(server, user=bind_dn or None, password=bind_pw or None,
                      auto_bind=ldap3.AUTO_BIND_NONE, raise_exceptions=False)

    if settings.LDAP_USE_STARTTLS and not settings.LDAP_URL.lower().startswith("ldaps://"):
        if not conn.start_tls():
            raise LdapAuthError(f"StartTLS failed: {conn.last_error}")

    if not conn.bind():
        raise LdapAuthError(f"Service-account bind failed: {conn.last_error}")

    return conn


def _get_groups(conn: Connection, user_dn: str) -> list[str]:
    """Return list of group DNs the user is a direct member of."""
    group_base = (settings.LDAP_GROUP_BASE_DN.strip()
                  or settings.LDAP_BASE_DN.strip())
    if not group_base:
        return []

    conn.search(
        search_base=group_base,
        search_filter=f"(member={user_dn})",
        search_scope=SUBTREE,
        attributes=["distinguishedName"],
    )
    return [entry.entry_dn for entry in conn.entries]


def _map_role(groups: list[str]) -> str | None:
    """
    Map group membership to a role string.
    Returns None if the user is not in any configured group.
    """
    admin_group = settings.LDAP_ADMIN_GROUP.strip()
    analyst_group = settings.LDAP_ANALYST_GROUP.strip()
    viewer_group = settings.LDAP_VIEWER_GROUP.strip()

    # Normalise to lowercase for case-insensitive comparison
    groups_lower = [g.lower() for g in groups]

    if admin_group and admin_group.lower() in groups_lower:
        return "admin"
    if analyst_group and analyst_group.lower() in groups_lower:
        return "analyst"
    if viewer_group and viewer_group.lower() in groups_lower:
        return "viewer"

    return None


# ── Public API ────────────────────────────────────────────────────────────────

def authenticate_ldap(username: str, password: str) -> LdapUserInfo:
    """
    Authenticate *username* / *password* against the configured LDAP directory.

    Steps:
      1. Bind with service account.
      2. Search for the user with ldap_user_filter (substituting {username}).
      3. Re-bind as the found user to verify the password.
      4. Look up group membership and map to a role.
      5. Return LdapUserInfo.

    Raises LdapAuthError on any failure.
    """
    if not settings.LDAP_ENABLED:
        raise LdapAuthError("LDAP authentication is disabled")

    base_dn = settings.LDAP_BASE_DN.strip()
    if not base_dn:
        raise LdapAuthError("LDAP_BASE_DN is not configured")

    email_attr = settings.LDAP_ATTR_EMAIL.strip() or "mail"
    dn_attr = settings.LDAP_ATTR_DISPLAY_NAME.strip() or "displayName"
    user_filter = settings.LDAP_USER_FILTER.strip() or "(sAMAccountName={username})"

    # Sanitise username: reject characters that could break the LDAP filter
    _safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                "@._-+= ")
    if not all(c in _safe for c in username):
        raise LdapAuthError("Username contains invalid characters")

    search_filter = user_filter.replace("{username}", username)

    try:
        service_conn = _service_bind()
    except LdapAuthError:
        raise
    except LDAPException as exc:
        logger.error("LDAP service bind exception: %s", exc)
        raise LdapAuthError("Could not connect to LDAP server") from exc

    try:
        service_conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[email_attr, dn_attr],
        )
    except LDAPException as exc:
        logger.error("LDAP user search exception: %s", exc)
        raise LdapAuthError("LDAP user search failed") from exc

    if not service_conn.entries:
        raise LdapAuthError(f"User {username!r} not found in LDAP directory")

    if len(service_conn.entries) > 1:
        raise LdapAuthError(f"Ambiguous LDAP search: {len(service_conn.entries)} entries match {username!r}")

    entry = service_conn.entries[0]
    user_dn: str = entry.entry_dn

    # Extract email and display name
    raw_email = entry[email_attr].value if email_attr in entry else None
    if not raw_email:
        raise LdapAuthError(f"LDAP entry for {username!r} has no {email_attr!r} attribute")
    email: str = str(raw_email).strip().lower()

    raw_display = entry[dn_attr].value if dn_attr in entry else None
    display_name: str = str(raw_display).strip() if raw_display else username

    # Verify password by re-binding as the user
    server = _build_server()
    user_conn = Connection(server, user=user_dn, password=password,
                           auto_bind=ldap3.AUTO_BIND_NONE, raise_exceptions=False)

    if settings.LDAP_USE_STARTTLS and not settings.LDAP_URL.lower().startswith("ldaps://"):
        if not user_conn.start_tls():
            raise LdapAuthError(f"StartTLS failed for user bind: {user_conn.last_error}")

    if not user_conn.bind():
        raise LdapAuthError("Invalid credentials")

    # Fetch group membership using the service connection (already open)
    try:
        groups = _get_groups(service_conn, user_dn)
    except LDAPException as exc:
        logger.warning("LDAP group search failed for %s: %s", user_dn, exc)
        groups = []

    service_conn.unbind()
    user_conn.unbind()

    role = _map_role(groups)
    if role is None:
        raise LdapAuthError(
            f"User {username!r} is not a member of any authorised group"
        )

    logger.info("LDAP authentication succeeded for %s (role=%s)", email, role)
    return LdapUserInfo(dn=user_dn, email=email, display_name=display_name, role=role)


def test_ldap_connection() -> dict:
    """
    Test LDAP connectivity and service-account bind.
    Returns a dict with 'ok' (bool) and 'message' or 'error' (str).
    Used by the admin test endpoint.
    """
    if not settings.LDAP_URL.strip():
        return {"ok": False, "error": "LDAP_URL is not configured"}

    try:
        conn = _service_bind()
        base_dn = settings.LDAP_BASE_DN.strip()
        user_count: int | None = None

        if base_dn:
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=[],
            )
            # Count users to confirm search base is reachable
            conn.search(
                search_base=base_dn,
                search_filter=settings.LDAP_USER_FILTER.replace("{username}", "*"),
                search_scope=SUBTREE,
                attributes=[],
                size_limit=1000,
            )
            user_count = len(conn.entries)

        conn.unbind()

        msg = "Service-account bind succeeded"
        if user_count is not None:
            msg += f"; found {user_count} user(s) in base DN"
        return {"ok": True, "message": msg}

    except LdapAuthError as exc:
        return {"ok": False, "error": exc.detail}
    except LDAPException as exc:
        logger.warning("LDAP test connection failed: %s", exc)
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        logger.error("LDAP test connection unexpected error: %s", exc)
        return {"ok": False, "error": "Unexpected error — check server logs"}
