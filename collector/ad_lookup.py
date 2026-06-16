#!/usr/bin/env python3
"""
AIGuard — Active Directory IP to Username lookup
Domain: YOUR_DOMAIN_NAME   #CUSTOMIZE
DC Primary:   YOUR_DC_IP_1  #CUSTOMIZE
DC Secondary: YOUR_DC_IP_2  #CUSTOMIZE

Fix v2:
  - _refresh_cache() now uses the same SSL/SIMPLE method as _check_ad()
  - Removed plain LDAP port 389 / NTLM attempts that triggered strongerAuthRequired
  - Tracks which DC is reachable and reuses it for cache refresh
"""

from datetime import datetime, timedelta
from ldap3 import Server, Connection, ALL, SIMPLE, Tls
import threading
import socket
import ssl

AD_SERVERS  = [
    "YOUR_DC_IP_1",
    "YOUR_DC_IP_2",
]
AD_USER     = "YOUR_DOMAIN_NAME\\YOUR_SERVICE_ACCOUNT"  #CUSTOMIZE
AD_PASSWORD = "YOUR_PASSWORD"                #CUSTOMIZE
AD_BASE_DN  = "dc=xxx,dc=xx,dc=xxxxx,dc=xx,dc=us"   #CUSTOMIZE

_cache            = {}
_cache_lock       = threading.Lock()
_last_refresh     = None
_ad_available     = False
_active_dc        = None          # IP of the DC that responded last
_refresh_lock     = threading.Lock()
_refresh_running  = False         # Prevents concurrent cache refresh threads


def _make_connection(server_ip):
    """
    Open an SSL LDAP connection to server_ip:636.
    Returns a bound Connection or raises on failure.
    """
    tls    = Tls(validate=ssl.CERT_NONE)
    server = Server(server_ip, port=636, use_ssl=True, tls=tls,
                    get_info=ALL, connect_timeout=3)
    conn   = Connection(server, user=AD_USER, password=AD_PASSWORD,
                        authentication=SIMPLE, auto_bind=True)
    return conn


def _check_ad():
    """
    Probe each DC in order. Sets _ad_available and _active_dc on success.
    Runs once at startup in a daemon thread.
    """
    global _ad_available, _active_dc
    for server_ip in AD_SERVERS:
        try:
            conn = _make_connection(server_ip)
            conn.unbind()
            _ad_available = True
            _active_dc    = server_ip
            print(f"[AD] Connected to {server_ip} (SSL/SIMPLE)")
            return
        except Exception as e:
            print(f"[AD] {server_ip} not available: {e}")
    _ad_available = False
    print("[AD] No domain controllers available — using DNS fallback")


def _refresh_cache():
    """
    Pull all user objects from AD and map sAMAccountName + department.
    Uses the same SSL/SIMPLE method as _check_ad() to avoid
    strongerAuthRequired on port 389.
    Only one refresh runs at a time — concurrent calls return immediately.
    """
    global _last_refresh, _ad_available, _active_dc, _refresh_running

    with _refresh_lock:
        if _refresh_running:
            return  # Another thread is already refreshing
        _refresh_running = True

    if not _ad_available:
        with _refresh_lock:
            _refresh_running = False
        return

    # Try _active_dc first, then fall back to full list
    candidates = ([_active_dc] + AD_SERVERS) if _active_dc else AD_SERVERS

    for server_ip in candidates:
        try:
            conn = _make_connection(server_ip)
            conn.search(
                AD_BASE_DN,
                '(objectClass=user)',
                attributes=['sAMAccountName', 'displayName', 'department']
            )
            new_entries = {}
            for entry in conn.entries:
                sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
                if not sam:
                    continue
                new_entries[sam] = {
                    "displayName": str(entry.displayName) if entry.displayName else sam,
                    "department":  str(entry.department)  if entry.department  else "Unknown",
                }
            conn.unbind()

            with _cache_lock:
                _cache.update(new_entries)   # merge — keeps IP→username mappings intact

            _last_refresh = datetime.now()
            _active_dc    = server_ip
            print(f"[AD] Cache refreshed via {server_ip} — {len(new_entries)} users loaded")
            with _refresh_lock:
                _refresh_running = False
            return

        except Exception as e:
            print(f"[AD] Cache refresh failed on {server_ip}: {e}")

    # All DCs failed
    _ad_available = False
    _active_dc    = None
    print("[AD] All DCs unreachable — falling back to DNS")

    with _refresh_lock:
        _refresh_running = False


def resolve_ip(ip):
    """
    Return a display string for ip:
      - username (from login event mapping)
      - hostname (from DNS reverse lookup)
      - ip (raw fallback)
    Also triggers a background cache refresh if stale (> 5 min).
    """
    global _last_refresh
    if _last_refresh is None or \
       datetime.now() - _last_refresh > timedelta(minutes=5):
        threading.Thread(target=_refresh_cache, daemon=True).start()

    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    # DNS reverse lookup as fallback
    # Only use result if it looks like a real hostname, not a reversed IP or octect
    try:
        fqdn = socket.gethostbyaddr(ip)[0]
        short = fqdn.split('.')[0].upper()
        # Reject if short name is purely numeric (reversed IP octect artifact)
        if short.isdigit():
            return ip
        # Reject if it looks like a reversed IP (e.g. 134.43.190.35.in-addr.arpa)
        if 'in-addr' in fqdn.lower() or 'arpa' in fqdn.lower():
            return ip
        return short
    except Exception:
        return ip


def update_from_login_event(ip, username, department=None):
    """
    Called when a Windows login event (Event ID 4624) is received,
    mapping an IP directly to a username.
    """
    with _cache_lock:
        _cache[ip] = {
            "username":   username,
            "department": department or "Unknown",
            "last_seen":  datetime.now().isoformat()
        }
    print(f"[AD] Mapped {ip} → {username} ({department})")


def get_display(ip):
    """
    Return a human-readable label for ip, used in log output and DB entries.
    """
    result = resolve_ip(ip)
    if isinstance(result, dict):
        dept = result.get('department', '')
        name = result.get('username', ip)
        return f"{name} ({dept})" if dept else name
    return result


# ── Startup probe ──
threading.Thread(target=_check_ad, daemon=True).start()
