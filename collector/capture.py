#!/usr/bin/env python3
"""
AIGuard Tier 1 — Packet Collector v12
Changes from v8:
  - Arctic Wolf syslog filtered by severity (v8)
  - Removed shared Cloudflare IP prefixes from AI_IP_PREFIXES (v9)
    Cloudflare ranges 172.64.x, 104.18.x, 162.158.x, 104.16.x, 104.17.x
    are shared by thousands of services (NinjaRMM, CDNs, etc.) and caused
    false positives (xai_grok, mistral). Detection for these providers
    now relies exclusively on DNS hostname matching, which is accurate.
  - Expanded google_gemini DNS hostnames and removed Google IP prefixes (v10)
    Google IPs (142.250.x, 172.217.x, 216.58.x) are shared across all Google
    services (Gmail, Drive, Maps, etc.). google_gemini now detected by DNS only.
  - SNI (Server Name Indication) detection added (v11)
    Extracts hostname from TLS Client Hello in plaintext before encryption.
    Solves DoH/DoT bypass and sessions where DNS was not captured by AIGuard.
    Detection priority: SNI > DNS cache > IP prefix.
  - Filter inbound (server→client) packets from being logged as user events (v12)
    Packets where src is an external AI provider IP are return traffic, not
    user-initiated events. Filtering prevents inflated counts and false DLP alerts.
"""

from scapy.all import sniff, IP, IPv6, TCP, DNS, DNSRR, Dot1Q
from datetime import datetime
import sqlite3, os, time, socket, threading
from collections import defaultdict
from ad_lookup import get_display

DB_PATH = "YOUR_DB_PATH"

VLAN_MAP = {
    1:   {"dept": "Management",              "sensitive": True,  "risk": 2.0, "compliance": []},
    3:   {"dept": "Nutanix HCI & CVMs",      "sensitive": True,  "risk": 2.5, "compliance": []},
    4:   {"dept": "Nutanix IPMI",            "sensitive": True,  "risk": 2.5, "compliance": []},
    6:   {"dept": "PEG TV",                  "sensitive": False, "risk": 1.0, "compliance": []},
    8:   {"dept": "PEG",                     "sensitive": False, "risk": 1.0, "compliance": []},
}

AI_HOSTNAMES = {
    "chat.openai.com": "openai", "api.openai.com": "openai", "openai.com": "openai",
    "claude.ai": "anthropic", "api.anthropic.com": "anthropic", "anthropic.com": "anthropic",
    # Google Gemini — DNS only (Google IPs are shared across all Google services)
    "gemini.google.com": "google_gemini",
    "generativelanguage.googleapis.com": "google_gemini",
    "aistudio.google.com": "google_gemini",
    "bard.google.com": "google_gemini",
    "labs.google": "google_gemini",
    "notebooklm.google.com": "google_gemini",
    "alkalimakersuite-pa.clients6.google.com": "google_gemini",
    "geminiforworkspace.google.com": "google_gemini",
    "copilot.microsoft": "ms_copilot", "sydney.bing.com": "ms_copilot",
    "copilot.cloud.microsoft": "ms_copilot", "ms-sso.copilot.microsoft.com": "ms_copilot",
    "grok.com": "xai_grok", "x.ai": "xai_grok", "api.x.ai": "xai_grok",
    "chat.mistral.ai": "mistral", "api.mistral.ai": "mistral",
    "huggingface.co": "huggingface",
    "perplexity.ai": "perplexity",
    "groq.com": "groq",
    "meta.ai": "meta_ai", "llama.meta.com": "meta_ai",
    "cohere.com": "cohere",
    "deepseek.com": "deepseek", "chat.deepseek.com": "deepseek",
    "you.com": "you_ai",
    "poe.com": "poe",
    "character.ai": "character_ai",
}

AI_IP_PREFIXES = {
    # Only IP ranges exclusively owned by a single provider.
    # Shared Cloudflare ranges (172.64.x, 104.18.x, 162.158.x, 104.16.x, 104.17.x)
    # removed — used by NinjaRMM and many other services, causing false positives.
    # xai_grok and mistral detection now relies on DNS hostname only.
    # Only IP ranges exclusively owned by a single provider.
    # google_gemini removed — Google IPs shared across Gmail, Drive, Maps, etc.
    # Detection for google_gemini, xai_grok, mistral relies on DNS hostname only.
    # openai relies on DNS hostname detection only — 13.107.246.x shared Microsoft infrastructure.
    # anthropic relies on DNS hostname detection only — 52.14.x and 3.134.x are shared AWS us-east-2.
    # ms_copilot relies on DNS hostname detection only — Microsoft IP ranges
    # are shared across all M365 services (Outlook, Teams, OneDrive, SharePoint).
    # IP prefix detection causes massive false positives.
    # huggingface relies on DNS hostname detection only — 34.148.x and 35.190.x are shared Google Cloud ranges.
    "deepseek":    ["103.238.", "47.236."],
}

INFRASTRUCTURE_IPS = {
    "YOUR_INFRA_IP_1",
    "YOUR_INFRA_IP_2",
    "YOUR_INFRA_IP_3",
    "YOUR_INFRA_IP_4",
    "YOUR_INFRA_IP_5",
    "YOUR_GATEWAY_IP",
    "YOUR_INFRA_IP_6",
    "YOUR_INFRA_IP_7",
    "YOUR_INFRA_IP_8",
    "YOUR_INFRA_IP_9",
}

DLP_PATTERNS = {
    "ssn":      r"\b\d{3}-\d{2}-\d{4}\b",
    "api_key":  r"(sk-[a-zA-Z0-9]{32,}|AIza[0-9A-Za-z\-_]{35})",
    "aws_key":  r"AKIA[0-9A-Z]{16}",
    "password": r"(password|passwd|pwd)\s*[:=]\s*\S+",
    "cc":       r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b",
}

dns_cache = {}
byte_counter = defaultdict(int)

# ── Arctic Wolf Syslog Integration ──
AW_SENSOR_IP   = "YOUR_MDR_SENSOR_IP"
AW_SENSOR_PORT = 514
AW_BATCH_INTERVAL = 3600  # seconds between HIGH digest sends (1 hour)

# Thread-safe queue for HIGH severity events pending batch send
_high_batch = []
_high_batch_lock = threading.Lock()


def send_to_arctic_wolf(severity, event_type, src_ip, provider, description):
    """
    Send a syslog message to the Arctic Wolf sensor.
    Called directly only for CRITICAL events.
    HIGH events are batched via queue_high_event().
    MEDIUM events are not sent to Arctic Wolf.
    """
    try:
        priority = {"CRITICAL": "2", "HIGH": "3",
                    "MEDIUM": "4", "INFO": "6"}.get(severity, "6")
        msg = (
            f"<{priority}>AIGuard: "
            f"event_type={event_type} "
            f"src_ip={src_ip} "
            f"provider={provider} "
            f"severity={severity} "
            f'description="{description}"'
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), (AW_SENSOR_IP, AW_SENSOR_PORT))
        sock.close()
        print(f"[AW]   Syslog sent ({severity}): {provider} from {src_ip}")
    except Exception as e:
        print(f"[AW]   Syslog error: {e}")


def queue_high_event(src_ip, provider, description):
    """Add a HIGH severity event to the pending batch queue."""
    with _high_batch_lock:
        _high_batch.append({
            "ts":          datetime.now().strftime("%H:%M:%S"),
            "src_ip":      src_ip,
            "provider":    provider,
            "description": description,
        })
    print(f"[AW]   HIGH queued for batch: {provider} from {src_ip} "
          f"(queue={len(_high_batch)})")


def flush_high_batch():
    """
    Send a single digest syslog message summarising all queued HIGH events,
    then clear the queue. Called by the background thread every AW_BATCH_INTERVAL.
    """
    with _high_batch_lock:
        if not _high_batch:
            return
        events   = list(_high_batch)
        _high_batch.clear()

    count     = len(events)
    providers = ", ".join(sorted({e["provider"] for e in events}))
    sources   = ", ".join(sorted({e["src_ip"]   for e in events}))
    first_ts  = events[0]["ts"]
    last_ts   = events[-1]["ts"]

    description = (
        f"HIGH digest: {count} event(s) in last {AW_BATCH_INTERVAL // 60} min | "
        f"providers=[{providers}] | "
        f"sources=[{sources}] | "
        f"window={first_ts}-{last_ts}"
    )
    send_to_arctic_wolf("HIGH", "dlp_digest", "AIGuard-T1", providers, description)
    print(f"[AW]   HIGH digest sent: {count} events")


def batch_sender_thread():
    """Background thread — wakes every AW_BATCH_INTERVAL and flushes the HIGH queue."""
    while True:
        time.sleep(AW_BATCH_INTERVAL)
        flush_high_batch()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, src TEXT, dst TEXT,
        provider TEXT, hostname TEXT, size INTEGER,
        proto TEXT, vlan_id INTEGER, department TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS dlp_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, src TEXT, provider TEXT,
        severity TEXT, pattern TEXT, department TEXT,
        vlan_id INTEGER, compliance TEXT
    )""")
    conn.commit()
    conn.close()
    print(f"[AIGuard] Database ready: {DB_PATH}")


def detect_hostname(hostname):
    hostname = hostname.lower().rstrip('.')
    for pattern, provider in AI_HOSTNAMES.items():
        if hostname == pattern or hostname.endswith('.' + pattern):
            return provider, hostname
    return None, None


def detect_ip(ip):
    for provider, prefixes in AI_IP_PREFIXES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None


def get_dept_info(vlan_id):
    if vlan_id and vlan_id in VLAN_MAP:
        return VLAN_MAP[vlan_id]
    return {"dept": "Unknown", "sensitive": False, "risk": 1.0, "compliance": []}


def dlp_check(src, provider, size, vlan_id):
    info       = get_dept_info(vlan_id)
    dept       = info["dept"]
    compliance = ", ".join(info["compliance"]) if info["compliance"] else "General Policy"
    severity   = None

    if info["sensitive"] and size > 50000:
        severity = "CRITICAL"
    elif info["risk"] >= 3.0:
        severity = "HIGH"
    elif info["risk"] >= 2.0:
        severity = "MEDIUM"

    if severity is None:
        return

    # Always write to local DB regardless of severity
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""INSERT INTO dlp_alerts
        (timestamp, src, provider, severity, pattern, department, vlan_id, compliance)
        VALUES (?,?,?,?,?,?,?,?)""",
        (datetime.now().isoformat(), src, provider, severity,
         f"AI access from {dept}", dept, vlan_id, compliance))
    conn.commit()
    conn.close()
    print(f"[DLP]  {severity} — {dept} → {provider} | {compliance}")

    description = f"{severity} AI access from {dept} to {provider} | {compliance}"

    # Arctic Wolf routing by severity:
    #   CRITICAL → immediate syslog
    #   HIGH     → queued for hourly digest
    #   MEDIUM   → local DB only, not forwarded to Arctic Wolf
    if severity == "CRITICAL":
        send_to_arctic_wolf("CRITICAL", "dlp_finding", src, provider, description)
    elif severity == "HIGH":
        queue_high_event(src, provider, description)
    # MEDIUM: no action toward Arctic Wolf


def process_dns(pkt):
    try:
        if not (pkt.haslayer(DNS) and pkt[DNS].ancount > 0):
            return
        dnsrr = pkt[DNS].an
        while dnsrr and hasattr(dnsrr, 'rrname'):
            try:
                rrname  = dnsrr.rrname
                hostname = (rrname.decode('utf-8', errors='ignore').rstrip('.')
                            if isinstance(rrname, bytes) else str(rrname).rstrip('.'))
                rdata   = dnsrr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode('utf-8', errors='ignore').rstrip('.')
                else:
                    rdata = str(rdata)
                provider, matched = detect_hostname(hostname)
                if provider:
                    dns_cache[rdata] = (provider, hostname)
                    print(f"[DNS]  cached {hostname} → {rdata} ({provider})")
            except Exception:
                pass
            dnsrr = dnsrr.payload
            if not hasattr(dnsrr, 'rrname'):
                break
    except Exception:
        pass


def log_event(src, dst, provider, hostname, size, vlan_id=None):
    info        = get_dept_info(vlan_id)
    dept        = info["dept"]
    display_src = get_display(src)
    conn        = sqlite3.connect(DB_PATH)
    conn.execute("""INSERT INTO events
        (timestamp, src, dst, provider, hostname, size, proto, vlan_id, department)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (datetime.now().isoformat(), display_src, dst, provider,
         hostname, size, "HTTPS", vlan_id, dept))
    conn.commit()
    conn.close()
    vlan_str = f"VLAN:{vlan_id} ({dept})" if vlan_id else ""
    ts       = datetime.now().strftime('%H:%M:%S')
    print(f"[AIGuard] {ts} {display_src} {vlan_str} → {provider} ({hostname}) {size}b")
    dlp_check(src, provider, size, vlan_id)


def extract_sni(pkt):
    """
    Extract the SNI hostname from a TLS Client Hello packet.
    The SNI field is sent in plaintext even in encrypted TLS sessions.
    Returns the SNI string or None if not found / not a Client Hello.

    TLS Client Hello structure (relevant offsets from TCP payload):
      [0]    = Content Type (0x16 = Handshake)
      [1-2]  = TLS Version
      [3-4]  = Record Length
      [5]    = Handshake Type (0x01 = Client Hello)
      ...
      Extensions start after: 5 + 4 + 2 + 32 + 1 + session_id_len +
                               2 + cipher_suites_len + 1 + compression_len
    """
    try:
        payload = bytes(pkt[TCP].payload)
        if len(payload) < 10:
            return None
        # Must be TLS Handshake (0x16) and Client Hello (0x01)
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None

        # Skip to extensions: fixed headers + variable fields
        pos = 43  # skip record header (5) + handshake header (4) + version (2) + random (32)
        if pos >= len(payload):
            return None

        # Session ID
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return None

        # Cipher suites
        cipher_suites_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload):
            return None

        # Compression methods
        compression_len = payload[pos]
        pos += 1 + compression_len
        if pos + 2 > len(payload):
            return None

        # Extensions length
        extensions_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end = pos + extensions_len

        # Walk extensions looking for SNI (type 0x0000)
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len  = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0x0000:  # SNI extension
                # SNI list length (2) + entry type (1) + name length (2) + name
                if pos + 5 > len(payload):
                    return None
                name_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                sni = payload[pos+5:pos+5+name_len].decode('utf-8', errors='ignore')
                return sni.lower()
            pos += ext_len

    except Exception:
        pass
    return None


def process_packet(pkt):
    vlan_id = None
    if Dot1Q in pkt:
        vlan_id = pkt[Dot1Q].vlan
    if DNS in pkt:
        process_dns(pkt)
        return
    try:
        if IP in pkt and TCP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            dport, sport = pkt[TCP].dport, pkt[TCP].sport
        elif IPv6 in pkt and TCP in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
            dport, sport = pkt[TCP].dport, pkt[TCP].sport
        else:
            return
        if src in INFRASTRUCTURE_IPS or dst in INFRASTRUCTURE_IPS:
            return
        if dport != 443 and sport != 443:
            return

        size   = len(pkt)
        target = dst if dport == 443 else src

        # ── Filter return traffic (server → client) ──
        # If src is an external IP already in dns_cache, this is a response packet.
        # Log only if dst is also internal — meaning it's a server pushing to a client.
        # The actual user event was already logged when the client sent the request.
        if dport != 443 and sport == 443:
            # This is inbound return traffic — skip to avoid double-counting
            return

        # ── Priority 1: SNI extraction from TLS Client Hello ──
        # Catches sessions where DNS was not seen by AIGuard (DoH/DoT, cached DNS)
        if dport == 443:
            sni = extract_sni(pkt)
            if sni:
                provider, matched = detect_hostname(sni)
                if provider:
                    # Update DNS cache so subsequent packets in this session are matched
                    dns_cache[target] = (provider, sni)
                    print(f"[SNI]  {sni} → {provider} (cached {target})")
                    log_event(src, dst, provider, sni, size, vlan_id)
                    return

        # ── Priority 2: DNS cache lookup ──
        if target in dns_cache:
            provider, hostname = dns_cache[target]
            log_event(src, dst, provider, hostname, size, vlan_id)
            return

        # ── Priority 3: IP prefix matching ──
        provider = detect_ip(target)
        if provider:
            log_event(src, dst, provider, target, size, vlan_id)

    except Exception:
        pass


if __name__ == "__main__":
    print("[AIGuard] Starting packet collector v8")
    print(f"[AIGuard] Monitoring {len(AI_HOSTNAMES)} AI hostnames")
    print(f"[AIGuard] VLAN awareness: {len(VLAN_MAP)} VLANs configured")
    print(f"[AIGuard] Arctic Wolf: CRITICAL=real-time | HIGH=digest/{AW_BATCH_INTERVAL//60}min | MEDIUM=local only")

    init_db()

    # Start background batch sender thread
    t = threading.Thread(target=batch_sender_thread, daemon=True)
    t.start()
    print(f"[AIGuard] HIGH batch sender started (interval={AW_BATCH_INTERVAL//60} min)")

    sniff(
        iface="enx00051b95762c",
        filter="tcp port 443 or port 53",
        prn=process_packet,
        store=False
    )
