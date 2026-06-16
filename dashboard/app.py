





#!/usr/bin/env python3
"""
AIGuard T1 — Dashboard API v8
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3
from datetime import datetime

app = FastAPI(title="AIGuard T1 Dashboard")
DB_PATH = "/home/aiguard/aiguard/data/events.db"

def query_db(sql, params=()):
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(sql, params)
    results = cursor.fetchall()
    conn.close()
    return results

def table_exists(name):
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

@app.get("/api/summary")
def summary():
    if not table_exists("events"):
        return {"total": 0, "providers": [], "volume": 0, "dlp_count": 0}
    total = query_db("SELECT COUNT(*) as c FROM events")[0]["c"]
    volume = query_db("SELECT SUM(size) as s FROM events")[0]["s"] or 0
    providers = query_db("""
        SELECT provider, COUNT(*) as connections,
               SUM(size) as bytes,
               MAX(timestamp) as last_seen
        FROM events GROUP BY provider ORDER BY connections DESC
    """)
    dlp_count = 0
    if table_exists("dlp_alerts"):
        dlp_count = query_db("SELECT COUNT(*) as c FROM dlp_alerts")[0]["c"]
    return {
        "total": total,
        "volume": volume,
        "providers": [dict(r) for r in providers],
        "dlp_count": dlp_count,
        "generated": datetime.now().isoformat()
    }

@app.get("/api/dlp")
def dlp_alerts():
    if not table_exists("dlp_alerts"):
        return []
    rows = query_db("""
        SELECT * FROM dlp_alerts
        ORDER BY timestamp DESC LIMIT 100
    """)
    return [dict(r) for r in rows]

@app.get("/api/events")
def recent_events():
    if not table_exists("events"):
        return []
    rows = query_db("""
        SELECT * FROM events
        ORDER BY timestamp DESC LIMIT 200
    """)
    return [dict(r) for r in rows]

@app.get("/api/copilot-context")
def copilot_context():
    if not table_exists("events"):
        return {"context": "No data yet."}
    summary_data = summary()
    lines = [
        f"AIGuard T1 Security Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Total AI connections detected: {summary_data['total']}",
        f"Total data volume: {round(summary_data['volume']/1024,1)} KB",
        f"DLP findings: {summary_data['dlp_count']}",
        "",
        "AI Providers detected:",
    ]
    for p in summary_data["providers"]:
        lines.append(f"  - {p['provider']}: {p['connections']} connections, {round(p['bytes']/1024,1)} KB")
    lines.append("")
    lines.append("Please analyze this data and:")
    lines.append("1. Identify the main security risks")
    lines.append("2. Highlight any shadow AI usage")
    lines.append("3. Recommend immediate actions")
    lines.append("4. Suggest policies to implement")
    return {"context": "\n".join(lines)}

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return open("/home/aiguard/aiguard/dashboard/index.html").read()

@app.get("/api/departments")
def departments():
    if not table_exists("events"):
        return []
    rows = query_db("""
        SELECT DISTINCT department, vlan_id
        FROM events
        WHERE department IS NOT NULL
        ORDER BY department
    """)
    return [dict(r) for r in rows]

@app.get("/api/events/filter")
def events_filter(department: str = None, vlan_id: int = None, limit: int = 200):
    if not table_exists("events"):
        return []
    if department:
        rows = query_db("""
            SELECT * FROM events
            WHERE department = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (department, limit))
    elif vlan_id:
        rows = query_db("""
            SELECT * FROM events
            WHERE vlan_id = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (vlan_id, limit))
    else:
        rows = query_db("""
            SELECT * FROM events
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    return [dict(r) for r in rows]

@app.get("/api/dlp/filter")
def dlp_filter(department: str = None, severity: str = None, limit: int = 100):
    if not table_exists("dlp_alerts"):
        return []
    if department and severity:
        rows = query_db("""
            SELECT * FROM dlp_alerts
            WHERE department = ? AND severity = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (department, severity, limit))
    elif department:
        rows = query_db("""
            SELECT * FROM dlp_alerts
            WHERE department = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (department, limit))
    elif severity:
        rows = query_db("""
            SELECT * FROM dlp_alerts
            WHERE severity = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (severity, limit))
    else:
        rows = query_db("""
            SELECT * FROM dlp_alerts
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    return [dict(r) for r in rows]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
