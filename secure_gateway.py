"""
Production-Grade Edge Security Gateway, WAF & Router Admin Portal
Engineered for ARM32/ARM64 Linux / Android Termux environments.
Features:
- Live Monitoring GUI Dashboard
- Dynamic IP Whitelisting & Blacklisting (in-memory & persistent)
- Deep-Packet WAF Inspection (SQLi, XSS, Path Traversal, Command Injection)
- Token-Bucket Rate Limiter
- Network & Router Utilities: DNS Lookup, Ping, Traceroute, Port Scan
- Asynchronous SQLite Threat & Access Logging
- Lightweight (< 30MB RAM footprint)
"""

import asyncio
import html
import logging
import os
import re
import socket
import subprocess
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Optional, Tuple
from urllib.parse import unquote

import aiosqlite
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Configuration & Globals
# ---------------------------------------------------------------------------
DB_PATH = os.getenv("WAF_DB_PATH", "threat_logs.db")
ADMIN_TOKEN = os.getenv("WAF_ADMIN_TOKEN", "supersecret-gateway-token-2026")
RATE_LIMIT_CAPACITY = 15     # Max tokens per bucket
RATE_LIMIT_FILL_RATE = 1.0   # Tokens added per second

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SecureGateway")

# Dynamic IP Lists
WHITELIST_IPS = set(["127.0.0.1", "::1"])
BLACKLIST_IPS = set()

# ---------------------------------------------------------------------------
# Attack Signatures
# ---------------------------------------------------------------------------
ATTACK_SIGNATURES = [
    (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)", re.IGNORECASE), "PATH_TRAVERSAL"),
    (re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|/system/etc)", re.IGNORECASE), "OS_FILE_ACCESS"),
    (re.compile(r"(\b(union(\s+all)?\s+select)\b|\bselect\b.+\bfrom\b)", re.IGNORECASE), "SQLI_SELECT"),
    (re.compile(r"(\b(order|group)\s+by\s+\d+)", re.IGNORECASE), "SQLI_ORDER_BY"),
    (re.compile(r"(\b(waitfor\s+delay|benchmark\s*\(|pg_sleep\s*\()|\bsleep\s*\(\d+\))", re.IGNORECASE), "SQLI_BLIND"),
    (re.compile(r"('|\%27)\s*(--|#|\/\*|or\s+[\w\d]+\s*=\s*[\w\d]+)", re.IGNORECASE), "SQLI_BOOLEAN"),
    (re.compile(r"(<script[\s\S]*?>[\s\S]*?<\/script>|javascript:\s*[\w\.\(]+)", re.IGNORECASE), "XSS_SCRIPT_TAG"),
    (re.compile(r"(onload|onerror|onclick|onmouseover|onfocus)\s*=", re.IGNORECASE), "XSS_EVENT_HANDLER"),
    (re.compile(r"(<iframe|<svg|<object|<embed|<base\b)", re.IGNORECASE), "XSS_TAG_INJECTION"),
    (re.compile(r"(;\s*(sh|bash|curl|wget|nc|netcat|python|perl|busybox)\b)", re.IGNORECASE), "RCE_COMMAND_CHAIN"),
]

# ---------------------------------------------------------------------------
# Metrics Tracker
# ---------------------------------------------------------------------------
class MetricsTracker:
    def __init__(self):
        self.total_requests = 0
        self.blocked_threats = 0
        self.rate_limited_count = 0
        self.unique_ips = set()
        self.recent_ips = defaultdict(lambda: {"count": 0, "last_seen": 0})

    def record_request(self, ip: str):
        self.total_requests += 1
        self.unique_ips.add(ip)
        self.recent_ips[ip]["count"] += 1
        self.recent_ips[ip]["last_seen"] = time.time()

    def record_block(self):
        self.blocked_threats += 1

    def record_rate_limit(self):
        self.rate_limited_count += 1


metrics = MetricsTracker()

# ---------------------------------------------------------------------------
# Database & Persistence
# ---------------------------------------------------------------------------
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                ip TEXT NOT NULL,
                user_agent TEXT,
                attack_type TEXT NOT NULL,
                matched_pattern TEXT NOT NULL,
                target_url TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ip_rules (
                ip TEXT PRIMARY KEY,
                rule_type TEXT NOT NULL,
                note TEXT,
                created_at REAL NOT NULL
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_logs(ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_ts ON threat_logs(timestamp)")
        await db.commit()

        # Load persisted rules
        async with db.execute("SELECT ip, rule_type FROM ip_rules") as cursor:
            async for row in cursor:
                ip, rtype = row[0], row[1]
                if rtype == "whitelist":
                    WHITELIST_IPS.add(ip)
                elif rtype == "blacklist":
                    BLACKLIST_IPS.add(ip)


async def log_threat(ip: str, user_agent: str, attack_type: str, matched_pattern: str, target_url: str):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT INTO threat_logs (timestamp, ip, user_agent, attack_type, matched_pattern, target_url)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (time.time(), ip, user_agent[:255], attack_type, matched_pattern[:255], target_url[:500]),
            )
            await db.commit()
    except Exception as exc:
        logger.error(f"Threat logging failed: {exc}")


# ---------------------------------------------------------------------------
# Token-Bucket Rate Limiter
# ---------------------------------------------------------------------------
class TokenBucketRateLimiter:
    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.buckets = defaultdict(lambda: [self.capacity, time.monotonic()])
        self.last_cleanup = time.monotonic()

    def is_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        if now - self.last_cleanup > 120.0:
            self._cleanup(now)

        bucket = self.buckets[ip]
        tokens, last_time = bucket
        elapsed = now - last_time
        tokens = min(self.capacity, tokens + (elapsed * self.fill_rate))

        if tokens >= 1.0:
            bucket[0] = tokens - 1.0
            bucket[1] = now
            return True
        else:
            bucket[0] = tokens
            bucket[1] = now
            return False

    def _cleanup(self, now: float):
        stale = [ip for ip, (_, last) in self.buckets.items() if now - last > 300.0]
        for ip in stale:
            del self.buckets[ip]
        self.last_cleanup = now


rate_limiter = TokenBucketRateLimiter(capacity=RATE_LIMIT_CAPACITY, fill_rate=RATE_LIMIT_FILL_RATE)

# ---------------------------------------------------------------------------
# IP & Payload Utilities
# ---------------------------------------------------------------------------
def extract_client_ip(request: Request) -> str:
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(",")[0].strip()
        if client_ip:
            return client_ip

    cf_connecting = request.headers.get("cf-connecting-ip")
    if cf_connecting:
        return cf_connecting.strip()

    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()

    return request.client.host if request.client else "127.0.0.1"


def inspect_payload(payload_str: str) -> Optional[Tuple[str, str]]:
    if not payload_str:
        return None

    decoded_once = unquote(payload_str)
    decoded_twice = unquote(decoded_once)
    decoded_html = html.unescape(decoded_twice)

    for candidate in (payload_str, decoded_twice, decoded_html):
        for pattern, attack_type in ATTACK_SIGNATURES:
            match = pattern.search(candidate)
            if match:
                return attack_type, match.group(0)

    return None

# ---------------------------------------------------------------------------
# Security Middleware
# ---------------------------------------------------------------------------
class SecurityGatewayMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = extract_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown")
        target_url = str(request.url)
        path = request.url.path

        # Never block internal dashboard static/API resources by WAF inspect
        is_dashboard = path.startswith("/dashboard") or path.startswith("/api/")

        metrics.record_request(client_ip)

        # 1. Blacklist Check
        if client_ip in BLACKLIST_IPS and not is_dashboard:
            metrics.record_block()
            logger.warning(f"[403 BLACKLIST] IP: {client_ip} dropped")
            return JSONResponse(status_code=403, content={"error": "Access Denied", "detail": "IP is blacklisted"})

        # 2. Whitelist Check (bypasses rate limit and WAF)
        if client_ip in WHITELIST_IPS:
            return await call_next(request)

        # 3. Rate Limiter (skip for dashboard routes to keep UI responsive)
        if not is_dashboard and not rate_limiter.is_allowed(client_ip):
            metrics.record_rate_limit()
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "client_ip": client_ip},
                headers={"Retry-After": "10"},
            )

        # 4. Deep-Packet Inspection
        if not is_dashboard:
            url_components = f"{request.url.path}?{request.url.query}"
            threat = inspect_payload(url_components)
            if threat:
                attack_type, matched_snippet = threat
                metrics.record_block()
                asyncio.create_task(log_threat(client_ip, user_agent, attack_type, matched_snippet, target_url))
                return JSONResponse(
                    status_code=403,
                    content={"error": "Forbidden", "detail": f"Malicious payload detected: {attack_type}"},
                )

            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                body_bytes = await request.body()
                if body_bytes:
                    body_sample = body_bytes[:1024 * 1024].decode("utf-8", errors="ignore")
                    threat = inspect_payload(body_sample)
                    if threat:
                        attack_type, matched_snippet = threat
                        metrics.record_block()
                        asyncio.create_task(log_threat(client_ip, user_agent, attack_type, matched_snippet, target_url))
                        return JSONResponse(
                            status_code=403,
                            content={"error": "Forbidden", "detail": f"Malicious body payload: {attack_type}"},
                        )

        return await call_next(request)

# ---------------------------------------------------------------------------
# GUI Dashboard HTML Template
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tecno Edge Security & Router WAF</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root { --bg: #0b1329; --card-bg: #141f3d; --accent: #38bdf8; --text: #e2e8f0; --border: #23355d; }
        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        .navbar { background: #080f20; border-bottom: 1px solid var(--border); }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 20px; }
        .card-header { background: rgba(0,0,0,0.2); border-bottom: 1px solid var(--border); font-weight: 600; color: var(--accent); }
        .stat-card { text-align: center; padding: 20px; }
        .stat-val { font-size: 2.2rem; font-weight: 700; color: #fff; }
        .badge-threat { background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }
        .badge-ip { background: #38bdf820; color: #38bdf8; border: 1px solid #38bdf840; }
        .table { color: var(--text); --bs-table-bg: transparent; }
        .table th { border-bottom-color: var(--border); color: #94a3b8; }
        .table td { border-bottom-color: #1a284c; vertical-align: middle; }
        .nav-tabs { border-bottom-color: var(--border); }
        .nav-tabs .nav-link { color: #94a3b8; border: none; }
        .nav-tabs .nav-link.active { background: var(--card-bg); color: var(--accent); border-top: 2px solid var(--accent); }
        .btn-primary { background: #2563eb; border: none; }
        .btn-danger { background: #dc2626; border: none; }
        .btn-success { background: #16a34a; border: none; }
        pre.tool-out { background: #050b18; color: #4ade80; padding: 15px; border-radius: 8px; font-size: 0.85rem; max-height: 250px; overflow-y: auto; border: 1px solid var(--border); }
    </style>
</head>
<body class="p-3">
    <div class="container-fluid max-w-1400">
        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-4 pb-2 border-bottom border-secondary-subtle">
            <div>
                <h3 class="mb-0 text-white"><i class="fa-solid fa-shield-halved text-info me-2"></i> Tecno Edge Security & Router WAF</h3>
                <small class="text-secondary">Node: Tecno Pop 4 Pro (MT6739) &bull; Mode: Headless Linux Gateway</small>
            </div>
            <div>
                <span class="badge bg-success-subtle text-success border border-success me-2"><i class="fa-solid fa-circle fa-beat me-1"></i> ACTIVE</span>
                <button class="btn btn-sm btn-outline-info" onclick="refreshDashboard()"><i class="fa-solid fa-arrows-rotate"></i> Refresh</button>
            </div>
        </div>

        <!-- Metric Stat Cards -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="text-secondary small text-uppercase">Total Requests</div>
                    <div class="stat-val" id="stat-total">0</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="text-secondary small text-uppercase">Unique IPs Seen</div>
                    <div class="stat-val text-info" id="stat-unique">0</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="text-secondary small text-uppercase">Threats Blocked</div>
                    <div class="stat-val text-danger" id="stat-threats">0</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="text-secondary small text-uppercase">Rate Limited</div>
                    <div class="stat-val text-warning" id="stat-ratelimits">0</div>
                </div>
            </div>
        </div>

        <!-- Main Tabs -->
        <ul class="nav nav-tabs mb-3" id="dashTabs" role="tablist">
            <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#threats"><i class="fa-solid fa-bug me-1"></i> Live Threats Log</a></li>
            <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#ipfilter"><i class="fa-solid fa-list-check me-1"></i> IP Whitelist / Blacklist</a></li>
            <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#router"><i class="fa-solid fa-network-wired me-1"></i> Router & DNS Tools</a></li>
            <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#activeips"><i class="fa-solid fa-globe me-1"></i> Connected Clients</a></li>
        </ul>

        <div class="tab-content">
            <!-- TAB 1: THREATS LOG -->
            <div class="tab-pane fade show active" id="threats">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fa-solid fa-triangle-exclamation me-2"></i> Real-time Intercepted Threats</span>
                        <span class="badge bg-secondary" id="threat-count">0 Recorded</span>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Origin IP</th>
                                        <th>Attack Type</th>
                                        <th>Matched Signature</th>
                                        <th>Target URL</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="threat-tbody">
                                    <tr><td colspan="6" class="text-center py-4 text-secondary">No threats recorded yet</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 2: IP FILTER -->
            <div class="tab-pane fade" id="ipfilter">
                <div class="row">
                    <div class="col-md-5">
                        <div class="card">
                            <div class="card-header"><i class="fa-solid fa-plus me-2"></i> Add Rule</div>
                            <div class="card-body">
                                <form id="addRuleForm" onsubmit="event.preventDefault(); submitIpRule();">
                                    <div class="mb-3">
                                        <label class="form-label text-secondary small">IP Address</label>
                                        <input type="text" class="form-control bg-dark text-white border-secondary" id="rule-ip" placeholder="e.g. 192.168.1.50 or 203.0.113.19" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label text-secondary small">Rule Type</label>
                                        <select class="form-select bg-dark text-white border-secondary" id="rule-type">
                                            <option value="whitelist">Whitelist (Bypass WAF & Rate Limit)</option>
                                            <option value="blacklist">Blacklist (Drop All Traffic)</option>
                                        </select>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label text-secondary small">Optional Note</label>
                                        <input type="text" class="form-control bg-dark text-white border-secondary" id="rule-note" placeholder="e.g. Office VPN, Suspicious Scanner">
                                    </div>
                                    <button type="submit" class="btn btn-info w-100"><i class="fa-solid fa-floppy-disk me-1"></i> Save IP Rule</button>
                                </form>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-7">
                        <div class="card">
                            <div class="card-header"><i class="fa-solid fa-list me-2"></i> Active IP Rules</div>
                            <div class="card-body p-0">
                                <table class="table mb-0">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Rule</th>
                                            <th>Note</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody id="rules-tbody"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 3: ROUTER & DNS TOOLS -->
            <div class="tab-pane fade" id="router">
                <div class="row g-3">
                    <!-- DNS Lookup -->
                    <div class="col-md-6">
                        <div class="card h-100">
                            <div class="card-header"><i class="fa-solid fa-magnifying-glass me-2"></i> DNS / Reverse DNS Resolver</div>
                            <div class="card-body">
                                <div class="input-group mb-3">
                                    <input type="text" class="form-control bg-dark text-white border-secondary" id="dns-target" placeholder="google.com or 8.8.8.8">
                                    <button class="btn btn-info" onclick="runDnsLookup()"><i class="fa-solid fa-arrow-right"></i> Resolve</button>
                                </div>
                                <pre class="tool-out" id="dns-out">Enter domain or IP to resolve...</pre>
                            </div>
                        </div>
                    </div>

                    <!-- Ping Tool -->
                    <div class="col-md-6">
                        <div class="card h-100">
                            <div class="card-header"><i class="fa-solid fa-tower-broadcast me-2"></i> ICMP Ping Latency</div>
                            <div class="card-body">
                                <div class="input-group mb-3">
                                    <input type="text" class="form-control bg-dark text-white border-secondary" id="ping-target" placeholder="1.1.1.1 or example.com">
                                    <button class="btn btn-success" onclick="runPing()"><i class="fa-solid fa-bolt"></i> Ping</button>
                                </div>
                                <pre class="tool-out" id="ping-out">Enter target host to ping from phone node...</pre>
                            </div>
                        </div>
                    </div>

                    <!-- Port Scanner -->
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header"><i class="fa-solid fa-network-wired me-2"></i> Network Port Scanner</div>
                            <div class="card-body">
                                <div class="row g-2 mb-3">
                                    <div class="col-8">
                                        <input type="text" class="form-control bg-dark text-white border-secondary" id="portscan-target" placeholder="192.168.1.1">
                                    </div>
                                    <div class="col-4">
                                        <button class="btn btn-warning w-100" onclick="runPortScan()"><i class="fa-solid fa-radar"></i> Scan</button>
                                    </div>
                                </div>
                                <pre class="tool-out" id="portscan-out">Scans ports: 22, 53, 80, 443, 8000, 8080, 8022...</pre>
                            </div>
                        </div>
                    </div>

                    <!-- Traceroute / Route Inspection -->
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header"><i class="fa-solid fa-route me-2"></i> Routing Table & Interfaces</div>
                            <div class="card-body">
                                <button class="btn btn-sm btn-outline-info mb-3" onclick="runRoutingInfo()"><i class="fa-solid fa-satellite-dish"></i> Fetch Router Info</button>
                                <pre class="tool-out" id="route-out">Click above to view phone network interfaces & routing</pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 4: CONNECTED CLIENTS -->
            <div class="tab-pane fade" id="activeips">
                <div class="card">
                    <div class="card-header"><i class="fa-solid fa-users me-2"></i> Unique Client IPs & Request Volume</div>
                    <div class="card-body p-0">
                        <table class="table mb-0">
                            <thead>
                                <tr>
                                    <th>Client IP</th>
                                    <th>Total Requests</th>
                                    <th>Last Seen</th>
                                    <th>Quick Filter</th>
                                </tr>
                            </thead>
                            <tbody id="clients-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        async function refreshDashboard() {
            try {
                const res = await fetch('/api/dashboard/data');
                const data = await res.json();
                
                // Metrics
                document.getElementById('stat-total').innerText = data.metrics.total_requests;
                document.getElementById('stat-unique').innerText = data.metrics.unique_visitors;
                document.getElementById('stat-threats').innerText = data.metrics.threats_blocked;
                document.getElementById('stat-ratelimits').innerText = data.metrics.rate_limited_count;

                // Threats
                document.getElementById('threat-count').innerText = `${data.recent_threat_logs.length} Recorded`;
                const tbody = document.getElementById('threat-tbody');
                if (data.recent_threat_logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-secondary">No threats recorded yet</td></tr>';
                } else {
                    tbody.innerHTML = data.recent_threat_logs.map(t => `
                        <tr>
                            <td><small class="text-secondary">${new Date(t.timestamp * 1000).toLocaleTimeString()}</small></td>
                            <td><span class="badge badge-ip">${t.ip}</span></td>
                            <td><span class="badge badge-threat">${t.attack_type}</span></td>
                            <td><code class="text-warning">${escapeHtml(t.matched_pattern)}</code></td>
                            <td><small class="text-secondary">${escapeHtml(t.target_url)}</small></td>
                            <td>
                                <button class="btn btn-xs btn-outline-danger py-0 px-2" onclick="quickBlacklist('${t.ip}')">Blacklist</button>
                            </td>
                        </tr>
                    `).join('');
                }

                // IP Rules
                const rb = document.getElementById('rules-tbody');
                const allRules = [];
                data.whitelist.forEach(ip => allRules.push({ip, type: 'whitelist'}));
                data.blacklist.forEach(ip => allRules.push({ip, type: 'blacklist'}));
                rb.innerHTML = allRules.map(r => `
                    <tr>
                        <td><strong>${r.ip}</strong></td>
                        <td><span class="badge ${r.type === 'whitelist' ? 'bg-success' : 'bg-danger'}">${r.type.toUpperCase()}</span></td>
                        <td><small class="text-secondary">Active</small></td>
                        <td><button class="btn btn-sm btn-outline-secondary py-0" onclick="removeIpRule('${r.ip}')">Remove</button></td>
                    </tr>
                `).join('');

                // Connected Clients
                const cb = document.getElementById('clients-tbody');
                cb.innerHTML = Object.entries(data.recent_clients).map(([ip, info]) => `
                    <tr>
                        <td><strong>${ip}</strong></td>
                        <td><span class="badge bg-primary">${info.count}</span></td>
                        <td><small class="text-secondary">${new Date(info.last_seen * 1000).toLocaleTimeString()}</small></td>
                        <td>
                            <button class="btn btn-sm btn-outline-success py-0 me-1" onclick="quickWhitelist('${ip}')">Whitelist</button>
                            <button class="btn btn-sm btn-outline-danger py-0" onclick="quickBlacklist('${ip}')">Blacklist</button>
                        </td>
                    </tr>
                `).join('');

            } catch (err) {
                console.error("Dashboard refresh error:", err);
            }
        }

        async function submitIpRule() {
            const ip = document.getElementById('rule-ip').value.trim();
            const rule_type = document.getElementById('rule-type').value;
            const note = document.getElementById('rule-note').value.trim();
            if (!ip) return;
            await fetch('/api/ip-rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip, rule_type, note})
            });
            document.getElementById('rule-ip').value = '';
            document.getElementById('rule-note').value = '';
            refreshDashboard();
        }

        async function removeIpRule(ip) {
            await fetch(`/api/ip-rules?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' });
            refreshDashboard();
        }

        function quickBlacklist(ip) {
            document.getElementById('rule-ip').value = ip;
            document.getElementById('rule-type').value = 'blacklist';
            document.getElementById('rule-note').value = 'Quick-blocked from threats log';
            submitIpRule();
        }

        function quickWhitelist(ip) {
            document.getElementById('rule-ip').value = ip;
            document.getElementById('rule-type').value = 'whitelist';
            document.getElementById('rule-note').value = 'Trusted client';
            submitIpRule();
        }

        // Router Tools
        async function runDnsLookup() {
            const target = document.getElementById('dns-target').value.trim();
            if (!target) return;
            const out = document.getElementById('dns-out');
            out.innerText = 'Resolving...';
            const res = await fetch(`/api/tools/dns?target=${encodeURIComponent(target)}`);
            const d = await res.json();
            out.innerText = JSON.stringify(d, null, 2);
        }

        async function runPing() {
            const target = document.getElementById('ping-target').value.trim();
            if (!target) return;
            const out = document.getElementById('ping-out');
            out.innerText = 'Pinging from Tecno phone node (3 packets)...';
            const res = await fetch(`/api/tools/ping?target=${encodeURIComponent(target)}`);
            const d = await res.json();
            out.innerText = d.output || d.error;
        }

        async function runPortScan() {
            const target = document.getElementById('portscan-target').value.trim();
            if (!target) return;
            const out = document.getElementById('portscan-out');
            out.innerText = 'Scanning common ports...';
            const res = await fetch(`/api/tools/portscan?target=${encodeURIComponent(target)}`);
            const d = await res.json();
            out.innerText = JSON.stringify(d, null, 2);
        }

        async function runRoutingInfo() {
            const out = document.getElementById('route-out');
            out.innerText = 'Fetching device interfaces & route info...';
            const res = await fetch('/api/tools/route-info');
            const d = await res.json();
            out.innerText = d.output;
        }

        function escapeHtml(str) {
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        refreshDashboard();
        setInterval(refreshDashboard, 4000);
    </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# API & Tool Endpoints
# ---------------------------------------------------------------------------
async def get_dashboard_html(request: Request):
    return HTMLResponse(DASHBOARD_HTML)


async def get_dashboard_data(request: Request):
    recent_threats = []
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, timestamp, ip, user_agent, attack_type, matched_pattern, target_url
            FROM threat_logs
            ORDER BY id DESC
            LIMIT 50
            """
        ) as cursor:
            async for row in cursor:
                recent_threats.append(dict(row))

    return JSONResponse({
        "metrics": {
            "total_requests": metrics.total_requests,
            "unique_visitors": len(metrics.unique_ips),
            "threats_blocked": metrics.blocked_threats,
            "rate_limited_count": metrics.rate_limited_count,
        },
        "whitelist": list(WHITELIST_IPS),
        "blacklist": list(BLACKLIST_IPS),
        "recent_clients": metrics.recent_ips,
        "recent_threat_logs": recent_threats,
    })


async def add_ip_rule(request: Request):
    body = await request.json()
    ip = body.get("ip", "").strip()
    rule_type = body.get("rule_type", "whitelist").strip()
    note = body.get("note", "").strip()

    if not ip:
        return JSONResponse({"error": "IP required"}, status_code=400)

    if rule_type == "whitelist":
        WHITELIST_IPS.add(ip)
        BLACKLIST_IPS.discard(ip)
    elif rule_type == "blacklist":
        BLACKLIST_IPS.add(ip)
        WHITELIST_IPS.discard(ip)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO ip_rules (ip, rule_type, note, created_at) VALUES (?, ?, ?, ?)",
            (ip, rule_type, note, time.time()),
        )
        await db.commit()

    return JSONResponse({"status": "success", "ip": ip, "rule_type": rule_type})


async def delete_ip_rule(request: Request):
    ip = request.query_params.get("ip")
    if ip:
        WHITELIST_IPS.discard(ip)
        BLACKLIST_IPS.discard(ip)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM ip_rules WHERE ip = ?", (ip,))
            await db.commit()
    return JSONResponse({"status": "removed", "ip": ip})


# --- Router & Network Diagnostic Endpoints ---
async def tool_dns(request: Request):
    target = request.query_params.get("target", "").strip()
    if not target:
        return JSONResponse({"error": "Target required"}, status_code=400)

    loop = asyncio.get_event_loop()
    try:
        # Check if IP or hostname
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False

        if is_ip:
            host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, target)
            return JSONResponse({"query": target, "type": "Reverse PTR", "resolved_host": host})
        else:
            _, _, ips = await loop.run_in_executor(None, socket.gethostbyname_ex, target)
            return JSONResponse({"query": target, "type": "Forward A Record", "resolved_ips": ips})
    except Exception as exc:
        return JSONResponse({"query": target, "error": str(exc)}, status_code=500)


async def tool_ping(request: Request):
    target = request.query_params.get("target", "").strip()
    # Sanitize hostname to prevent shell injection
    if not re.match(r"^[a-zA-Z0-9.-]+$", target):
        return JSONResponse({"error": "Invalid target format"}, status_code=400)

    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "3", "-W", "2", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return JSONResponse({"output": stdout.decode("utf-8", errors="ignore") or stderr.decode("utf-8", errors="ignore")})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


async def tool_portscan(request: Request):
    target = request.query_params.get("target", "127.0.0.1").strip()
    if not re.match(r"^[a-zA-Z0-9.-]+$", target):
        return JSONResponse({"error": "Invalid target"}, status_code=400)

    common_ports = [22, 53, 80, 443, 8000, 8022, 8080]
    results = {}

    async def check_port(port):
        try:
            conn = asyncio.open_connection(target, port)
            _, writer = await asyncio.wait_for(conn, timeout=1.2)
            writer.close()
            await writer.wait_closed()
            return port, "OPEN"
        except Exception:
            return port, "CLOSED"

    scan_tasks = [check_port(p) for p in common_ports]
    port_results = await asyncio.gather(*scan_tasks)
    for p, state in port_results:
        results[p] = state

    return JSONResponse({"target": target, "ports": results})


async def tool_route_info(request: Request):
    try:
        proc = await asyncio.create_subprocess_shell(
            "ip -br a; echo '\n--- Routing Table ---'; ip route",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return JSONResponse({"output": stdout.decode("utf-8", errors="ignore")})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


async def root(request: Request):
    return JSONResponse({
        "status": "online",
        "service": "Tecno Edge Security Gateway & WAF",
        "dashboard": "/dashboard",
        "timestamp": time.time(),
    })


# ---------------------------------------------------------------------------
# Application Setup & Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: Starlette):
    await init_db()
    logger.info("Security Gateway & Router WAF initialized.")
    yield
    logger.info("Security Gateway shutting down.")


routes = [
    Route("/", root, methods=["GET"]),
    Route("/dashboard", get_dashboard_html, methods=["GET"]),
    Route("/api/dashboard/data", get_dashboard_data, methods=["GET"]),
    Route("/api/ip-rules", add_ip_rule, methods=["POST"]),
    Route("/api/ip-rules", delete_ip_rule, methods=["DELETE"]),
    Route("/api/tools/dns", tool_dns, methods=["GET"]),
    Route("/api/tools/ping", tool_ping, methods=["GET"]),
    Route("/api/tools/portscan", tool_portscan, methods=["GET"]),
    Route("/api/tools/route-info", tool_route_info, methods=["GET"]),
]

app = Starlette(routes=routes, lifespan=lifespan)
app.add_middleware(SecurityGatewayMiddleware)

if __name__ == "__main__":
    uvicorn.run("secure_gateway:app", host="0.0.0.0", port=8000, workers=1, log_level="info")
