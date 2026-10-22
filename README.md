RTScanner v3.2.0 — README

Elite Red Team Web Security Assessment Tool
Author: Dwi Joko Purwanto

---

⚠️ LEGAL DISCLAIMER

Tool ini HANYA boleh digunakan untuk authorized security assessment terhadap sistem yang Anda miliki atau memiliki izin tertulis eksplisit dari pemiliknya. Penggunaan tanpa izin adalah ilegal dan dapat melanggar hukum pidana (UU ITE di Indonesia, CFAA di AS, dan regulasi serupa di negara lain).

Dengan menggunakan tool ini, Anda menyetujui bahwa Anda bertanggung jawab penuh atas segala tindakan Anda. Penulis tidak bertanggung jawab atas penyalahgunaan.

---

📖 Deskripsi

RTScanner adalah framework penetration testing web berfitur lengkap yang dirancang untuk professional red team operations. Menggabungkan reconnaissance, vulnerability discovery, exploitation verification, dan reporting dalam satu tool async berperforma tinggi.

Fitur Utama v3.2.0

# Fitur Deskripsi
1 SQLite State & Resume Scan dapat dilanjutkan setelah crash/rate-limit
2 Deep Endpoint Discovery Auto-discovery via sitemap, JS bundles, Swagger/OpenAPI
3 Interactive Shell Post-exploitation REPL untuk RCE/SQLi/LFI terkonfirmasi
4 Wordlist & Plugin Ecosystem Load wordlist eksternal (SecLists) & plugin Python
5 Advanced Evasion TLS/JA3/JA4 impersonation (curl_cffi) + HTTP/2 fingerprint spoof

Fitur Carry-Over

· Proxy Chaining — SOCKS4/5, Tor, SSH dynamic tunnel
· WAF Evasion — Payload mutation (URL-encode, case-swap, null-byte, overlong UTF-8)
· Smart Session — Playwright-based SPA login, CSRF harvesting, auto-refresh
· Safe PoC Verification — Konfirmasi finding dengan probe aman (reduksi false positive)
· Gaussian Jitter — Delay randomization berbasis distribusi normal
· Anti-Forensic Cleanup — Auto-hapus artifacts saat exit
· OOB Blind Detection — Interactsh-compatible server
· 15+ Vulnerability Classes — SQLi, XSS, LFI, RFI, SSRF, SSTI, CMDi, NoSQLi, LDAP, CRLF, Open Redirect, XXE, CORS, JWT, GraphQL, dll.
· Multi-Format Reports — HTML, JSON, SARIF 2.1.0
· CVE Correlation — NVD API lookup (optional live mode)
· Async Concurrency — httpx-based parallel scanning

---

🔧 Instalasi

Requirement Minimum

· Python 3.9+
· pip

Core Dependencies

```bash
pip install httpx requests beautifulsoup4 urllib3
```

Optional Dependencies (fitur lanjutan)

```bash
# SOCKS proxy support
pip install PySocks

# SSH tunneling
pip install paramiko sshtunnel

# Smart session (SPA/CSRF)
pip install playwright
playwright install chromium

# TLS/JA3/JA4 impersonation
pip install curl_cffi

# HTTP/2 fingerprint spoofing
pip install h2
```

Verifikasi Instalasi

```bash
python scanner.py --help
```

---

🚀 Quick Start

1. Basic Scan (minimum)

```bash
python scanner.py \
  -u https://target.example.com \
  --authorized \
  --authorization-ref "CONTRACT-2024-1234"
```

2. Full Scan dengan Deep Discovery + Evasion

```bash
python scanner.py \
  -u https://target.example.com \
  --authorized \
  --authorization-ref "PENTEST-2024-001" \
  --evade \
  --verify-poc \
  --state-db scan.db \
  --impersonate chrome124 \
  --http2-spoof \
  --format html,json,sarif
```

3. Authorized Scan dengan Authentication

```bash
python scanner.py \
  -u https://app.example.com \
  --authorized \
  --authorization-ref "AUTH-2024-XYZ" \
  --auth-form-url https://app.example.com/login \
  --auth-user admin \
  --auth-pass 'P@ssw0rd!' \
  --session-keepalive 300
```

4. Scan melalui Proxy Chain / Tor

```bash
python scanner.py \
  -u https://target.example.com \
  --authorized \
  --proxy-chain "socks5://127.0.0.1:1080>tor"
```

5. Resume Scan yang Terhenti

```bash
python scanner.py \
  -u https://target.example.com \
  --authorized \
  --state-db scan.db \
  --resume
```

---

📋 Parameter Reference

Required Arguments

Flag Deskripsi
-u, --url Target URL (wajib)
--authorized Konfirmasi otorisasi (wajib)
--authorization-ref Referensi dokumen otorisasi (sangat direkomendasikan)

Target & Scope

Flag Default Deskripsi
--scope FILE — File berisi in-scope host/CIDR/regex (1 per baris)
--max-links N 40 Jumlah maksimum URL untuk crawl
--operator NAME $USER Nama operator (muncul di report)
--delay SEC 0.0 Delay antar request (sync)

Proxy & Tunneling

Flag Deskripsi
--proxy URL Single HTTP proxy (legacy)
--proxy-chain SPEC Chain: socks5://h:1080>http://h2:8080>tor
--ssh-tunnel URI ssh://user:pass@host:22 — spawn SOCKS5 otomatis

Evasion

Flag Deskripsi
--evade Aktifkan WAF evasion (mutasi payload standar)
--evade-aggressive Mutator agresif (comment, null-byte, overlong UTF-8)
--impersonate PROFILE chrome120/chrome124/firefox120/safari17_0/edge101
--http2-spoof Probe server HTTP/2 SETTINGS fingerprint

Authentication

Flag Deskripsi
--auth-cookie STR Raw Cookie header
--auth-bearer TOKEN Bearer token
--auth-basic USER:PASS HTTP Basic auth
--auth-form-url URL Login form URL (aktifkan SmartSession)
--auth-user STR / --auth-pass STR Kredensial form
--auth-user-field NAME Nama field username (default: username)
--auth-pass-field NAME Nama field password (default: password)
--session-keepalive SEC Interval refresh session (default: 300)
--no-browser Disable Playwright

Detection & Verification

Flag Deskripsi
--verify-poc Jalankan safe PoC verification
--oob-server URL Interactsh-compatible server
--oob-token TOKEN OOB auth token
--oob-timeout SEC Poll timeout (default: 15)
--oob-interval SEC Poll interval (default: 2.0)
--templates DIR Directory JSON templates

Jitter & Stealth

Flag Default Deskripsi
--jitter-base SEC 0.3 Mean delay (Gaussian)
--jitter-sigma SEC 0.25 Standard deviation
--jitter-max SEC 5.0 Maximum delay
--anti-forensic — Hapus artifacts saat exit
--keep-reports — Exempt reports dari cleanup

State & Resume (v3.2.0)

Flag Deskripsi
--state-db PATH Path SQLite state DB
--resume Resume scan dari --state-db

Wordlist & Plugins (v3.2.0)

Flag Deskripsi
--param-wordlist FILE File berisi nama parameter (1 per baris)
--payload-dir DIR Directory berisi sqli.txt, xss.txt, lfi.txt, dst.
--plugin-dir DIR Directory plugin Python

Post-Exploitation (v3.2.0)

Flag Deskripsi
--interactive-shell Drop into REPL setelah konfirmasi RCE/SQLi/LFI
--os-cmd CMD Single command via RCE terkonfirmasi

Reporting

Flag Default Deskripsi
--format LIST html,json Format output: html,json,sarif
--cve-cache PATH cve_cache.json Cache CVE lokal
--cve-live — Query NVD API live (slow, rate-limited)
--concurrency N 20 Async worker count

---

🎯 Vulnerability Coverage

Tool ini mendeteksi 15+ kelas vulnerability:

Vulnerability Detection Method
SQL Injection Error-based + time-based + PoC verify
Reflected XSS Payload reflection detection
Local File Inclusion Path traversal + PHP wrappers
Remote File Inclusion OOB callback
SSRF OOB + cloud metadata probe
SSTI Template expression evaluation
Command Injection Time-based + PoC verify
NoSQL Injection Mongo operator heuristics
Open Redirect Location header manipulation
CRLF Injection Response header injection
LDAP Injection Error signature detection
XXE External entity processing
GraphQL Introspection Schema exposure
CORS Misconfiguration Origin reflection test
JWT Weakness alg=none detection
Sensitive File Exposure .env, .git/HEAD, backups, phpinfo
Secret Leakage in JS AWS/GCP/Stripe/Slack/private keys

---

🔌 Plugin Development

Buat file .py di directory --plugin-dir:

```python
# my_plugin.py
from typing import Optional

class Plugin:
    name = "My Custom Check"

    async def check(self, client, url: str, param: str) -> Optional[object]:
        """
        Return a Finding object if vulnerability detected, else None.
        """
        r = await client.get(f"{url}?{param}=test")
        if r and "custom-signature" in r.text:
            from scanner import Finding, SEVERITY_MAP
            return Finding(
                vuln_type="Custom Vuln",
                endpoint=f"{url}?{param}=test",
                severity="High",
                cvss_score=SEVERITY_MAP["High"]["cvss"],
                details="Custom detection triggered.",
                evidence="custom-signature",
                cwe_id="CWE-XXX",
                owasp_category="A0X:2021",
                remediation="Fix it."
            )
        return None
```

Jalankan dengan:

```bash
python scanner.py -u https://target --authorized --plugin-dir ./plugins
```

---

📝 Template System

Template JSON untuk custom checks:

```json
{
  "id": "cve-2024-9999",
  "name": "Example CVE",
  "severity": "Critical",
  "method": "GET",
  "path": "/vulnerable/endpoint",
  "payloads": [
    {"name": "id", "value": "{{OOB}}", "in": "query"}
  ],
  "matchers": [
    {"type": "status", "value": 200},
    {"type": "regex", "value": "error signature"},
    {"type": "oob"}
  ],
  "cwe": "CWE-89",
  "owasp": "A03:2021",
  "cve": ["CVE-2024-9999"],
  "remediation": "Apply vendor patch."
}
```

Matcher types: status, word, regex, oob

---

📊 Output Reports

HTML Report

Human-readable report dengan executive summary, severity breakdown, dan detailed findings.

JSON Report

Full structured data via asdict(ScanReport) — ideal untuk automation/parsing.

SARIF Report

Format SARIF 2.1.0 kompatibel dengan GitHub Advanced Security, Azure DevOps, dan tools SAST lainnya.

Contoh:

```bash
python scanner.py ... --format html,json,sarif
# Menghasilkan:
#   report_domain_20240115_103045.html
#   report_domain_20240115_103045.json
#   report_domain_20240115_103045.sarif
```

---

🎓 Interactive Shell (Post-Exploitation)

Setelah finding Critical/High terkonfirmasi (RCE/SQLi/LFI), tool dapat membuka REPL:

```bash
python scanner.py ... --interactive-shell
```

Contoh session:

```
shell> whoami
www-data
shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
shell> read /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
shell> sql SELECT user(), database()
admin@localhost | app_db
shell> exit
```

⚠️ Catatan: Command dibatasi pada SAFE_COMMANDS. Semua command & output di-log ke session_log.

---

🧪 Contoh Workflow Pentest Lengkap

```bash
# 1. Recon + fingerprint (dijalankan otomatis)
python scanner.py \
  -u https://client-app.com \
  --authorized \
  --authorization-ref "PT-2024-CLIENT-01" \
  --scope scope.txt \
  --operator "dwi" \
  --state-db client_app.db \
  --evade \
  --verify-poc \
  --oob-server https://oob.myserver.com \
  --oob-token $OOB_TOKEN \
  --impersonate chrome124 \
  --http2-spoof \
  --format html,json,sarif \
  -v

# 2. Jika scan terhenti, resume:
python scanner.py \
  -u https://client-app.com \
  --authorized \
  --state-db client_app.db \
  --resume \
  --format html,json
```

---

🏗️ Arsitektur

```
scanner.py
├── Config & Data Models
│   ├── Finding, ScanReport
│   └── SEVERITY_MAP
├── [1] ScanStateDB (SQLite persistence)
├── [A] ProxyChain / SSHTunnel
├── [5] ImpersonatingClient (curl_cffi) + Http2SpoofClient
├── [B] EvasionEngine (WAF bypass)
├── [E] Jitter (Gaussian delay)
├── [C] SmartSession (Playwright + CSRF)
├── AuthConfig
├── StealthClient (sync) / AsyncClient (async)
├── OOBClient (blind detection)
├── TemplateLoader
├── Scope validation (wildcard/CIDR/regex)
├── [2] EndpointDiscoverer
│   ├── SitemapParser
│   ├── JSParser (endpoints + secrets)
│   └── SwaggerParser
├── [3] InteractiveShell
├── [4] WordlistLoader / PluginManager
├── Recon (WAF detect + fingerprint)
├── CVELookup (NVD API)
├── [D] PoC verification (SQLi/LFI/CMDi/SSRF)
├── Vuln Checks (15+ tests)
├── Orchestration (crawl + scan_parameters_async)
├── Reporters (HTML/JSON/SARIF)
└── CLI (argparse)
```

---

🐛 Troubleshooting

Problem Solution
httpx not installed pip install httpx
Playwright not installed pip install playwright && playwright install chromium
curl_cffi not installed pip install curl_cffi (untuk --impersonate)
h2 library missing pip install h2 (untuk --http2-spoof)
sshtunnel required pip install sshtunnel paramiko
PySocks not installed pip install PySocks
Rate limited (429) Naikkan --jitter-base, aktifkan --evade
False positive tinggi Gunakan --verify-poc
Scan terlalu lambat Turunkan --concurrency, aktifkan --resume
Session expired Naikkan --session-keepalive atau gunakan Playwright

---

📌 Best Practices

1. Selalu gunakan --scope untuk membatasi target ke domain in-scope.
2. Simpan --state-db untuk scan yang panjang — memungkinkan resume.
3. Aktifkan --verify-poc untuk produksi — mengurangi false positive.
4. Gunakan --jitter lebih tinggi saat target punya WAF aktif.
5. Gunakan OOB server (Interactsh/Burp Collaborator) untuk deteksi blind vuln.
6. Report dengan --format html,json,sarif untuk kompatibilitas maksimal.
7. Selalu simpan --authorization-ref untuk audit trail.
8. Jangan gunakan --interactive-shell / --os-cmd tanpa izin eksplisit untuk eksploitasi.

---

📄 Lisensi & Etika

Tool ini disediakan AS-IS untuk keperluan edukasi dan authorized penetration testing. Penggunaan tanpa izin melanggar hukum.

Wajib:

· ✅ Miliki izin tertulis sebelum scanning
· ✅ Hormati scope yang disepakati
· ✅ Laporkan findings secara bertanggung jawab
· ✅ Ikuti responsible disclosure

Dilarang:

· ❌ Scan sistem tanpa izin
· ❌ Eksploitasi data pengguna
· ❌ Disrupt production services

---

👤 Author

Dwi Joko Purwanto

---

RTScanner v3.2.0 — Authorized Security Assessment Only