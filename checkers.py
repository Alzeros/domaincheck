"""域名检测引擎 — RDAP 优先，Whois 兜底，辅以 DNS 预检"""

import asyncio
import socket
import time
from typing import Optional

import aiohttp
import whois

from config import Config


# ── RDAP 端点映射（已知支持 RDAP 的 TLD） ────────────────
RDAP_ENDPOINTS: dict[str, str] = {
    "com":  "https://rdap.verisign.com/com/v1/domain/",
    "net":  "https://rdap.verisign.com/net/v1/domain/",
    "org":  "https://rdap.publicinterestregistry.org/rdap/domain/",
    "io":   "https://rdap.nic.io/domain/",
    "xyz":  "https://rdap.nic.xyz/domain/",
    "cn":   "https://rdap.cnnic.net.cn/domain/",
    "cc":   "https://rdap.nic.cc/domain/",
    "me":   "https://rdap.nic.me/domain/",
    "top":  "https://rdap.nic.top/domain/",
    "vip":  "https://rdap.nic.vip/domain/",
    "app":  "https://rdap.nic.google/domain/",
    "dev":  "https://rdap.nic.google/domain/",
    "co":   "https://rdap.co/?name=",
    "info": "https://rdap.afilias.net/rdap/domain/",
    "biz":  "https://rdap.nic.biz/domain/",
    "cv":   "https://rdap.nic.cv/domain/",
    "tech": "https://rdap.radix.host/rdap/domain/",
}

# ── 已知不支持 RDAP 的 TLD，跳过 RDAP 直接走 Whois ──────
NO_RDAP_TLDS = {"de", "uk", "jp", "fr", "it", "es", "nl", "ru", "br", "au", "pl", "be", "at", "ch", "se", "dk", "fi", "no"}

# ── 注册局限速 ────────────────────────────────────────────
# Radix(.tech) 的 RDAP 约 60 次/分钟后返回 429（Retry-After: 60），
# 但其 whois 服务器更宽松且回复里直接写明是否可注册，因此这些 TLD 优先走 whois。
WHOIS_FIRST_TLDS = {"tech"}

# whois.nic.cv 无响应，.cv 只能走 RDAP
NO_WHOIS_TLDS = {"cv"}

TLD_QUERY_RATE: dict[str, float] = {
    "tech": 1.0,   # whois.nic.tech 约 90 次/分钟后限流
    "cv": 3.0,     # rdap.nic.cv 实测 3 次/秒稳定
}
DEFAULT_QUERY_RATE = 10.0


class _RateLimiter:
    """简单的固定间隔限速器，同一进程内所有扫描共用。"""

    def __init__(self, rate_per_sec: float):
        self._interval = 1.0 / rate_per_sec
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            self._next = now + self._interval


_limiters: dict[tuple[str, str], _RateLimiter] = {}

# RDAP 429 后按 Retry-After 冷却，冷却期内直接走 whois
_rdap_cooldown: dict[str, float] = {}


def _limiter(tld: str, kind: str) -> _RateLimiter:
    key = (tld, kind)
    if key not in _limiters:
        _limiters[key] = _RateLimiter(TLD_QUERY_RATE.get(tld, DEFAULT_QUERY_RATE))
    return _limiters[key]



def rdap_url(tld: str, domain: str) -> Optional[str]:
    base = RDAP_ENDPOINTS.get(tld)
    if base is None:
        return None
    return base + domain


# ── 1. DNS 预检 ──────────────────────────────────────────

async def dns_precheck(domain: str) -> bool:
    """DNS 快速预检。True = 已解析（高概率已注册）。"""
    try:
        await asyncio.get_event_loop().getaddrinfo(
            domain, 80, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        return True
    except (socket.gaierror, OSError):
        return False


# ── 2. RDAP 查询 ─────────────────────────────────────────

async def check_rdap(session: aiohttp.ClientSession, tld: str, domain: str) -> Optional[bool]:
    """RDAP 查询。
   返回 True=已注册, False=可注册, None=查询失败/不支持。"""
    if tld in NO_RDAP_TLDS:
        return None
    url = rdap_url(tld, domain)
    if url is None:
        return None
    if _rdap_cooldown.get(tld, 0) > time.monotonic():
        return None
    await _limiter(tld, "rdap").acquire()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return True
            if resp.status == 404:
                return False
            if resp.status == 429:
                try:
                    retry_after = float(resp.headers.get("Retry-After", "60"))
                except ValueError:
                    retry_after = 60.0
                _rdap_cooldown[tld] = time.monotonic() + min(max(retry_after, 15.0), 300.0)
                return None
            return None
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


# ── 3. Whois（python-whois 库） ──────────────────────────

def check_whois_lib(domain: str) -> Optional[bool]:
    """python-whois 库查询。
   返回 True=已注册, False=可注册, None=无法判断。"""
    try:
        w = whois.whois(domain)
        if w.domain_name is None:
            return False
        if isinstance(w.domain_name, list):
            if len(w.domain_name) == 0:
                return False
        return True
    except whois.WhoisError as e:
        msg = str(e)
        if "No match for" in msg or "NOT FOUND" in msg.upper() or "Status: free" in msg:
            return False
        return None
    except Exception:
        return None


# ── 4. Whois 直接 Socket 查询（针对 DENIC 等特殊服务器） ──

async def check_whois_socket(cfg: Config, domain: str) -> Optional[bool]:
    """直接 TCP 连接 whois 服务器查询（绕过 python-whois 的解析层）。
   针对 whois.denic.de 等特殊格式优化，同时兼容 Radix(.tech) 的回复。"""
    whois_host = f"whois.nic.{cfg.tld}"  # 通用模式
    if cfg.tld == "de":
        whois_host = "whois.denic.de"
    if cfg.tld in NO_WHOIS_TLDS:
        return None

    await _limiter(cfg.tld, "whois").acquire()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(whois_host, 43),
            timeout=cfg.timeout,
        )
        query = f"{domain}\r\n"
        writer.write(query.encode())
        await writer.drain()

        data = await asyncio.wait_for(reader.read(8192), timeout=cfg.timeout)
        writer.close()
        await writer.wait_closed()

        response = data.decode("utf-8", errors="ignore")
        lowered = response.lower()

        # Radix(.tech)：「>>> Domain x.tech is available for registration」
        # 注意先判断 "not available"，它包含 "available" 子串
        if "not available for registration" in lowered:
            return True
        if "available for registration" in lowered:
            return False
        # DENIC 特征
        if "status: free" in lowered:
            return False
        if "no entries found" in lowered or "not found" in lowered or "no match for" in lowered:
            return False
        # 常见注册局：已注册域名都带 "Domain Name:"
        if "domain name:" in lowered:
            return True
        if "domain:" in response and "status:" in response:
            # 有 Domain 和 Status 行 → 大概率已注册
            return True
        # 其他情况保守
        return None
    except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
        return None


# ── 统一检测接口 ──────────────────────────────────────────

async def check_domain(
    cfg: Config,
    domain: str,
    session: aiohttp.ClientSession,
    executor,
) -> tuple[str, bool, dict]:
    """对单个域名执行多级检测。
   返回 (domain, is_available, meta)。
   meta 包含 {'whois_queried': bool, 'rate_limited': bool} 用于统计和自适应限速。"""
    tld = cfg.tld
    meta: dict = {"whois_queried": False, "rate_limited": False}

    # 第一级：DNS 预检（秒级）
    try:
        has_dns = await dns_precheck(domain)
        if has_dns:
            return (domain, False, meta)
    except Exception:
        pass

    # whois 优先的 TLD：直接 socket 查询最快且解析最可靠
    if tld in WHOIS_FIRST_TLDS:
        socket_result = await check_whois_socket(cfg, domain)
        if socket_result is not None:
            meta["whois_queried"] = True
            return (domain, not socket_result, meta)

    # RDAP（不支持 RDAP 的 TLD 自动跳过）
    rdap_result = await check_rdap(session, tld, domain)
    if rdap_result is not None:
        return (domain, not rdap_result, meta)

    # Whois 库
    if tld not in NO_WHOIS_TLDS:
        meta["whois_queried"] = True
        await _limiter(tld, "whois").acquire()
        whois_lib_result = await asyncio.get_event_loop().run_in_executor(
            executor, check_whois_lib, domain
        )
        if whois_lib_result is not None:
            return (domain, not whois_lib_result, meta)

        # 直接 Socket Whois（针对 DENIC 等优化）
        whois_socket_result = await check_whois_socket(cfg, domain)
        if whois_socket_result is not None:
            return (domain, not whois_socket_result, meta)

    # 全部失败 → 标记为 rate_limited + 保守不可注册
    meta["rate_limited"] = True
    return (domain, False, meta)