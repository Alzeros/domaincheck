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
    # ── Verisign ──
    "com":  "https://rdap.verisign.com/com/v1/domain/",
    "net":  "https://rdap.verisign.com/net/v1/domain/",
    "cc":   "https://tld-rdap.verisign.com/cc/v1/domain/",
    # ── Public Interest Registry ──
    "org":  "https://rdap.publicinterestregistry.org/rdap/domain/",
    # ── Identity Digital（原 Donuts / Afilias）──
    "io":     "https://rdap.identitydigital.services/rdap/domain/",
    "me":     "https://rdap.identitydigital.services/rdap/domain/",
    "info":   "https://rdap.identitydigital.services/rdap/domain/",
    "agency": "https://rdap.identitydigital.services/rdap/domain/",
    "digital":"https://rdap.identitydigital.services/rdap/domain/",
    "email":  "https://rdap.identitydigital.services/rdap/domain/",
    "pizza":  "https://rdap.identitydigital.services/rdap/domain/",
    # ── Google Registry ──
    "app": "https://pubapi.registry.google/rdap/domain/",
    "dev": "https://pubapi.registry.google/rdap/domain/",
    # ── Radix：以下 10 个 TLD 共用一个 host，限流是 host 级的 ──
    #    （RDAP_HOST_RATE 里按 host 限速，冷却也按 host 生效）
    "tech":   "https://rdap.radix.host/rdap/domain/",
    "site":   "https://rdap.radix.host/rdap/domain/",
    "online": "https://rdap.radix.host/rdap/domain/",
    "store":  "https://rdap.radix.host/rdap/domain/",
    "space":  "https://rdap.radix.host/rdap/domain/",
    "website":"https://rdap.radix.host/rdap/domain/",
    "pw":     "https://rdap.radix.host/rdap/domain/",
    "press":  "https://rdap.radix.host/rdap/domain/",
    "host":   "https://rdap.radix.host/rdap/domain/",
    "fun":    "https://rdap.radix.host/rdap/domain/",
    # ── CentralNic ──
    "xyz":     "https://rdap.centralnic.com/xyz/domain/",
    "fm":      "https://rdap.centralnic.com/fm/domain/",
    "art":     "https://rdap.centralnic.com/art/domain/",
    "best":    "https://rdap.centralnic.com/best/domain/",
    "icu":     "https://rdap.centralnic.com/icu/domain/",
    "lol":     "https://rdap.centralnic.com/lol/domain/",
    "monster": "https://rdap.centralnic.com/monster/domain/",
    "sbs":     "https://rdap.centralnic.com/sbs/domain/",
    # ── 其他注册局 ──
    "top":     "https://rdap.zdnsgtld.com/top/domain/",
    "vip":     "https://rdap.nic.vip/domain/",
    "biz":     "https://rdap.nic.biz/domain/",
    "cv":      "https://rdap.nic.cv/domain/",
    "link":    "https://rdap.uniregistry.net/rdap/domain/",
    "one":     "https://rdap.nic.one/domain/",
    "tv":      "https://rdap.nic.tv/domain/",
    "buzz":    "https://rdap.nic.buzz/domain/",
    "club":    "https://rdap.nic.club/domain/",
    "design":  "https://rdap.nic.design/domain/",
    "wiki":    "https://rdap.nic.wiki/domain/",
    "work":    "https://rdap.nic.work/domain/",
    "review":  "https://rdap.nic.review/domain/",
    "science": "https://rdap.nic.science/domain/",
    "moe":     "https://rdap.nic.moe/domain/",
    "beer":    "https://rdap.nic.beer/domain/",
    "gift":    "https://rdap.registry.gift/rdap/domain/",
    "click":   "https://rdap.registry.click/rdap/domain/",
    "cloud":   "https://rdap.registry.cloud/rdap/domain/",
    "ly":      "https://rdap.nic.ly/domain/",
    "to":      "https://rdap.tonicregistry.to/rdap/domain/",
    "bank":    "https://rdap.nic.bank/domain/",
    "nl":      "https://rdap.sidn.nl/domain/",
    "fr":      "https://rdap.nic.fr/domain/",
    "uk":      "https://rdap.nominet.uk/uk/domain/",
    "br":      "https://rdap.registro.br/domain/",
}

# ── 刻意不放进 RDAP_ENDPOINTS 的 TLD ─────────────────────
# .co —— rdap.co/?name= 对任何域名都返回 200（含根本不存在的域名），
#        会把任意候选都误判成「已注册」，因此只走 whois。
# .cn —— CNNIC 无 RDAP 服务，且 rdap.cnnic.net.cn 的域名在本机解析失败，
#        只走 whois。
# .de —— DENIC 至今无 RDAP，只走 whois.denic.de。

# ── 已知不支持 RDAP 的 TLD，跳过 RDAP 直接走 Whois ──────
NO_RDAP_TLDS = {"de", "jp", "it", "es", "ru", "au", "pl", "be", "at", "ch", "se", "dk", "fi", "no"}

# ── 注册局限速 ────────────────────────────────────────────
# 此前 .tech 走 whois 优先，但实测从本机连续查询约 20 次后 whois.nic.tech
# 开始返回空回复（被限流），反而不如 RDAP 稳定；且 Radix 一族的 RDAP 限流
# 是 host 级的（tech/site/online/… 共用 rdap.radix.host），
# 改由 RDAP_HOST_RATE 按 host 统一限速，比按 TLD 限速更准确。
# Radix 的 whois 回复格式仍被 check_whois_socket 兼容，作为 RDAP 失败时的兜底。
WHOIS_FIRST_TLDS: set[str] = set()

# whois.nic.cv 无响应，.cv 只能走 RDAP
NO_WHOIS_TLDS = {"cv"}

# whois 限速（按 TLD 维度，单位：次/秒）
TLD_QUERY_RATE: dict[str, float] = {
    "tech": 1.0,   # whois.nic.tech 约 90 次/分钟后限流
    "cv": 3.0,     # rdap.nic.cv 实测 3 次/秒稳定
}
DEFAULT_QUERY_RATE = 10.0

# RDAP 限速（按 host 维度，单位：次/秒）。
# 关键点：多个 TLD 可能共用同一个 RDAP host——Radix 的 10 个后缀就共用
# rdap.radix.host，CentralNic 的 8 个后缀共用 rdap.centralnic.com。
# 限流是 host 级的，若按 TLD 各自限速，各后缀一起满速查询会把 host 打挂，
# 因此这里按 host 建共享令牌桶。
RDAP_HOST_RATE: dict[str, float] = {
    "rdap.radix.host": 0.9,      # 实测整分钟约 58 次后返回 429(Retry-After: 60)，取 54 次/分
    "rdap.sidn.nl": 1.0,          # 实测突发即触发 429
    "rdap.centralnic.com": 4.0,   # 实测约 6 次/秒
    "rdap.identitydigital.services": 5.0,
    "rdap.verisign.com": 10.0,
    "tld-rdap.verisign.com": 10.0,
    "rdap.registro.br": 3.0,
}
DEFAULT_RDAP_RATE = 5.0


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


def _limiter(key: str, kind: str) -> _RateLimiter:
    """取共享限速器。kind='rdap' 时 key 是 host，其余情况 key 是 TLD。"""
    k = (key, kind)
    if k not in _limiters:
        if kind == "rdap":
            rate = RDAP_HOST_RATE.get(key, DEFAULT_RDAP_RATE)
        else:
            rate = TLD_QUERY_RATE.get(key, DEFAULT_QUERY_RATE)
        _limiters[k] = _RateLimiter(rate)
    return _limiters[k]



def rdap_url(tld: str, domain: str) -> Optional[str]:
    base = RDAP_ENDPOINTS.get(tld)
    if base is None:
        return None
    return base + domain


def _rdap_host(tld: str) -> str:
    """取该 TLD 的 RDAP host，用于按 host 维度限流与冷却。

    Radix、CentralNic 等注册商把多个 TLD 放在同一个 host 上，
    限流与冷却都是 host 级的，按 TLD 分别处理会导致该 host 上所有后缀一起被限。"""
    base = RDAP_ENDPOINTS.get(tld)
    if not base:
        return ""
    return base.split("//", 1)[-1].split("/", 1)[0]


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
    host = _rdap_host(tld)
    if _rdap_cooldown.get(host, 0) > time.monotonic():
        return None
    await _limiter(host, "rdap").acquire()
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
                # 冷却整个 host：该 host 上的所有 TLD 一起退避
                _rdap_cooldown[host] = time.monotonic() + min(max(retry_after, 15.0), 300.0)
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
        # python-whois 在域名未注册时抛 WhoisDomainNotFoundError（WhoisError 子类），
        # 但各注册局的文案不同，必须覆盖多种措辞，否则会被当成「查询失败」
        # 而误判为不可注册。例如 .cn 的 CNNIC 回复 "No matching record."，
        # .de 的 DENIC 回复 "Status: free"。
        msg = str(e)
        lowered = msg.lower()
        if ("no match for" in lowered
                or "no matching record" in lowered
                or "no matches" in lowered
                or "not found" in lowered
                or "no entries found" in lowered
                or "status: free" in lowered
                or "status: available" in lowered):
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