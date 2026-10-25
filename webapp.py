#!/usr/bin/env python3
"""Domain Checker Web App — FastAPI + SSE 实时推送"""

import asyncio
import hashlib
import json
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

import aiohttp
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import StreamingResponse

from checkers import check_domain
from config import Config
from generators import generate_all
import history

# ── 访问密码 ─────────────────────────────────────────────
DC_PASSWORD = os.environ.get("DC_PASSWORD", "")
_valid_tokens: set[str] = set()


def _check_token(request: Request) -> bool:
    """校验请求中的 token 是否有效。无密码配置时放行。"""
    if not DC_PASSWORD:
        return True  # 未设密码则不校验
    # Header: Authorization: Bearer xxx
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        if auth[7:] in _valid_tokens:
            return True
    # Query: ?token=xxx （EventSource 不支持自定义 header 的备选方案）
    query_token = request.query_params.get("token", "")
    if query_token and query_token in _valid_tokens:
        return True
    return False

# ── 全局状态 ──────────────────────────────────────────────
# scan_id → { queue, domains, results, config, cancelled, ... }
scans: dict[str, dict] = {}
_scan_counter = 0  # 用于生成可读的 scan 编号

LAST_SCAN_FILE = Path("last_scan_result.json")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 被动重启前,把内存里还没归档的扫描抢救进历史,避免成果随进程消失
    for sid, s in scans.items():
        if s.get("finished", False) or s.get("cancelled", False) or s.get("archived", False):
            continue
        s["archived"] = True
        _archive_partial(s, s.get("results", []), "服务重启")
    scans.clear()
    history.init_db()  # 建表(幂等)
    _load_word_config()  # 词表启停/自定义覆盖配置
    yield


app = FastAPI(title="Domain Checker", lifespan=lifespan)

# 公开路由（无需 token）
_PUBLIC_PATHS = {"/", "/auth/check", "/verify"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if DC_PASSWORD and request.url.path not in _PUBLIC_PATHS:
        if not _check_token(request):
            return JSONResponse({"error": "未授权，请先验证密码"}, status_code=401)
    return await call_next(request)


def _archive_partial(scan: dict, results: list, reason: str):
    """把一场没跑完的扫描归档进历史(手动停止/异常中断/重启丢失)。

    后端持有全部已检测结果,所以由后端兜底落库;即使前端已经关掉 SSE
    或服务随后重启,这次扫描的成果也不会丢。
    """
    try:
        available_list = [d for d, ok in results if ok]
        cfg = scan.get("cfg")
        total = scan.get("full_count", len(scan.get("domains", [])))
        asyncio.get_running_loop().create_task(
            history.save_scan(
                query_key=scan.get("query_key", ""),
                tld=cfg.tld if cfg else "",
                mode=scan.get("mode", "brute"),
                params=scan.get("params", {}),
                total=total,
                available=available_list,
                cancelled=True,
                checked=len(results),
            )
        )
        print(
            f"[历史] 扫描{reason},已归档部分结果:"
            f"{len(available_list)} 个可注册 / 已检测 {len(results)} / 候选 {total}"
        )
    except Exception as e:
        print(f"[历史] {reason}归档失败(忽略):{e}")


def _save_last_scan(tld: str, domains: list[str], timestamp: float):
    try:
        data = {
            "tld": tld,
            "domains": domains,
            "timestamp": timestamp,
            "count": len(domains),
        }
        LAST_SCAN_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


# ── 首页 ──────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    html = Path("templates/index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


# ── 认证 ─────────────────────────────────────────────────

@app.get("/auth/check")
async def auth_check():
    """前端查询是否需要密码认证。"""
    return {"need_auth": bool(DC_PASSWORD)}


@app.post("/verify")
async def verify_password(data: dict):
    """校验密码，返回 token。"""
    if not DC_PASSWORD:
        return {"token": "", "ok": True}  # 未设密码直接通过
    password = data.get("password", "")
    if password == DC_PASSWORD:
        token = uuid.uuid4().hex
        _valid_tokens.add(token)
        return {"token": token, "ok": True}
    return JSONResponse({"ok": False, "error": "密码错误"}, status_code=401)


# ── 单词表缓存 ──────────────────────────────────────────

def load_words(length: int) -> dict:
    """加载单词表"""
    path = Path(f"words_{length}.json")
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"total": 0, "common_count": 0, "words": []}


WORD_CACHE: dict[int, dict] = {}


# ── 词表覆盖配置(启停/自定义) ────────────────────────────
# 预设词表(words_N.json)保持只读,用户在词表管理面板里的停用/添加
# 写入 wordlist_config.json 作为覆盖层,扫描时应用。
WORD_CONFIG_FILE = Path("wordlist_config.json")
WORD_CONFIG: dict[str, dict] = {}  # "3" -> {"disabled": set, "added": list}


def _load_word_config():
    global WORD_CONFIG
    try:
        raw = json.loads(WORD_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    config: dict[str, dict] = {}
    for key, val in (raw or {}).items():
        if not isinstance(val, dict):
            continue
        config[str(key)] = {
            "disabled": {str(w) for w in val.get("disabled", [])},
            "added": [str(w) for w in val.get("added", [])],
        }
    WORD_CONFIG = config


def _save_word_config():
    data = {
        k: {"disabled": sorted(v["disabled"]), "added": v["added"]}
        for k, v in WORD_CONFIG.items()
    }
    tmp = WORD_CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    tmp.replace(WORD_CONFIG_FILE)


def _base_word_set(length: int) -> set:
    if length not in WORD_CACHE:
        WORD_CACHE[length] = load_words(length)
    return set(WORD_CACHE[length].get("words", []))


def _apply_word_overlay(length: int, only_common: bool, only_custom: bool = False) -> list[str]:
    """按覆盖配置计算一次扫描实际要用的单词表。

    仅自定义:只扫用户添加的词(跨长度不适用,按当前长度取);
    停用的词剔除;only_common 只保留预设里的常用词;
    自定义添加的词永远启用、按常用词对待(用户特意加的,不该被
    「仅常用词」过滤掉)。"""
    if length not in WORD_CACHE:
        WORD_CACHE[length] = load_words(length)
    wl = WORD_CACHE[length]
    words = wl.get("words", [])
    common_set = set(words[: wl.get("common_count", 0)])
    wcfg = WORD_CONFIG.get(str(length)) or {"disabled": set(), "added": []}

    if only_custom:
        return list(wcfg["added"])

    base = [w for w in words if w not in wcfg["disabled"]]
    if only_common:
        base = [w for w in base if w in common_set]
    added = [w for w in wcfg["added"] if w not in set(base)]
    return base + added


# ── 发起扫描 ──────────────────────────────────────────────

@app.post("/scan")
async def start_scan(data: dict):
    global _scan_counter
    tld = data.get("tld", "de")
    mode = data.get("mode", "brute")  # "brute" | "prefix_word"
    use_digits = data.get("use_digits", False)

    domains: list[str] = []

    if mode == "prefix_word":
        # "前缀 + 单词 + 后缀"模式(词表经过用户启停/自定义覆盖)
        prefix = data.get("prefix", "x").lower()
        suffix = data.get("suffix", "@").lower()
        word_length = data.get("word_length", 3)
        only_common = data.get("only_common", True)
        only_custom = bool(data.get("only_custom", False))

        words = _apply_word_overlay(word_length, only_common, only_custom)
        if only_custom and not words:
            return JSONResponse(
                {"error": f"{word_length} 字母词表还没有自定义词，请先在「管理词表」中添加"},
                status_code=400,
            )

        p = prefix if prefix not in ("@", "") else ""
        s = suffix if suffix not in ("@", "") else ""
        domains = [f"{p}{word}{s}.{tld}" for word in words]

        if p and s:
            print(f"[扫描] 前后缀模式: {p}+单词+{s} → {tld}")
        elif p:
            print(f"[扫描] 前缀模式: {p} + {len(words)} 个 {word_length}字母单词 → {tld}")
        elif s:
            print(f"[扫描] 后缀模式: 单词+{s} → {tld}")
        else:
            print(f"[扫描] 单词模式: {len(words)} 个 {word_length}字母单词 → {tld}")

        cfg = Config(tld=tld, concurrency=10, batch_sleep=1.0, timeout=20)

    else:
        # 暴力扫描模式
        lengths = data.get("lengths", [2])
        cfg = Config(
            tld=tld,
            min_len=min(lengths),
            max_len=max(lengths),
            use_digits=use_digits,
            concurrency=10,
            batch_sleep=1.0,
            timeout=20,
        )
        domains = generate_all(cfg)

    if not domains:
        return JSONResponse({"error": "没有生成候选域名"}, status_code=400)

    # ── 计算查询参数指纹,用于增量复检 ──
    if mode == "prefix_word":
        params = {
            "tld": tld,
            "prefix": data.get("prefix", "x"),
            "suffix": data.get("suffix", "@"),
            "word_length": word_length,
            "only_common": only_common and not only_custom,
            "only_custom": only_custom,
        }
    else:
        params = {
            "tld": tld,
            "lengths": data.get("lengths", [2]),
            "use_digits": use_digits,
        }
    query_key = history.make_query_key(mode, params)
    if mode == "prefix_word":
        # 词表内容(预设+用户启停/自定义)参与指纹:候选集变了就是一次
        # 新查询。否则增量复检会把新加入、从未检测过的词当成
        # 「已知注册域名」直接跳过,产出假结果。
        fp = hashlib.md5(",".join(sorted(domains)).encode("utf-8")).hexdigest()[:10]
        query_key += f"|w{fp}"
    full_count = len(domains)   # 全量候选数(归档用)
    incremental = False         # 是否命中增量复检
    skipped = 0                 # 跳过了多少已知注册域名

    # ── 增量复检:命中历史时只复检"上次可注册"的域名子集 ──
    try:
        prev = await history.find_by_key(query_key)
        if prev and prev["available_list"]:
            prev_available = prev["available_list"]
            # 与本次候选取交集(候选变了的话,只复检交集)
            domain_set = set(domains)
            recheck = [d for d in prev_available if d in domain_set]
            if recheck:
                skipped = len(domains) - len(recheck)
                # 只有真正减少了工作量才走增量
                if skipped > 0:
                    domains = recheck
                    incremental = True
                    print(f"[增量] 命中历史 {query_key}:跳过 {skipped} 个已知注册域名,复检 {len(recheck)} 个")
    except Exception as e:
        print(f"[增量] 查询历史失败(忽略,走全量):{e}")

    _scan_counter += 1
    scan_id = uuid.uuid4().hex[:12]
    queue: asyncio.Queue = asyncio.Queue()
    start_ts = time.time()
    scans[scan_id] = {
        "queue": queue,
        "domains": domains,
        "results": [],
        "cfg": cfg,
        "cancelled": False,
        "started_at": start_ts,
        "checked": 0,
        # 归档用元数据(扫描完成后写历史)
        "query_key": query_key,
        "mode": mode,
        "params": params,
        "full_count": full_count,
        "incremental": incremental,
        "skipped": skipped,
    }

    scan_task = asyncio.create_task(_run_scan(scan_id))
    scans[scan_id]["task"] = scan_task

    resp = {
        "scan_id": scan_id,
        "total": len(domains),
        "tld": tld,
        "incremental": incremental,
        "skipped": skipped,
        "full_count": full_count,
    }
    if mode == "prefix_word":
        resp["mode"] = "prefix_word"
        resp["prefix"] = data.get("prefix", "x")
        resp["suffix"] = data.get("suffix", "@")
        resp["word_length"] = data.get("word_length", 3)
    else:
        resp["lengths"] = data.get("lengths", [2])
    return resp


# ── SSE 实时推送 ──────────────────────────────────────────

@app.get("/scan/events/{scan_id}")
async def scan_events(scan_id: str, request: Request):
    scan = scans.get(scan_id)
    if scan is None:
        return JSONResponse({"error": "扫描不存在"}, status_code=404)

    # 如果扫描已完成，立即发 done 事件然后结束
    is_done = scan.get("finished", False)

    async def event_stream():
        queue = scan["queue"]
        # 先发一个快照事件
        checked = scan.get("checked", 0)
        total = len(scan["domains"])
        snapshot = {
            'checked': checked,
            'total': total,
            'incremental': scan.get('incremental', False),
            'skipped': scan.get('skipped', 0),
            'full_count': scan.get('full_count', total),
        }
        yield f"event: snapshot\ndata: {json.dumps(snapshot)}\n\n"

        # 如果扫描已完成，直接发完成事件
        if is_done:
            results = scan["results"]
            available_list = [d for d, ok in results if ok]
            yield (
                f"event: done\n"
                f"data: {json.dumps({
                    'total_checked': total,
                    'available_count': len(available_list),
                    'elapsed': round(scan.get('elapsed', 0), 1),
                    'whois_queried': scan.get('whois_queried', 0),
                    'rate_limited': scan.get('rate_limited', 0),
                })}\n\n"
            )
            return

        while True:
            if await request.is_disconnected():
                break
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=3)
            except asyncio.TimeoutError:
                yield "event: heartbeat\ndata: \n\n"
                continue

            yield f"event: {msg['type']}\ndata: {json.dumps(msg['data'])}\n\n"

            if msg["type"] == "done" or msg["type"] == "error":
                break

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── 获取扫描状态 ──────────────────────────────────────────

@app.get("/scan/active")
async def get_active_scan():
    """返回当前正在运行的扫描（如果有），供页面恢复连接用"""
    for scan_id, scan in scans.items():
        finished = scan.get("finished", False)
        cancelled = scan.get("cancelled", False)
        print(f"  [DEBUG] scan={scan_id[:8]} finished={finished} cancelled={cancelled} checked={scan.get('checked',0)}/{len(scan['domains'])}")
        if not finished and not cancelled:
            cfg = scan["cfg"]
            checked = scan.get("checked", 0)
            total = len(scan["domains"])
            return {
                "scan_id": scan_id,
                "tld": cfg.tld,
                "total": total,
                "checked": checked,
                "pct": round(checked / total * 100, 1) if total > 0 else 0,
                "elapsed": round(time.time() - scan.get("started_at", time.time()), 1),
            }
    print("  [DEBUG] 没有活跃扫描")
    return {"scan_id": None}


# ── 获取单词表 ────────────────────────────────────────────

@app.get("/words-meta")
async def get_words_meta():
    """返回可用单词表的元信息(已应用启停/自定义覆盖)。"""
    meta = {}
    for length in [1, 2, 3, 4]:
        if length not in WORD_CACHE:
            WORD_CACHE[length] = load_words(length)
        enabled = _apply_word_overlay(length, only_common=False)
        enabled_common = _apply_word_overlay(length, only_common=True)
        custom = _apply_word_overlay(length, only_common=False, only_custom=True)
        meta[str(length)] = {
            "total": len(enabled),
            "common_count": len(enabled_common),
            "custom_count": len(custom),
        }
    return meta


def _words_manage_payload(length: int) -> dict:
    if length not in WORD_CACHE:
        WORD_CACHE[length] = load_words(length)
    wl = WORD_CACHE[length]
    words = wl.get("words", [])
    common_set = set(words[: wl.get("common_count", 0)])
    wcfg = WORD_CONFIG.get(str(length)) or {"disabled": set(), "added": []}
    items = [
        {"w": w, "common": w in common_set, "disabled": w in wcfg["disabled"], "added": False}
        for w in words
    ]
    items += [
        {"w": w, "common": True, "disabled": False, "added": True}
        for w in wcfg["added"]
    ]
    enabled = [i for i in items if not i["disabled"]]
    return {
        "length": length,
        "items": items,
        "total": len(items),
        "enabled_total": len(enabled),
        "enabled_common": len([i for i in enabled if i["common"]]),
    }


_WORD_RE = re.compile(r"^[a-z]{1,8}$")


@app.get("/words/{length}/manage")
async def words_manage(length: int):
    """词表管理面板数据:每个词的常用/停用/自定义状态。"""
    if length not in (1, 2, 3, 4):
        return JSONResponse({"error": "不支持的词表长度"}, status_code=404)
    return _words_manage_payload(length)


@app.post("/words/{length}/manage")
async def words_manage_update(length: int, data: dict):
    """更新词表覆盖配置。
    body: {disable: [w], enable: [w], add: [w], remove_added: [w], reset: bool}"""
    if length not in (1, 2, 3, 4):
        return JSONResponse({"error": "不支持的词表长度"}, status_code=404)
    if not isinstance(data, dict):
        return JSONResponse({"error": "无效请求"}, status_code=400)

    if data.get("reset"):
        WORD_CONFIG.pop(str(length), None)
    else:
        wcfg = WORD_CONFIG.setdefault(str(length), {"disabled": set(), "added": []})
        base_set = _base_word_set(length)

        for w in data.get("disable") or []:
            w = str(w).strip().lower()
            if _WORD_RE.match(w) and w in base_set:
                wcfg["disabled"].add(w)
        for w in data.get("enable") or []:
            wcfg["disabled"].discard(str(w).strip().lower())
        for w in data.get("add") or []:
            w = str(w).strip().lower()
            # 自定义词:必须是指定长度的纯字母,且不能与预设重复
            if not _WORD_RE.match(w) or len(w) != length:
                continue
            if w in base_set or w in wcfg["added"]:
                continue
            wcfg["added"].append(w)
        for w in data.get("remove_added") or []:
            w = str(w).strip().lower()
            if w in wcfg["added"]:
                wcfg["added"].remove(w)
        wcfg["added"] = wcfg["added"][:500]  # 防御上限

    try:
        _save_word_config()
    except Exception as e:
        print(f"[词表] 配置写入失败:{e}")
    return _words_manage_payload(length)


@app.get("/words/{length}")
async def get_words(length: int):
    """返回指定长度的单词表"""
    if length not in WORD_CACHE:
        WORD_CACHE[length] = load_words(length)
    return WORD_CACHE[length]


# ── 获取扫描结果 ──────────────────────────────────────────

@app.get("/scan/results/{scan_id}")
async def get_results(scan_id: str):
    scan = scans.get(scan_id)
    if scan is None:
        return JSONResponse({"error": "扫描不存在"}, status_code=404)
    return {
        "total": len(scan["domains"]),
        "checked": len(scan["results"]),
        "available": [d for d, ok in scan["results"] if ok],
        "elapsed": scan.get("elapsed", 0),
        "finished": scan.get("finished", False),
    }


# ── 取消扫描 ──────────────────────────────────────────────

@app.post("/scan/cancel/{scan_id}")
async def cancel_scan(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        return {"status": "gone"}  # 扫描已清理

    already_finished = scan.get("finished", False)
    if scan.get("cancelled", False):
        return {"status": "already_cancelled", "finished": already_finished}

    scan["cancelled"] = True
    # 立刻归档这次已检测到的结果,不等后台任务收尾
    if not already_finished and not scan.get("archived", False):
        scan["archived"] = True
        _archive_partial(scan, scan.get("results", []), "手动停止")
    return {"status": "cancelled", "finished": already_finished}


# ── 获取最新持久化结果 ──────────────────────────────────

@app.get("/scan/last")
async def get_last_scan():
    if LAST_SCAN_FILE.exists():
        try:
            data = json.loads(LAST_SCAN_FILE.read_text(encoding="utf-8"))
            return data
        except Exception:
            pass
    return {"domains": [], "tld": "", "count": 0}


# ── 历史记录(SQLite) ────────────────────────────────────

def _params_summary(rec: dict) -> str:
    """把查询参数转成一句话摘要,供历史列表展示。"""
    mode = rec.get("mode", "brute")
    tld = rec.get("tld", "")
    p = rec.get("params", {}) or {}
    # 中途停止的扫描,摘要里标明,避免误以为是完整结果
    flag = " · 已停止" if rec.get("cancelled") else ""
    if mode == "prefix_word":
        prefix = p.get("prefix", "")
        suffix = p.get("suffix", "")
        wl = p.get("word_length", "")
        parts = []
        if prefix and prefix != "@":
            parts.append(f"前缀 {prefix}")
        parts.append(f"{wl} 字母单词")
        if suffix and suffix != "@":
            parts.append(f"后缀 {suffix}")
        return f"{', '.join(parts)} → .{tld}{flag}"
    lengths = p.get("lengths", [])
    digits = " +数字" if p.get("use_digits") else ""
    lengths_str = "/".join(str(x) for x in lengths) if lengths else "?"
    return f"暴力 {lengths_str} 字母{digits} → .{tld}{flag}"


@app.get("/history")
async def list_history(limit: int = 100):
    """历史列表(最近 N 条,不含完整域名列表)。"""
    rows = await history.list_recent(limit)
    for r in rows:
        r["summary"] = _params_summary(r)
        r["updated_at"] = r.get("updated_at", 0)
        r["created_at"] = r.get("created_at", 0)
    return {"items": rows, "count": len(rows)}


@app.get("/history/{scan_db_id}")
async def get_history_detail(scan_db_id: int):
    """单条历史详情(含完整可注册域名列表)。"""
    rec = await history.get_by_id(scan_db_id)
    if rec is None:
        return JSONResponse({"error": "历史记录不存在"}, status_code=404)
    rec["summary"] = _params_summary(rec)
    return rec


@app.post("/history/delete/{scan_db_id}")
async def delete_history(scan_db_id: int):
    ok = await history.delete_scan(scan_db_id)
    if not ok:
        return JSONResponse({"error": "历史记录不存在"}, status_code=404)
    return {"status": "deleted"}


# ── 扫描后台任务 ──────────────────────────────────────────

async def _run_scan(scan_id: str):
    scan = scans[scan_id]
    cfg: Config = scan["cfg"]
    domains: list[str] = scan["domains"]
    queue: asyncio.Queue = scan["queue"]
    results: list = scan["results"]
    total = len(domains)

    headers = {
        "User-Agent": "DomainChecker/1.0",
        "Accept": "application/rdap+json",
    }

    # 整个扫描共用一个 session/executor。此前每个域名都新建 ClientSession 和
    # ThreadPoolExecutor,其 __exit__ 里的 shutdown(wait=True) 会在事件循环线程上
    # 等待 whois 线程结束,一旦 whois 卡住就会冻结整个服务。
    connector = aiohttp.TCPConnector(limit=cfg.concurrency, limit_per_host=cfg.concurrency)
    session = aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=cfg.timeout + 10),
        headers=headers,
    )
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")
    sem = asyncio.Semaphore(cfg.concurrency)
    start_ts = time.time()

    # 边扫边存:每这么多秒把已检测结果落库一次,进程被 kill/OOM 也不丢
    last_partial_save = 0.0
    PARTIAL_SAVE_INTERVAL = 5.0
    _partial_forced = False

    whois_queried = 0
    rate_limited_count = 0
    timed_out_count = 0
    retried_count = 0
    consecutive_rate_limit = 0
    current_sleep = cfg.batch_sleep
    max_sleep = 30
    uncertain: list[str] = []

    per_domain_timeout = cfg.timeout * 2

    async def check_one(domain: str) -> tuple[str, bool, dict]:
        if scan["cancelled"]:
            return (domain, False, {})
        async with sem:
            if scan["cancelled"]:
                return (domain, False, {})
            try:
                return await asyncio.wait_for(
                    check_domain(cfg, domain, session, executor),
                    timeout=per_domain_timeout,
                )
            except asyncio.TimeoutError:
                return (domain, False, {"timed_out": True})
            except Exception:
                return (domain, False, {})

    batch_size = cfg.concurrency * 5
    # 看门狗:一个批次里的域名全部卡死时,超过这个时间就跳过剩余部分继续下一批
    batch_timeout = (batch_size / max(cfg.concurrency, 1)) * per_domain_timeout + 30
    checked = 0

    async def maybe_partial_save(force: bool = False):
        """定期把部分结果写入历史(cancelled=1),保证崩溃后仍有记录。"""
        nonlocal last_partial_save
        if not scan.get("query_key"):
            return
        now = time.time()
        if not force and now - last_partial_save < PARTIAL_SAVE_INTERVAL:
            return
        last_partial_save = now
        try:
            await history.save_scan(
                query_key=scan["query_key"],
                tld=cfg.tld,
                mode=scan.get("mode", "brute"),
                params=scan.get("params", {}),
                total=scan.get("full_count", total),
                available=[d for d, ok in results if ok],
                cancelled=True,
                checked=len(results),
            )
        except Exception as e:
            print(f"[历史] 自动存档失败(忽略):{e}")

    async def emit_progress():
        await queue.put({
            "type": "progress",
            "data": {
                "checked": checked,
                "total": total,
                "pct": round(checked / total * 100, 1),
                "whois_queried": whois_queried,
                "rate_limited": rate_limited_count,
                "timed_out": timed_out_count,
            },
        })

    try:
        for i in range(0, total, batch_size):
            if scan["cancelled"]:
                if not scan.get("archived", False):
                    scan["archived"] = True
                    _archive_partial(scan, results, "被停止")
                await queue.put({"type": "done", "data": {"cancelled": True}})
                return

            batch = domains[i : i + batch_size]
            tasks = [asyncio.create_task(check_one(d)) for d in batch]
            done_domains: set[str] = set()
            try:
                for fut in asyncio.as_completed(tasks, timeout=batch_timeout):
                    # 逐个结果检查取消，避免批次内响应延迟
                    if scan["cancelled"]:
                        if not scan.get("archived", False):
                            scan["archived"] = True
                            _archive_partial(scan, results, "被停止")
                        break
                    domain, available, meta = await fut
                    done_domains.add(domain)
                    checked += 1
                    results.append((domain, available))
                    scan["checked"] = checked

                    if meta.get("whois_queried"):
                        whois_queried += 1
                    if meta.get("timed_out"):
                        timed_out_count += 1
                    if meta.get("rate_limited"):
                        rate_limited_count += 1
                        consecutive_rate_limit += 1
                        uncertain.append(domain)
                    elif meta.get("timed_out"):
                        uncertain.append(domain)
                    else:
                        consecutive_rate_limit = 0

                    # 自适应退避
                    if consecutive_rate_limit >= 5:
                        current_sleep = min(current_sleep * 1.5, max_sleep)
                        consecutive_rate_limit = 0
                        await queue.put({
                            "type": "ratelimit",
                            "data": {"sleep": round(current_sleep, 1)},
                        })
                    elif current_sleep > cfg.batch_sleep and consecutive_rate_limit == 0:
                        current_sleep = max(current_sleep * 0.8, cfg.batch_sleep)

                    await emit_progress()
                    if not _partial_forced:
                        _partial_forced = True
                        await maybe_partial_save(force=True)
                    else:
                        await maybe_partial_save()

                    if available:
                        await queue.put({
                            "type": "found",
                            "data": {"domain": domain},
                        })
            except asyncio.TimeoutError:
                # 看门狗触发:把没完成的域名记为不可用,扫描继续,不能整场卡死
                missing = [d for d in batch if d not in done_domains]
                checked += len(missing)
                timed_out_count += len(missing)
                results.extend((d, False) for d in missing)
                scan["checked"] = checked
                print(f"[扫描] 批次超时,跳过 {len(missing)} 个未完成域名")
                await emit_progress()
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

            actual_sleep = current_sleep if rate_limited_count > 0 else cfg.batch_sleep
            if actual_sleep > 0 and i + batch_size < total:
                await maybe_partial_save()
                await asyncio.sleep(actual_sleep)

        # ── 冷却复检：限流/超时导致结果不确定的域名,等注册局配额恢复后重查一次 ──
        if uncertain and not scan["cancelled"]:
            cooldown = 65
            await queue.put({
                "type": "retry",
                "data": {"count": len(uncertain), "wait": cooldown},
            })
            for _ in range(cooldown):
                if scan["cancelled"]:
                    break
                await asyncio.sleep(1)
            if not scan["cancelled"]:
                retry_sem = asyncio.Semaphore(3)

                async def recheck_one(domain: str):
                    async with retry_sem:
                        if scan["cancelled"]:
                            return (domain, None, {})
                        try:
                            return await asyncio.wait_for(
                                check_domain(cfg, domain, session, executor),
                                timeout=per_domain_timeout,
                            )
                        except asyncio.TimeoutError:
                            return (domain, None, {"timed_out": True})
                        except Exception:
                            return (domain, None, {})

                retry_results = await asyncio.gather(
                    *[recheck_one(d) for d in uncertain], return_exceptions=False
                )
                idx = {d: i for i, (d, _) in enumerate(results)}
                still_uncertain = 0
                for domain, available, meta in retry_results:
                    retried_count += 1
                    if available is None:
                        still_uncertain += 1
                        continue
                    if domain in idx:
                        results[idx[domain]] = (domain, available)
                    if available:
                        await queue.put({
                            "type": "found",
                            "data": {"domain": domain},
                        })
                rate_limited_count = still_uncertain
                scan["checked"] = checked
                await emit_progress()

        elapsed = time.time() - start_ts
        scan["elapsed"] = elapsed
        scan["finished"] = True
        scan["whois_queried"] = whois_queried
        scan["rate_limited"] = rate_limited_count
        scan["timed_out"] = timed_out_count

        available_list = [d for d, ok in results if ok]
        _save_last_scan(cfg.tld, available_list, time.time())

        # ── 写入/更新历史(SQLite) ──
        # 增量扫描时 available_list 是复检后仍可注册的子集,直接归档(更精确)。
        try:
            await history.save_scan(
                query_key=scan.get("query_key", ""),
                tld=cfg.tld,
                mode=scan.get("mode", "brute"),
                params=scan.get("params", {}),
                total=scan.get("full_count", total),  # 记全量候选数,而非增量后的
                available=available_list,
                cancelled=False,
                checked=total,  # 完整跑完,清除"已停止"标记
            )
        except Exception as e:
            print(f"[历史] 写入失败(忽略):{e}")

        await queue.put({
            "type": "done",
            "data": {
                "total_checked": total,
                "available_count": len(available_list),
                "elapsed": round(elapsed, 1),
                "whois_queried": whois_queried,
                "rate_limited": rate_limited_count,
                "timed_out": timed_out_count,
                "retried": retried_count,
                "incremental": scan.get("incremental", False),
                "skipped": scan.get("skipped", 0),
            },
        })
    except Exception as e:
        scan["finished"] = True
        if not scan.get("archived", False):
            scan["archived"] = True
            _archive_partial(scan, results, "异常中断")
        await queue.put({"type": "error", "data": {"message": str(e)}})
    finally:
        await session.close()
        executor.shutdown(wait=False, cancel_futures=True)


# ── 启动 ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webapp:app", host="0.0.0.0", port=8000, reload=True)