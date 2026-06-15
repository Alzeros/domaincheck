#!/usr/bin/env python3
"""Domain Checker Web App — FastAPI + SSE 实时推送"""

import asyncio
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

import aiohttp
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from checkers import check_domain
from config import Config
from generators import generate_all

# ── 全局状态 ──────────────────────────────────────────────
# scan_id → { queue, domains, results, config, cancelled, ... }
scans: dict[str, dict] = {}
_scan_counter = 0  # 用于生成可读的 scan 编号

LAST_SCAN_FILE = Path("last_scan_result.json")


@asynccontextmanager
async def lifespan(app: FastAPI):
    scans.clear()
    yield


app = FastAPI(title="Domain Checker", lifespan=lifespan)


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


# ── 发起扫描 ──────────────────────────────────────────────

@app.post("/scan")
async def start_scan(data: dict):
    global _scan_counter
    tld = data.get("tld", "de")
    mode = data.get("mode", "brute")  # "brute" | "prefix_word"
    use_digits = data.get("use_digits", False)

    domains: list[str] = []

    if mode == "prefix_word":
        # "前缀 + 单词"模式
        prefix = data.get("prefix", "x").lower()
        word_length = data.get("word_length", 3)
        only_common = data.get("only_common", True)

        if word_length not in WORD_CACHE:
            WORD_CACHE[word_length] = load_words(word_length)
        wl = WORD_CACHE[word_length]
        words = wl.get("words", [])
        if only_common:
            common_count = wl.get("common_count", 0)
            words = words[:common_count]

        if prefix in ("@", ""):
                # 无前缀：直接使用单词作为域名主体
                domains = [f"{word}.{tld}" for word in words]
                print(f"[扫描] 单词模式: {len(words)} 个 {word_length}字母单词 → {tld}")
            else:
                domains = [f"{prefix}{word}.{tld}" for word in words]
                print(f"[扫描] 前缀模式: {prefix} + {len(words)} 个 {word_length}字母单词 → {tld}")

    else:
        # 暴力扫描模式（原来的逻辑）
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

    # 两种模式都需要 cfg
    if "cfg" not in locals() or cfg is None:
        cfg = Config(tld=tld, concurrency=10, batch_sleep=1.0, timeout=20)

    if not domains:
        return JSONResponse({"error": "没有生成候选域名"}, status_code=400)

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
    }

    asyncio.create_task(_run_scan(scan_id))

    resp = {
        "scan_id": scan_id,
        "total": len(domains),
        "tld": tld,
    }
    if mode == "prefix_word":
        resp["mode"] = "prefix_word"
        resp["prefix"] = data.get("prefix", "x")
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
        yield f"event: snapshot\ndata: {json.dumps({'checked': checked, 'total': total})}\n\n"

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

    from starlette.responses import StreamingResponse
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
    """返回可用单词表的元信息"""
    meta = {}
    for length in [3, 4]:
        if length not in WORD_CACHE:
            WORD_CACHE[length] = load_words(length)
        wl = WORD_CACHE[length]
        meta[str(length)] = {
            "total": wl["total"],
            "common_count": wl["common_count"],
        }
    return meta


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
    if scan:
        scan["cancelled"] = True
    return {"status": "cancelled"}


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


# ── 扫描后台任务 ──────────────────────────────────────────

async def _run_scan(scan_id: str):
    scan = scans[scan_id]
    cfg: Config = scan["cfg"]
    domains: list[str] = scan["domains"]
    queue: asyncio.Queue = scan["queue"]
    results: list = scan["results"]
    total = len(domains)

    connector = aiohttp.TCPConnector(limit=cfg.concurrency, limit_per_host=cfg.concurrency)
    sem = asyncio.Semaphore(cfg.concurrency)
    start_ts = time.time()

    headers = {
        "User-Agent": "DomainChecker/1.0",
        "Accept": "application/rdap+json",
    }

    whois_queried = 0
    rate_limited_count = 0
    consecutive_rate_limit = 0
    current_sleep = cfg.batch_sleep
    max_sleep = 30

    async def check_one(domain: str) -> tuple[str, bool, dict]:
        if scan["cancelled"]:
            return (domain, False, {})
        async with sem:
            try:
                async with aiohttp.ClientSession(
                    connector=connector, timeout=aiohttp.ClientTimeout(total=30), headers=headers
                ) as session:
                    with ThreadPoolExecutor(max_workers=4) as executor:
                        return await check_domain(cfg, domain, session, executor)
            except Exception:
                return (domain, False, {})

    batch_size = cfg.concurrency * 5
    checked = 0

    try:
        for i in range(0, total, batch_size):
            if scan["cancelled"]:
                await queue.put({"type": "done", "data": {"cancelled": True}})
                return

            batch = domains[i : i + batch_size]
            tasks = [check_one(d) for d in batch]
            for coro in asyncio.as_completed(tasks):
                domain, available, meta = await coro
                checked += 1
                results.append((domain, available))
                scan["checked"] = checked

                if meta.get("whois_queried"):
                    whois_queried += 1
                if meta.get("rate_limited"):
                    rate_limited_count += 1
                    consecutive_rate_limit += 1
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

                await queue.put({
                    "type": "progress",
                    "data": {
                        "checked": checked,
                        "total": total,
                        "pct": round(checked / total * 100, 1),
                        "whois_queried": whois_queried,
                        "rate_limited": rate_limited_count,
                    },
                })

                if available:
                    await queue.put({
                        "type": "found",
                        "data": {"domain": domain},
                    })

            actual_sleep = current_sleep if rate_limited_count > 0 else cfg.batch_sleep
            if actual_sleep > 0 and i + batch_size < total:
                await asyncio.sleep(actual_sleep)

        elapsed = time.time() - start_ts
        scan["elapsed"] = elapsed
        scan["finished"] = True
        scan["whois_queried"] = whois_queried
        scan["rate_limited"] = rate_limited_count

        available_list = [d for d, ok in results if ok]
        _save_last_scan(cfg.tld, available_list, time.time())
        await queue.put({
            "type": "done",
            "data": {
                "total_checked": total,
                "available_count": len(available_list),
                "elapsed": round(elapsed, 1),
                "whois_queried": whois_queried,
                "rate_limited": rate_limited_count,
            },
        })
    except Exception as e:
        scan["finished"] = True
        await queue.put({"type": "error", "data": {"message": str(e)}})


# ── 启动 ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webapp:app", host="0.0.0.0", port=8000, reload=True)