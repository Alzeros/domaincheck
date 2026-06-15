"""调度器：异步并发 + 限速 + 进度追踪 + 结果收集"""

import asyncio
import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor

import aiohttp
from tqdm.asyncio import tqdm

from config import Config
from checkers import check_domain


async def run_check(cfg: Config, domains: list[str]) -> list[tuple[str, bool]]:
    """并发检测所有域名"""
    connector = aiohttp.TCPConnector(limit=cfg.concurrency, limit_per_host=cfg.concurrency)
    timeout = aiohttp.ClientTimeout(total=30)
    sem = asyncio.Semaphore(cfg.concurrency)

    headers = {
        "User-Agent": "DomainChecker/1.0 (research project)",
        "Accept": "application/rdap+json",
    }

    async def _check_one(domain: str) -> tuple[str, bool]:
        async with sem:
            try:
                async with aiohttp.ClientSession(
                    connector=connector, timeout=timeout, headers=headers
                ) as session:
                    with ThreadPoolExecutor(max_workers=4) as executor:
                        return await check_domain(cfg, domain, session, executor)
            except Exception:
                return (domain, False)

    tasks = [_check_one(d) for d in domains]
    results: list[tuple[str, bool]] = []

    batch_size = cfg.concurrency * 5
    total_batches = (len(tasks) + batch_size - 1) // batch_size

    for i in range(0, len(tasks), batch_size):
        batch = tasks[i : i + batch_size]
        batch_num = i // batch_size + 1
        for coro in tqdm.as_completed(batch, desc=f"检测中 {batch_num}/{total_batches}"):
            result = await coro
            results.append(result)

        if cfg.batch_sleep > 0 and i + batch_size < len(tasks):
            await asyncio.sleep(cfg.batch_sleep)

    return results


def save_results(cfg: Config, results: list[tuple[str, bool]]):
    """保存可注册域名到 CSV 和 JSON"""
    available = [domain for domain, ok in results if ok]
    available.sort(key=lambda d: (len(d.split(".")[0]), d))

    # CSV
    with open(cfg.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "length"])
        for domain in available:
            sld = domain.split(".")[0]
            writer.writerow([domain, len(sld)])

    # JSON
    with open(cfg.output_json, "w", encoding="utf-8") as f:
        json.dump(
            {
                "tld": cfg.tld,
                "total_checked": len(results),
                "available_count": len(available),
                "domains": available,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    return available


def print_summary(results: list[tuple[str, bool]], elapsed: float):
    """打印汇总"""
    total = len(results)
    available = [d for d, ok in results if ok]
    registered = total - len(available)

    print(f"\n{'='*55}")
    print(f"  检测完成！耗时 {elapsed:.1f} 秒")
    print(f"  共检测 {total} 个域名")
    print(f"  ✅ 可注册: {len(available)}")
    print(f"  ❌ 已注册: {registered}")
    print(f"  {'='*55}")

    if available:
        by_len: dict[int, list[str]] = {}
        for d in available:
            sld = d.split(".")[0]
            by_len.setdefault(len(sld), []).append(d)

        print("\n📋 可注册域名（按长度）:")
        for length in sorted(by_len):
            domains = by_len[length]
            print(f"\n  [{length} 字母] 共 {len(domains)} 个:")
            for d in domains[:20]:
                print(f"    {d}")
            if len(domains) > 20:
                print(f"    ... 还有 {len(domains) - 20} 个（见 CSV/JSON）")