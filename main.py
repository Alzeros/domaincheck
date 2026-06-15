#!/usr/bin/env python3
"""
短域名批量注册检测工具

用法:
    python3 main.py                          # 默认查 .de 2-3 字母
    python3 main.py --tld com                # 查 .com
    python3 main.py --tld xyz --min-len 3 --max-len 4   # 查 3-4 字母 .xyz
    python3 main.py --tld de --digits        # 查 .de 含数字
    python3 main.py --tld io --concurrency 5 --batch-sleep 2  # 慢速防封
"""

import argparse
import asyncio
import time

from config import Config
from generators import generate_all
from runner import run_check, save_results, print_summary


def build_config(args: argparse.Namespace) -> Config:
    return Config(
        tld=args.tld,
        min_len=args.min_len,
        max_len=args.max_len,
        use_digits=args.digits,
        use_hyphen=args.hyphen,
        concurrency=args.concurrency,
        batch_sleep=args.batch_sleep,
        timeout=args.timeout,
    )


async def main():
    parser = argparse.ArgumentParser(
        description="短域名批量注册检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python3 main.py                         # .de 2-3 字母\n"
               "  python3 main.py --tld com --max-len 2   # .com 2 字母\n"
               "  python3 main.py --tld xyz --digits      # .xyz 含数字\n",
    )
    parser.add_argument("--tld", default="de", help="目标顶级域（默认 de）")
    parser.add_argument("--min-len", type=int, default=2, help="最短域名长度（默认 2）")
    parser.add_argument("--max-len", type=int, default=3, help="最长域名长度（默认 3）")
    parser.add_argument("--digits", action="store_true", help="包含数字 0-9")
    parser.add_argument("--hyphen", action="store_true", help="包含中划线 -")
    parser.add_argument("--concurrency", type=int, default=10, help="并发数（默认 10）")
    parser.add_argument("--batch-sleep", type=float, default=1.0, help="每批间隔秒数（默认 1.0）")
    parser.add_argument("--timeout", type=int, default=20, help="查询超时秒数（默认 20）")

    args = parser.parse_args()
    cfg = build_config(args)

    print("=" * 55)
    print(f"  短域名注册检测工具")
    print(f"  目标: .{cfg.tld}  长度: {cfg.min_len}-{cfg.max_len}")
    if cfg.use_digits:
        print(f"  包含数字: 是")
    print("=" * 55)

    # 1. 生成候选列表
    domains = generate_all(cfg)
    if not domains:
        print("没有生成任何候选域名，请调整参数。")
        return

    # 2. 并发检测
    print(f"\n开始检测 {len(domains)} 个域名 ...")
    start = time.time()
    results = await run_check(cfg, domains)
    elapsed = time.time() - start

    # 3. 保存结果
    available = save_results(cfg, results)

    # 4. 打印汇总
    print_summary(results, elapsed)


if __name__ == "__main__":
    asyncio.run(main())