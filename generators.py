"""域名组合生成器"""

import itertools

from config import Config


def _charset(cfg: Config) -> str:
    """返回可用的字符集"""
    chars = "abcdefghijklmnopqrstuvwxyz"
    if cfg.use_digits:
        chars += "0123456789"
    if cfg.use_hyphen:
        chars += "-"
    return chars


def generate_all(cfg: Config) -> list[str]:
    """生成所有候选域名（完整列表）"""
    chars = _charset(cfg)
    if not chars:
        return []
    candidates: list[str] = []
    for length in range(cfg.min_len, cfg.max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            sld = "".join(combo)
            if sld.startswith("-") or sld.endswith("-"):
                continue
            domain = f"{sld}.{cfg.tld}"
            if domain not in cfg.blacklist:
                candidates.append(domain)

    total_candidates = sum(
        len(chars) ** l
        for l in range(cfg.min_len, cfg.max_len + 1)
    )
    # 去除了中划线首尾和黑名单，但数量级差不多，简单估算
    print(f"[生成] {cfg.tld} → {len(chars)}^{cfg.min_len}-{cfg.max_len} = {total_candidates} 种组合"
          f"，过滤后 {len(candidates)} 个候选")
    return candidates