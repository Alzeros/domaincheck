#!/usr/bin/env python3
"""生成 1 字母和 2 字母单词表 JSON"""

import json, re
from pathlib import Path

# ── 1 字母：26 个英文字母 ──
WORDS_1 = {
    "total": 26,
    "common_count": 26,
    "words": [chr(i) for i in range(ord('a'), ord('z') + 1)],
}

# ── 2 字母常见词 ──
COMMON_2 = set("""
am an as at be by do go he hi if in is it me my no of on or so to up us we
""".split())

def build_words_2():
    words = set()
    for path in ["/usr/share/dict/american-english-huge", "/usr/share/dict/words"]:
        p = Path(path)
        if p.exists():
            for line in p.read_text().splitlines():
                w = line.strip().lower()
                if re.match(r'^[a-z]{2}$', w):
                    words.add(w)

    enable_path = Path("/tmp/enable1.txt")
    if enable_path.exists():
        for line in enable_path.read_text().splitlines():
            w = line.strip().lower()
            if re.match(r'^[a-z]{2}$', w):
                words.add(w)

    sorted_words = sorted(words)
    # 排序：常见词优先
    sorted_words.sort(key=lambda w: (w not in COMMON_2, w))
    common_count = sum(1 for w in sorted_words if w in COMMON_2)

    return {
        "total": len(sorted_words),
        "common_count": common_count,
        "words": sorted_words,
    }

if __name__ == "__main__":
    # 1 字母
    Path("words_1.json").write_text(
        json.dumps(WORDS_1, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"words_1.json: {WORDS_1['total']} words ({WORDS_1['common_count']} common)")

    # 2 字母
    w2 = build_words_2()
    Path("words_2.json").write_text(
        json.dumps(w2, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"words_2.json: {w2['total']} words ({w2['common_count']} common)")
    print(f"  常用词: {' '.join(w2['words'][:w2['common_count']])}")
    print(f"  非常用词: {' '.join(w2['words'][w2['common_count']:w2['common_count']+30])}...")
