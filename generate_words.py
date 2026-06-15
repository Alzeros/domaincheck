#!/usr/bin/env python3
"""从 ENABLE + 系统词典提取常用 3/4 字母单词，生成干净的词表 JSON"""

import json
import re
from pathlib import Path

# ── 常见词白名单（保证包含这些） ──
COMMON_3 = """
the and for are but not you all can had her was one our out day get has him
his how its may new now old see way who did got let say she too use man dog
cat big red run top hot fun win yes box key air end far few job law map net
own put set tax arm ago age add ask bad bag bar bed bit bus buy cab car cup
cut dry ear eat egg eye fan fat fit fly gas gun guy hat ice ill ink its jam
jar jet kid kit lab lap leg lid lip log mad mix mom mud nap nod nut oak odd
oil pad pan paw pen pet pie pig pin pit pot rag ram rat ray rib rim rob rod
row rug sad sea sir sit six ski sky son sum sun tab tag tan tap tea ten tie
tin tip toe ton tow toy try two van vow war wax way web wet win wit wow yak
yes yet zen zip zoo
""".split()

COMMON_4 = """
that with have this will your from they been call come each make like long look
more much need only open over part plan play pull push real safe same seem show
side sign site size some sort sure take tell test text than them then time true
type unit upon very want well what when wild wind wish wood word year zero able
also area away back ball band bank base bath bear beat bell best bird bite blow
blue boat body bomb bone born boss both burn busy cake camp card care cash cast
cell chat chip city club coat code cold cook cool copy cost crew crop cure dark
date dead deal dear deep diet dirt dish disk dock does done door dose down draw
drew drop drum dual duke dull duty each earl earn east easy edge else even ever
evil exam face fact fail fair fall farm fast fate fear feed feel fell file fill
film find fire firm fish flag flat flew flip flow fold folk food foot ford form
fund fury game gang garden gate gift girl give glad glas goes gold golf gone
good grab gray grew grid grim grip grow gulf gull guru hack hair half hall hand
hang hard harm hate have head heal hear heat heed heel held hell help here hero
high hike hill hint hire hold hole holy home hood hook hope horn host hour huge
hull hung hunt hurt icon idea inch info into iron isle item jack jail jazz jean
join joke jury just keen keep kept kick kids kill kind king kiss kite knee knew
knit knob knot know lace lack laid lake lamp land lane last late lawn lead leaf
leak left lend less life lift like limb lime limp line link lion list live load
loan lock logo long look lord lose loss lost lots loud love luck lush maid mail
main make male mall malt many mark mars mask mass mate maze meal mean meat meet
melt memo menu mere mesh mild milk mill mind mine mint miss mist mode monk mood
moon more moss most moth move much mule muse mush must myth nail name navy near
neat neck need nest news next nice nine node none noon norm nose note noun numb
obey odds odor okay onceのみ only onto ooze open oral ours oust oval oven over
pace pack page paid pain pair pale palm pane park part pass past path pave peak
peel peer pick pile pine pink pipe pity plan play plea plot plow plug plus poem
poem poet pole poll polo pond pool poor pope port pose post pour pray prey pull
pulp pump pure push quit quiz race rack radar rage raid rail rain rake ramp
rand rang rank rare rash rate rave read real rear redo reef reel rein rely rend
rent rest rice rich ride riff rift right rigid riot rise risk risky road robe
rock rode role roll roof room root rope rose Ross ruin rule rump rune rush rust
sack safe sage said sail sake sale salt same sand sane sang sank save scat seal
seat sect seed seek seem seen self sell send sent sept shed shit shop shot show
shut sick side siege sign silk silly sing sink site size ski skin skip slap slim
slip slit slot slow slug snap snow soak soap soar sock soda soil sold sole some
song soon sort soul sour sown spam span spar sped spin spit spot spun spur stab
stag star stay stem step stew stir stop stub stud stun such suit sump sung sunk
sure surf swim tabs tack tact tail take tale talk tall tame tank tape task taxi
team tear tell tend tent term test text than that them then they thin this thus
tick tide tidy tied tier tile till tilt time tiny tips tire toad toes toil told
toll tomb tone took tool toptore torn toss tour town trap tray tree trek trim
trio trip troop trot true tube tuck tuft tuna tune turn twin type ugly undo
unit unto upon used user vain vale vane vary vast veer verb very vest veto vice
view vine void volt vote wade wage wail wait wake walk wall wand want ward warm
warn warp wary wash wave wavy waxy weak wear weed week weep weigh weird weld
well went were west what when whim whip whom wick wide wife wild will wilt
wily wind wine wing wink wipe wire wise wish wisp with woke wolf womb wood
wool word wore work worm worn wove wrap wren yard yarn year yell yelp yoga yoke
zero zone zoom
""".split()


def load_dict() -> set[str]:
    """从系统词典读取"""
    words = set()
    for path in ["/usr/share/dict/american-english-huge", "/usr/share/dict/words"]:
        p = Path(path)
        if p.exists():
            for line in p.read_text().splitlines():
                w = line.strip().lower()
                if re.match(r'^[a-z]+$', w):
                    words.add(w)
    return words


def load_enable(path: str) -> set[str]:
    """从 ENABLE 词表文件读取"""
    words = set()
    if Path(path).exists():
        for line in Path(path).read_text().splitlines():
            w = line.strip().lower()
            if re.match(r'^[a-z]+$', w):
                words.add(w)
    return words


def build_wordlist(length: int, common_words: list[str]) -> dict:
    """生成指定长度的单词表"""
    dict_words = load_dict()
    enable_words = load_enable("/tmp/enable1.txt")

    # 合并
    merged = set()
    merged.update(dict_words)
    merged.update(enable_words)
    for w in common_words:
        if len(w) == length:
            merged.add(w)

    # 基础过滤
    vowels = set("aeiouy")
    candidates = {}
    for w in merged:
        if len(w) != length:
            continue
        if not re.match(r'^[a-z]+$', w):
            continue
        # 必须有元音
        if not any(v in w for v in vowels):
            continue

        # 判断是否"常用"
        is_common = w in common_words

        # 判断是否"有意义"——在 ENABLE 词表中就算有意义
        in_enable = w in enable_words

        # 从系统词典来但不在 ENABLE 的可能不太常用，但留着手动选
        candidates[w] = {
            "word": w,
            "common": is_common,
            "in_enable": in_enable,
            "source": [],
        }
        if w in dict_words:
            candidates[w]["source"].append("dict")
        if w in enable_words:
            candidates[w]["source"].append("enable")

    # 排序：常用优先，然后按字母
    sorted_words = sorted(candidates.values(), key=lambda x: (not x["common"], x["word"]))

    return {
        "total": len(sorted_words),
        "common_count": sum(1 for w in sorted_words if w["common"]),
        "words": [w["word"] for w in sorted_words],
        "words_detail": sorted_words,
    }


def main():
    print("=" * 50)
    print("  单词表生成工具")
    print("=" * 50)

    for length, common in [(3, COMMON_3), (4, COMMON_4)]:
        print(f"\n[{length} 字母单词]")
        data = build_wordlist(length, common)

        out_file = f"words_{length}.json"
        # 只保存精简版（供 web 用）
        simple = {"total": data["total"], "common_count": data["common_count"], "words": data["words"]}
        Path(out_file).write_text(
            json.dumps(simple, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        print(f"  共 {data['total']} 个单词（常用 {data['common_count']} 个）")
        print(f"  已保存 {out_file}")
        print(f"  常用词: {' '.join(data['words'][:data['common_count']][:15])}...")
        print(f"  全部示例: {data['words'][:10]}...")

    print(f"\n✅ 完成")


if __name__ == "__main__":
    main()