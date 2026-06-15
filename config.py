"""域名字段配置（可通过命令行覆盖）"""

from dataclasses import dataclass, field


@dataclass
class Config:
    # ── 目标顶级域 ──
    tld: str = "de"

    # ── 短域名长度范围 ──
    min_len: int = 2
    max_len: int = 3

    # ── 字符集 ──
    use_digits: bool = False   # True = a-z + 0-9
    use_hyphen: bool = False   # True = 包含中划线

    # ── 并发与限速 ──
    concurrency: int = 10       # DENIC 限流严格，默认调低
    batch_sleep: float = 1.0   # 每批次休眠（秒）
    timeout: int = 20          # 单次查询超时

    # ── 输出 ──
    output_csv: str = "available_domains.csv"
    output_json: str = "available_domains.json"

    # ── 忽略列表 ──
    blacklist: set = field(default_factory=lambda: {
        "example.de", "test.de", "invalid.de",
        "www.de", "ftp.de", "mail.de",
    })

    @property
    def output_prefix(self) -> str:
        return f"available_{self.tld}"

    def __post_init__(self):
        self.output_csv = f"{self.output_prefix}.csv"
        self.output_json = f"{self.output_prefix}.json"