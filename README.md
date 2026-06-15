# DomainChecker 🔍

实时检测短域名注册状态的工具，支持 CLI 和 Web 界面。

## 功能

- 🔍 **多级检测**：DNS 预检 → RDAP 查询 → Whois 库 → 直连 Whois 服务器
- 🌐 **Web 界面**：暗色科技风 UI，实时 SSE 推送进度
- 🖥 **CLI 模式**：命令行批量扫描，支持 CSV/JSON 导出
- 🧩 **两种扫描模式**：暴力枚举所有组合 / 前缀+常用单词组合
- 🌍 **多 TLD 支持**：de、com、io、xyz、org、net、cn、cc、top、vip、me
- ⚡ **自适应限速**：检测到限流自动降速

## 快速开始

```bash
pip install -r requirements.txt

# Web 界面
uvicorn webapp:app --host 0.0.0.0 --port 8000

# CLI 模式
python main.py --tld de --min-len 2 --max-len 3
```

## 项目结构

```
domain-checker/
├── main.py              # CLI 入口
├── webapp.py            # FastAPI Web 服务
├── checkers.py          # 域名检测引擎（DNS/RDAP/Whois）
├── config.py            # 配置数据类
├── generators.py        # 域名组合生成器
├── runner.py            # CLI 异步调度器
├── generate_words.py    # 单词表构建脚本
├── words_3.json         # 3 字母单词表
├── words_4.json         # 4 字母单词表
├── templates/
│   └── index.html       # Web 前端界面
└── requirements.txt     # Python 依赖
```

## License

MIT
