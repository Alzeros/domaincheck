#!/usr/bin/env python3
"""扫描历史持久化模块 —— SQLite。

按"查询参数指纹"(query_key)归档扫描结果:
- 相同的查询(query_key 命中)会被 UPSERT,而不是新增一条
- 命中时,历史里记录的 available 域名可用于"增量复检":
  下次相同查询只复检这些域名是否仍然可注册,跳过已知注册域名

并发说明:sqlite3 是同步调用,所有公开函数都通过 asyncio.to_thread 调用,
避免阻塞 FastAPI 的事件循环。
"""

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

DB_PATH = Path("history.db")

_schema = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tld         TEXT NOT NULL,
    query_key   TEXT NOT NULL UNIQUE,
    mode        TEXT NOT NULL,          -- 'brute' | 'prefix_word'
    params_json TEXT NOT NULL,          -- 完整查询参数
    total       INTEGER NOT NULL,       -- 本次扫描候选域名总数
    available   TEXT NOT NULL,          -- 可注册域名 JSON 数组
    cancelled   INTEGER NOT NULL DEFAULT 0,  -- 1 = 中途停止,available 只是部分结果
    checked     INTEGER NOT NULL DEFAULT 0,  -- 本次实际检测了多少个域名
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
"""


# ── 连接 ────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    """建表(幂等)。启动时调用一次。"""
    conn = _connect()
    try:
        conn.executescript(_schema)
        # 旧库平滑升级:补上后续版本新增的列
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
        for col, ddl in (
            ("cancelled", "INTEGER NOT NULL DEFAULT 0"),
            ("checked", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if col not in cols:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {ddl}")
        conn.commit()
    finally:
        conn.close()


# ── 查询参数指纹 ────────────────────────────────────────────

def make_query_key(mode: str, params: dict) -> str:
    """根据查询模式 + 参数生成稳定指纹。

    brute:        brute|{tld}|{sorted lengths}|{use_digits}
    prefix_word:  pw|{tld}|{prefix}|{suffix}|{word_length}|{only_common}

    同样的输入必然得到同样的 key,从而判定"这是否是重复查询"。
    """
    if mode == "prefix_word":
        key = "|".join([
            "pw",
            str(params.get("tld", "")),
            str(params.get("prefix", "")),
            str(params.get("suffix", "")),
            str(params.get("word_length", "")),
            "1" if params.get("only_common") else "0",
        ])
        # 仅自定义扫描是不同的查询目标;只在开启时附加,
        # 避免旧历史键全部失配(丢失增量复检的命中)
        if params.get("only_custom"):
            key += "|custom"
        return key
    # brute
    lengths = sorted(params.get("lengths", []))
    return "|".join([
        "brute",
        str(params.get("tld", "")),
        ",".join(str(x) for x in lengths),
        "1" if params.get("use_digits") else "0",
    ])


# ── 写入 ────────────────────────────────────────────────────

def _save_sync(
    query_key: str,
    tld: str,
    mode: str,
    params: dict,
    total: int,
    available: list[str],
    now: float,
    cancelled: bool = False,
    checked=None,
):
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO scans (tld, query_key, mode, params_json, total, available,
                               cancelled, checked, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(query_key) DO UPDATE SET
                tld=excluded.tld,
                mode=excluded.mode,
                params_json=excluded.params_json,
                total=excluded.total,
                available=excluded.available,
                cancelled=excluded.cancelled,
                checked=excluded.checked,
                updated_at=excluded.updated_at
            """,
            (
                tld, query_key, mode,
                json.dumps(params, ensure_ascii=False),
                total,
                json.dumps(available, ensure_ascii=False),
                1 if cancelled else 0,
                total if checked is None else checked,
                now, now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


async def save_scan(
    query_key: str,
    tld: str,
    mode: str,
    params: dict,
    total: int,
    available: list[str],
    cancelled: bool = False,
    checked=None,
) -> None:
    """UPSERT 一条扫描记录。created_at 首次写入后不再变,updated_at 每次刷新。

    cancelled=True 表示这场扫描是中途停止的,available 只是部分结果,
    历史列表里会标注"已停止",避免和完整结果混淆。
    """
    await asyncio.to_thread(
        _save_sync, query_key, tld, mode, params, total, available, time.time(),
        cancelled, checked,
    )


# ── 查询 ────────────────────────────────────────────────────

def _find_by_key_sync(query_key: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE query_key = ?", (query_key,)
        ).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()


async def find_by_key(query_key: str) -> Optional[dict]:
    return await asyncio.to_thread(_find_by_key_sync, query_key)


def _list_recent_sync(limit: int = 100) -> list[dict]:
    """最近 N 条(按 updated_at 倒序)。不返回 available 列表本体,只返回数量。"""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for r in rows:
            d = _row_to_dict(r)
            avail = d.pop("available_list")  # 丢弃完整列表
            d["available_count"] = len(avail)
            d.pop("available_raw", None)
            d.pop("available", None)  # 丢弃原始 JSON 字符串
            out.append(d)
        return out
    finally:
        conn.close()


async def list_recent(limit: int = 100) -> list[dict]:
    return await asyncio.to_thread(_list_recent_sync, limit)


def _get_by_id_sync(scan_id: int) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()


async def get_by_id(scan_id: int) -> Optional[dict]:
    return await asyncio.to_thread(_get_by_id_sync, scan_id)


def _delete_sync(scan_id: int) -> bool:
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


async def delete_scan(scan_id: int) -> bool:
    return await asyncio.to_thread(_delete_sync, scan_id)


# ── 工具 ────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["available_list"] = json.loads(d.get("available") or "[]")
    d["available_raw"] = d.get("available")
    d["params"] = json.loads(d.get("params_json") or "{}")
    d["cancelled"] = bool(d.get("cancelled"))
    return d
