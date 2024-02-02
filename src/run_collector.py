#!/usr/bin/env python3
"""
Stage 1.3 & 1.4: 数据采集系统演示
==================================

整合 Fetcher、Parser、Storage 模块，演示完整的数据采集流程

运行方式：
    source venv/bin/activate
    python src/run_collector.py --blocks 5        # 采集最近5个区块
    python src/run_collector.py --range 19000000 19000005  # 采集指定范围
    python src/run_collector.py --watch           # 实时监听新区块
"""

import argparse
import sys
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.fetcher.block_fetcher import BlockFetcher, BlockFetcherStats, FetchResult
from src.storage.sqlite_storage import SQLiteStorage

console = Console()


def display_fetch_result(result: FetchResult, storage: SQLiteStorage):
    """显示并存储采集结果"""
    block = result.block

    # 显示区块摘要
    console.print(
        f"[bold green]区块 #{block.number:,}[/bold green] | "
        f"{block.datetime.strftime('%Y-%m-%d %H:%M:%S')} | "
        f"{len(result.transactions)} txs | "
        f"{len(result.token_transfers)} transfers"
    )

    # 显示风险交易
    high_risk_txs = [tx for tx in result.transactions if tx.risk_level.value == "high"]
    attention_txs = [tx for tx in result.transactions if tx.risk_level.value == "attention"]

    if high_risk_txs:
        console.print(f"  [red]⚠ 高风险交易: {len(high_risk_txs)}[/red]")
        for tx in high_risk_txs[:3]:
            console.print(f"    [red]• {tx.hash[:20]}... {tx.risk_signals[0] if tx.risk_signals else ''}[/red]")

    if attention_txs:
        console.print(f"  [yellow]⚡ 关注交易: {len(attention_txs)}[/yellow]")
        for tx in attention_txs[:2]:
            console.print(f"    [yellow]• {tx.hash[:20]}... {tx.method_name or 'Unknown'}[/yellow]")

    # 保存到数据库
    storage.save_batch(
        blocks=[result.block],
        transactions=result.transactions,
        transfers=result.token_transfers,
        events=result.events
    )


def run_batch_collection(fetcher: BlockFetcher, storage: SQLiteStorage, start: int, end: int):
    """批量采集区块"""
    console.print(Panel(
        f"[bold]批量采集模式[/bold]\n"
        f"范围: #{start:,} - #{end:,}\n"
        f"共 {end - start + 1} 个区块",
        title="采集任务",
        border_style="cyan"
    ))

    stats = BlockFetcherStats()

    def on_result(result: FetchResult):
        stats.update(result)
        display_fetch_result(result, storage)

    # 执行采集
    for result in fetcher.fetch_block_range(start, end, callback=on_result):
        pass

    # 显示统计
    summary = stats.summary()
    display_stats(summary, storage)


def run_realtime_watch(fetcher: BlockFetcher, storage: SQLiteStorage):
    """实时监听模式"""
    console.print(Panel(
        "[bold]实时监听模式[/bold]\n"
        "按 Ctrl+C 停止",
        title="监听任务",
        border_style="green"
    ))

    stats = BlockFetcherStats()

    def on_new_block(result: FetchResult):
        stats.update(result)
        display_fetch_result(result, storage)

        # 每10个区块显示一次统计
        if stats.blocks_processed % 10 == 0:
            console.print(f"[dim]已处理 {stats.blocks_processed} 个区块, {stats.transactions_processed} 笔交易[/dim]")

    fetcher.watch_new_blocks(callback=on_new_block, poll_interval=12.0)

    # 显示最终统计
    summary = stats.summary()
    display_stats(summary, storage)


def display_stats(summary: dict, storage: SQLiteStorage):
    """显示统计信息"""
    console.print("\n")

    # 采集统计
    table = Table(title="采集统计")
    table.add_column("指标", style="cyan")
    table.add_column("值", style="green")

    table.add_row("处理区块数", f"{summary['blocks_processed']:,}")
    table.add_row("处理交易数", f"{summary['transactions_processed']:,}")
    table.add_row("代币转账数", f"{summary['transfers_processed']:,}")
    table.add_row("事件日志数", f"{summary['events_processed']:,}")
    table.add_row("高风险交易", f"[red]{summary['high_risk_count']}[/red]")
    table.add_row("关注交易", f"[yellow]{summary['attention_count']}[/yellow]")
    table.add_row("平均采集耗时", f"{summary['avg_fetch_time_ms']:.0f} ms/区块")
    table.add_row("采集速率", f"{summary['blocks_per_second']:.2f} 区块/秒")

    console.print(table)

    # 数据库统计
    db_stats = storage.get_stats()

    table2 = Table(title="数据库统计")
    table2.add_column("指标", style="cyan")
    table2.add_column("值", style="green")

    table2.add_row("存储区块数", f"{db_stats['block_count']:,}")
    if db_stats['min_block'] and db_stats['max_block']:
        table2.add_row("区块范围", f"#{db_stats['min_block']:,} - #{db_stats['max_block']:,}")
    else:
        table2.add_row("区块范围", "暂无数据")
    table2.add_row("存储交易数", f"{db_stats['transaction_count']:,}")

    if db_stats['risk_distribution']:
        for risk, count in db_stats['risk_distribution'].items():
            style = "red" if risk == "high" else "yellow" if risk == "attention" else "green"
            table2.add_row(f"风险-{risk}", f"[{style}]{count}[/{style}]")

    console.print(table2)


def display_architecture():
    """显示系统架构"""
    arch = """
[bold]数据采集系统架构：[/bold]

┌─────────────────────────────────────────────────────────────────┐
│                     run_collector.py                            │
│                     (调度与控制)                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────┐                                          │
│   │   BlockFetcher  │──────┐                                   │
│   │   (数据采集)     │      │                                   │
│   │                 │      ▼                                   │
│   │  • 单区块获取    │   ┌─────────────────┐                    │
│   │  • 批量获取     │   │ TransactionParser│                    │
│   │  • 实时监听     │   │   (数据解析)     │                    │
│   └─────────────────┘   │                 │                    │
│                         │  • Method ID解码 │                    │
│                         │  • 事件日志解析  │                    │
│                         │  • 风险评估     │                    │
│                         └────────┬────────┘                    │
│                                  │                              │
│                                  ▼                              │
│                         ┌─────────────────┐                    │
│                         │  SQLiteStorage  │                    │
│                         │   (数据存储)     │                    │
│                         │                 │                    │
│                         │  • 区块表       │                    │
│                         │  • 交易表       │                    │
│                         │  • 转账表       │                    │
│                         │  • 事件表       │                    │
│                         └─────────────────┘                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

[bold]数据流：[/bold]

  Ethereum RPC  ──▶  Fetcher  ──▶  Parser  ──▶  Storage  ──▶  SQLite DB
     (链上)        (原始数据)    (结构化)      (持久化)      (查询)
"""
    console.print(Panel(arch, title="Stage 1.3 & 1.4 系统架构", border_style="blue"))


def main():
    parser = argparse.ArgumentParser(description="Web3 链上数据采集系统")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--blocks", "-b",
        type=int,
        help="采集最近N个区块"
    )
    group.add_argument(
        "--range", "-r",
        nargs=2,
        type=int,
        metavar=("START", "END"),
        help="采集指定区块范围"
    )
    group.add_argument(
        "--watch", "-w",
        action="store_true",
        help="实时监听新区块"
    )
    group.add_argument(
        "--arch",
        action="store_true",
        help="显示系统架构"
    )

    args = parser.parse_args()

    # 显示架构
    if args.arch:
        display_architecture()
        return

    # 初始化组件
    console.print(Panel.fit(
        "[bold]Web3 链上数据采集系统[/bold]\n"
        "Stage 1.3 & 1.4 演示",
        border_style="blue"
    ))

    fetcher = BlockFetcher()
    storage = SQLiteStorage()

    if not fetcher.w3.is_connected():
        console.print("[red]连接失败，请检查RPC配置[/red]")
        return

    latest = fetcher.get_latest_block_number()
    console.print(f"[green]✓ 已连接，最新区块: #{latest:,}[/green]\n")

    # 执行采集任务
    if args.blocks:
        start = latest - args.blocks + 1
        run_batch_collection(fetcher, storage, start, latest)

    elif args.range:
        start, end = args.range
        run_batch_collection(fetcher, storage, start, end)

    elif args.watch:
        run_realtime_watch(fetcher, storage)

    else:
        # 默认：采集最近3个区块
        console.print("[dim]未指定参数，默认采集最近3个区块[/dim]\n")
        start = latest - 2
        run_batch_collection(fetcher, storage, start, latest)

    storage.close()
    console.print("\n[bold green]✓ 采集完成！[/bold green]")
    console.print(f"[dim]数据已保存到: data/blockchain.db[/dim]")


if __name__ == "__main__":
    main()
