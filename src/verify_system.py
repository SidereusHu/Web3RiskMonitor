#!/usr/bin/env python3
"""
Stage 1.5: 系统验证
==================

验证所有模块的正确性和完整性

运行方式：
    source venv/bin/activate
    python src/verify_system.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from web3 import Web3

console = Console()


def test_models():
    """测试数据模型"""
    console.print("\n[bold cyan]1. 测试数据模型[/bold cyan]")

    from src.models.ethereum import (
        Block, Transaction, TokenTransfer, EventLog,
        TransactionType, CategoryType, RiskLevel
    )
    from datetime import datetime as dt

    # 创建测试区块
    block = Block(
        number=19000000,
        hash="0x" + "a" * 64,
        parent_hash="0x" + "b" * 64,
        timestamp=1700000000,
        datetime=dt.fromtimestamp(1700000000),
        miner="0x" + "c" * 40,
        gas_used=15000000,
        gas_limit=30000000,
        base_fee_per_gas=30000000000,
        transaction_count=150
    )

    # 创建测试交易
    tx = Transaction(
        hash="0x" + "d" * 64,
        block_number=19000000,
        block_timestamp=1700000000,
        transaction_index=0,
        from_address="0x" + "e" * 40,
        to_address="0x" + "f" * 40,
        value=1000000000000000000,
        value_eth=1.0,
        gas=21000,
        gas_price=30000000000,
        input="0x",
        nonce=5,
        tx_type=TransactionType.ETH_TRANSFER,
        category=CategoryType.TRANSFER,
        risk_level=RiskLevel.NORMAL,
    )

    console.print("  [green]✓[/green] Block 模型创建成功")
    console.print("  [green]✓[/green] Transaction 模型创建成功")
    console.print(f"    └─ 示例: Block #{block.number:,}, {block.transaction_count} txs")

    return True


def test_signatures():
    """测试签名数据库"""
    console.print("\n[bold cyan]2. 测试签名数据库[/bold cyan]")

    from src.parser.signatures import (
        FUNCTION_SIGNATURES, EVENT_SIGNATURES, SANCTIONED_ADDRESSES,
        compute_selector, get_function_info, check_address_risk
    )

    # 测试Method ID计算
    method_id = compute_selector("transfer(address,uint256)")
    assert method_id == "0xa9059cbb", f"Expected 0xa9059cbb, got {method_id}"
    console.print("  [green]✓[/green] Method ID 计算正确")

    # 测试函数信息获取
    func_info = get_function_info("0xa9059cbb")
    assert func_info["name"] == "transfer"
    console.print("  [green]✓[/green] 函数信息查询正确")

    # 测试地址风险检查
    risk = check_address_risk("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b")
    assert risk["is_risky"] == True
    assert risk["risk_level"] == "high"
    console.print("  [green]✓[/green] 制裁地址检测正确")

    console.print(f"    └─ 函数签名库: {len(FUNCTION_SIGNATURES)} 个")
    console.print(f"    └─ 事件签名库: {len(EVENT_SIGNATURES)} 个")
    console.print(f"    └─ 制裁地址库: {len(SANCTIONED_ADDRESSES)} 个")

    return True


def test_parser():
    """测试交易解析器"""
    console.print("\n[bold cyan]3. 测试交易解析器[/bold cyan]")

    from src.parser.transaction_parser import TransactionParser
    from src.models.ethereum import TransactionType, RiskLevel

    parser = TransactionParser()

    # 模拟一笔ERC-20 transfer交易
    mock_tx = {
        "hash": bytes.fromhex("d" * 64),
        "blockNumber": 19000000,
        "blockTimestamp": 1700000000,
        "transactionIndex": 0,
        "from": "0x" + "a" * 40,
        "to": "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "value": 0,
        "gas": 100000,
        "gasPrice": 30000000000,
        "input": "0xa9059cbb" + "0" * 64 + "0" * 56 + "de0b6b3a7640000",  # transfer
        "nonce": 10,
    }

    parsed = parser.parse_transaction(mock_tx)

    assert parsed.tx_type == TransactionType.CONTRACT_CALL
    assert parsed.method_id == "0xa9059cbb"
    assert parsed.method_name == "transfer"
    console.print("  [green]✓[/green] ERC-20 transfer 解析正确")

    # 测试混币器交易风险检测
    mock_mixer_tx = {
        "hash": bytes.fromhex("e" * 64),
        "blockNumber": 19000000,
        "blockTimestamp": 1700000000,
        "transactionIndex": 1,
        "from": "0x" + "b" * 40,
        "to": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # Tornado Cash
        "value": 1000000000000000000,
        "gas": 200000,
        "gasPrice": 30000000000,
        "input": "0xb214faa5" + "0" * 64,  # deposit
        "nonce": 0,
    }

    parsed_mixer = parser.parse_transaction(mock_mixer_tx)

    assert parsed_mixer.risk_level == RiskLevel.HIGH
    assert any("制裁地址" in s or "混币器" in s for s in parsed_mixer.risk_signals)
    console.print("  [green]✓[/green] 混币器交易风险检测正确")

    console.print(f"    └─ 风险信号: {parsed_mixer.risk_signals}")

    return True


def test_storage():
    """测试存储模块"""
    console.print("\n[bold cyan]4. 测试存储模块[/bold cyan]")

    from src.storage.sqlite_storage import SQLiteStorage
    from src.models.ethereum import Block, Transaction, TransactionType, CategoryType, RiskLevel
    from datetime import datetime as dt
    import os

    # 使用测试数据库
    test_db = "data/test_blockchain.db"
    if os.path.exists(test_db):
        os.remove(test_db)

    storage = SQLiteStorage(test_db)
    console.print("  [green]✓[/green] SQLite 数据库初始化成功")

    # 保存测试区块
    block = Block(
        number=19000000,
        hash="0x" + "a" * 64,
        parent_hash="0x" + "b" * 64,
        timestamp=1700000000,
        datetime=dt.fromtimestamp(1700000000),
        miner="0x" + "c" * 40,
        gas_used=15000000,
        gas_limit=30000000,
        base_fee_per_gas=30000000000,
        transaction_count=150
    )
    storage.save_block(block)
    console.print("  [green]✓[/green] 区块保存成功")

    # 保存测试交易
    tx = Transaction(
        hash="0x" + "d" * 64,
        block_number=19000000,
        block_timestamp=1700000000,
        transaction_index=0,
        from_address="0x" + "e" * 40,
        to_address="0x" + "f" * 40,
        value=1000000000000000000,
        value_eth=1.0,
        gas=21000,
        gas_price=30000000000,
        input="0x",
        nonce=5,
        tx_type=TransactionType.ETH_TRANSFER,
        category=CategoryType.TRANSFER,
        risk_level=RiskLevel.NORMAL,
    )
    storage.save_transaction(tx)
    console.print("  [green]✓[/green] 交易保存成功")

    # 验证查询
    retrieved_block = storage.get_block(19000000)
    assert retrieved_block is not None
    assert retrieved_block["number"] == 19000000
    console.print("  [green]✓[/green] 区块查询成功")

    retrieved_tx = storage.get_transaction("0x" + "d" * 64)
    assert retrieved_tx is not None
    console.print("  [green]✓[/green] 交易查询成功")

    # 获取统计
    stats = storage.get_stats()
    console.print(f"    └─ 存储: {stats['block_count']} 区块, {stats['transaction_count']} 交易")

    storage.close()

    # 清理测试数据库
    os.remove(test_db)

    return True


def test_fetcher():
    """测试采集器（仅连接测试）"""
    console.print("\n[bold cyan]5. 测试采集器连接[/bold cyan]")

    from src.fetcher.block_fetcher import BlockFetcher

    fetcher = BlockFetcher()

    if fetcher.w3.is_connected():
        latest = fetcher.get_latest_block_number()
        console.print(f"  [green]✓[/green] RPC 连接成功")
        console.print(f"    └─ 端点: {fetcher.rpc_url[:50]}...")
        console.print(f"    └─ 最新区块: #{latest:,}")
        return True
    else:
        console.print("  [yellow]⚠[/yellow] RPC 连接失败（可能需要配置API Key）")
        console.print("    └─ 这不影响本地模块的功能验证")
        return True  # 允许继续


def show_summary():
    """显示项目摘要"""
    console.print("\n")

    # 文件结构
    structure = """
[bold]项目结构：[/bold]

Web3RiskMonitor/
├── src/
│   ├── models/
│   │   └── ethereum.py       # 数据模型定义
│   ├── parser/
│   │   ├── signatures.py     # 签名数据库
│   │   └── transaction_parser.py  # 交易解析器
│   ├── fetcher/
│   │   └── block_fetcher.py  # 区块采集器
│   ├── storage/
│   │   └── sqlite_storage.py # SQLite存储
│   ├── explore_ethereum_basics.py  # Stage 1.1
│   ├── explore_transaction_parsing.py  # Stage 1.2
│   ├── run_collector.py      # Stage 1.3 & 1.4
│   └── verify_system.py      # Stage 1.5
├── config/
│   └── settings.py           # 配置管理
├── data/
│   └── blockchain.db         # SQLite数据库
├── requirements.txt
└── .env.example
"""
    console.print(Panel(structure, title="Phase 1 完成", border_style="green"))

    # 下一步
    next_steps = """
[bold]Phase 1 已完成！接下来：[/bold]

1. [cyan]配置自己的RPC[/cyan]
   - 注册 Alchemy 或 Infura 获取免费API Key
   - 创建 .env 文件: ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

2. [cyan]运行完整采集[/cyan]
   python src/run_collector.py --blocks 10

3. [cyan]开始 Phase 2: 地址画像[/cyan]
   - 实现地址聚类
   - 构建交易图谱
   - 设计标签体系

4. [cyan]撰写博客[/cyan]
   《链上数据的本质：从交易结构理解区块链风控的起点》
"""
    console.print(Panel(next_steps, title="下一步", border_style="cyan"))


def main():
    console.print(Panel.fit(
        "[bold]Stage 1.5: 系统验证[/bold]\n"
        "验证 Phase 1 所有模块的完整性",
        border_style="blue"
    ))

    tests = [
        ("数据模型", test_models),
        ("签名数据库", test_signatures),
        ("交易解析器", test_parser),
        ("存储模块", test_storage),
        ("采集器连接", test_fetcher),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result, None))
        except Exception as e:
            results.append((name, False, str(e)))
            console.print(f"  [red]✗[/red] {name} 测试失败: {e}")

    # 显示测试结果
    console.print("\n")
    table = Table(title="测试结果汇总")
    table.add_column("模块", style="cyan")
    table.add_column("状态", style="green")

    all_passed = True
    for name, passed, error in results:
        if passed:
            table.add_row(name, "[green]✓ 通过[/green]")
        else:
            table.add_row(name, f"[red]✗ 失败: {error}[/red]")
            all_passed = False

    console.print(table)

    if all_passed:
        console.print("\n[bold green]✓ 所有测试通过！Phase 1 验证完成！[/bold green]")
        show_summary()
    else:
        console.print("\n[bold red]✗ 部分测试失败，请检查错误信息[/bold red]")


if __name__ == "__main__":
    main()
