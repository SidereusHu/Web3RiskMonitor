#!/usr/bin/env python3
"""
Phase 2 演示: 地址画像与行为分析
================================

演示地址画像系统的各项能力：
- 地址类型识别
- 标签体系应用
- 行为特征提取
- 关联图谱构建

运行方式：
    source venv/bin/activate
    python src/explore_address_profiling.py
"""

import sys
from pathlib import Path
from datetime import datetime as dt

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()


def demo_address_analyzer():
    """演示地址分析器"""
    console.print("\n[bold cyan]═══ 1. 地址类型识别 ═══[/bold cyan]\n")

    from src.profiler.address_analyzer import AddressAnalyzer

    analyzer = AddressAnalyzer()

    # 示例地址
    addresses = [
        ("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "Vitalik (EOA)"),
        ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT (Token)"),
        ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "Uniswap V2 Router"),
        ("0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b", "Tornado Cash (制裁)"),
    ]

    table = Table(title="地址类型识别结果")
    table.add_column("描述", style="cyan", width=25)
    table.add_column("类型", style="green", width=12)
    table.add_column("余额(ETH)", style="yellow", width=15)
    table.add_column("代码大小", width=10)
    table.add_column("标签", style="magenta", width=30)

    for addr, desc in addresses:
        try:
            profile = analyzer.analyze_address(addr)
            summary = analyzer.get_address_summary(profile)

            code_size = f"{summary['code_size']} bytes" if summary['code_size'] else "N/A"
            labels = ", ".join(summary['labels'][:3]) if summary['labels'] else "-"

            table.add_row(
                desc,
                summary['type'],
                summary['balance_eth'],
                code_size,
                labels,
            )
        except Exception as e:
            table.add_row(desc, f"Error: {str(e)[:20]}", "-", "-", "-")

    console.print(table)

    # 解释
    explanation = """
[bold]地址类型识别逻辑：[/bold]

  ┌────────────────────────────────────────────────────────┐
  │  get_code(address) == 0x  →  EOA (外部账户)            │
  │  get_code(address) != 0x  →  Contract (合约账户)       │
  │                                                        │
  │  Contract 进一步识别:                                  │
  │    - 调用 totalSupply() 成功 → ERC-20 Token           │
  │    - supportsInterface(0x80ac58cd) → ERC-721 NFT      │
  │    - 在已知列表中 → DEX/交易所/混币器等                │
  └────────────────────────────────────────────────────────┘
"""
    console.print(Panel(explanation, title="识别原理", border_style="cyan"))


def demo_label_system():
    """演示标签体系"""
    console.print("\n[bold cyan]═══ 2. 标签体系 ═══[/bold cyan]\n")

    from src.profiler.label_system import LabelManager, LabelCategory

    manager = LabelManager()

    # 显示预定义标签分类
    categories = [
        (LabelCategory.ENTITY, "实体标签"),
        (LabelCategory.BEHAVIOR, "行为标签"),
        (LabelCategory.RISK, "风险标签"),
        (LabelCategory.CONTRACT, "合约标签"),
    ]

    for cat, name in categories:
        labels = manager.list_predefined_labels(cat)
        console.print(f"\n[bold]{name}[/bold] ({len(labels)} 个):")

        # 只显示前5个
        for label in labels[:5]:
            risk_color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "none": "green",
            }.get(label.risk_tier.value, "white")

            console.print(f"  • {label.name} [{risk_color}]{label.risk_tier.value}[/{risk_color}] - {label.description}")

        if len(labels) > 5:
            console.print(f"  [dim]... 还有 {len(labels) - 5} 个标签[/dim]")

    # 演示风险检查
    console.print("\n[bold]风险检查示例：[/bold]\n")

    test_addresses = [
        "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # Tornado Cash
        "0x28c6c06298d514db089934071355e5743bf21d60",  # Binance
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap
        "0x1234567890123456789012345678901234567890",  # Unknown
    ]

    table = Table(title="地址风险检查")
    table.add_column("地址", style="cyan", width=45)
    table.add_column("风险分数", width=10)
    table.add_column("最高风险", width=10)
    table.add_column("标签", style="yellow", width=30)

    for addr in test_addresses:
        result = manager.check_risk(addr)
        risk_color = "red" if result["is_sanctioned"] else "green"

        table.add_row(
            f"{addr[:10]}...{addr[-8:]}",
            f"[{risk_color}]{result['risk_score']:.0f}[/{risk_color}]",
            result["highest_risk"],
            ", ".join(result["all_labels"][:3]) or "无",
        )

    console.print(table)


def demo_behavior_analysis():
    """演示行为分析"""
    console.print("\n[bold cyan]═══ 3. 行为特征分析 ═══[/bold cyan]\n")

    from src.profiler.behavior_analyzer import BehaviorAnalyzer, TimePattern, AmountPattern
    from src.models.ethereum import Transaction, TransactionType, CategoryType, RiskLevel
    import random

    analyzer = BehaviorAnalyzer()

    # 创建模拟交易数据
    mock_transactions = []
    base_time = int(dt.now().timestamp()) - 86400 * 30  # 30天前

    for i in range(50):
        tx = Transaction(
            hash=f"0x{'a' * 62}{i:02d}",
            block_number=19000000 + i,
            block_timestamp=base_time + i * 3600 * random.randint(1, 24),
            transaction_index=0,
            from_address="0xAnalyzedAddress000000000000000000000001",
            to_address=f"0xCounterparty{i:03d}00000000000000000000",
            value=random.randint(1, 100) * 10**16,
            value_eth=random.uniform(0.01, 1.0),
            gas=21000,
            gas_price=30000000000,
            input="0x" if random.random() > 0.7 else "0xa9059cbb" + "0" * 120,
            nonce=i,
            tx_type=TransactionType.ETH_TRANSFER if random.random() > 0.7 else TransactionType.CONTRACT_CALL,
            method_id="0xa9059cbb" if random.random() > 0.5 else None,
            method_name="transfer" if random.random() > 0.5 else None,
            category=CategoryType.TRANSFER,
            risk_level=RiskLevel.NORMAL,
        )
        mock_transactions.append(tx)

    # 分析
    features = analyzer.analyze_transactions(
        "0xAnalyzedAddress000000000000000000000001",
        mock_transactions
    )

    # 显示结果
    tree = Tree("[bold]行为特征分析结果[/bold]")

    # 频率特征
    freq = tree.add("[cyan]交易频率[/cyan]")
    freq.add(f"总交易数: {features.total_tx_count}")
    freq.add(f"日均交易: {features.avg_tx_per_day:.2f}")
    freq.add(f"单日最大: {features.max_tx_per_day}")
    freq.add(f"活跃天数: {features.active_days}")
    freq.add(f"账户年龄: {features.account_age_days} 天")

    # 时间特征
    time = tree.add("[cyan]时间分布[/cyan]")
    time.add(f"时间模式: {features.time_pattern.value}")
    time.add(f"高峰小时: {features.peak_hour}:00")
    time.add(f"高峰星期: 周{['一','二','三','四','五','六','日'][features.peak_weekday]}")

    # 金额特征
    amount = tree.add("[cyan]金额特征[/cyan]")
    amount.add(f"金额模式: {features.amount_pattern.value}")
    amount.add(f"总交易量: {features.total_volume_eth:.4f} ETH")
    amount.add(f"平均金额: {features.avg_tx_value_eth:.4f} ETH")
    amount.add(f"最大单笔: {features.max_tx_value_eth:.4f} ETH")

    # 操作特征
    ops = tree.add("[cyan]操作类型[/cyan]")
    ops.add(f"合约交互比例: {features.contract_interaction_ratio*100:.1f}%")
    ops.add(f"DeFi操作比例: {features.defi_ratio*100:.1f}%")
    ops.add(f"常用方法: {', '.join(features.top_methods[:3]) or 'N/A'}")

    # 交互对象
    counter = tree.add("[cyan]交互对象[/cyan]")
    counter.add(f"唯一交互地址: {features.unique_counterparties}")

    # 行为标签
    tags = tree.add("[cyan]行为标签[/cyan]")
    if features.behavior_tags:
        for tag in features.behavior_tags:
            tags.add(f"[yellow]{tag}[/yellow]")
    else:
        tags.add("[dim]无特殊标签[/dim]")

    console.print(tree)


def demo_address_graph():
    """演示地址图谱"""
    console.print("\n[bold cyan]═══ 4. 地址关联图谱 ═══[/bold cyan]\n")

    from src.profiler.address_graph import AddressGraph, EdgeType
    from datetime import datetime as dt

    graph = AddressGraph()

    # 构建示例图谱
    # 模拟一个洗钱路径: A -> B -> C -> 交易所
    # 还有正常交互: A -> DEX, B -> NFT市场

    edges = [
        ("0xSuspectA", "0xMiddlemanB", 10.0, EdgeType.ETH_TRANSFER),
        ("0xMiddlemanB", "0xMiddlemanC", 9.5, EdgeType.ETH_TRANSFER),
        ("0xMiddlemanC", "0xExchange", 9.0, EdgeType.ETH_TRANSFER),
        ("0xSuspectA", "0xUniswap", 1.0, EdgeType.CONTRACT_CALL),
        ("0xMiddlemanB", "0xOpenSea", 0.5, EdgeType.CONTRACT_CALL),
        ("0xNormalUser1", "0xSuspectA", 5.0, EdgeType.ETH_TRANSFER),
        ("0xNormalUser2", "0xMiddlemanB", 3.0, EdgeType.ETH_TRANSFER),
    ]

    for from_addr, to_addr, value, edge_type in edges:
        graph.add_edge(from_addr, to_addr, edge_type, value, dt.now())

    # 统计信息
    stats = graph.get_statistics()
    console.print(f"图谱统计: {stats['nodes']} 节点, {stats['edges']} 边, 总交易量 {stats['total_volume_eth']:.2f} ETH\n")

    # 查找路径
    console.print("[bold]路径分析：[/bold]")
    path = graph.find_path("0xSuspectA", "0xExchange")
    if path:
        console.print(f"  0xSuspectA → 0xExchange 路径: {' → '.join(path)}")
    else:
        console.print("  未找到路径")

    # N跳邻居
    console.print("\n[bold]关联分析：[/bold]")
    hop_neighbors = graph.get_n_hop_neighbors("0xSuspectA", n=2)
    for hop, addrs in hop_neighbors.items():
        console.print(f"  {hop}跳邻居: {len(addrs)} 个地址")

    # 中心度分析
    console.print("\n[bold]中心度分析：[/bold]")
    central_nodes = graph.find_high_centrality_nodes(top_n=5)
    for addr, score in central_nodes:
        console.print(f"  {addr}: 度数 {score}")

    # 可视化导出格式说明
    viz_data = graph.export_for_visualization()
    console.print(f"\n[dim]可视化数据: {len(viz_data['nodes'])} 节点, {len(viz_data['edges'])} 边[/dim]")

    # 图谱示意
    graph_viz = """
[bold]示例图谱结构：[/bold]

  ┌─────────────┐
  │ NormalUser1 │
  └──────┬──────┘
         │ 5 ETH
         ▼
  ┌─────────────┐      1 ETH      ┌──────────┐
  │  SuspectA   │────────────────▶│ Uniswap  │
  └──────┬──────┘                 └──────────┘
         │ 10 ETH
         ▼
  ┌─────────────┐      0.5 ETH    ┌──────────┐
  │ MiddlemanB  │────────────────▶│ OpenSea  │
  └──────┬──────┘                 └──────────┘
         │ 9.5 ETH
         ▼
  ┌─────────────┐
  │ MiddlemanC  │
  └──────┬──────┘
         │ 9 ETH
         ▼
  ┌─────────────┐
  │  Exchange   │  ← 资金最终流向
  └─────────────┘

[yellow]风控洞察: 检测到3跳内资金流向交易所的路径[/yellow]
"""
    console.print(Panel(graph_viz, title="关联图谱可视化", border_style="cyan"))


def demo_comprehensive_profiler():
    """演示综合画像服务"""
    console.print("\n[bold cyan]═══ 5. 综合地址画像 ═══[/bold cyan]\n")

    from src.profiler.profiler import AddressProfiler

    profiler = AddressProfiler()

    # 快速风险检查
    test_addresses = [
        ("0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b", "Tornado Cash"),
        ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "Uniswap V2"),
    ]

    console.print("[bold]快速风险检查：[/bold]\n")

    for addr, name in test_addresses:
        try:
            result = profiler.quick_risk_check(addr)

            risk_color = "red" if result['is_sanctioned'] else "green"
            console.print(f"  [{risk_color}]●[/{risk_color}] {name}")
            console.print(f"    地址类型: {result['address_type']}")
            console.print(f"    风险分数: {result['risk_score']:.0f}")
            console.print(f"    已知标签: {', '.join(result['known_labels'][:3]) or '无'}")
            console.print()
        except Exception as e:
            console.print(f"  [red]✗[/red] {name}: {str(e)[:50]}")
            console.print()


def show_phase2_summary():
    """显示Phase 2总结"""
    summary = """
[bold]Phase 2 地址画像系统架构：[/bold]

┌─────────────────────────────────────────────────────────────────┐
│                      AddressProfiler                            │
│                      (综合画像服务)                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐      │
│   │ AddressAnalyzer│  │ LabelManager  │  │BehaviorAnalyzer│     │
│   │  (类型识别)    │  │  (标签管理)   │  │  (行为分析)    │     │
│   └───────┬───────┘  └───────┬───────┘  └───────┬───────┘      │
│           │                  │                  │               │
│           └──────────────────┼──────────────────┘               │
│                              ▼                                  │
│                     ┌───────────────┐                          │
│                     │ AddressGraph  │                          │
│                     │  (关联图谱)   │                          │
│                     └───────────────┘                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

[bold]核心能力：[/bold]

  ✓ 地址类型识别 (EOA/Contract/Token/DEX/Mixer...)
  ✓ 多维标签体系 (实体/行为/风险/合约)
  ✓ 行为特征提取 (频率/时间/金额/操作/交互)
  ✓ 关联图谱分析 (邻居/路径/中心度/聚类)
  ✓ 综合风险评估 (评分/因子/层级)

[bold]文件结构：[/bold]

  src/profiler/
  ├── address_analyzer.py   # 地址分析器
  ├── label_system.py       # 标签体系
  ├── behavior_analyzer.py  # 行为分析
  ├── address_graph.py      # 关联图谱
  └── profiler.py           # 综合服务
"""
    console.print(Panel(summary, title="Phase 2 完成", border_style="green"))


def main():
    console.print(Panel.fit(
        "[bold]Phase 2: 地址画像与行为分析[/bold]\n"
        "演示地址画像系统的各项能力",
        border_style="blue"
    ))

    # 1. 地址类型识别
    demo_address_analyzer()

    # 2. 标签体系
    demo_label_system()

    # 3. 行为分析
    demo_behavior_analysis()

    # 4. 关联图谱
    demo_address_graph()

    # 5. 综合画像
    demo_comprehensive_profiler()

    # 总结
    show_phase2_summary()

    console.print("\n[bold green]✓ Phase 2 演示完成！[/bold green]\n")


if __name__ == "__main__":
    main()
