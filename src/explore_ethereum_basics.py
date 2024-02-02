#!/usr/bin/env python3
"""
Stage 1.1: 以太坊基础概念探索
============================

本脚本通过实际获取链上数据，帮助理解以太坊核心概念：
- 网络连接与节点交互
- 区块结构与区块链时间线
- 账户类型：EOA vs 合约账户
- 交易的基本结构

运行方式：
    source venv/bin/activate
    python src/explore_ethereum_basics.py

注意：需要配置 .env 文件中的 ETH_RPC_URL
"""

import os
import sys
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from web3 import Web3
from web3.types import BlockData

# 加载环境变量
load_dotenv()

console = Console()


class EthereumExplorer:
    """以太坊基础概念探索器"""

    def __init__(self, rpc_url: Optional[str] = None):
        """初始化连接

        Args:
            rpc_url: 以太坊节点RPC地址，如未提供则从环境变量读取
        """
        self.rpc_url = rpc_url or os.getenv(
            "ETH_RPC_URL",
            "https://eth-mainnet.g.alchemy.com/v2/demo"  # 公共demo端点
        )
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

    def check_connection(self) -> bool:
        """检查与以太坊网络的连接状态"""
        console.print("\n[bold cyan]═══ 1. 网络连接检查 ═══[/bold cyan]\n")

        is_connected = self.w3.is_connected()

        if is_connected:
            chain_id = self.w3.eth.chain_id
            latest_block = self.w3.eth.block_number

            # 网络ID映射
            network_names = {
                1: "Ethereum Mainnet",
                5: "Goerli Testnet",
                11155111: "Sepolia Testnet",
                137: "Polygon Mainnet",
                42161: "Arbitrum One",
            }
            network_name = network_names.get(chain_id, f"Unknown (Chain ID: {chain_id})")

            table = Table(title="网络连接状态", show_header=False)
            table.add_column("属性", style="cyan")
            table.add_column("值", style="green")
            table.add_row("连接状态", "✓ 已连接")
            table.add_row("网络", network_name)
            table.add_row("Chain ID", str(chain_id))
            table.add_row("最新区块", f"#{latest_block:,}")
            table.add_row("RPC端点", self.rpc_url[:50] + "..." if len(self.rpc_url) > 50 else self.rpc_url)

            console.print(table)
            console.print("\n[dim]→ 风控启示：Chain ID用于区分主网/测试网，防止跨链重放攻击[/dim]")
        else:
            console.print("[red]✗ 连接失败，请检查RPC URL配置[/red]")

        return is_connected

    def explore_block_structure(self, block_number: Optional[int] = None) -> Optional[BlockData]:
        """探索区块结构

        Args:
            block_number: 区块号，如未指定则获取最新区块
        """
        console.print("\n[bold cyan]═══ 2. 区块结构解析 ═══[/bold cyan]\n")

        if block_number is None:
            block_number = self.w3.eth.block_number

        block = self.w3.eth.get_block(block_number, full_transactions=True)

        # 区块时间戳转换
        block_time = datetime.fromtimestamp(block["timestamp"])

        # 构建区块结构树
        tree = Tree(f"[bold]Block #{block['number']:,}[/bold]")

        # Header分支
        header = tree.add("[cyan]Header (区块头)[/cyan]")
        header.add(f"hash: {block['hash'].hex()[:20]}...")
        header.add(f"parentHash: {block['parentHash'].hex()[:20]}... [dim]← 链接前一区块[/dim]")
        header.add(f"timestamp: {block_time} ({block['timestamp']})")
        header.add(f"miner/validator: {block['miner']}")
        header.add(f"gasUsed: {block['gasUsed']:,} / {block['gasLimit']:,} ({block['gasUsed']/block['gasLimit']*100:.1f}%)")

        if "baseFeePerGas" in block:
            base_fee_gwei = self.w3.from_wei(block["baseFeePerGas"], "gwei")
            header.add(f"baseFeePerGas: {base_fee_gwei:.2f} Gwei [dim](EIP-1559)[/dim]")

        # Transactions分支
        tx_branch = tree.add(f"[cyan]Transactions ({len(block['transactions'])} 笔)[/cyan]")
        for i, tx in enumerate(block["transactions"][:3]):  # 只显示前3笔
            tx_type = "合约调用" if tx["input"] != "0x" else "ETH转账"
            value_eth = self.w3.from_wei(tx["value"], "ether")
            tx_branch.add(f"[{i}] {tx['hash'].hex()[:16]}... | {tx_type} | {value_eth:.4f} ETH")

        if len(block["transactions"]) > 3:
            tx_branch.add(f"[dim]... 还有 {len(block['transactions']) - 3} 笔交易[/dim]")

        console.print(tree)

        # 风控视角的解读
        console.print("\n[bold yellow]风控视角解读：[/bold yellow]")
        insights = """
┌─────────────────────────────────────────────────────────────────┐
│  字段              │  风控含义                                   │
├─────────────────────────────────────────────────────────────────┤
│  timestamp         │  交易时间锚定，用于时序分析                  │
│  miner/validator   │  MEV分析的关键，识别可疑打包行为             │
│  gasUsed           │  区块拥堵度，高Gas可能伴随异常活动            │
│  baseFeePerGas     │  网络状态指标，急剧变化可能反映市场恐慌       │
│  transactions      │  核心监控对象，每笔交易都是风控数据点         │
└─────────────────────────────────────────────────────────────────┘
"""
        console.print(Panel(insights, title="区块字段的风控语义", border_style="yellow"))

        return block

    def explore_account_types(self):
        """探索账户类型：EOA vs 合约账户"""
        console.print("\n[bold cyan]═══ 3. 账户类型对比 ═══[/bold cyan]\n")

        # 示例地址
        examples = {
            "EOA (普通账户)": {
                "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",  # Vitalik
                "description": "Vitalik Buterin 的公开地址"
            },
            "Contract (合约账户)": {
                "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
                "description": "USDT (Tether) 合约"
            },
            "Risk Contract (风险合约)": {
                "address": "0xD90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # Tornado Cash
                "description": "Tornado Cash Router (已被OFAC制裁)"
            }
        }

        table = Table(title="账户类型对比")
        table.add_column("类型", style="cyan", width=20)
        table.add_column("地址", style="white", width=45)
        table.add_column("Code大小", style="green", width=12)
        table.add_column("余额 (ETH)", style="yellow", width=15)
        table.add_column("说明", style="dim", width=30)

        for account_type, info in examples.items():
            address = info["address"]
            checksum_addr = Web3.to_checksum_address(address)

            # 获取账户信息
            code = self.w3.eth.get_code(checksum_addr)
            balance = self.w3.eth.get_balance(checksum_addr)
            balance_eth = self.w3.from_wei(balance, "ether")

            code_size = len(code)
            is_contract = code_size > 0

            table.add_row(
                account_type,
                f"{address[:10]}...{address[-8:]}",
                f"{code_size:,} bytes" if is_contract else "0 (EOA)",
                f"{balance_eth:,.4f}",
                info["description"]
            )

        console.print(table)

        # 核心概念说明
        explanation = """
[bold]账户类型识别逻辑：[/bold]

  if get_code(address) == "0x":
      account_type = "EOA"        # 由私钥控制的外部账户
  else:
      account_type = "Contract"   # 智能合约账户

[bold]风控含义：[/bold]

  ┌────────────┬─────────────────────────────────────────────┐
  │    EOA     │ 真实用户或由人控制的地址                      │
  │            │ 可追溯到具体行为人                            │
  │            │ nonce递增反映账户活跃度                       │
  ├────────────┼─────────────────────────────────────────────┤
  │  Contract  │ 代码逻辑决定行为                              │
  │            │ 需分析合约功能(DEX/借贷/混币器等)              │
  │            │ 创建者和交互者都是风控关注点                   │
  └────────────┴─────────────────────────────────────────────┘
"""
        console.print(Panel(explanation, title="EOA vs Contract", border_style="cyan"))

    def explore_transaction_anatomy(self, tx_hash: Optional[str] = None):
        """解剖交易结构

        Args:
            tx_hash: 交易哈希，如未指定则从最新区块取样
        """
        console.print("\n[bold cyan]═══ 4. 交易结构解剖 ═══[/bold cyan]\n")

        if tx_hash is None:
            # 获取最新区块的第一笔交易
            latest_block = self.w3.eth.get_block("latest", full_transactions=True)
            if latest_block["transactions"]:
                tx = latest_block["transactions"][0]
            else:
                console.print("[yellow]最新区块无交易，跳过此部分[/yellow]")
                return
        else:
            tx = self.w3.eth.get_transaction(tx_hash)

        # 获取交易收据
        receipt = self.w3.eth.get_transaction_receipt(tx["hash"])

        # 交易类型判断
        if tx["to"] is None:
            tx_type = "合约创建"
            tx_type_detail = "部署新合约"
        elif tx["input"] == "0x" or tx["input"] == b"":
            tx_type = "ETH转账"
            tx_type_detail = "简单价值转移"
        else:
            tx_type = "合约调用"
            input_hex = tx["input"].hex() if isinstance(tx["input"], bytes) else tx["input"]
            method_id = input_hex[:10] if len(input_hex) >= 10 else input_hex
            tx_type_detail = f"Method: {method_id}"

        # 构建交易结构展示
        tree = Tree(f"[bold]Transaction {tx['hash'].hex()[:20]}...[/bold]")

        # 基础信息
        basic = tree.add("[cyan]基础信息[/cyan]")
        basic.add(f"类型: {tx_type} ({tx_type_detail})")
        basic.add(f"from: {tx['from']}")
        basic.add(f"to: {tx['to'] if tx['to'] else '[新合约]'}")
        basic.add(f"value: {self.w3.from_wei(tx['value'], 'ether')} ETH")
        basic.add(f"nonce: {tx['nonce']} [dim]← 发送方的第{tx['nonce']+1}笔交易[/dim]")

        # Gas信息
        gas = tree.add("[cyan]Gas信息[/cyan]")
        gas.add(f"gasLimit: {tx['gas']:,}")
        gas.add(f"gasUsed: {receipt['gasUsed']:,} ({receipt['gasUsed']/tx['gas']*100:.1f}%)")

        if "maxFeePerGas" in tx:
            # EIP-1559交易
            gas.add(f"maxFeePerGas: {self.w3.from_wei(tx['maxFeePerGas'], 'gwei'):.2f} Gwei")
            gas.add(f"maxPriorityFee: {self.w3.from_wei(tx['maxPriorityFeePerGas'], 'gwei'):.2f} Gwei")
        elif "gasPrice" in tx:
            gas.add(f"gasPrice: {self.w3.from_wei(tx['gasPrice'], 'gwei'):.2f} Gwei")

        actual_cost = receipt["gasUsed"] * (tx.get("effectiveGasPrice", tx.get("gasPrice", 0)))
        gas.add(f"实际花费: {self.w3.from_wei(actual_cost, 'ether'):.6f} ETH")

        # Input数据
        input_data = tree.add("[cyan]Input Data (调用数据)[/cyan]")
        input_hex = tx["input"].hex() if isinstance(tx["input"], bytes) else tx["input"]
        if input_hex == "0x" or input_hex == "":
            input_data.add("[dim]空 (简单转账)[/dim]")
        else:
            input_data.add(f"长度: {len(input_hex)//2 - 1} bytes")
            input_data.add(f"Method ID: {input_hex[:10]}")
            if len(input_hex) > 10:
                input_data.add(f"参数数据: {input_hex[10:74]}...")

        # 执行结果
        result = tree.add("[cyan]执行结果[/cyan]")
        status = "✓ 成功" if receipt["status"] == 1 else "✗ 失败"
        result.add(f"状态: {status}")
        result.add(f"区块: #{receipt['blockNumber']:,}")
        result.add(f"日志数: {len(receipt['logs'])} 条")

        console.print(tree)

        # 风控信号解读
        signals = f"""
[bold]该交易的风控信号分析：[/bold]

  发送方 nonce = {tx['nonce']}
    └─ {'新账户(首笔交易)，需关注资金来源' if tx['nonce'] == 0 else '活跃账户' if tx['nonce'] > 100 else '低频账户'}

  交易类型 = {tx_type}
    └─ {'需分析合约功能和调用参数' if tx_type == '合约调用' else '简单转账，关注金额和对手方'}

  Gas使用率 = {receipt['gasUsed']/tx['gas']*100:.1f}%
    └─ {'执行复杂，可能涉及多步操作' if receipt['gasUsed']/tx['gas'] > 0.8 else '执行简单'}

  状态 = {'成功' if receipt['status'] == 1 else '失败'}
    └─ {'正常' if receipt['status'] == 1 else '失败交易也需监控(可能是攻击尝试)'}
"""
        console.print(Panel(signals, title="风控信号", border_style="yellow"))

    def summarize_concepts(self):
        """概念总结"""
        console.print("\n[bold cyan]═══ 5. 核心概念总结 ═══[/bold cyan]\n")

        summary = """
[bold]以太坊核心概念与风控关联图：[/bold]

                    ┌─────────────────────────────────────┐
                    │           Ethereum Network          │
                    │  (公开、透明、不可篡改的数据来源)     │
                    └────────────────┬────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
        ┌──────────┐          ┌──────────┐          ┌──────────┐
        │  Blocks  │          │ Accounts │          │   Txns   │
        │  区块    │          │  账户    │          │   交易   │
        ├──────────┤          ├──────────┤          ├──────────┤
        │时间锚点   │          │EOA:人    │          │行为记录   │
        │打包顺序   │          │Contract: │          │意图载体   │
        │共识确认   │          │  代码    │          │资金流向   │
        └──────────┘          └──────────┘          └──────────┘
              │                      │                      │
              └──────────────────────┼──────────────────────┘
                                     ▼
                         ┌───────────────────────┐
                         │    风控分析基础       │
                         │  - 谁在什么时间       │
                         │  - 与谁交互           │
                         │  - 做了什么           │
                         │  - 涉及多少资金       │
                         └───────────────────────┘

[bold]下一步学习方向：[/bold]

  Phase 1.2 → 深入解析 input 字段，理解合约调用的"意图解码"
  Phase 1.3 → 设计数据采集架构，批量获取链上数据
  Phase 1.4 → 实现核心采集模块，构建数据管道
"""
        console.print(Panel(summary, border_style="green"))


def main():
    """主函数"""
    console.print(Panel.fit(
        "[bold]Stage 1.1: 以太坊基础概念探索[/bold]\n"
        "通过实际链上数据理解核心概念",
        border_style="blue"
    ))

    explorer = EthereumExplorer()

    # 1. 检查连接
    if not explorer.check_connection():
        console.print("\n[red]请配置正确的RPC URL后重试[/red]")
        console.print("1. 注册 Alchemy 或 Infura 获取免费API Key")
        console.print("2. 复制 .env.example 为 .env 并填入你的API Key")
        sys.exit(1)

    # 2. 探索区块结构
    explorer.explore_block_structure()

    # 3. 探索账户类型
    explorer.explore_account_types()

    # 4. 解剖交易结构
    explorer.explore_transaction_anatomy()

    # 5. 概念总结
    explorer.summarize_concepts()

    console.print("\n[bold green]✓ Stage 1.1 探索完成！[/bold green]\n")


if __name__ == "__main__":
    main()
