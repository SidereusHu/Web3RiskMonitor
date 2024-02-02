#!/usr/bin/env python3
"""
Stage 1.2: 交易数据结构深度解析
==============================

本脚本深入解析交易的 input 字段和事件日志，理解：
- 函数选择器（Method ID）的计算与匹配
- ABI编码参数的解析
- ERC-20/ERC-721 Transfer事件解析
- 常见DeFi操作的识别

运行方式：
    source venv/bin/activate
    python src/explore_transaction_parsing.py
"""

import os
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime

from dotenv import load_dotenv
from eth_abi import decode
from eth_utils import keccak, to_checksum_address
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from web3 import Web3

load_dotenv()
console = Console()


# ============================================================================
# 常见函数签名数据库（风控核心知识）
# ============================================================================

KNOWN_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # ERC-20 标准
    "0xa9059cbb": {
        "name": "transfer",
        "signature": "transfer(address,uint256)",
        "params": ["address", "uint256"],
        "category": "ERC20",
        "risk_level": "normal",
        "description": "ERC-20代币转账"
    },
    "0x23b872dd": {
        "name": "transferFrom",
        "signature": "transferFrom(address,address,uint256)",
        "params": ["address", "address", "uint256"],
        "category": "ERC20",
        "risk_level": "normal",
        "description": "ERC-20授权转账"
    },
    "0x095ea7b3": {
        "name": "approve",
        "signature": "approve(address,uint256)",
        "params": ["address", "uint256"],
        "category": "ERC20",
        "risk_level": "attention",
        "description": "ERC-20授权（无限授权需警惕）"
    },

    # Uniswap V2 Router
    "0x7ff36ab5": {
        "name": "swapExactETHForTokens",
        "signature": "swapExactETHForTokens(uint256,address[],address,uint256)",
        "params": ["uint256", "address[]", "address", "uint256"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V2: ETH换Token"
    },
    "0x18cbafe5": {
        "name": "swapExactTokensForETH",
        "signature": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
        "params": ["uint256", "uint256", "address[]", "address", "uint256"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V2: Token换ETH"
    },
    "0x38ed1739": {
        "name": "swapExactTokensForTokens",
        "signature": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        "params": ["uint256", "uint256", "address[]", "address", "uint256"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V2: Token换Token"
    },

    # Uniswap V3 Router
    "0x04e45aaf": {
        "name": "exactInputSingle",
        "signature": "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        "params": ["tuple"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V3: 单池精确输入交换"
    },

    # 混币器 (高风险)
    "0xb214faa5": {
        "name": "deposit",
        "signature": "deposit(bytes32)",
        "params": ["bytes32"],
        "category": "Mixer",
        "risk_level": "high",
        "description": "Tornado Cash: 存款（已被OFAC制裁）"
    },
    "0x21a0adb6": {
        "name": "withdraw",
        "signature": "withdraw(bytes,bytes32,bytes32,address,address,uint256,uint256)",
        "params": ["bytes", "bytes32", "bytes32", "address", "address", "uint256", "uint256"],
        "category": "Mixer",
        "risk_level": "high",
        "description": "Tornado Cash: 提款"
    },

    # 跨链桥
    "0x0f5287b0": {
        "name": "depositETH",
        "signature": "depositETH(uint32,bytes)",
        "params": ["uint32", "bytes"],
        "category": "Bridge",
        "risk_level": "attention",
        "description": "跨链桥ETH存款"
    },

    # NFT (ERC-721)
    "0x42842e0e": {
        "name": "safeTransferFrom",
        "signature": "safeTransferFrom(address,address,uint256)",
        "params": ["address", "address", "uint256"],
        "category": "NFT",
        "risk_level": "normal",
        "description": "ERC-721 NFT安全转账"
    },

    # 多签钱包
    "0x6a761202": {
        "name": "execTransaction",
        "signature": "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        "params": ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"],
        "category": "MultiSig",
        "risk_level": "normal",
        "description": "Gnosis Safe: 执行交易"
    },
}

# 已知事件签名
KNOWN_EVENTS: Dict[str, Dict[str, Any]] = {
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {
        "name": "Transfer",
        "signature": "Transfer(address,address,uint256)",
        "indexed": ["from", "to"],
        "data": ["value"],
        "category": "ERC20/ERC721",
        "description": "代币转账事件"
    },
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": {
        "name": "Approval",
        "signature": "Approval(address,address,uint256)",
        "indexed": ["owner", "spender"],
        "data": ["value"],
        "category": "ERC20",
        "description": "授权事件"
    },
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": {
        "name": "Swap",
        "signature": "Swap(address,uint256,uint256,uint256,uint256,address)",
        "indexed": ["sender", "to"],
        "data": ["amount0In", "amount1In", "amount0Out", "amount1Out"],
        "category": "DEX",
        "description": "Uniswap V2交换事件"
    },
}

# 高风险合约地址
HIGH_RISK_ADDRESSES: Dict[str, str] = {
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Router",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash 0.1 ETH",
    "0xdd4c48c0b24039969fc16d1cdf626eab821d3384": "Tornado Cash 1 ETH",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 10 ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 100 ETH",
}


@dataclass
class DecodedTransaction:
    """解码后的交易"""
    tx_hash: str
    tx_type: str
    method_id: Optional[str]
    method_name: Optional[str]
    method_signature: Optional[str]
    category: str
    risk_level: str
    decoded_params: Optional[Dict]
    from_addr: str
    to_addr: str
    value_eth: float
    description: str


@dataclass
class DecodedEvent:
    """解码后的事件"""
    log_index: int
    event_name: str
    event_signature: str
    contract_address: str
    topics: List[str]
    decoded_data: Dict
    category: str


class TransactionParser:
    """交易解析器"""

    def __init__(self, rpc_url: Optional[str] = None):
        self.rpc_url = rpc_url or os.getenv(
            "ETH_RPC_URL",
            "https://eth-mainnet.g.alchemy.com/v2/demo"
        )
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

    def compute_method_id(self, signature: str) -> str:
        """计算函数选择器

        Method ID = keccak256(函数签名)的前4字节

        Args:
            signature: 函数签名，如 "transfer(address,uint256)"

        Returns:
            0x开头的8字符十六进制字符串
        """
        return "0x" + keccak(text=signature).hex()[:8]

    def demonstrate_method_id_calculation(self):
        """演示Method ID的计算过程"""
        console.print("\n[bold cyan]═══ 1. Method ID 计算原理 ═══[/bold cyan]\n")

        examples = [
            "transfer(address,uint256)",
            "approve(address,uint256)",
            "swapExactETHForTokens(uint256,address[],address,uint256)",
            "deposit(bytes32)",  # Tornado Cash
        ]

        table = Table(title="函数签名 → Method ID 映射")
        table.add_column("函数签名", style="cyan", width=55)
        table.add_column("Method ID", style="green", width=12)
        table.add_column("类别", style="yellow", width=10)

        for sig in examples:
            method_id = self.compute_method_id(sig)
            info = KNOWN_SIGNATURES.get(method_id, {})
            category = info.get("category", "Unknown")
            table.add_row(sig, method_id, category)

        console.print(table)

        explanation = """
[bold]计算过程：[/bold]

  Method ID = keccak256("transfer(address,uint256)")[:4bytes]

  步骤分解：
  ┌─────────────────────────────────────────────────────────────┐
  │  1. 取函数签名字符串（注意：参数类型间无空格）               │
  │  2. 对字符串进行 Keccak-256 哈希                            │
  │  3. 取哈希值的前4个字节（8个十六进制字符）                   │
  │  4. 加上 "0x" 前缀                                          │
  └─────────────────────────────────────────────────────────────┘

[bold]风控意义：[/bold]

  • Method ID 是识别"用户意图"的第一步
  • 建立 Method ID → 风险等级 的映射表是风控基础
  • 未知的 Method ID 不代表安全，可能是新型攻击
"""
        console.print(Panel(explanation, title="Method ID 计算说明", border_style="cyan"))

    def decode_input_data(self, input_hex: str) -> Tuple[Optional[str], Optional[Dict]]:
        """解码交易input数据

        Args:
            input_hex: 十六进制input数据

        Returns:
            (method_id, decoded_params) 元组
        """
        if not input_hex or input_hex == "0x":
            return None, None

        if len(input_hex) < 10:
            return None, None

        method_id = input_hex[:10].lower()
        params_hex = input_hex[10:]

        sig_info = KNOWN_SIGNATURES.get(method_id)
        if not sig_info:
            return method_id, None

        # 尝试解码参数
        try:
            param_types = sig_info["params"]
            if params_hex and param_types:
                decoded = decode(param_types, bytes.fromhex(params_hex))
                param_names = self._get_param_names(sig_info["name"])
                return method_id, dict(zip(param_names, decoded))
        except Exception:
            pass

        return method_id, None

    def _get_param_names(self, method_name: str) -> List[str]:
        """根据方法名获取参数名称"""
        param_names_map = {
            "transfer": ["to", "amount"],
            "transferFrom": ["from", "to", "amount"],
            "approve": ["spender", "amount"],
            "swapExactETHForTokens": ["amountOutMin", "path", "to", "deadline"],
            "swapExactTokensForETH": ["amountIn", "amountOutMin", "path", "to", "deadline"],
            "deposit": ["commitment"],
        }
        return param_names_map.get(method_name, [f"param{i}" for i in range(10)])

    def analyze_sample_transactions(self):
        """分析样例交易"""
        console.print("\n[bold cyan]═══ 2. 真实交易解析示例 ═══[/bold cyan]\n")

        # 获取最新区块的几笔交易进行分析
        latest_block = self.w3.eth.get_block("latest", full_transactions=True)
        transactions = latest_block["transactions"][:10]  # 取前10笔

        # 统计分类
        categories = {}
        risk_txs = []

        for tx in transactions:
            decoded = self._decode_transaction(tx)

            if decoded.category not in categories:
                categories[decoded.category] = []
            categories[decoded.category].append(decoded)

            if decoded.risk_level in ["high", "attention"]:
                risk_txs.append(decoded)

        # 显示分类统计
        table = Table(title=f"区块 #{latest_block['number']:,} 交易分类")
        table.add_column("类别", style="cyan")
        table.add_column("数量", style="green")
        table.add_column("示例Method", style="yellow")

        for cat, txs in categories.items():
            methods = set(t.method_name or "N/A" for t in txs)
            table.add_row(cat, str(len(txs)), ", ".join(list(methods)[:3]))

        console.print(table)

        # 详细展示一笔合约调用
        contract_calls = [t for t in transactions if t["input"] != "0x" and t["to"]]
        if contract_calls:
            self._display_detailed_transaction(contract_calls[0])

    def _decode_transaction(self, tx) -> DecodedTransaction:
        """解码单笔交易"""
        input_hex = tx["input"].hex() if isinstance(tx["input"], bytes) else tx["input"]

        # 确定交易类型
        if tx["to"] is None:
            tx_type = "Contract Creation"
            category = "Deployment"
            risk_level = "attention"
            method_id = None
            method_name = None
            method_sig = None
            description = "新合约部署"
            decoded_params = None
        elif input_hex == "0x" or not input_hex:
            tx_type = "ETH Transfer"
            category = "Transfer"
            risk_level = "normal"
            method_id = None
            method_name = None
            method_sig = None
            description = "简单ETH转账"
            decoded_params = None
        else:
            tx_type = "Contract Call"
            method_id, decoded_params = self.decode_input_data(input_hex)

            sig_info = KNOWN_SIGNATURES.get(method_id, {})
            method_name = sig_info.get("name")
            method_sig = sig_info.get("signature")
            category = sig_info.get("category", "Unknown")
            risk_level = sig_info.get("risk_level", "unknown")
            description = sig_info.get("description", "未知合约调用")

        # 检查目标地址风险
        to_addr = tx["to"].lower() if tx["to"] else ""
        if to_addr in HIGH_RISK_ADDRESSES:
            risk_level = "high"
            description = f"[危险] 与 {HIGH_RISK_ADDRESSES[to_addr]} 交互"

        return DecodedTransaction(
            tx_hash=tx["hash"].hex(),
            tx_type=tx_type,
            method_id=method_id,
            method_name=method_name,
            method_signature=method_sig,
            category=category,
            risk_level=risk_level,
            decoded_params=decoded_params,
            from_addr=tx["from"],
            to_addr=tx["to"] if tx["to"] else "Contract Creation",
            value_eth=float(self.w3.from_wei(tx["value"], "ether")),
            description=description
        )

    def _display_detailed_transaction(self, tx):
        """详细展示单笔交易的解析过程"""
        console.print("\n[bold]详细解析示例：[/bold]\n")

        decoded = self._decode_transaction(tx)
        input_hex = tx["input"].hex() if isinstance(tx["input"], bytes) else tx["input"]

        tree = Tree(f"[bold]交易解析: {decoded.tx_hash[:20]}...[/bold]")

        # 原始数据层
        raw = tree.add("[cyan]原始数据层[/cyan]")
        raw.add(f"from: {decoded.from_addr}")
        raw.add(f"to: {decoded.to_addr}")
        raw.add(f"value: {decoded.value_eth} ETH")
        raw.add(f"input长度: {len(input_hex)//2 - 1} bytes")

        # 解析层
        parsed = tree.add("[cyan]解析层[/cyan]")
        if decoded.method_id:
            parsed.add(f"Method ID: {decoded.method_id}")
            parsed.add(f"Method Name: {decoded.method_name or '[未知]'}")
            parsed.add(f"Signature: {decoded.method_signature or '[未知]'}")
        else:
            parsed.add("[dim]无合约调用数据[/dim]")

        # 语义层
        semantic = tree.add("[cyan]语义层[/cyan]")
        semantic.add(f"类别: {decoded.category}")
        semantic.add(f"描述: {decoded.description}")

        # 风控层
        risk_style = {
            "high": "red",
            "attention": "yellow",
            "normal": "green",
            "unknown": "dim"
        }.get(decoded.risk_level, "white")

        risk = tree.add("[cyan]风控层[/cyan]")
        risk.add(f"风险等级: [{risk_style}]{decoded.risk_level.upper()}[/{risk_style}]")

        console.print(tree)

    def analyze_event_logs(self):
        """分析事件日志"""
        console.print("\n[bold cyan]═══ 3. 事件日志（Logs）解析 ═══[/bold cyan]\n")

        explanation = """
[bold]为什么事件日志对风控至关重要？[/bold]

  交易的 input 字段告诉我们"用户想做什么"
  事件日志告诉我们"实际发生了什么"

  ┌─────────────────────────────────────────────────────────────┐
  │  很多关键信息只存在于日志中：                               │
  │                                                             │
  │  • ERC-20 转账的实际金额（input可能被多层封装）             │
  │  • DEX交易的实际成交价格                                    │
  │  • 闪电贷的借款和还款详情                                   │
  │  • NFT的实际转移记录                                        │
  └─────────────────────────────────────────────────────────────┘

[bold]日志结构：[/bold]

  Log {
    address:  合约地址（事件来源）
    topics:   [事件签名, indexed参数1, indexed参数2, ...]
    data:     非indexed参数的ABI编码
  }

  topics[0] = keccak256("Transfer(address,address,uint256)")
"""
        console.print(Panel(explanation, title="事件日志原理", border_style="cyan"))

        # 获取最新区块的日志
        latest_block = self.w3.eth.block_number
        logs = self.w3.eth.get_logs({
            "fromBlock": latest_block,
            "toBlock": latest_block,
        })

        # 统计事件类型
        event_counts: Dict[str, int] = {}
        for log in logs[:100]:  # 只分析前100条
            topic0 = log["topics"][0].hex() if log["topics"] else "0x"
            event_info = KNOWN_EVENTS.get(topic0, {})
            event_name = event_info.get("name", "Unknown")
            event_counts[event_name] = event_counts.get(event_name, 0) + 1

        table = Table(title=f"区块 #{latest_block:,} 事件统计（前100条）")
        table.add_column("事件名称", style="cyan")
        table.add_column("次数", style="green")
        table.add_column("风控含义", style="yellow")

        risk_meanings = {
            "Transfer": "资金流动，核心监控对象",
            "Approval": "授权操作，无限授权需警惕",
            "Swap": "DEX交易，追踪资金去向",
            "Unknown": "未识别事件，可能需要补充签名库",
        }

        for event_name, count in sorted(event_counts.items(), key=lambda x: -x[1]):
            meaning = risk_meanings.get(event_name, "待分析")
            table.add_row(event_name, str(count), meaning)

        console.print(table)

        # 展示一个Transfer事件的详细解析
        self._demonstrate_transfer_event_parsing(logs)

    def _demonstrate_transfer_event_parsing(self, logs: List):
        """演示Transfer事件的解析"""
        # 找一个Transfer事件
        transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

        for log in logs:
            if log["topics"] and log["topics"][0].hex() == transfer_topic:
                console.print("\n[bold]Transfer 事件解析示例：[/bold]\n")

                tree = Tree("[bold]Transfer Event[/bold]")

                # 原始数据
                raw = tree.add("[cyan]原始日志数据[/cyan]")
                raw.add(f"address: {log['address']} [dim](Token合约地址)[/dim]")
                raw.add(f"topics[0]: {log['topics'][0].hex()[:20]}... [dim](事件签名)[/dim]")
                if len(log["topics"]) > 1:
                    raw.add(f"topics[1]: {log['topics'][1].hex()} [dim](from地址)[/dim]")
                if len(log["topics"]) > 2:
                    raw.add(f"topics[2]: {log['topics'][2].hex()} [dim](to地址)[/dim]")
                raw.add(f"data: {log['data'].hex()[:40]}... [dim](转账金额)[/dim]")

                # 解析后
                parsed = tree.add("[cyan]解析后数据[/cyan]")

                if len(log["topics"]) > 2:
                    from_addr = "0x" + log["topics"][1].hex()[-40:]
                    to_addr = "0x" + log["topics"][2].hex()[-40:]
                    value = int(log["data"].hex(), 16)

                    parsed.add(f"Token: {log['address']}")
                    parsed.add(f"From: {from_addr}")
                    parsed.add(f"To: {to_addr}")
                    parsed.add(f"Value: {value} (原始值，需除以decimals)")

                console.print(tree)
                break

    def show_risk_patterns(self):
        """展示常见风险模式"""
        console.print("\n[bold cyan]═══ 4. 风险模式识别 ═══[/bold cyan]\n")

        patterns = """
[bold]基于交易解析的风险信号：[/bold]

┌─────────────────────────────────────────────────────────────────────┐
│  信号类型          │  检测方法                    │  风险等级      │
├─────────────────────────────────────────────────────────────────────┤
│  混币器交互        │  to地址在黑名单 OR           │  [red]高危[/red]          │
│                    │  Method ID匹配混币器函数     │                │
├─────────────────────────────────────────────────────────────────────┤
│  无限授权          │  approve(spender, 2^256-1)   │  [yellow]关注[/yellow]          │
│                    │  允许他人转走所有Token       │                │
├─────────────────────────────────────────────────────────────────────┤
│  新合约交互        │  to地址code_size > 0 且      │  [yellow]关注[/yellow]          │
│                    │  合约创建时间 < 24h          │                │
├─────────────────────────────────────────────────────────────────────┤
│  高滑点交易        │  DEX swap的amountOutMin过低  │  [yellow]关注[/yellow]          │
│                    │  可能是三明治攻击受害者      │                │
├─────────────────────────────────────────────────────────────────────┤
│  闪电贷调用        │  识别flashLoan相关Method ID  │  [yellow]关注[/yellow]          │
│                    │  常用于攻击的资金来源        │                │
├─────────────────────────────────────────────────────────────────────┤
│  大额转账          │  value > 阈值                │  [green]监控[/green]          │
│                    │  资金异动基础监控            │                │
└─────────────────────────────────────────────────────────────────────┘

[bold]识别逻辑伪代码：[/bold]

  def assess_risk(tx):
      risk_signals = []

      # 检查目标地址
      if tx.to in SANCTIONED_ADDRESSES:
          risk_signals.append(("HIGH", "制裁地址交互"))

      # 检查Method ID
      if tx.method_id in MIXER_METHODS:
          risk_signals.append(("HIGH", "混币器操作"))

      # 检查授权金额
      if tx.method_id == "0x095ea7b3":  # approve
          if decoded_amount == MAX_UINT256:
              risk_signals.append(("MEDIUM", "无限授权"))

      # 检查转账金额
      if tx.value > LARGE_TRANSFER_THRESHOLD:
          risk_signals.append(("LOW", "大额转账"))

      return risk_signals
"""
        console.print(Panel(patterns, title="风险模式", border_style="red"))

    def summarize(self):
        """总结"""
        console.print("\n[bold cyan]═══ 5. Stage 1.2 总结 ═══[/bold cyan]\n")

        summary = """
[bold]本阶段核心产出：[/bold]

  ┌────────────────────────────────────────────────────────────────┐
  │  1. Method ID 计算与匹配                                       │
  │     └─ 函数签名 → keccak256 → 前4字节                          │
  │     └─ 建立 Method ID → 风险等级 映射表                        │
  │                                                                │
  │  2. Input 数据解码                                             │
  │     └─ 提取 Method ID + 参数数据                               │
  │     └─ ABI解码参数值                                           │
  │                                                                │
  │  3. 事件日志解析                                               │
  │     └─ topics[0] = 事件签名哈希                                │
  │     └─ indexed参数在topics中，非indexed在data中                │
  │                                                                │
  │  4. 风险模式库                                                 │
  │     └─ 高风险Method ID清单                                     │
  │     └─ 制裁地址/风险合约清单                                   │
  │     └─ 异常行为识别规则                                        │
  └────────────────────────────────────────────────────────────────┘

[bold]下一步：Stage 1.3 数据采集架构[/bold]

  将上述解析能力整合到数据采集管道中：
  • 实时区块监听
  • 批量历史数据回溯
  • 结构化存储设计
"""
        console.print(Panel(summary, border_style="green"))


def main():
    console.print(Panel.fit(
        "[bold]Stage 1.2: 交易数据结构深度解析[/bold]\n"
        "理解 input 字段与事件日志的解码",
        border_style="blue"
    ))

    parser = TransactionParser()

    # 检查连接
    if not parser.w3.is_connected():
        console.print("[red]连接失败，请检查RPC配置[/red]")
        return

    console.print(f"[green]✓ 已连接到以太坊主网，最新区块: #{parser.w3.eth.block_number:,}[/green]")

    # 1. 演示Method ID计算
    parser.demonstrate_method_id_calculation()

    # 2. 分析真实交易
    parser.analyze_sample_transactions()

    # 3. 分析事件日志
    parser.analyze_event_logs()

    # 4. 展示风险模式
    parser.show_risk_patterns()

    # 5. 总结
    parser.summarize()

    console.print("\n[bold green]✓ Stage 1.2 完成！[/bold green]\n")


if __name__ == "__main__":
    main()
