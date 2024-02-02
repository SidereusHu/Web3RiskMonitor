"""
区块数据采集器

负责从以太坊网络获取区块和交易数据
支持：
- 单区块获取
- 批量区块获取
- 实时区块监听
"""

import os
import time
from datetime import datetime as dt
from typing import Dict, List, Optional, Generator, Callable, Any
from dataclasses import dataclass

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from web3 import Web3
from web3.types import BlockData

from src.models.ethereum import Block, Transaction, TokenTransfer, EventLog
from src.parser.transaction_parser import TransactionParser

load_dotenv()
console = Console()


@dataclass
class FetchResult:
    """采集结果"""
    block: Block
    transactions: List[Transaction]
    token_transfers: List[TokenTransfer]
    events: List[EventLog]
    fetch_time_ms: float


class BlockFetcher:
    """区块采集器"""

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        requests_per_second: int = 10
    ):
        """初始化采集器

        Args:
            rpc_url: RPC端点URL
            requests_per_second: 每秒最大请求数（用于速率限制）
        """
        # 尝试多个公共RPC端点
        public_rpcs = [
            "https://eth.llamarpc.com",
            "https://rpc.ankr.com/eth",
            "https://ethereum.publicnode.com",
            "https://1rpc.io/eth",
        ]

        self.rpc_url = rpc_url or os.getenv("ETH_RPC_URL")

        if self.rpc_url:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        else:
            # 尝试公共端点
            for rpc in public_rpcs:
                try:
                    self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 10}))
                    if self.w3.is_connected():
                        self.rpc_url = rpc
                        break
                except Exception:
                    continue
            else:
                # 使用第一个作为默认
                self.rpc_url = public_rpcs[0]
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.parser = TransactionParser(self.w3)
        self.request_interval = 1.0 / requests_per_second
        self.last_request_time = 0

    def _rate_limit(self):
        """速率限制"""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.request_interval:
            time.sleep(self.request_interval - elapsed)
        self.last_request_time = time.time()

    def get_latest_block_number(self) -> int:
        """获取最新区块号"""
        self._rate_limit()
        return self.w3.eth.block_number

    def fetch_block(
        self,
        block_number: int,
        include_receipts: bool = True
    ) -> FetchResult:
        """获取单个区块的完整数据

        Args:
            block_number: 区块号
            include_receipts: 是否获取交易收据

        Returns:
            FetchResult对象
        """
        start_time = time.time()

        # 获取区块（包含完整交易）
        self._rate_limit()
        raw_block = self.w3.eth.get_block(block_number, full_transactions=True)

        # 解析区块
        block = self._parse_block(raw_block)

        # 解析交易
        transactions = []
        token_transfers = []
        events = []

        for tx in raw_block["transactions"]:
            # 获取交易收据
            receipt = None
            if include_receipts:
                self._rate_limit()
                receipt = self.w3.eth.get_transaction_receipt(tx["hash"])

            # 添加区块时间戳
            tx_dict = dict(tx)
            tx_dict["blockTimestamp"] = raw_block["timestamp"]

            # 解析交易
            parsed_tx = self.parser.parse_transaction(tx_dict, receipt)
            transactions.append(parsed_tx)

            # 解析日志
            if receipt and receipt.get("logs"):
                tx_events, tx_transfers = self.parser.parse_logs(
                    receipt["logs"],
                    parsed_tx.hash,
                    block_number
                )
                events.extend(tx_events)
                token_transfers.extend(tx_transfers)

        fetch_time = (time.time() - start_time) * 1000

        return FetchResult(
            block=block,
            transactions=transactions,
            token_transfers=token_transfers,
            events=events,
            fetch_time_ms=fetch_time,
        )

    def fetch_block_range(
        self,
        start_block: int,
        end_block: int,
        include_receipts: bool = True,
        callback: Optional[Callable[[FetchResult], None]] = None,
        show_progress: bool = True
    ) -> Generator[FetchResult, None, None]:
        """批量获取区块范围

        Args:
            start_block: 起始区块（含）
            end_block: 结束区块（含）
            include_receipts: 是否获取交易收据
            callback: 每个区块处理完成后的回调函数
            show_progress: 是否显示进度条

        Yields:
            FetchResult对象
        """
        total_blocks = end_block - start_block + 1

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"[cyan]采集区块 {start_block} - {end_block}",
                    total=total_blocks
                )

                for block_num in range(start_block, end_block + 1):
                    try:
                        result = self.fetch_block(block_num, include_receipts)

                        if callback:
                            callback(result)

                        progress.update(
                            task,
                            advance=1,
                            description=f"[cyan]区块 #{block_num:,} | {len(result.transactions)} txs | {result.fetch_time_ms:.0f}ms"
                        )

                        yield result

                    except Exception as e:
                        console.print(f"[red]区块 {block_num} 采集失败: {e}[/red]")
                        progress.update(task, advance=1)
        else:
            for block_num in range(start_block, end_block + 1):
                try:
                    result = self.fetch_block(block_num, include_receipts)
                    if callback:
                        callback(result)
                    yield result
                except Exception as e:
                    console.print(f"[red]区块 {block_num} 采集失败: {e}[/red]")

    def watch_new_blocks(
        self,
        callback: Callable[[FetchResult], None],
        include_receipts: bool = True,
        poll_interval: float = 12.0
    ):
        """监听新区块（轮询模式）

        Args:
            callback: 新区块回调函数
            include_receipts: 是否获取交易收据
            poll_interval: 轮询间隔（秒），默认约等于以太坊出块时间
        """
        console.print("[cyan]开始监听新区块...[/cyan]")
        last_block = self.get_latest_block_number()
        console.print(f"[dim]当前最新区块: #{last_block:,}[/dim]")

        try:
            while True:
                time.sleep(poll_interval)

                current_block = self.get_latest_block_number()

                if current_block > last_block:
                    # 处理所有新区块
                    for block_num in range(last_block + 1, current_block + 1):
                        try:
                            result = self.fetch_block(block_num, include_receipts)
                            console.print(
                                f"[green]新区块 #{block_num:,}[/green] | "
                                f"{len(result.transactions)} txs | "
                                f"{len(result.token_transfers)} transfers | "
                                f"{result.fetch_time_ms:.0f}ms"
                            )
                            callback(result)
                        except Exception as e:
                            console.print(f"[red]区块 {block_num} 处理失败: {e}[/red]")

                    last_block = current_block

        except KeyboardInterrupt:
            console.print("\n[yellow]监听已停止[/yellow]")

    def _parse_block(self, raw_block: BlockData) -> Block:
        """解析原始区块数据"""
        return Block(
            number=raw_block["number"],
            hash=raw_block["hash"].hex(),
            parent_hash=raw_block["parentHash"].hex(),
            timestamp=raw_block["timestamp"],
            datetime=dt.fromtimestamp(raw_block["timestamp"]),
            miner=raw_block["miner"],
            gas_used=raw_block["gasUsed"],
            gas_limit=raw_block["gasLimit"],
            base_fee_per_gas=raw_block.get("baseFeePerGas"),
            transaction_count=len(raw_block["transactions"]),
        )


class BlockFetcherStats:
    """采集统计"""

    def __init__(self):
        self.blocks_processed = 0
        self.transactions_processed = 0
        self.transfers_processed = 0
        self.events_processed = 0
        self.high_risk_count = 0
        self.attention_count = 0
        self.total_fetch_time_ms = 0
        self.start_time = time.time()

    def update(self, result: FetchResult):
        """更新统计"""
        self.blocks_processed += 1
        self.transactions_processed += len(result.transactions)
        self.transfers_processed += len(result.token_transfers)
        self.events_processed += len(result.events)
        self.total_fetch_time_ms += result.fetch_time_ms

        # 统计风险交易
        for tx in result.transactions:
            if tx.risk_level.value == "high":
                self.high_risk_count += 1
            elif tx.risk_level.value == "attention":
                self.attention_count += 1

    def summary(self) -> Dict[str, Any]:
        """获取统计摘要"""
        elapsed = time.time() - self.start_time
        return {
            "blocks_processed": self.blocks_processed,
            "transactions_processed": self.transactions_processed,
            "transfers_processed": self.transfers_processed,
            "events_processed": self.events_processed,
            "high_risk_count": self.high_risk_count,
            "attention_count": self.attention_count,
            "avg_fetch_time_ms": self.total_fetch_time_ms / max(1, self.blocks_processed),
            "elapsed_seconds": elapsed,
            "blocks_per_second": self.blocks_processed / max(1, elapsed),
        }
