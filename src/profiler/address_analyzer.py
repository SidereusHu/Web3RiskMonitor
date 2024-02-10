"""
地址分析器

Phase 2.1: 地址信息采集与类型识别

功能：
- 地址类型识别（EOA vs Contract）
- 基础信息采集（余额、nonce、代码）
- 合约元数据分析（创建者、创建时间）
- 地址活跃度评估
"""

import os
from datetime import datetime as dt
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from dotenv import load_dotenv
from web3 import Web3
from eth_utils import to_checksum_address

load_dotenv()


class AddressType(str, Enum):
    """地址类型"""
    EOA = "eoa"                    # 外部账户
    CONTRACT = "contract"          # 智能合约
    TOKEN = "token"                # 代币合约 (ERC-20/721/1155)
    DEX = "dex"                    # DEX相关合约
    DEFI = "defi"                  # DeFi协议
    BRIDGE = "bridge"             # 跨链桥
    MULTISIG = "multisig"          # 多签钱包
    MIXER = "mixer"                # 混币器
    EXCHANGE = "exchange"          # 中心化交易所
    UNKNOWN = "unknown"


class ActivityLevel(str, Enum):
    """活跃度等级"""
    INACTIVE = "inactive"          # 无活动
    LOW = "low"                    # 低频 (<10 txs)
    MEDIUM = "medium"              # 中频 (10-100 txs)
    HIGH = "high"                  # 高频 (100-1000 txs)
    VERY_HIGH = "very_high"        # 超高频 (>1000 txs)


@dataclass
class AddressProfile:
    """地址画像"""
    address: str

    # 基础信息
    address_type: AddressType = AddressType.UNKNOWN
    is_contract: bool = False
    balance_wei: int = 0
    balance_eth: float = 0.0
    nonce: int = 0  # EOA的交易计数

    # 合约特有信息
    code_hash: Optional[str] = None
    code_size: int = 0
    creator: Optional[str] = None
    creation_tx: Optional[str] = None
    creation_block: Optional[int] = None

    # 标签
    labels: List[str] = field(default_factory=list)
    risk_labels: List[str] = field(default_factory=list)

    # 活跃度
    activity_level: ActivityLevel = ActivityLevel.INACTIVE
    first_seen_block: Optional[int] = None
    last_seen_block: Optional[int] = None

    # 统计信息
    tx_count: int = 0
    internal_tx_count: int = 0
    token_transfer_count: int = 0
    unique_interactions: int = 0  # 交互过的唯一地址数

    # 资金流向
    total_received_eth: float = 0.0
    total_sent_eth: float = 0.0

    # 元数据
    analyzed_at: dt = field(default_factory=dt.now)
    data_source: str = "on-chain"


class AddressAnalyzer:
    """地址分析器"""

    def __init__(self, rpc_url: Optional[str] = None):
        """初始化分析器"""
        # 尝试多个公共RPC
        public_rpcs = [
            "https://eth.llamarpc.com",
            "https://rpc.ankr.com/eth",
            "https://ethereum.publicnode.com",
        ]

        self.rpc_url = rpc_url or os.getenv("ETH_RPC_URL")

        if self.rpc_url:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        else:
            for rpc in public_rpcs:
                try:
                    self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 10}))
                    if self.w3.is_connected():
                        self.rpc_url = rpc
                        break
                except Exception:
                    continue
            else:
                self.rpc_url = public_rpcs[0]
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

        # 已知地址标签库
        self._load_known_addresses()

    def _load_known_addresses(self):
        """加载已知地址标签"""
        from src.parser.signatures import (
            SANCTIONED_ADDRESSES, KNOWN_EXCHANGES, KNOWN_DEX_ROUTERS
        )

        self.known_addresses: Dict[str, Dict[str, Any]] = {}

        # 制裁地址
        for addr, info in SANCTIONED_ADDRESSES.items():
            self.known_addresses[addr.lower()] = {
                "type": AddressType.MIXER,
                "labels": [info["name"]],
                "risk_labels": ["OFAC_SANCTIONED"],
            }

        # 交易所
        for addr, name in KNOWN_EXCHANGES.items():
            self.known_addresses[addr.lower()] = {
                "type": AddressType.EXCHANGE,
                "labels": [name],
                "risk_labels": [],
            }

        # DEX
        for addr, name in KNOWN_DEX_ROUTERS.items():
            self.known_addresses[addr.lower()] = {
                "type": AddressType.DEX,
                "labels": [name],
                "risk_labels": [],
            }

    def analyze_address(self, address: str) -> AddressProfile:
        """分析单个地址

        Args:
            address: 以太坊地址

        Returns:
            AddressProfile 对象
        """
        address = to_checksum_address(address)
        addr_lower = address.lower()

        profile = AddressProfile(address=address)

        # 1. 获取基础链上数据
        self._fetch_basic_info(profile)

        # 2. 判断地址类型
        self._determine_type(profile)

        # 3. 应用已知标签
        if addr_lower in self.known_addresses:
            known = self.known_addresses[addr_lower]
            profile.address_type = known["type"]
            profile.labels.extend(known["labels"])
            profile.risk_labels.extend(known["risk_labels"])

        # 4. 如果是合约，尝试获取更多信息
        if profile.is_contract:
            self._analyze_contract(profile)

        # 5. 评估活跃度
        self._assess_activity(profile)

        return profile

    def _fetch_basic_info(self, profile: AddressProfile):
        """获取基础链上信息"""
        address = profile.address

        try:
            # 余额
            balance = self.w3.eth.get_balance(address)
            profile.balance_wei = balance
            profile.balance_eth = float(self.w3.from_wei(balance, 'ether'))

            # 代码
            code = self.w3.eth.get_code(address)
            profile.is_contract = len(code) > 0
            profile.code_size = len(code)

            if profile.is_contract:
                profile.code_hash = self.w3.keccak(code).hex()

            # Nonce (仅对EOA有意义)
            if not profile.is_contract:
                profile.nonce = self.w3.eth.get_transaction_count(address)
                profile.tx_count = profile.nonce

        except Exception as e:
            profile.labels.append(f"fetch_error: {str(e)[:50]}")

    def _determine_type(self, profile: AddressProfile):
        """判断地址类型"""
        if not profile.is_contract:
            profile.address_type = AddressType.EOA
            return

        profile.address_type = AddressType.CONTRACT

        # 基于代码大小的启发式判断
        if profile.code_size < 100:
            # 非常小的合约，可能是代理或最小合约
            profile.labels.append("minimal_contract")
        elif profile.code_size > 20000:
            # 大型合约，可能是复杂DeFi协议
            profile.labels.append("large_contract")

    def _analyze_contract(self, profile: AddressProfile):
        """分析合约详细信息"""
        # 尝试识别常见合约类型
        address = profile.address

        try:
            # 检查是否是ERC-20
            if self._is_erc20(address):
                profile.address_type = AddressType.TOKEN
                profile.labels.append("ERC-20")

            # 检查是否是ERC-721
            elif self._is_erc721(address):
                profile.address_type = AddressType.TOKEN
                profile.labels.append("ERC-721")

        except Exception:
            pass

    def _is_erc20(self, address: str) -> bool:
        """检查是否为ERC-20代币"""
        # ERC-20 必须有 totalSupply, balanceOf, transfer 方法
        erc20_abi = [
            {"name": "totalSupply", "type": "function", "inputs": [], "outputs": [{"type": "uint256"}]},
            {"name": "balanceOf", "type": "function", "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}]},
        ]

        try:
            contract = self.w3.eth.contract(address=address, abi=erc20_abi)
            # 尝试调用 totalSupply
            contract.functions.totalSupply().call()
            return True
        except Exception:
            return False

    def _is_erc721(self, address: str) -> bool:
        """检查是否为ERC-721 NFT"""
        # ERC-721 支持 ERC-165 接口检测
        erc165_abi = [
            {"name": "supportsInterface", "type": "function",
             "inputs": [{"type": "bytes4"}], "outputs": [{"type": "bool"}]},
        ]

        try:
            contract = self.w3.eth.contract(address=address, abi=erc165_abi)
            # ERC-721 interface ID: 0x80ac58cd
            return contract.functions.supportsInterface(bytes.fromhex("80ac58cd")).call()
        except Exception:
            return False

    def _assess_activity(self, profile: AddressProfile):
        """评估地址活跃度"""
        tx_count = profile.tx_count or profile.nonce

        if tx_count == 0:
            profile.activity_level = ActivityLevel.INACTIVE
        elif tx_count < 10:
            profile.activity_level = ActivityLevel.LOW
        elif tx_count < 100:
            profile.activity_level = ActivityLevel.MEDIUM
        elif tx_count < 1000:
            profile.activity_level = ActivityLevel.HIGH
        else:
            profile.activity_level = ActivityLevel.VERY_HIGH

    def analyze_batch(self, addresses: List[str]) -> List[AddressProfile]:
        """批量分析地址

        Args:
            addresses: 地址列表

        Returns:
            AddressProfile列表
        """
        profiles = []
        for addr in addresses:
            try:
                profile = self.analyze_address(addr)
                profiles.append(profile)
            except Exception as e:
                # 创建错误档案
                profile = AddressProfile(
                    address=addr,
                    labels=[f"analysis_error: {str(e)[:50]}"]
                )
                profiles.append(profile)

        return profiles

    def get_address_summary(self, profile: AddressProfile) -> Dict[str, Any]:
        """获取地址摘要（用于显示）"""
        return {
            "address": profile.address,
            "type": profile.address_type.value,
            "is_contract": profile.is_contract,
            "balance_eth": f"{profile.balance_eth:.4f}",
            "activity": profile.activity_level.value,
            "tx_count": profile.tx_count or profile.nonce,
            "labels": profile.labels,
            "risk_labels": profile.risk_labels,
            "code_size": profile.code_size if profile.is_contract else None,
        }


# 已知合约特征码（用于类型识别）
CONTRACT_SIGNATURES = {
    # Uniswap V2 Pair
    "0x0dfe1681": "token0()",  # Uniswap V2 Pair
    "0xd21220a7": "token1()",

    # Uniswap V3 Pool
    "0x3850c7bd": "slot0()",

    # ERC-20
    "0x18160ddd": "totalSupply()",
    "0x70a08231": "balanceOf(address)",

    # ERC-721
    "0x6352211e": "ownerOf(uint256)",

    # Gnosis Safe
    "0xa0e67e2b": "getOwners()",
    "0xe75235b8": "getThreshold()",
}
