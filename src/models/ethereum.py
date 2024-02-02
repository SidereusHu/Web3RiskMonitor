"""
以太坊数据模型

定义区块、交易、事件等核心数据结构
"""

from datetime import datetime as dt
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """风险等级"""
    HIGH = "high"
    ATTENTION = "attention"
    NORMAL = "normal"
    UNKNOWN = "unknown"


class TransactionType(str, Enum):
    """交易类型"""
    ETH_TRANSFER = "eth_transfer"
    CONTRACT_CALL = "contract_call"
    CONTRACT_CREATION = "contract_creation"


class CategoryType(str, Enum):
    """交易分类"""
    TRANSFER = "transfer"
    ERC20 = "erc20"
    ERC721 = "erc721"
    DEX = "dex"
    DEFI = "defi"
    MIXER = "mixer"
    BRIDGE = "bridge"
    MULTISIG = "multisig"
    UNKNOWN = "unknown"


class Block(BaseModel):
    """区块数据模型"""
    number: int = Field(..., description="区块高度")
    hash: str = Field(..., description="区块哈希")
    parent_hash: str = Field(..., description="父区块哈希")
    timestamp: int = Field(..., description="时间戳")
    datetime: dt = Field(..., description="区块时间")
    miner: str = Field(..., description="矿工/验证者地址")
    gas_used: int = Field(..., description="已用Gas")
    gas_limit: int = Field(..., description="Gas上限")
    base_fee_per_gas: Optional[int] = Field(None, description="基础Gas费(EIP-1559)")
    transaction_count: int = Field(..., description="交易数量")

    class Config:
        json_encoders = {
            dt: lambda v: v.isoformat()
        }


class Transaction(BaseModel):
    """交易数据模型"""
    hash: str = Field(..., description="交易哈希")
    block_number: int = Field(..., description="所在区块")
    block_timestamp: int = Field(..., description="区块时间戳")
    transaction_index: int = Field(..., description="交易在区块中的索引")

    # 交易主体
    from_address: str = Field(..., description="发送方地址")
    to_address: Optional[str] = Field(None, description="接收方地址(合约创建时为空)")
    value: int = Field(..., description="转账金额(wei)")
    value_eth: float = Field(..., description="转账金额(ETH)")

    # Gas信息
    gas: int = Field(..., description="Gas限额")
    gas_price: Optional[int] = Field(None, description="Gas价格")
    max_fee_per_gas: Optional[int] = Field(None, description="最大Gas费")
    max_priority_fee_per_gas: Optional[int] = Field(None, description="最大优先费")
    gas_used: Optional[int] = Field(None, description="实际使用Gas")
    effective_gas_price: Optional[int] = Field(None, description="实际Gas价格")

    # Input数据
    input: str = Field(..., description="原始input数据")
    nonce: int = Field(..., description="发送方nonce")

    # 解析后的数据
    tx_type: TransactionType = Field(..., description="交易类型")
    method_id: Optional[str] = Field(None, description="函数选择器")
    method_name: Optional[str] = Field(None, description="函数名称")
    method_signature: Optional[str] = Field(None, description="函数签名")
    decoded_params: Optional[Dict[str, Any]] = Field(None, description="解码后的参数")

    # 分类与风控
    category: CategoryType = Field(default=CategoryType.UNKNOWN, description="交易分类")
    risk_level: RiskLevel = Field(default=RiskLevel.UNKNOWN, description="风险等级")
    risk_signals: List[str] = Field(default_factory=list, description="风险信号列表")

    # 执行结果
    status: Optional[int] = Field(None, description="执行状态(1成功,0失败)")
    contract_address: Optional[str] = Field(None, description="创建的合约地址")


class TokenTransfer(BaseModel):
    """代币转账事件"""
    tx_hash: str = Field(..., description="交易哈希")
    log_index: int = Field(..., description="日志索引")
    block_number: int = Field(..., description="区块高度")

    token_address: str = Field(..., description="代币合约地址")
    token_type: str = Field(default="ERC20", description="代币类型(ERC20/ERC721/ERC1155)")

    from_address: str = Field(..., description="发送方")
    to_address: str = Field(..., description="接收方")
    value: int = Field(..., description="转账数量(原始值)")
    token_id: Optional[int] = Field(None, description="NFT Token ID")


class EventLog(BaseModel):
    """事件日志"""
    tx_hash: str = Field(..., description="交易哈希")
    log_index: int = Field(..., description="日志索引")
    block_number: int = Field(..., description="区块高度")

    address: str = Field(..., description="合约地址")
    topics: List[str] = Field(..., description="主题列表")
    data: str = Field(..., description="数据")

    # 解析后
    event_name: Optional[str] = Field(None, description="事件名称")
    event_signature: Optional[str] = Field(None, description="事件签名")
    decoded_data: Optional[Dict[str, Any]] = Field(None, description="解码后的数据")


class AddressInfo(BaseModel):
    """地址信息"""
    address: str = Field(..., description="地址")
    is_contract: bool = Field(..., description="是否为合约")
    code_hash: Optional[str] = Field(None, description="合约代码哈希")
    balance: int = Field(default=0, description="ETH余额(wei)")

    # 标签
    labels: List[str] = Field(default_factory=list, description="地址标签")
    risk_level: RiskLevel = Field(default=RiskLevel.UNKNOWN, description="风险等级")

    # 统计信息
    first_seen_block: Optional[int] = Field(None, description="首次出现区块")
    tx_count: int = Field(default=0, description="交易数量")


class FetchTask(BaseModel):
    """采集任务"""
    task_id: str = Field(..., description="任务ID")
    task_type: str = Field(..., description="任务类型(block/range/realtime)")
    start_block: int = Field(..., description="起始区块")
    end_block: Optional[int] = Field(None, description="结束区块")
    status: str = Field(default="pending", description="任务状态")
    created_at: dt = Field(default_factory=dt.now, description="创建时间")
    completed_at: Optional[dt] = Field(None, description="完成时间")
    blocks_processed: int = Field(default=0, description="已处理区块数")
    error_message: Optional[str] = Field(None, description="错误信息")
