"""
智能合约数据模型

定义合约分析相关的数据结构：
- 合约基本信息
- 字节码特征
- 漏洞类型与报告
- 风险评估结果
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt
from typing import Dict, List, Optional, Any, Set
from enum import Enum


class ContractType(str, Enum):
    """合约类型"""
    UNKNOWN = "unknown"
    ERC20 = "erc20"                      # ERC-20代币
    ERC721 = "erc721"                    # ERC-721 NFT
    ERC1155 = "erc1155"                  # ERC-1155多代币
    PROXY = "proxy"                      # 代理合约
    UPGRADEABLE = "upgradeable"          # 可升级合约
    MULTISIG = "multisig"                # 多签钱包
    DEX_ROUTER = "dex_router"            # DEX路由器
    DEX_PAIR = "dex_pair"                # DEX交易对
    LENDING = "lending"                  # 借贷协议
    BRIDGE = "bridge"                    # 跨链桥
    STAKING = "staking"                  # 质押合约
    GOVERNANCE = "governance"            # 治理合约
    MIXER = "mixer"                      # 混币器


class VulnerabilityType(str, Enum):
    """漏洞类型"""
    # 重入攻击
    REENTRANCY = "reentrancy"

    # 整数溢出
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"

    # 访问控制
    UNPROTECTED_FUNCTION = "unprotected_function"
    MISSING_ACCESS_CONTROL = "missing_access_control"
    TX_ORIGIN_AUTH = "tx_origin_auth"

    # 逻辑漏洞
    UNCHECKED_RETURN = "unchecked_return"
    UNCHECKED_CALL = "unchecked_call"
    UNCHECKED_SEND = "unchecked_send"

    # 代理相关
    DELEGATECALL_INJECTION = "delegatecall_injection"
    STORAGE_COLLISION = "storage_collision"
    UNINITIALIZED_PROXY = "uninitialized_proxy"

    # 闪电贷相关
    FLASH_LOAN_VULNERABLE = "flash_loan_vulnerable"
    PRICE_MANIPULATION = "price_manipulation"

    # 其他
    SELFDESTRUCT = "selfdestruct"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    BLOCK_NUMBER_DEPENDENCE = "block_number_dependence"
    FRONT_RUNNING = "front_running"
    DOS_GAS_LIMIT = "dos_gas_limit"

    # 代币特定
    HIDDEN_MINT = "hidden_mint"
    HIDDEN_FEE = "hidden_fee"
    HONEYPOT = "honeypot"
    BLACKLIST_FUNCTION = "blacklist_function"
    PAUSE_FUNCTION = "pause_function"

    # 中心化风险
    OWNER_PRIVILEGE = "owner_privilege"
    CENTRALIZED_CONTROL = "centralized_control"


class VulnerabilitySeverity(str, Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"    # 可直接导致资金损失
    HIGH = "high"            # 高风险，需要特定条件
    MEDIUM = "medium"        # 中等风险
    LOW = "low"              # 低风险
    INFO = "info"            # 信息性发现


@dataclass
class Vulnerability:
    """漏洞信息"""
    vuln_type: VulnerabilityType
    severity: VulnerabilitySeverity
    title: str
    description: str

    # 位置信息
    location: Optional[str] = None       # 函数名或代码位置
    bytecode_offset: Optional[int] = None

    # 详细信息
    details: Dict[str, Any] = dc_field(default_factory=dict)

    # 修复建议
    recommendation: str = ""

    # 参考
    references: List[str] = dc_field(default_factory=list)
    cwe_id: Optional[str] = None         # CWE编号
    swc_id: Optional[str] = None         # SWC编号（智能合约弱点分类）

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.vuln_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "bytecode_offset": self.bytecode_offset,
            "details": self.details,
            "recommendation": self.recommendation,
            "references": self.references,
            "cwe_id": self.cwe_id,
            "swc_id": self.swc_id,
        }


@dataclass
class BytecodeFeatures:
    """字节码特征"""
    # 基本信息
    bytecode_hash: str = ""
    bytecode_size: int = 0

    # 操作码统计
    opcode_count: Dict[str, int] = dc_field(default_factory=dict)

    # 检测到的函数选择器
    function_selectors: List[str] = dc_field(default_factory=list)

    # 特征标志
    has_delegatecall: bool = False
    has_selfdestruct: bool = False
    has_create: bool = False
    has_create2: bool = False
    has_callcode: bool = False
    has_staticcall: bool = False

    # 外部调用
    external_calls: List[str] = dc_field(default_factory=list)

    # 存储访问
    storage_reads: int = 0
    storage_writes: int = 0

    # 代码模式
    is_proxy: bool = False
    is_minimal_proxy: bool = False       # EIP-1167
    is_upgradeable: bool = False

    # 标准接口
    implements_erc20: bool = False
    implements_erc721: bool = False
    implements_erc1155: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bytecode_hash": self.bytecode_hash,
            "bytecode_size": self.bytecode_size,
            "opcode_count": self.opcode_count,
            "function_selectors": self.function_selectors,
            "has_delegatecall": self.has_delegatecall,
            "has_selfdestruct": self.has_selfdestruct,
            "has_create": self.has_create,
            "has_create2": self.has_create2,
            "is_proxy": self.is_proxy,
            "is_upgradeable": self.is_upgradeable,
            "implements_erc20": self.implements_erc20,
            "implements_erc721": self.implements_erc721,
        }


@dataclass
class ContractInfo:
    """合约信息"""
    address: str

    # 链上数据
    bytecode: str = ""
    bytecode_hash: str = ""
    creator: Optional[str] = None
    creation_tx: Optional[str] = None
    creation_time: Optional[dt] = None

    # 合约类型
    contract_type: ContractType = ContractType.UNKNOWN
    contract_name: Optional[str] = None

    # 验证信息
    is_verified: bool = False
    source_code: Optional[str] = None
    compiler_version: Optional[str] = None
    optimization_enabled: bool = False

    # ABI
    abi: Optional[List[Dict]] = None

    # 字节码特征
    features: Optional[BytecodeFeatures] = None

    # 标签
    labels: List[str] = dc_field(default_factory=list)

    # 统计
    tx_count: int = 0
    unique_callers: int = 0
    total_value_received: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "bytecode_hash": self.bytecode_hash,
            "creator": self.creator,
            "creation_tx": self.creation_tx,
            "creation_time": self.creation_time.isoformat() if self.creation_time else None,
            "contract_type": self.contract_type.value,
            "contract_name": self.contract_name,
            "is_verified": self.is_verified,
            "compiler_version": self.compiler_version,
            "features": self.features.to_dict() if self.features else None,
            "labels": self.labels,
        }


@dataclass
class ContractRiskReport:
    """合约风险报告"""
    address: str
    analyzed_at: dt = dc_field(default_factory=dt.now)

    # 合约信息
    contract_info: Optional[ContractInfo] = None

    # 发现的漏洞
    vulnerabilities: List[Vulnerability] = dc_field(default_factory=list)

    # 风险评分
    risk_score: int = 0                  # 0-100
    risk_level: str = "unknown"

    # 分类评分
    security_score: int = 100            # 安全性评分（100 - 漏洞扣分）
    centralization_score: int = 0        # 中心化程度（0最低，100最高）
    code_quality_score: int = 100        # 代码质量评分

    # 风险因素
    risk_factors: List[str] = dc_field(default_factory=list)

    # 建议
    recommendations: List[str] = dc_field(default_factory=list)

    # 统计
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # 元数据
    analysis_version: str = "1.0"
    analysis_time_ms: float = 0.0

    def count_by_severity(self):
        """按严重程度统计漏洞"""
        self.critical_count = sum(1 for v in self.vulnerabilities
                                   if v.severity == VulnerabilitySeverity.CRITICAL)
        self.high_count = sum(1 for v in self.vulnerabilities
                               if v.severity == VulnerabilitySeverity.HIGH)
        self.medium_count = sum(1 for v in self.vulnerabilities
                                 if v.severity == VulnerabilitySeverity.MEDIUM)
        self.low_count = sum(1 for v in self.vulnerabilities
                              if v.severity == VulnerabilitySeverity.LOW)
        self.info_count = sum(1 for v in self.vulnerabilities
                               if v.severity == VulnerabilitySeverity.INFO)

    def to_dict(self) -> Dict[str, Any]:
        self.count_by_severity()
        return {
            "address": self.address,
            "analyzed_at": self.analyzed_at.isoformat(),
            "contract_info": self.contract_info.to_dict() if self.contract_info else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "security_score": self.security_score,
            "centralization_score": self.centralization_score,
            "code_quality_score": self.code_quality_score,
            "risk_factors": self.risk_factors,
            "recommendations": self.recommendations,
            "stats": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "analysis_version": self.analysis_version,
            "analysis_time_ms": self.analysis_time_ms,
        }

    def summary(self) -> str:
        """生成摘要"""
        self.count_by_severity()
        lines = [
            f"Contract Risk Report: {self.address}",
            f"Risk Score: {self.risk_score}/100 ({self.risk_level})",
            f"Vulnerabilities: {len(self.vulnerabilities)} total",
            f"  - Critical: {self.critical_count}",
            f"  - High: {self.high_count}",
            f"  - Medium: {self.medium_count}",
            f"  - Low: {self.low_count}",
        ]
        if self.risk_factors:
            lines.append("Risk Factors:")
            for factor in self.risk_factors[:5]:
                lines.append(f"  - {factor}")
        return "\n".join(lines)
