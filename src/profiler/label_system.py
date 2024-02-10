"""
地址标签体系

Phase 2.2: 多维度标签管理

标签分类：
- 实体标签：交易所、项目方、个人等
- 行为标签：高频交易者、套利者、MEV等
- 风险标签：制裁、黑名单、可疑等
- 合约标签：代币、DEX、借贷等
"""

from enum import Enum
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime as dt


class LabelCategory(str, Enum):
    """标签类别"""
    ENTITY = "entity"           # 实体标签
    BEHAVIOR = "behavior"       # 行为标签
    RISK = "risk"               # 风险标签
    CONTRACT = "contract"       # 合约标签
    CUSTOM = "custom"           # 自定义标签


class RiskTier(str, Enum):
    """风险层级"""
    CRITICAL = "critical"       # 致命风险（制裁地址）
    HIGH = "high"               # 高风险
    MEDIUM = "medium"           # 中风险
    LOW = "low"                 # 低风险
    NONE = "none"               # 无风险


@dataclass
class Label:
    """标签定义"""
    name: str                                 # 标签名称
    category: LabelCategory                   # 标签类别
    risk_tier: RiskTier = RiskTier.NONE      # 关联风险层级
    description: str = ""                     # 描述
    source: str = "system"                    # 来源
    confidence: float = 1.0                   # 置信度 (0-1)
    created_at: dt = field(default_factory=dt.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AddressLabels:
    """地址标签集合"""
    address: str
    labels: List[Label] = field(default_factory=list)
    risk_score: float = 0.0                   # 综合风险评分 (0-100)
    highest_risk: RiskTier = RiskTier.NONE
    last_updated: dt = field(default_factory=dt.now)

    def add_label(self, label: Label):
        """添加标签"""
        # 避免重复
        existing_names = {l.name for l in self.labels}
        if label.name not in existing_names:
            self.labels.append(label)
            self._update_risk()

    def remove_label(self, label_name: str):
        """移除标签"""
        self.labels = [l for l in self.labels if l.name != label_name]
        self._update_risk()

    def has_label(self, label_name: str) -> bool:
        """检查是否有某标签"""
        return any(l.name == label_name for l in self.labels)

    def get_labels_by_category(self, category: LabelCategory) -> List[Label]:
        """获取某类别的所有标签"""
        return [l for l in self.labels if l.category == category]

    def _update_risk(self):
        """更新风险评估"""
        if not self.labels:
            self.risk_score = 0.0
            self.highest_risk = RiskTier.NONE
            return

        # 风险权重
        risk_weights = {
            RiskTier.CRITICAL: 100,
            RiskTier.HIGH: 70,
            RiskTier.MEDIUM: 40,
            RiskTier.LOW: 15,
            RiskTier.NONE: 0,
        }

        # 计算最高风险
        risk_labels = [l for l in self.labels if l.risk_tier != RiskTier.NONE]
        if risk_labels:
            self.highest_risk = max(risk_labels, key=lambda l: risk_weights[l.risk_tier]).risk_tier
        else:
            self.highest_risk = RiskTier.NONE

        # 计算综合风险分数
        scores = [risk_weights[l.risk_tier] * l.confidence for l in self.labels]
        self.risk_score = min(100, sum(scores))


class LabelManager:
    """标签管理器"""

    def __init__(self):
        # 预定义标签库
        self.predefined_labels = self._init_predefined_labels()

        # 地址-标签映射
        self.address_labels: Dict[str, AddressLabels] = {}

        # 加载已知地址标签
        self._load_known_labels()

    def _init_predefined_labels(self) -> Dict[str, Label]:
        """初始化预定义标签"""
        labels = {}

        # ========== 实体标签 ==========
        entity_labels = [
            ("CEX", "中心化交易所", RiskTier.NONE),
            ("DEX", "去中心化交易所", RiskTier.NONE),
            ("CEX_HOT_WALLET", "交易所热钱包", RiskTier.NONE),
            ("CEX_COLD_WALLET", "交易所冷钱包", RiskTier.NONE),
            ("MINING_POOL", "矿池", RiskTier.NONE),
            ("STAKING_POOL", "质押池", RiskTier.NONE),
            ("PROJECT_TREASURY", "项目金库", RiskTier.NONE),
            ("VC_FUND", "风投基金", RiskTier.NONE),
            ("WHALE", "巨鲸", RiskTier.LOW),
        ]

        for name, desc, risk in entity_labels:
            labels[name] = Label(
                name=name,
                category=LabelCategory.ENTITY,
                risk_tier=risk,
                description=desc,
            )

        # ========== 行为标签 ==========
        behavior_labels = [
            ("HIGH_FREQUENCY_TRADER", "高频交易者", RiskTier.NONE),
            ("ARBITRAGEUR", "套利者", RiskTier.NONE),
            ("MEV_BOT", "MEV机器人", RiskTier.LOW),
            ("SANDWICH_ATTACKER", "三明治攻击者", RiskTier.MEDIUM),
            ("FLASHLOAN_USER", "闪电贷用户", RiskTier.LOW),
            ("AIRDROP_HUNTER", "空投猎人", RiskTier.NONE),
            ("NFT_TRADER", "NFT交易者", RiskTier.NONE),
            ("DEFI_POWER_USER", "DeFi高级用户", RiskTier.NONE),
            ("LIQUIDITY_PROVIDER", "流动性提供者", RiskTier.NONE),
            ("GOVERNANCE_PARTICIPANT", "治理参与者", RiskTier.NONE),
        ]

        for name, desc, risk in behavior_labels:
            labels[name] = Label(
                name=name,
                category=LabelCategory.BEHAVIOR,
                risk_tier=risk,
                description=desc,
            )

        # ========== 风险标签 ==========
        risk_labels = [
            ("OFAC_SANCTIONED", "OFAC制裁地址", RiskTier.CRITICAL),
            ("MIXER_USER", "混币器用户", RiskTier.HIGH),
            ("MIXER_CONTRACT", "混币器合约", RiskTier.CRITICAL),
            ("PHISHING", "钓鱼地址", RiskTier.CRITICAL),
            ("SCAM", "诈骗地址", RiskTier.CRITICAL),
            ("HACK_RELATED", "黑客相关", RiskTier.CRITICAL),
            ("RUGPULL", "跑路项目", RiskTier.CRITICAL),
            ("MONEY_LAUNDERING", "洗钱嫌疑", RiskTier.HIGH),
            ("DARKNET", "暗网关联", RiskTier.HIGH),
            ("SUSPICIOUS_ACTIVITY", "可疑活动", RiskTier.MEDIUM),
            ("HIGH_RISK_INTERACTION", "高风险交互", RiskTier.MEDIUM),
            ("NEW_ADDRESS_LARGE_TX", "新地址大额交易", RiskTier.LOW),
            ("UNLIMITED_APPROVAL", "无限授权", RiskTier.LOW),
        ]

        for name, desc, risk in risk_labels:
            labels[name] = Label(
                name=name,
                category=LabelCategory.RISK,
                risk_tier=risk,
                description=desc,
            )

        # ========== 合约标签 ==========
        contract_labels = [
            ("ERC20_TOKEN", "ERC-20代币", RiskTier.NONE),
            ("ERC721_NFT", "ERC-721 NFT", RiskTier.NONE),
            ("ERC1155_MULTI", "ERC-1155多代币", RiskTier.NONE),
            ("UNISWAP_PAIR", "Uniswap交易对", RiskTier.NONE),
            ("LENDING_PROTOCOL", "借贷协议", RiskTier.NONE),
            ("YIELD_FARM", "收益农场", RiskTier.NONE),
            ("BRIDGE", "跨链桥", RiskTier.LOW),
            ("MULTISIG_WALLET", "多签钱包", RiskTier.NONE),
            ("PROXY_CONTRACT", "代理合约", RiskTier.NONE),
            ("UNVERIFIED_CONTRACT", "未验证合约", RiskTier.LOW),
            ("NEW_CONTRACT", "新部署合约", RiskTier.LOW),
        ]

        for name, desc, risk in contract_labels:
            labels[name] = Label(
                name=name,
                category=LabelCategory.CONTRACT,
                risk_tier=risk,
                description=desc,
            )

        return labels

    def _load_known_labels(self):
        """加载已知地址的标签"""
        from src.parser.signatures import (
            SANCTIONED_ADDRESSES, KNOWN_EXCHANGES, KNOWN_DEX_ROUTERS
        )

        # 制裁地址
        for addr, info in SANCTIONED_ADDRESSES.items():
            addr_lower = addr.lower()
            self.address_labels[addr_lower] = AddressLabels(address=addr_lower)
            self.address_labels[addr_lower].add_label(Label(
                name="OFAC_SANCTIONED",
                category=LabelCategory.RISK,
                risk_tier=RiskTier.CRITICAL,
                description=info.get("description", "OFAC Sanctioned"),
                metadata={"entity_name": info.get("name", "")},
            ))
            self.address_labels[addr_lower].add_label(Label(
                name="MIXER_CONTRACT",
                category=LabelCategory.RISK,
                risk_tier=RiskTier.CRITICAL,
                description="Tornado Cash",
            ))

        # 交易所
        for addr, name in KNOWN_EXCHANGES.items():
            addr_lower = addr.lower()
            self.address_labels[addr_lower] = AddressLabels(address=addr_lower)

            wallet_type = "CEX_HOT_WALLET" if "Hot" in name else "CEX_COLD_WALLET"
            self.address_labels[addr_lower].add_label(Label(
                name=wallet_type,
                category=LabelCategory.ENTITY,
                risk_tier=RiskTier.NONE,
                description=name,
                metadata={"exchange": name.split()[0]},
            ))

        # DEX
        for addr, name in KNOWN_DEX_ROUTERS.items():
            addr_lower = addr.lower()
            self.address_labels[addr_lower] = AddressLabels(address=addr_lower)
            self.address_labels[addr_lower].add_label(Label(
                name="DEX",
                category=LabelCategory.ENTITY,
                risk_tier=RiskTier.NONE,
                description=name,
            ))

    def get_labels(self, address: str) -> AddressLabels:
        """获取地址的所有标签"""
        addr_lower = address.lower()
        if addr_lower not in self.address_labels:
            self.address_labels[addr_lower] = AddressLabels(address=addr_lower)
        return self.address_labels[addr_lower]

    def add_label(
        self,
        address: str,
        label_name: str,
        source: str = "system",
        confidence: float = 1.0,
        metadata: Optional[Dict] = None
    ):
        """为地址添加标签"""
        addr_lower = address.lower()

        # 获取预定义标签或创建新标签
        if label_name in self.predefined_labels:
            label = Label(
                name=self.predefined_labels[label_name].name,
                category=self.predefined_labels[label_name].category,
                risk_tier=self.predefined_labels[label_name].risk_tier,
                description=self.predefined_labels[label_name].description,
                source=source,
                confidence=confidence,
                metadata=metadata or {},
            )
        else:
            label = Label(
                name=label_name,
                category=LabelCategory.CUSTOM,
                risk_tier=RiskTier.NONE,
                source=source,
                confidence=confidence,
                metadata=metadata or {},
            )

        addr_labels = self.get_labels(addr_lower)
        addr_labels.add_label(label)

    def check_risk(self, address: str) -> Dict[str, Any]:
        """检查地址风险"""
        addr_labels = self.get_labels(address.lower())

        return {
            "address": address,
            "risk_score": addr_labels.risk_score,
            "highest_risk": addr_labels.highest_risk.value,
            "is_sanctioned": addr_labels.has_label("OFAC_SANCTIONED"),
            "risk_labels": [
                l.name for l in addr_labels.labels
                if l.category == LabelCategory.RISK
            ],
            "all_labels": [l.name for l in addr_labels.labels],
        }

    def get_predefined_label(self, name: str) -> Optional[Label]:
        """获取预定义标签"""
        return self.predefined_labels.get(name)

    def list_predefined_labels(self, category: Optional[LabelCategory] = None) -> List[Label]:
        """列出预定义标签"""
        labels = list(self.predefined_labels.values())
        if category:
            labels = [l for l in labels if l.category == category]
        return labels
