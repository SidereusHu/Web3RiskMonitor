"""
行为特征分析器

Phase 2.3: 交易行为特征提取

从交易历史中提取行为特征：
- 交易频率与时间分布
- 金额分布特征
- 交互对象分析
- 操作类型偏好
"""

from dataclasses import dataclass, field
from datetime import datetime as dt, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import Counter, defaultdict
from enum import Enum
import statistics

from src.models.ethereum import Transaction, RiskLevel


class TimePattern(str, Enum):
    """时间模式"""
    RANDOM = "random"               # 随机分布
    BUSINESS_HOURS = "business"     # 工作时间为主
    OFF_HOURS = "off_hours"         # 非工作时间为主
    CONCENTRATED = "concentrated"   # 集中在某时段
    BOT_LIKE = "bot_like"          # 机器人特征（均匀分布）


class AmountPattern(str, Enum):
    """金额模式"""
    MICRO = "micro"                 # 微额（<0.01 ETH）
    SMALL = "small"                 # 小额（0.01-1 ETH）
    MEDIUM = "medium"               # 中等（1-10 ETH）
    LARGE = "large"                 # 大额（10-100 ETH）
    WHALE = "whale"                 # 巨额（>100 ETH）
    MIXED = "mixed"                 # 混合


@dataclass
class BehaviorFeatures:
    """行为特征集"""
    address: str

    # ===== 交易频率特征 =====
    total_tx_count: int = 0
    avg_tx_per_day: float = 0.0
    max_tx_per_day: int = 0
    active_days: int = 0
    first_tx_time: Optional[dt] = None
    last_tx_time: Optional[dt] = None
    account_age_days: int = 0

    # ===== 时间分布特征 =====
    time_pattern: TimePattern = TimePattern.RANDOM
    hourly_distribution: Dict[int, int] = field(default_factory=dict)
    weekday_distribution: Dict[int, int] = field(default_factory=dict)
    peak_hour: int = 0
    peak_weekday: int = 0

    # ===== 金额特征 =====
    amount_pattern: AmountPattern = AmountPattern.MIXED
    total_volume_eth: float = 0.0
    avg_tx_value_eth: float = 0.0
    max_tx_value_eth: float = 0.0
    min_tx_value_eth: float = 0.0
    value_std_dev: float = 0.0

    # ===== 操作类型分布 =====
    operation_distribution: Dict[str, int] = field(default_factory=dict)
    top_methods: List[str] = field(default_factory=list)
    contract_interaction_ratio: float = 0.0  # 合约交互占比
    defi_ratio: float = 0.0                  # DeFi操作占比

    # ===== 交互对象特征 =====
    unique_counterparties: int = 0
    top_counterparties: List[Tuple[str, int]] = field(default_factory=list)
    exchange_interaction_count: int = 0
    defi_protocol_count: int = 0
    mixer_interaction_count: int = 0

    # ===== 风险相关特征 =====
    high_risk_tx_count: int = 0
    suspicious_patterns: List[str] = field(default_factory=list)

    # ===== 聚合指标 =====
    behavior_tags: List[str] = field(default_factory=list)


class BehaviorAnalyzer:
    """行为分析器"""

    def __init__(self):
        """初始化分析器"""
        # 加载已知地址
        from src.parser.signatures import KNOWN_EXCHANGES, KNOWN_DEX_ROUTERS

        self.known_exchanges = set(k.lower() for k in KNOWN_EXCHANGES.keys())
        self.known_dex = set(k.lower() for k in KNOWN_DEX_ROUTERS.keys())

        # DeFi相关Method ID
        self.defi_methods = {
            "0x7ff36ab5", "0x18cbafe5", "0x38ed1739",  # Uniswap V2
            "0x04e45aaf", "0xb858183f",                 # Uniswap V3
            "0xe8eda9df", "0x69328dec",                 # Aave
            "0xa9059cbb", "0x095ea7b3",                 # ERC-20
        }

    def analyze_transactions(
        self,
        address: str,
        transactions: List[Transaction]
    ) -> BehaviorFeatures:
        """分析交易历史提取行为特征

        Args:
            address: 目标地址
            transactions: 该地址相关的交易列表

        Returns:
            BehaviorFeatures 对象
        """
        features = BehaviorFeatures(address=address)

        if not transactions:
            return features

        addr_lower = address.lower()

        # 分离发送和接收
        sent_txs = [tx for tx in transactions if tx.from_address.lower() == addr_lower]
        received_txs = [tx for tx in transactions if tx.to_address and tx.to_address.lower() == addr_lower]

        # 基础统计
        features.total_tx_count = len(transactions)

        # 时间特征
        self._analyze_time_features(features, transactions)

        # 金额特征
        self._analyze_amount_features(features, sent_txs)

        # 操作类型
        self._analyze_operation_features(features, sent_txs)

        # 交互对象
        self._analyze_counterparties(features, transactions, addr_lower)

        # 风险特征
        self._analyze_risk_features(features, transactions)

        # 生成行为标签
        self._generate_behavior_tags(features)

        return features

    def _analyze_time_features(
        self,
        features: BehaviorFeatures,
        transactions: List[Transaction]
    ):
        """分析时间分布特征"""
        if not transactions:
            return

        # 提取时间戳
        timestamps = []
        for tx in transactions:
            if tx.block_timestamp:
                timestamps.append(dt.fromtimestamp(tx.block_timestamp))

        if not timestamps:
            return

        timestamps.sort()

        # 基本时间统计
        features.first_tx_time = timestamps[0]
        features.last_tx_time = timestamps[-1]
        features.account_age_days = (timestamps[-1] - timestamps[0]).days + 1

        # 活跃天数
        active_dates = set(ts.date() for ts in timestamps)
        features.active_days = len(active_dates)

        # 日均交易
        if features.account_age_days > 0:
            features.avg_tx_per_day = len(transactions) / features.account_age_days

        # 单日最大交易数
        date_counts = Counter(ts.date() for ts in timestamps)
        features.max_tx_per_day = max(date_counts.values()) if date_counts else 0

        # 小时分布
        hour_counts = Counter(ts.hour for ts in timestamps)
        features.hourly_distribution = dict(hour_counts)
        features.peak_hour = hour_counts.most_common(1)[0][0] if hour_counts else 0

        # 星期分布
        weekday_counts = Counter(ts.weekday() for ts in timestamps)
        features.weekday_distribution = dict(weekday_counts)
        features.peak_weekday = weekday_counts.most_common(1)[0][0] if weekday_counts else 0

        # 判断时间模式
        features.time_pattern = self._classify_time_pattern(hour_counts, weekday_counts)

    def _classify_time_pattern(
        self,
        hour_counts: Counter,
        weekday_counts: Counter
    ) -> TimePattern:
        """分类时间模式"""
        if not hour_counts:
            return TimePattern.RANDOM

        total = sum(hour_counts.values())

        # 工作时间 (9-18点)
        business_hours = sum(hour_counts.get(h, 0) for h in range(9, 18))
        business_ratio = business_hours / total if total > 0 else 0

        # 检查分布均匀性（机器人特征）
        hour_values = list(hour_counts.values())
        if len(hour_values) >= 12:  # 至少覆盖一半的小时
            cv = statistics.stdev(hour_values) / statistics.mean(hour_values) if statistics.mean(hour_values) > 0 else 0
            if cv < 0.3:  # 变异系数很小，分布均匀
                return TimePattern.BOT_LIKE

        # 检查集中度
        top_3_hours = sum(c for _, c in hour_counts.most_common(3))
        concentration = top_3_hours / total if total > 0 else 0

        if concentration > 0.7:
            return TimePattern.CONCENTRATED
        elif business_ratio > 0.7:
            return TimePattern.BUSINESS_HOURS
        elif business_ratio < 0.3:
            return TimePattern.OFF_HOURS
        else:
            return TimePattern.RANDOM

    def _analyze_amount_features(
        self,
        features: BehaviorFeatures,
        sent_txs: List[Transaction]
    ):
        """分析金额特征"""
        if not sent_txs:
            return

        values = [tx.value_eth for tx in sent_txs]

        features.total_volume_eth = sum(values)
        features.avg_tx_value_eth = statistics.mean(values)
        features.max_tx_value_eth = max(values)
        features.min_tx_value_eth = min(values)

        if len(values) > 1:
            features.value_std_dev = statistics.stdev(values)

        # 判断金额模式
        avg = features.avg_tx_value_eth
        if avg < 0.01:
            features.amount_pattern = AmountPattern.MICRO
        elif avg < 1:
            features.amount_pattern = AmountPattern.SMALL
        elif avg < 10:
            features.amount_pattern = AmountPattern.MEDIUM
        elif avg < 100:
            features.amount_pattern = AmountPattern.LARGE
        else:
            features.amount_pattern = AmountPattern.WHALE

    def _analyze_operation_features(
        self,
        features: BehaviorFeatures,
        sent_txs: List[Transaction]
    ):
        """分析操作类型特征"""
        if not sent_txs:
            return

        # 统计方法调用
        method_counts = Counter()
        contract_calls = 0
        defi_calls = 0

        for tx in sent_txs:
            if tx.method_name:
                method_counts[tx.method_name] += 1

            if tx.method_id:  # 有method_id说明是合约调用
                contract_calls += 1
                if tx.method_id in self.defi_methods:
                    defi_calls += 1

        features.operation_distribution = dict(method_counts)
        features.top_methods = [m for m, _ in method_counts.most_common(5)]
        features.contract_interaction_ratio = contract_calls / len(sent_txs) if sent_txs else 0
        features.defi_ratio = defi_calls / len(sent_txs) if sent_txs else 0

    def _analyze_counterparties(
        self,
        features: BehaviorFeatures,
        transactions: List[Transaction],
        addr_lower: str
    ):
        """分析交互对象"""
        counterparty_counts = Counter()

        for tx in transactions:
            if tx.from_address.lower() == addr_lower and tx.to_address:
                counterparty_counts[tx.to_address.lower()] += 1
            elif tx.to_address and tx.to_address.lower() == addr_lower:
                counterparty_counts[tx.from_address.lower()] += 1

        features.unique_counterparties = len(counterparty_counts)
        features.top_counterparties = counterparty_counts.most_common(10)

        # 统计特定类型交互
        for addr, count in counterparty_counts.items():
            if addr in self.known_exchanges:
                features.exchange_interaction_count += count
            if addr in self.known_dex:
                features.defi_protocol_count += count

    def _analyze_risk_features(
        self,
        features: BehaviorFeatures,
        transactions: List[Transaction]
    ):
        """分析风险特征"""
        features.high_risk_tx_count = sum(
            1 for tx in transactions
            if tx.risk_level in [RiskLevel.HIGH, RiskLevel.ATTENTION]
        )

        # 检测可疑模式
        suspicious = []

        # 模式1: 大量小额交易后一笔大额
        if features.total_tx_count > 10 and features.max_tx_value_eth > features.avg_tx_value_eth * 10:
            suspicious.append("large_tx_after_small_pattern")

        # 模式2: 新账户大额交易
        if features.account_age_days < 7 and features.total_volume_eth > 10:
            suspicious.append("new_account_large_volume")

        # 模式3: 机器人行为 + 高频
        if features.time_pattern == TimePattern.BOT_LIKE and features.avg_tx_per_day > 10:
            suspicious.append("automated_high_frequency")

        # 模式4: 与交易所高频互动
        if features.exchange_interaction_count > features.total_tx_count * 0.5:
            suspicious.append("heavy_exchange_interaction")

        features.suspicious_patterns = suspicious

    def _generate_behavior_tags(self, features: BehaviorFeatures):
        """生成行为标签"""
        tags = []

        # 基于频率
        if features.avg_tx_per_day > 50:
            tags.append("HIGH_FREQUENCY_TRADER")
        elif features.avg_tx_per_day > 10:
            tags.append("ACTIVE_TRADER")

        # 基于金额
        if features.amount_pattern == AmountPattern.WHALE:
            tags.append("WHALE")
        elif features.total_volume_eth > 1000:
            tags.append("HIGH_VOLUME")

        # 基于时间模式
        if features.time_pattern == TimePattern.BOT_LIKE:
            tags.append("BOT_SUSPECTED")

        # 基于操作类型
        if features.defi_ratio > 0.7:
            tags.append("DEFI_POWER_USER")
        if features.contract_interaction_ratio > 0.9:
            tags.append("CONTRACT_HEAVY")

        # 基于交互对象
        if features.unique_counterparties < 5 and features.total_tx_count > 20:
            tags.append("CONCENTRATED_INTERACTIONS")
        if features.exchange_interaction_count > 10:
            tags.append("EXCHANGE_USER")

        features.behavior_tags = tags

    def get_behavior_summary(self, features: BehaviorFeatures) -> Dict[str, Any]:
        """获取行为摘要"""
        return {
            "address": features.address,
            "tx_count": features.total_tx_count,
            "account_age_days": features.account_age_days,
            "avg_tx_per_day": round(features.avg_tx_per_day, 2),
            "total_volume_eth": round(features.total_volume_eth, 4),
            "time_pattern": features.time_pattern.value,
            "amount_pattern": features.amount_pattern.value,
            "unique_counterparties": features.unique_counterparties,
            "contract_ratio": round(features.contract_interaction_ratio * 100, 1),
            "defi_ratio": round(features.defi_ratio * 100, 1),
            "behavior_tags": features.behavior_tags,
            "suspicious_patterns": features.suspicious_patterns,
            "top_methods": features.top_methods[:5],
        }
