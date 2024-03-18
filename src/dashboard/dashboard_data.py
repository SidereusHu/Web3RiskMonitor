"""
仪表盘数据聚合器

聚合各模块数据，提供仪表盘展示所需的统计信息
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from collections import defaultdict
import statistics


@dataclass
class TimeSeriesData:
    """时间序列数据"""
    timestamps: List[dt] = dc_field(default_factory=list)
    values: List[float] = dc_field(default_factory=list)
    label: str = ""

    def add_point(self, timestamp: dt, value: float):
        """添加数据点"""
        self.timestamps.append(timestamp)
        self.values.append(value)

    def get_recent(self, hours: int = 24) -> "TimeSeriesData":
        """获取最近N小时数据"""
        cutoff = dt.now() - timedelta(hours=hours)
        recent = TimeSeriesData(label=self.label)
        for ts, val in zip(self.timestamps, self.values):
            if ts >= cutoff:
                recent.add_point(ts, val)
        return recent

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "label": self.label,
            "data": [
                {"timestamp": ts.isoformat(), "value": val}
                for ts, val in zip(self.timestamps, self.values)
            ]
        }


@dataclass
class RiskDistribution:
    """风险分布"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    minimal: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.minimal

    def to_dict(self) -> Dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "minimal": self.minimal,
            "total": self.total,
        }

    def percentages(self) -> Dict[str, float]:
        """百分比分布"""
        total = self.total
        if total == 0:
            return {k: 0.0 for k in ["critical", "high", "medium", "low", "minimal"]}
        return {
            "critical": round(self.critical / total * 100, 1),
            "high": round(self.high / total * 100, 1),
            "medium": round(self.medium / total * 100, 1),
            "low": round(self.low / total * 100, 1),
            "minimal": round(self.minimal / total * 100, 1),
        }


@dataclass
class DashboardMetrics:
    """仪表盘核心指标"""
    # 总览
    total_addresses_monitored: int = 0
    total_transactions_analyzed: int = 0
    total_contracts_scanned: int = 0
    total_alerts_generated: int = 0

    # 风险分布
    address_risk_distribution: RiskDistribution = dc_field(default_factory=RiskDistribution)
    contract_risk_distribution: RiskDistribution = dc_field(default_factory=RiskDistribution)

    # 告警统计
    active_alerts: int = 0
    resolved_alerts: int = 0
    false_positive_rate: float = 0.0

    # 实时指标
    transactions_per_minute: float = 0.0
    alerts_per_hour: float = 0.0
    average_risk_score: float = 0.0

    # 趋势
    risk_trend: str = "stable"  # rising, falling, stable
    alert_trend: str = "stable"

    # 时间范围
    data_start_time: Optional[dt] = None
    data_end_time: Optional[dt] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "overview": {
                "addresses_monitored": self.total_addresses_monitored,
                "transactions_analyzed": self.total_transactions_analyzed,
                "contracts_scanned": self.total_contracts_scanned,
                "alerts_generated": self.total_alerts_generated,
            },
            "risk_distribution": {
                "addresses": self.address_risk_distribution.to_dict(),
                "contracts": self.contract_risk_distribution.to_dict(),
            },
            "alerts": {
                "active": self.active_alerts,
                "resolved": self.resolved_alerts,
                "false_positive_rate": self.false_positive_rate,
            },
            "realtime": {
                "transactions_per_minute": self.transactions_per_minute,
                "alerts_per_hour": self.alerts_per_hour,
                "average_risk_score": self.average_risk_score,
            },
            "trends": {
                "risk": self.risk_trend,
                "alerts": self.alert_trend,
            },
            "time_range": {
                "start": self.data_start_time.isoformat() if self.data_start_time else None,
                "end": self.data_end_time.isoformat() if self.data_end_time else None,
            }
        }


class AggregationPeriod(Enum):
    """聚合周期"""
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


@dataclass
class TopRiskItem:
    """高风险项目"""
    identifier: str  # 地址或合约
    risk_score: int
    risk_level: str
    category: str  # address, contract, transaction
    last_activity: dt
    alert_count: int = 0
    details: Dict[str, Any] = dc_field(default_factory=dict)


class DashboardDataAggregator:
    """仪表盘数据聚合器"""

    def __init__(self):
        # 存储
        self._address_risks: Dict[str, int] = {}
        self._contract_risks: Dict[str, int] = {}
        self._alerts: List[Dict[str, Any]] = []
        self._transactions: List[Dict[str, Any]] = []

        # 时间序列
        self._risk_score_series = TimeSeriesData(label="average_risk_score")
        self._alert_count_series = TimeSeriesData(label="alert_count")
        self._transaction_count_series = TimeSeriesData(label="transaction_count")

        # 统计
        self._start_time = dt.now()

    def record_address_risk(self, address: str, risk_score: int, risk_level: str):
        """记录地址风险"""
        self._address_risks[address.lower()] = risk_score

    def record_contract_risk(self, address: str, risk_score: int, risk_level: str):
        """记录合约风险"""
        self._contract_risks[address.lower()] = risk_score

    def record_alert(self, alert: Dict[str, Any]):
        """记录告警"""
        self._alerts.append({
            **alert,
            "recorded_at": dt.now(),
        })

    def record_transaction(self, tx: Dict[str, Any]):
        """记录交易"""
        self._transactions.append({
            **tx,
            "recorded_at": dt.now(),
        })

    def get_metrics(self) -> DashboardMetrics:
        """获取仪表盘指标"""
        metrics = DashboardMetrics()

        # 总览
        metrics.total_addresses_monitored = len(self._address_risks)
        metrics.total_contracts_scanned = len(self._contract_risks)
        metrics.total_transactions_analyzed = len(self._transactions)
        metrics.total_alerts_generated = len(self._alerts)

        # 地址风险分布
        metrics.address_risk_distribution = self._calculate_risk_distribution(
            list(self._address_risks.values())
        )

        # 合约风险分布
        metrics.contract_risk_distribution = self._calculate_risk_distribution(
            list(self._contract_risks.values())
        )

        # 告警统计
        active = sum(1 for a in self._alerts if a.get("status") != "resolved")
        resolved = sum(1 for a in self._alerts if a.get("status") == "resolved")
        false_positives = sum(1 for a in self._alerts if a.get("is_false_positive", False))

        metrics.active_alerts = active
        metrics.resolved_alerts = resolved
        metrics.false_positive_rate = (
            false_positives / len(self._alerts) * 100 if self._alerts else 0
        )

        # 实时指标
        now = dt.now()
        one_minute_ago = now - timedelta(minutes=1)
        one_hour_ago = now - timedelta(hours=1)

        recent_txs = sum(
            1 for tx in self._transactions
            if tx.get("recorded_at", now) >= one_minute_ago
        )
        recent_alerts = sum(
            1 for a in self._alerts
            if a.get("recorded_at", now) >= one_hour_ago
        )

        metrics.transactions_per_minute = recent_txs
        metrics.alerts_per_hour = recent_alerts

        # 平均风险分
        all_risks = list(self._address_risks.values()) + list(self._contract_risks.values())
        metrics.average_risk_score = (
            statistics.mean(all_risks) if all_risks else 0
        )

        # 趋势分析
        metrics.risk_trend = self._analyze_trend(self._risk_score_series)
        metrics.alert_trend = self._analyze_trend(self._alert_count_series)

        # 时间范围
        metrics.data_start_time = self._start_time
        metrics.data_end_time = now

        return metrics

    def _calculate_risk_distribution(self, scores: List[int]) -> RiskDistribution:
        """计算风险分布"""
        dist = RiskDistribution()
        for score in scores:
            if score >= 80:
                dist.critical += 1
            elif score >= 60:
                dist.high += 1
            elif score >= 40:
                dist.medium += 1
            elif score >= 20:
                dist.low += 1
            else:
                dist.minimal += 1
        return dist

    def _analyze_trend(self, series: TimeSeriesData) -> str:
        """分析趋势"""
        if len(series.values) < 2:
            return "stable"

        recent = series.values[-5:] if len(series.values) >= 5 else series.values
        if len(recent) < 2:
            return "stable"

        # 简单线性趋势
        first_half = statistics.mean(recent[:len(recent)//2]) if recent[:len(recent)//2] else 0
        second_half = statistics.mean(recent[len(recent)//2:]) if recent[len(recent)//2:] else 0

        diff = second_half - first_half
        threshold = 0.1 * first_half if first_half > 0 else 1

        if diff > threshold:
            return "rising"
        elif diff < -threshold:
            return "falling"
        return "stable"

    def get_top_risks(
        self,
        category: str = "all",
        limit: int = 10
    ) -> List[TopRiskItem]:
        """获取高风险项目"""
        items = []

        if category in ("all", "address"):
            for addr, score in self._address_risks.items():
                items.append(TopRiskItem(
                    identifier=addr,
                    risk_score=score,
                    risk_level=self._score_to_level(score),
                    category="address",
                    last_activity=dt.now(),
                    alert_count=sum(
                        1 for a in self._alerts
                        if a.get("address", "").lower() == addr
                    ),
                ))

        if category in ("all", "contract"):
            for addr, score in self._contract_risks.items():
                items.append(TopRiskItem(
                    identifier=addr,
                    risk_score=score,
                    risk_level=self._score_to_level(score),
                    category="contract",
                    last_activity=dt.now(),
                    alert_count=sum(
                        1 for a in self._alerts
                        if a.get("contract", "").lower() == addr
                    ),
                ))

        # 按风险分排序
        items.sort(key=lambda x: x.risk_score, reverse=True)
        return items[:limit]

    def _score_to_level(self, score: int) -> str:
        """分数转等级"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "minimal"

    def get_time_series(
        self,
        metric: str,
        period: AggregationPeriod = AggregationPeriod.HOUR,
        hours: int = 24
    ) -> TimeSeriesData:
        """获取时间序列数据"""
        if metric == "risk_score":
            return self._risk_score_series.get_recent(hours)
        elif metric == "alert_count":
            return self._alert_count_series.get_recent(hours)
        elif metric == "transaction_count":
            return self._transaction_count_series.get_recent(hours)
        return TimeSeriesData(label=metric)

    def get_alert_summary(self) -> Dict[str, Any]:
        """获取告警摘要"""
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        by_status = defaultdict(int)

        for alert in self._alerts:
            by_severity[alert.get("severity", "unknown")] += 1
            by_type[alert.get("type", "unknown")] += 1
            by_status[alert.get("status", "pending")] += 1

        return {
            "total": len(self._alerts),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "by_status": dict(by_status),
        }

    def get_category_statistics(self) -> Dict[str, Any]:
        """获取分类统计"""
        address_categories = defaultdict(int)
        contract_types = defaultdict(int)

        # 模拟分类统计
        for addr in self._address_risks:
            # 基于地址特征分类
            if addr.startswith("0x000"):
                address_categories["exchange"] += 1
            elif addr.startswith("0xdead"):
                address_categories["burn"] += 1
            else:
                address_categories["normal"] += 1

        return {
            "address_categories": dict(address_categories),
            "contract_types": dict(contract_types),
        }

    def export_snapshot(self) -> Dict[str, Any]:
        """导出数据快照"""
        return {
            "timestamp": dt.now().isoformat(),
            "metrics": self.get_metrics().to_dict(),
            "top_risks": [
                {
                    "identifier": r.identifier,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "category": r.category,
                }
                for r in self.get_top_risks(limit=20)
            ],
            "alert_summary": self.get_alert_summary(),
            "statistics": {
                "addresses": len(self._address_risks),
                "contracts": len(self._contract_risks),
                "transactions": len(self._transactions),
                "alerts": len(self._alerts),
            }
        }

    def clear(self):
        """清空数据"""
        self._address_risks.clear()
        self._contract_risks.clear()
        self._alerts.clear()
        self._transactions.clear()
        self._risk_score_series = TimeSeriesData(label="average_risk_score")
        self._alert_count_series = TimeSeriesData(label="alert_count")
        self._transaction_count_series = TimeSeriesData(label="transaction_count")
        self._start_time = dt.now()
