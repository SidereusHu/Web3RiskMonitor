"""
地址画像服务

Phase 2.5: 整合所有分析模块，提供统一的画像API

功能：
- 综合地址分析
- 画像生成
- 风险评估
"""

from dataclasses import dataclass, field
from datetime import datetime as dt
from typing import Dict, List, Optional, Any

from src.profiler.address_analyzer import AddressAnalyzer, AddressProfile, AddressType
from src.profiler.label_system import LabelManager, LabelCategory, RiskTier
from src.profiler.behavior_analyzer import BehaviorAnalyzer, BehaviorFeatures
from src.profiler.address_graph import AddressGraph, GraphBuilder
from src.models.ethereum import Transaction


@dataclass
class ComprehensiveProfile:
    """综合画像"""
    address: str
    analyzed_at: dt = field(default_factory=dt.now)

    # 基础信息
    basic: Optional[AddressProfile] = None

    # 行为特征
    behavior: Optional[BehaviorFeatures] = None

    # 标签
    labels: List[str] = field(default_factory=list)
    risk_labels: List[str] = field(default_factory=list)

    # 关联分析
    direct_contacts: int = 0
    contact_with_risk: int = 0

    # 综合评分
    risk_score: float = 0.0
    risk_tier: str = "unknown"
    risk_factors: List[str] = field(default_factory=list)

    # 画像摘要
    summary: Dict[str, Any] = field(default_factory=dict)


class AddressProfiler:
    """地址画像服务"""

    def __init__(self, rpc_url: Optional[str] = None):
        """初始化画像服务"""
        self.address_analyzer = AddressAnalyzer(rpc_url)
        self.label_manager = LabelManager()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.graph_builder = GraphBuilder()

    def profile_address(
        self,
        address: str,
        transactions: Optional[List[Transaction]] = None,
        include_behavior: bool = True,
        include_graph: bool = True
    ) -> ComprehensiveProfile:
        """生成完整地址画像

        Args:
            address: 目标地址
            transactions: 相关交易列表（可选）
            include_behavior: 是否包含行为分析
            include_graph: 是否包含图分析

        Returns:
            ComprehensiveProfile 对象
        """
        profile = ComprehensiveProfile(address=address)

        # 1. 基础分析
        profile.basic = self.address_analyzer.analyze_address(address)

        # 2. 标签分析
        addr_labels = self.label_manager.get_labels(address)
        profile.labels = [l.name for l in addr_labels.labels]
        profile.risk_labels = [
            l.name for l in addr_labels.labels
            if l.category == LabelCategory.RISK
        ]

        # 3. 行为分析（需要交易数据）
        if include_behavior and transactions:
            profile.behavior = self.behavior_analyzer.analyze_transactions(
                address, transactions
            )
            # 将行为标签加入
            profile.labels.extend(profile.behavior.behavior_tags)

        # 4. 图分析（需要交易数据）
        if include_graph and transactions:
            for tx in transactions:
                self.graph_builder.add_transaction(tx)

            graph = self.graph_builder.graph
            neighbors = graph.get_neighbors(address, "both")
            profile.direct_contacts = len(neighbors)

            # 检查邻居中的风险地址
            for neighbor_addr, _ in neighbors:
                neighbor_risk = self.label_manager.check_risk(neighbor_addr)
                if neighbor_risk["is_sanctioned"]:
                    profile.contact_with_risk += 1

        # 5. 综合风险评估
        self._calculate_risk_score(profile)

        # 6. 生成摘要
        profile.summary = self._generate_summary(profile)

        return profile

    def _calculate_risk_score(self, profile: ComprehensiveProfile):
        """计算综合风险评分"""
        score = 0.0
        factors = []

        # 基于标签的风险
        if profile.basic:
            if profile.basic.risk_labels:
                for label in profile.basic.risk_labels:
                    if "SANCTION" in label.upper():
                        score += 100
                        factors.append("OFAC制裁地址")
                    elif "MIXER" in label.upper():
                        score += 80
                        factors.append("混币器关联")

        # 基于已知标签
        label_check = self.label_manager.check_risk(profile.address)
        if label_check["risk_score"] > 0:
            score = max(score, label_check["risk_score"])
            if label_check["is_sanctioned"]:
                factors.append("制裁名单地址")

        # 基于行为的风险
        if profile.behavior:
            if profile.behavior.suspicious_patterns:
                score += len(profile.behavior.suspicious_patterns) * 15
                factors.extend(profile.behavior.suspicious_patterns)

            if profile.behavior.mixer_interaction_count > 0:
                score += 50
                factors.append("与混币器交互")

        # 基于关联的风险
        if profile.contact_with_risk > 0:
            score += profile.contact_with_risk * 20
            factors.append(f"与{profile.contact_with_risk}个风险地址有交互")

        # 限制分数范围
        profile.risk_score = min(100, score)
        profile.risk_factors = factors

        # 确定风险层级
        if score >= 80:
            profile.risk_tier = "critical"
        elif score >= 50:
            profile.risk_tier = "high"
        elif score >= 30:
            profile.risk_tier = "medium"
        elif score > 0:
            profile.risk_tier = "low"
        else:
            profile.risk_tier = "none"

    def _generate_summary(self, profile: ComprehensiveProfile) -> Dict[str, Any]:
        """生成画像摘要"""
        summary = {
            "address": profile.address,
            "analyzed_at": profile.analyzed_at.isoformat(),
        }

        # 基础信息
        if profile.basic:
            summary["type"] = profile.basic.address_type.value
            summary["is_contract"] = profile.basic.is_contract
            summary["balance_eth"] = f"{profile.basic.balance_eth:.4f}"
            summary["activity_level"] = profile.basic.activity_level.value

        # 行为摘要
        if profile.behavior:
            summary["tx_count"] = profile.behavior.total_tx_count
            summary["account_age_days"] = profile.behavior.account_age_days
            summary["time_pattern"] = profile.behavior.time_pattern.value
            summary["amount_pattern"] = profile.behavior.amount_pattern.value
            summary["behavior_tags"] = profile.behavior.behavior_tags

        # 风险摘要
        summary["risk"] = {
            "score": profile.risk_score,
            "tier": profile.risk_tier,
            "factors": profile.risk_factors,
            "labels": profile.risk_labels,
        }

        # 关联摘要
        summary["connections"] = {
            "direct_contacts": profile.direct_contacts,
            "risky_contacts": profile.contact_with_risk,
        }

        return summary

    def quick_risk_check(self, address: str) -> Dict[str, Any]:
        """快速风险检查（不需要交易数据）"""
        # 检查已知标签
        label_result = self.label_manager.check_risk(address)

        # 基础链上检查
        basic = self.address_analyzer.analyze_address(address)

        return {
            "address": address,
            "is_sanctioned": label_result["is_sanctioned"],
            "risk_score": label_result["risk_score"],
            "highest_risk": label_result["highest_risk"],
            "known_labels": label_result["all_labels"],
            "address_type": basic.address_type.value,
            "is_contract": basic.is_contract,
            "balance_eth": basic.balance_eth,
        }

    def batch_risk_check(self, addresses: List[str]) -> List[Dict[str, Any]]:
        """批量风险检查"""
        results = []
        for addr in addresses:
            try:
                result = self.quick_risk_check(addr)
                results.append(result)
            except Exception as e:
                results.append({
                    "address": addr,
                    "error": str(e),
                })
        return results
