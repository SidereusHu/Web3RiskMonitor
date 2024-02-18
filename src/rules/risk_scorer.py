"""
风险评分聚合器

将多个规则评估结果聚合为综合风险评估：
- 分数聚合策略（累加、最大值、加权等）
- 风险等级判定
- 风险因子分析
"""

from dataclasses import dataclass, field
from datetime import datetime as dt
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import logging

from src.rules.rule_model import Rule, RuleSeverity, RuleCategory
from src.rules.rule_engine import RuleResult

logger = logging.getLogger(__name__)


class AggregationStrategy(str, Enum):
    """分数聚合策略"""
    SUM = "sum"                      # 累加
    MAX = "max"                      # 取最大值
    WEIGHTED_SUM = "weighted_sum"    # 加权累加
    AVERAGE = "average"              # 平均值
    SEVERITY_BASED = "severity"      # 基于严重程度


class RiskLevel(str, Enum):
    """风险等级"""
    CRITICAL = "critical"            # 严重风险 (>=80)
    HIGH = "high"                    # 高风险 (60-79)
    MEDIUM = "medium"                # 中等风险 (40-59)
    LOW = "low"                      # 低风险 (20-39)
    MINIMAL = "minimal"              # 极低风险 (1-19)
    NONE = "none"                    # 无风险 (0)


@dataclass
class RiskFactor:
    """风险因子"""
    name: str                        # 因子名称
    category: str                    # 因子分类
    score: int                       # 贡献分数
    severity: str                    # 严重程度
    description: str                 # 描述
    source_rule: str                 # 来源规则ID
    evidence: List[str] = field(default_factory=list)  # 证据（匹配的条件）


@dataclass
class RiskAssessment:
    """综合风险评估结果"""
    # 评估对象
    subject: str                     # 评估对象（地址/交易哈希）
    subject_type: str                # 对象类型（address/transaction）

    # 综合评分
    total_score: int = 0             # 总分
    risk_level: RiskLevel = RiskLevel.NONE
    confidence: float = 1.0          # 置信度 (0-1)

    # 分类评分
    category_scores: Dict[str, int] = field(default_factory=dict)

    # 风险因子
    risk_factors: List[RiskFactor] = field(default_factory=list)

    # 规则统计
    rules_evaluated: int = 0         # 评估的规则数
    rules_triggered: int = 0         # 触发的规则数

    # 建议动作
    recommended_actions: List[str] = field(default_factory=list)

    # 时间
    assessed_at: dt = field(default_factory=dt.now)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "subject": self.subject,
            "subject_type": self.subject_type,
            "total_score": self.total_score,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "category_scores": self.category_scores,
            "risk_factors": [
                {
                    "name": f.name,
                    "category": f.category,
                    "score": f.score,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in self.risk_factors
            ],
            "rules_evaluated": self.rules_evaluated,
            "rules_triggered": self.rules_triggered,
            "recommended_actions": self.recommended_actions,
            "assessed_at": self.assessed_at.isoformat(),
        }


class RiskScorer:
    """风险评分器"""

    # 严重程度权重
    SEVERITY_WEIGHTS = {
        RuleSeverity.CRITICAL: 2.0,
        RuleSeverity.HIGH: 1.5,
        RuleSeverity.MEDIUM: 1.0,
        RuleSeverity.LOW: 0.5,
        RuleSeverity.INFO: 0.2,
    }

    # 风险等级阈值
    RISK_THRESHOLDS = {
        RiskLevel.CRITICAL: 80,
        RiskLevel.HIGH: 60,
        RiskLevel.MEDIUM: 40,
        RiskLevel.LOW: 20,
        RiskLevel.MINIMAL: 1,
    }

    def __init__(
        self,
        strategy: AggregationStrategy = AggregationStrategy.SEVERITY_BASED,
        max_score: int = 100
    ):
        """初始化评分器

        Args:
            strategy: 分数聚合策略
            max_score: 最大分数限制
        """
        self.strategy = strategy
        self.max_score = max_score

        # 策略处理函数
        self._aggregators: Dict[AggregationStrategy, Callable] = {
            AggregationStrategy.SUM: self._aggregate_sum,
            AggregationStrategy.MAX: self._aggregate_max,
            AggregationStrategy.WEIGHTED_SUM: self._aggregate_weighted,
            AggregationStrategy.AVERAGE: self._aggregate_average,
            AggregationStrategy.SEVERITY_BASED: self._aggregate_severity_based,
        }

        # 规则元数据缓存
        self._rule_metadata: Dict[str, Rule] = {}

    def register_rule(self, rule: Rule):
        """注册规则元数据（用于评估时获取规则信息）"""
        self._rule_metadata[rule.rule_id] = rule

    def assess(
        self,
        subject: str,
        subject_type: str,
        results: List[RuleResult],
    ) -> RiskAssessment:
        """执行风险评估

        Args:
            subject: 评估对象（地址或交易哈希）
            subject_type: 对象类型
            results: 规则评估结果列表

        Returns:
            RiskAssessment 综合评估结果
        """
        assessment = RiskAssessment(
            subject=subject,
            subject_type=subject_type,
            rules_evaluated=len(results),
        )

        triggered_results = [r for r in results if r.triggered]
        assessment.rules_triggered = len(triggered_results)

        if not triggered_results:
            return assessment

        # 提取风险因子
        assessment.risk_factors = self._extract_risk_factors(triggered_results)

        # 计算分类分数
        assessment.category_scores = self._calculate_category_scores(triggered_results)

        # 聚合总分
        aggregator = self._aggregators.get(self.strategy, self._aggregate_sum)
        raw_score = aggregator(triggered_results)

        # 限制最大分数
        assessment.total_score = min(raw_score, self.max_score)

        # 判定风险等级
        assessment.risk_level = self._determine_risk_level(assessment.total_score)

        # 计算置信度
        assessment.confidence = self._calculate_confidence(results, triggered_results)

        # 生成建议动作
        assessment.recommended_actions = self._generate_recommendations(assessment)

        return assessment

    def _extract_risk_factors(self, results: List[RuleResult]) -> List[RiskFactor]:
        """提取风险因子"""
        factors = []

        for result in results:
            rule = self._rule_metadata.get(result.rule_id)

            factor = RiskFactor(
                name=result.rule_name,
                category=rule.category.value if rule else "unknown",
                score=result.risk_score,
                severity=rule.severity.value if rule else "medium",
                description=f"Rule {result.rule_id} triggered",
                source_rule=result.rule_id,
                evidence=result.matched_conditions,
            )
            factors.append(factor)

        # 按分数排序
        factors.sort(key=lambda f: f.score, reverse=True)
        return factors

    def _calculate_category_scores(self, results: List[RuleResult]) -> Dict[str, int]:
        """计算各分类的风险分"""
        category_scores: Dict[str, int] = {}

        for result in results:
            rule = self._rule_metadata.get(result.rule_id)
            category = rule.category.value if rule else "unknown"

            if category not in category_scores:
                category_scores[category] = 0
            category_scores[category] += result.risk_score

        return category_scores

    def _aggregate_sum(self, results: List[RuleResult]) -> int:
        """累加聚合"""
        return sum(r.risk_score for r in results)

    def _aggregate_max(self, results: List[RuleResult]) -> int:
        """最大值聚合"""
        if not results:
            return 0
        return max(r.risk_score for r in results)

    def _aggregate_weighted(self, results: List[RuleResult]) -> int:
        """加权累加聚合"""
        total = 0
        for result in results:
            rule = self._rule_metadata.get(result.rule_id)
            weight = 1.0
            if rule:
                weight = self.SEVERITY_WEIGHTS.get(rule.severity, 1.0)
            total += int(result.risk_score * weight)
        return total

    def _aggregate_average(self, results: List[RuleResult]) -> int:
        """平均值聚合"""
        if not results:
            return 0
        total = sum(r.risk_score for r in results)
        return int(total / len(results))

    def _aggregate_severity_based(self, results: List[RuleResult]) -> int:
        """基于严重程度的聚合

        逻辑：
        - Critical规则触发直接给予高分
        - 其他规则按权重累加
        - 考虑规则数量的衰减
        """
        if not results:
            return 0

        base_score = 0
        critical_boost = 0

        for result in results:
            rule = self._rule_metadata.get(result.rule_id)
            if not rule:
                base_score += result.risk_score
                continue

            if rule.severity == RuleSeverity.CRITICAL:
                # Critical规则直接给予高基础分
                critical_boost = max(critical_boost, 70)
                base_score += result.risk_score * 0.5  # 额外贡献
            else:
                weight = self.SEVERITY_WEIGHTS.get(rule.severity, 1.0)
                base_score += int(result.risk_score * weight)

        # 最终分数 = 基础分 + Critical加成
        return int(base_score + critical_boost)

    def _determine_risk_level(self, score: int) -> RiskLevel:
        """判定风险等级"""
        for level, threshold in self.RISK_THRESHOLDS.items():
            if score >= threshold:
                return level
        return RiskLevel.NONE

    def _calculate_confidence(
        self,
        all_results: List[RuleResult],
        triggered_results: List[RuleResult]
    ) -> float:
        """计算置信度

        基于以下因素：
        - 触发规则数量
        - 触发规则的严重程度
        - 证据数量（匹配条件数）
        """
        if not triggered_results:
            return 1.0  # 没有触发规则，置信度为100%（确定无风险）

        # 基础置信度
        confidence = 0.5

        # 根据触发规则数量提升
        trigger_ratio = len(triggered_results) / max(len(all_results), 1)
        confidence += trigger_ratio * 0.2

        # 根据证据数量提升
        total_evidence = sum(len(r.matched_conditions) for r in triggered_results)
        evidence_factor = min(total_evidence / 10, 0.2)  # 最多加0.2
        confidence += evidence_factor

        # 根据严重程度提升
        has_critical = any(
            self._rule_metadata.get(r.rule_id) and
            self._rule_metadata.get(r.rule_id).severity == RuleSeverity.CRITICAL
            for r in triggered_results
        )
        if has_critical:
            confidence += 0.1

        return min(confidence, 1.0)

    def _generate_recommendations(self, assessment: RiskAssessment) -> List[str]:
        """生成建议动作"""
        recommendations = []

        if assessment.risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "立即人工审核",
                "暂停相关交易",
                "提交可疑活动报告(SAR)",
            ])
        elif assessment.risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "优先人工审核",
                "加强交易监控",
                "考虑额度限制",
            ])
        elif assessment.risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "纳入定期审核队列",
                "增加监控频率",
            ])
        elif assessment.risk_level == RiskLevel.LOW:
            recommendations.append("保持常规监控")

        # 根据具体风险因子添加建议
        for factor in assessment.risk_factors:
            if factor.category == "sanction":
                recommendations.append("核实OFAC制裁名单状态")
            elif factor.category == "aml":
                recommendations.append("审查资金来源")
            elif factor.category == "fraud":
                recommendations.append("验证交易真实性")

        # 去重
        return list(dict.fromkeys(recommendations))

    def quick_score(self, results: List[RuleResult]) -> int:
        """快速计算风险分（不生成完整评估）"""
        triggered = [r for r in results if r.triggered]
        if not triggered:
            return 0
        aggregator = self._aggregators.get(self.strategy, self._aggregate_sum)
        return min(aggregator(triggered), self.max_score)

    def compare_assessments(
        self,
        assessment1: RiskAssessment,
        assessment2: RiskAssessment
    ) -> Dict[str, Any]:
        """比较两个评估结果"""
        return {
            "subject1": assessment1.subject,
            "subject2": assessment2.subject,
            "score_diff": assessment1.total_score - assessment2.total_score,
            "level_same": assessment1.risk_level == assessment2.risk_level,
            "factors_diff": {
                "only_in_1": [f.name for f in assessment1.risk_factors
                             if f.name not in [f2.name for f2 in assessment2.risk_factors]],
                "only_in_2": [f.name for f in assessment2.risk_factors
                             if f.name not in [f1.name for f1 in assessment1.risk_factors]],
            }
        }
