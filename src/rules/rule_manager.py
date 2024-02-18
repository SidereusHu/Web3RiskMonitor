"""
规则管理器

提供：
- 规则CRUD操作
- 规则持久化
- 预置规则库
- 规则导入/导出
"""

from dataclasses import dataclass, field
from datetime import datetime as dt
from typing import Dict, List, Optional, Any
import json
import os
import logging

from src.rules.rule_model import (
    Rule,
    RuleCondition,
    RuleAction,
    RuleBuilder,
    RuleSeverity,
    RuleCategory,
    ConditionOperator,
    ActionType,
)
from src.rules.rule_engine import RuleEngine, RuleResult
from src.rules.risk_scorer import RiskScorer, RiskAssessment
from src.rules.alert_system import AlertManager, Alert

logger = logging.getLogger(__name__)


class RuleManager:
    """规则管理器"""

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        load_preset: bool = True
    ):
        """初始化规则管理器

        Args:
            rules_dir: 规则存储目录
            load_preset: 是否加载预置规则
        """
        self.rules_dir = rules_dir
        self.engine = RuleEngine()
        self.scorer = RiskScorer()
        self.alert_manager = AlertManager()

        if load_preset:
            self._load_preset_rules()

        if rules_dir and os.path.exists(rules_dir):
            self._load_rules_from_dir(rules_dir)

    def _load_preset_rules(self):
        """加载预置规则"""
        preset_rules = create_preset_rules()
        for rule in preset_rules:
            self.add_rule(rule)
        logger.info(f"Loaded {len(preset_rules)} preset rules")

    def _load_rules_from_dir(self, rules_dir: str):
        """从目录加载规则"""
        count = 0
        for filename in os.listdir(rules_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(rules_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        rule_data = json.load(f)
                    rule = Rule.from_dict(rule_data)
                    self.add_rule(rule)
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to load rule from {filepath}: {e}")
        logger.info(f"Loaded {count} rules from {rules_dir}")

    def add_rule(self, rule: Rule):
        """添加规则"""
        self.engine.add_rule(rule)
        self.scorer.register_rule(rule)

    def remove_rule(self, rule_id: str):
        """移除规则"""
        self.engine.remove_rule(rule_id)

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """获取规则"""
        return self.engine.get_rule(rule_id)

    def list_rules(
        self,
        category: Optional[str] = None,
        enabled_only: bool = True
    ) -> List[Rule]:
        """列出规则"""
        return self.engine.list_rules(category, enabled_only)

    def enable_rule(self, rule_id: str) -> bool:
        """启用规则"""
        rule = self.engine.get_rule(rule_id)
        if rule:
            rule.enabled = True
            rule.updated_at = dt.now()
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """禁用规则"""
        rule = self.engine.get_rule(rule_id)
        if rule:
            rule.enabled = False
            rule.updated_at = dt.now()
            return True
        return False

    def save_rule(self, rule: Rule, filepath: Optional[str] = None):
        """保存规则到文件"""
        if filepath is None and self.rules_dir:
            filepath = os.path.join(self.rules_dir, f"{rule.rule_id}.json")

        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(rule.to_dict(), f, indent=2, ensure_ascii=False)
            logger.info(f"Rule saved to {filepath}")

    def export_rules(self, filepath: str, rule_ids: Optional[List[str]] = None):
        """导出规则"""
        rules = self.list_rules(enabled_only=False)
        if rule_ids:
            rules = [r for r in rules if r.rule_id in rule_ids]

        rules_data = [r.to_dict() for r in rules]

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(rules_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported {len(rules)} rules to {filepath}")

    def import_rules(self, filepath: str, overwrite: bool = False):
        """导入规则"""
        with open(filepath, "r", encoding="utf-8") as f:
            rules_data = json.load(f)

        count = 0
        for rule_data in rules_data:
            rule = Rule.from_dict(rule_data)

            # 检查是否已存在
            existing = self.get_rule(rule.rule_id)
            if existing and not overwrite:
                logger.warning(f"Rule {rule.rule_id} already exists, skipping")
                continue

            self.add_rule(rule)
            count += 1

        logger.info(f"Imported {count} rules from {filepath}")

    # ===== 评估接口 =====

    def evaluate_transaction(
        self,
        tx_data: Dict[str, Any],
        generate_alerts: bool = True
    ) -> RiskAssessment:
        """评估交易

        Args:
            tx_data: 交易数据
            generate_alerts: 是否生成告警

        Returns:
            RiskAssessment 风险评估结果
        """
        # 执行规则评估
        results = self.engine.evaluate_transaction(tx_data)

        # 聚合风险评分
        subject = tx_data.get("hash", tx_data.get("tx_hash", "unknown"))
        assessment = self.scorer.assess(
            subject=subject,
            subject_type="transaction",
            results=results,
        )

        # 生成告警
        if generate_alerts:
            self._generate_alerts(results, subject, "transaction", assessment)

        return assessment

    def evaluate_address(
        self,
        address_data: Dict[str, Any],
        generate_alerts: bool = True
    ) -> RiskAssessment:
        """评估地址

        Args:
            address_data: 地址数据
            generate_alerts: 是否生成告警

        Returns:
            RiskAssessment 风险评估结果
        """
        # 执行规则评估
        results = self.engine.evaluate_address(address_data)

        # 聚合风险评分
        subject = address_data.get("address", "unknown")
        assessment = self.scorer.assess(
            subject=subject,
            subject_type="address",
            results=results,
        )

        # 生成告警
        if generate_alerts:
            self._generate_alerts(results, subject, "address", assessment)

        return assessment

    def quick_check(self, data: Dict[str, Any], data_type: str = "address") -> Dict[str, Any]:
        """快速风险检查

        返回简化的风险信息
        """
        if data_type == "address":
            assessment = self.evaluate_address(data, generate_alerts=False)
        else:
            assessment = self.evaluate_transaction(data, generate_alerts=False)

        return {
            "subject": assessment.subject,
            "risk_score": assessment.total_score,
            "risk_level": assessment.risk_level.value,
            "rules_triggered": assessment.rules_triggered,
            "top_factors": [f.name for f in assessment.risk_factors[:3]],
        }

    def _generate_alerts(
        self,
        results: List[RuleResult],
        subject: str,
        subject_type: str,
        assessment: RiskAssessment
    ):
        """生成告警"""
        triggered = [r for r in results if r.triggered]

        for result in triggered:
            self.alert_manager.create_alert_from_result(
                result=result,
                subject=subject,
                subject_type=subject_type,
                assessment=assessment,
            )

    # ===== 统计接口 =====

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        rules = self.list_rules(enabled_only=False)
        enabled_rules = [r for r in rules if r.enabled]
        triggered_rules = [r for r in rules if r.trigger_count > 0]

        # 按分类统计
        category_counts = {}
        for rule in rules:
            cat = rule.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "total_rules": len(rules),
            "enabled_rules": len(enabled_rules),
            "triggered_rules": len(triggered_rules),
            "by_category": category_counts,
            "alert_stats": self.alert_manager.get_statistics(),
        }


# ===== 预置规则库 =====

def create_preset_rules() -> List[Rule]:
    """创建预置规则库"""
    rules = []

    # ===== 制裁相关规则 =====

    # SANCTION-001: OFAC制裁地址检查
    rules.append(
        RuleBuilder("SANCTION-001")
        .name("OFAC Sanctioned Address")
        .description("检测与OFAC制裁名单地址的交互")
        .when(RuleCondition.eq("is_sanctioned", True))
        .then(RuleAction.alert("Interaction with OFAC sanctioned address detected"))
        .then(RuleAction.add_score(100, "OFAC sanctioned"))
        .severity(RuleSeverity.CRITICAL)
        .category(RuleCategory.SANCTION)
        .risk_score(100)
        .applies_to("address", "transaction")
        .tags("ofac", "sanction", "compliance")
        .build()
    )

    # SANCTION-002: Tornado Cash交互
    rules.append(
        RuleBuilder("SANCTION-002")
        .name("Tornado Cash Interaction")
        .description("检测与Tornado Cash混币器的交互")
        .when(
            RuleCondition.or_(
                RuleCondition.contains("labels", "TORNADO_CASH"),
                RuleCondition.contains("counterparty_labels", "TORNADO_CASH"),
                RuleCondition.eq("to_address", "0x722122df12d4e14e13ac3b6895a86e84145b6967"),
            )
        )
        .then(RuleAction.alert("Tornado Cash interaction detected"))
        .then(RuleAction.add_score(80, "Mixer interaction"))
        .severity(RuleSeverity.CRITICAL)
        .category(RuleCategory.SANCTION)
        .risk_score(80)
        .applies_to("address", "transaction")
        .tags("mixer", "tornado", "sanction")
        .build()
    )

    # ===== AML规则 =====

    # AML-001: 大额交易
    rules.append(
        RuleBuilder("AML-001")
        .name("Large Value Transaction")
        .description("检测超过阈值的大额交易")
        .when(RuleCondition.gte("value_eth", 100))
        .then(RuleAction.alert("Large value transaction detected"))
        .then(RuleAction.add_score(30, "Large transaction"))
        .severity(RuleSeverity.MEDIUM)
        .category(RuleCategory.AML)
        .risk_score(30)
        .applies_to("transaction")
        .tags("large_tx", "aml")
        .build()
    )

    # AML-002: 快速资金流转
    rules.append(
        RuleBuilder("AML-002")
        .name("Rapid Fund Movement")
        .description("检测快速的资金流转模式（收到后短时间内转出）")
        .when(
            RuleCondition.and_(
                RuleCondition.lte("time_to_outflow_minutes", 60),
                RuleCondition.gte("outflow_ratio", 0.9),
            )
        )
        .then(RuleAction.alert("Rapid fund movement pattern detected"))
        .then(RuleAction.add_score(50, "Rapid fund movement"))
        .severity(RuleSeverity.HIGH)
        .category(RuleCategory.AML)
        .risk_score(50)
        .applies_to("address")
        .tags("layering", "aml")
        .build()
    )

    # AML-003: 结构化交易（拆分）
    rules.append(
        RuleBuilder("AML-003")
        .name("Structuring Pattern")
        .description("检测可能的结构化交易（拆分以规避监控）")
        .when(
            RuleCondition.and_(
                RuleCondition.gte("similar_amount_tx_count", 5),
                RuleCondition.lte("amount_variance", 0.1),
                RuleCondition.lte("time_span_hours", 24),
            )
        )
        .then(RuleAction.alert("Possible structuring pattern detected"))
        .then(RuleAction.add_score(60, "Structuring suspected"))
        .severity(RuleSeverity.HIGH)
        .category(RuleCategory.AML)
        .risk_score(60)
        .applies_to("address")
        .tags("structuring", "aml")
        .build()
    )

    # AML-004: 新账户大额交易
    rules.append(
        RuleBuilder("AML-004")
        .name("New Account High Volume")
        .description("新账户短期内有大额交易")
        .when(
            RuleCondition.and_(
                RuleCondition.lte("account_age_days", 7),
                RuleCondition.gte("total_volume_eth", 10),
            )
        )
        .then(RuleAction.alert("New account with high volume"))
        .then(RuleAction.add_score(40, "New account high volume"))
        .severity(RuleSeverity.MEDIUM)
        .category(RuleCategory.AML)
        .risk_score(40)
        .applies_to("address")
        .tags("new_account", "aml")
        .build()
    )

    # ===== 行为异常规则 =====

    # BEHAVIOR-001: 机器人行为
    rules.append(
        RuleBuilder("BEHAVIOR-001")
        .name("Bot-like Behavior")
        .description("检测自动化机器人行为特征")
        .when(
            RuleCondition.and_(
                RuleCondition.eq("time_pattern", "bot_like"),
                RuleCondition.gte("avg_tx_per_day", 50),
            )
        )
        .then(RuleAction.alert("Automated bot behavior detected"))
        .then(RuleAction.add_score(20, "Bot behavior"))
        .then(RuleAction.flag_address("BOT_SUSPECTED"))
        .severity(RuleSeverity.LOW)
        .category(RuleCategory.BEHAVIOR)
        .risk_score(20)
        .applies_to("address")
        .tags("bot", "automation")
        .build()
    )

    # BEHAVIOR-002: 异常交易时间
    rules.append(
        RuleBuilder("BEHAVIOR-002")
        .name("Unusual Transaction Time")
        .description("检测非典型时间的交易活动")
        .when(
            RuleCondition.and_(
                RuleCondition.eq("time_pattern", "off_hours"),
                RuleCondition.gte("off_hours_ratio", 0.8),
            )
        )
        .then(RuleAction.add_score(10, "Unusual timing"))
        .severity(RuleSeverity.INFO)
        .category(RuleCategory.BEHAVIOR)
        .risk_score(10)
        .applies_to("address")
        .tags("timing", "pattern")
        .build()
    )

    # BEHAVIOR-003: 集中交互模式
    rules.append(
        RuleBuilder("BEHAVIOR-003")
        .name("Concentrated Interactions")
        .description("地址交互高度集中于少数对手方")
        .when(
            RuleCondition.and_(
                RuleCondition.lte("unique_counterparties", 5),
                RuleCondition.gte("total_tx_count", 20),
            )
        )
        .then(RuleAction.add_score(25, "Concentrated interactions"))
        .severity(RuleSeverity.LOW)
        .category(RuleCategory.BEHAVIOR)
        .risk_score(25)
        .applies_to("address")
        .tags("pattern", "concentration")
        .build()
    )

    # ===== 欺诈检测规则 =====

    # FRAUD-001: 钓鱼地址
    rules.append(
        RuleBuilder("FRAUD-001")
        .name("Known Phishing Address")
        .description("已知钓鱼地址检测")
        .when(RuleCondition.contains("labels", "PHISHING"))
        .then(RuleAction.alert("Known phishing address detected", ["urgent"]))
        .then(RuleAction.add_score(90, "Phishing address"))
        .severity(RuleSeverity.CRITICAL)
        .category(RuleCategory.FRAUD)
        .risk_score(90)
        .applies_to("address", "transaction")
        .tags("phishing", "scam")
        .build()
    )

    # FRAUD-002: 诈骗地址
    rules.append(
        RuleBuilder("FRAUD-002")
        .name("Known Scam Address")
        .description("已知诈骗地址检测")
        .when(RuleCondition.contains("labels", "SCAM"))
        .then(RuleAction.alert("Known scam address detected", ["urgent"]))
        .then(RuleAction.add_score(90, "Scam address"))
        .severity(RuleSeverity.CRITICAL)
        .category(RuleCategory.FRAUD)
        .risk_score(90)
        .applies_to("address", "transaction")
        .tags("scam", "fraud")
        .build()
    )

    # FRAUD-003: 黑客相关
    rules.append(
        RuleBuilder("FRAUD-003")
        .name("Hack Related Address")
        .description("与已知黑客事件相关的地址")
        .when(RuleCondition.contains("labels", "HACK"))
        .then(RuleAction.alert("Hack-related address detected"))
        .then(RuleAction.add_score(85, "Hack related"))
        .severity(RuleSeverity.CRITICAL)
        .category(RuleCategory.FRAUD)
        .risk_score(85)
        .applies_to("address", "transaction")
        .tags("hack", "exploit")
        .build()
    )

    # ===== 合规规则 =====

    # COMPLIANCE-001: 高风险地区
    rules.append(
        RuleBuilder("COMPLIANCE-001")
        .name("High Risk Jurisdiction")
        .description("与高风险司法管辖区相关的地址")
        .when(RuleCondition.in_list("jurisdiction", ["NK", "IR", "SY", "CU"]))
        .then(RuleAction.alert("High risk jurisdiction interaction"))
        .then(RuleAction.add_score(70, "High risk jurisdiction"))
        .severity(RuleSeverity.HIGH)
        .category(RuleCategory.COMPLIANCE)
        .risk_score(70)
        .applies_to("address")
        .tags("jurisdiction", "compliance")
        .build()
    )

    # COMPLIANCE-002: 未验证交易所
    rules.append(
        RuleBuilder("COMPLIANCE-002")
        .name("Unverified Exchange")
        .description("与未经验证/未授权交易所的交互")
        .when(
            RuleCondition.and_(
                RuleCondition.contains("labels", "EXCHANGE"),
                RuleCondition.not_(RuleCondition.contains("labels", "VERIFIED")),
            )
        )
        .then(RuleAction.add_score(20, "Unverified exchange"))
        .severity(RuleSeverity.LOW)
        .category(RuleCategory.COMPLIANCE)
        .risk_score(20)
        .applies_to("address", "transaction")
        .tags("exchange", "kyc")
        .build()
    )

    # ===== 安全规则 =====

    # SECURITY-001: 合约漏洞交互
    rules.append(
        RuleBuilder("SECURITY-001")
        .name("Vulnerable Contract Interaction")
        .description("与已知存在漏洞的合约交互")
        .when(RuleCondition.contains("contract_labels", "VULNERABLE"))
        .then(RuleAction.alert("Interaction with vulnerable contract"))
        .then(RuleAction.add_score(50, "Vulnerable contract"))
        .severity(RuleSeverity.HIGH)
        .category(RuleCategory.SECURITY)
        .risk_score(50)
        .applies_to("transaction")
        .tags("security", "vulnerability")
        .build()
    )

    # SECURITY-002: 闪电贷攻击模式
    rules.append(
        RuleBuilder("SECURITY-002")
        .name("Flash Loan Attack Pattern")
        .description("检测可能的闪电贷攻击模式")
        .when(
            RuleCondition.and_(
                RuleCondition.contains("methods", "flashLoan"),
                RuleCondition.gte("profit_eth", 10),
                RuleCondition.eq("is_same_block", True),
            )
        )
        .then(RuleAction.alert("Possible flash loan attack detected", ["urgent"]))
        .then(RuleAction.add_score(80, "Flash loan attack"))
        .severity(RuleSeverity.CRITICAL)
        .category(RuleCategory.SECURITY)
        .risk_score(80)
        .applies_to("transaction")
        .tags("flashloan", "attack")
        .build()
    )

    return rules
