"""
Phase 3 探索脚本：风险规则引擎

演示：
1. 规则定义与DSL
2. 条件评估
3. 风险评分聚合
4. 告警生成
"""

import sys
sys.path.insert(0, "/Users/sidereus/Documents/FindJobs/Web3RiskMonitor")

from src.rules.rule_model import (
    Rule,
    RuleCondition,
    RuleAction,
    RuleBuilder,
    RuleSeverity,
    RuleCategory,
)
from src.rules.rule_engine import RuleEngine, ConditionEvaluator
from src.rules.risk_scorer import RiskScorer, AggregationStrategy
from src.rules.alert_system import AlertManager, console_channel, log_channel
from src.rules.rule_manager import RuleManager


def demo_rule_dsl():
    """演示规则DSL"""
    print("\n" + "="*60)
    print("1. 规则定义DSL演示")
    print("="*60)

    # 方式1：使用RuleBuilder（流畅API）
    rule1 = (
        RuleBuilder("DEMO-001")
        .name("Large ETH Transfer")
        .description("检测大额ETH转账")
        .when(RuleCondition.gte("value_eth", 100))
        .then(RuleAction.alert("Large transfer detected"))
        .then(RuleAction.add_score(30, "Large transfer"))
        .severity(RuleSeverity.MEDIUM)
        .category(RuleCategory.AML)
        .risk_score(30)
        .applies_to("transaction")
        .tags("large_tx", "monitoring")
        .build()
    )

    print(f"\n规则1 (Builder方式):")
    print(f"  ID: {rule1.rule_id}")
    print(f"  Name: {rule1.name}")
    print(f"  Severity: {rule1.severity.value}")
    print(f"  Risk Score: {rule1.risk_score}")

    # 方式2：复合条件
    rule2 = (
        RuleBuilder("DEMO-002")
        .name("Suspicious New Account")
        .description("新账户可疑行为检测")
        .when(
            RuleCondition.and_(
                RuleCondition.lte("account_age_days", 7),
                RuleCondition.or_(
                    RuleCondition.gte("total_volume_eth", 10),
                    RuleCondition.gte("tx_count", 50),
                )
            )
        )
        .then(RuleAction.alert("Suspicious new account activity"))
        .then(RuleAction.flag_address("SUSPICIOUS_NEW"))
        .severity(RuleSeverity.HIGH)
        .category(RuleCategory.AML)
        .risk_score(50)
        .build()
    )

    print(f"\n规则2 (复合条件):")
    print(f"  ID: {rule2.rule_id}")
    print(f"  Condition: AND(account_age<=7, OR(volume>=10, tx_count>=50))")

    # 方式3：直接构造
    rule3 = Rule(
        rule_id="DEMO-003",
        name="Mixer Interaction Alert",
        description="混币器交互警告",
        condition=RuleCondition.contains("labels", "MIXER"),
        actions=[
            RuleAction.alert("Mixer interaction detected", ["urgent"]),
            RuleAction.add_score(80, "Mixer usage"),
        ],
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SANCTION,
        risk_score=80,
    )

    print(f"\n规则3 (直接构造):")
    print(f"  ID: {rule3.rule_id}")
    print(f"  Severity: {rule3.severity.value}")

    # 序列化演示
    print("\n规则JSON序列化:")
    rule_json = rule1.to_json()
    print(rule_json[:500] + "...")

    return [rule1, rule2, rule3]


def demo_condition_evaluation():
    """演示条件评估"""
    print("\n" + "="*60)
    print("2. 条件评估演示")
    print("="*60)

    evaluator = ConditionEvaluator()

    # 测试数据
    test_data = {
        "address": "0x1234567890abcdef1234567890abcdef12345678",
        "value_eth": 150.5,
        "account_age_days": 5,
        "total_volume_eth": 25.0,
        "tx_count": 30,
        "labels": ["EXCHANGE_USER", "HIGH_VOLUME"],
        "counterparty": {
            "type": "contract",
            "labels": ["DEX", "UNISWAP"],
        },
    }

    print(f"\n测试数据:")
    for key, value in test_data.items():
        print(f"  {key}: {value}")

    # 测试各种条件
    test_cases = [
        ("value_eth >= 100", RuleCondition.gte("value_eth", 100)),
        ("account_age_days <= 7", RuleCondition.lte("account_age_days", 7)),
        ("labels contains 'EXCHANGE_USER'", RuleCondition.contains("labels", "EXCHANGE_USER")),
        ("labels contains 'MIXER'", RuleCondition.contains("labels", "MIXER")),
        ("counterparty.type == 'contract'", RuleCondition.eq("counterparty.type", "contract")),
        ("AND(age<=7, volume>=10)", RuleCondition.and_(
            RuleCondition.lte("account_age_days", 7),
            RuleCondition.gte("total_volume_eth", 10),
        )),
        ("OR(volume>=100, tx_count>=50)", RuleCondition.or_(
            RuleCondition.gte("total_volume_eth", 100),
            RuleCondition.gte("tx_count", 50),
        )),
    ]

    print("\n条件评估结果:")
    for desc, condition in test_cases:
        matched = []
        result = evaluator.evaluate(condition, test_data, matched)
        status = "✓ MATCH" if result else "✗ NO MATCH"
        print(f"  {desc}")
        print(f"    Result: {status}")
        if matched:
            print(f"    Evidence: {matched}")


def demo_rule_engine():
    """演示规则引擎"""
    print("\n" + "="*60)
    print("3. 规则引擎演示")
    print("="*60)

    engine = RuleEngine()

    # 添加测试规则
    rules = [
        RuleBuilder("TEST-001")
        .name("Large Transfer")
        .when(RuleCondition.gte("value_eth", 100))
        .then(RuleAction.add_score(30, "Large transfer"))
        .risk_score(30)
        .build(),

        RuleBuilder("TEST-002")
        .name("New Account Activity")
        .when(RuleCondition.lte("account_age_days", 7))
        .then(RuleAction.add_score(20, "New account"))
        .risk_score(20)
        .build(),

        RuleBuilder("TEST-003")
        .name("Mixer Label")
        .when(RuleCondition.contains("labels", "MIXER"))
        .then(RuleAction.add_score(80, "Mixer"))
        .severity(RuleSeverity.CRITICAL)
        .risk_score(80)
        .build(),

        RuleBuilder("TEST-004")
        .name("Exchange User")
        .when(RuleCondition.contains("labels", "EXCHANGE_USER"))
        .then(RuleAction.add_score(5, "Exchange user"))
        .risk_score(5)
        .build(),
    ]

    for rule in rules:
        engine.add_rule(rule)

    print(f"\n已加载 {len(rules)} 条规则")

    # 测试数据
    test_tx = {
        "hash": "0xabc123...",
        "value_eth": 150.0,
        "account_age_days": 3,
        "labels": ["EXCHANGE_USER", "HIGH_VOLUME"],
    }

    print(f"\n测试交易数据:")
    for key, value in test_tx.items():
        print(f"  {key}: {value}")

    # 评估
    results = engine.evaluate_all(test_tx)

    print(f"\n评估结果:")
    print(f"  规则总数: {len(results)}")

    triggered = engine.get_triggered_rules(results)
    print(f"  触发规则数: {len(triggered)}")

    for result in triggered:
        print(f"\n  触发: {result.rule_name}")
        print(f"    Risk Score: +{result.risk_score}")
        print(f"    Evidence: {result.matched_conditions}")

    total_score = engine.calculate_total_risk_score(results)
    print(f"\n  总风险分: {total_score}")


def demo_risk_scorer():
    """演示风险评分聚合"""
    print("\n" + "="*60)
    print("4. 风险评分聚合演示")
    print("="*60)

    # 创建规则和引擎
    engine = RuleEngine()
    scorer = RiskScorer(strategy=AggregationStrategy.SEVERITY_BASED)

    rules = [
        RuleBuilder("RISK-001")
        .name("OFAC Sanction")
        .when(RuleCondition.eq("is_sanctioned", True))
        .then(RuleAction.add_score(100, "Sanctioned"))
        .severity(RuleSeverity.CRITICAL)
        .category(RuleCategory.SANCTION)
        .risk_score(100)
        .build(),

        RuleBuilder("RISK-002")
        .name("Mixer Usage")
        .when(RuleCondition.contains("labels", "MIXER"))
        .then(RuleAction.add_score(70, "Mixer"))
        .severity(RuleSeverity.HIGH)
        .category(RuleCategory.AML)
        .risk_score(70)
        .build(),

        RuleBuilder("RISK-003")
        .name("New Account")
        .when(RuleCondition.lte("account_age_days", 7))
        .then(RuleAction.add_score(20, "New"))
        .severity(RuleSeverity.LOW)
        .category(RuleCategory.BEHAVIOR)
        .risk_score(20)
        .build(),
    ]

    for rule in rules:
        engine.add_rule(rule)
        scorer.register_rule(rule)

    # 测试场景1：普通地址
    print("\n场景1：普通新账户")
    data1 = {"address": "0xaaa...", "account_age_days": 3, "labels": []}
    results1 = engine.evaluate_all(data1)
    assessment1 = scorer.assess("0xaaa...", "address", results1)

    print(f"  Address: {assessment1.subject}")
    print(f"  Total Score: {assessment1.total_score}")
    print(f"  Risk Level: {assessment1.risk_level.value}")
    print(f"  Triggered Rules: {assessment1.rules_triggered}")

    # 测试场景2：混币器用户
    print("\n场景2：混币器用户")
    data2 = {"address": "0xbbb...", "account_age_days": 30, "labels": ["MIXER"]}
    results2 = engine.evaluate_all(data2)
    assessment2 = scorer.assess("0xbbb...", "address", results2)

    print(f"  Address: {assessment2.subject}")
    print(f"  Total Score: {assessment2.total_score}")
    print(f"  Risk Level: {assessment2.risk_level.value}")
    print(f"  Risk Factors: {[f.name for f in assessment2.risk_factors]}")
    print(f"  Recommendations: {assessment2.recommended_actions[:2]}")

    # 测试场景3：制裁地址
    print("\n场景3：制裁名单地址")
    data3 = {"address": "0xccc...", "is_sanctioned": True, "labels": ["OFAC"]}
    results3 = engine.evaluate_all(data3)
    assessment3 = scorer.assess("0xccc...", "address", results3)

    print(f"  Address: {assessment3.subject}")
    print(f"  Total Score: {assessment3.total_score}")
    print(f"  Risk Level: {assessment3.risk_level.value}")
    print(f"  Confidence: {assessment3.confidence:.2f}")
    print(f"  Recommendations: {assessment3.recommended_actions}")


def demo_alert_system():
    """演示告警系统"""
    print("\n" + "="*60)
    print("5. 告警系统演示")
    print("="*60)

    alert_manager = AlertManager()

    # 注册控制台通知渠道
    alert_manager.register_channel("console", console_channel)

    # 创建规则引擎
    engine = RuleEngine()
    scorer = RiskScorer()

    rule = (
        RuleBuilder("ALERT-001")
        .name("Critical Risk Detected")
        .when(RuleCondition.gte("risk_score", 80))
        .then(RuleAction.alert("Critical risk level reached"))
        .severity(RuleSeverity.CRITICAL)
        .risk_score(90)
        .build()
    )
    engine.add_rule(rule)
    scorer.register_rule(rule)

    # 模拟触发告警
    test_data = {
        "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fF00",
        "risk_score": 95,
        "is_sanctioned": True,
    }

    print("\n评估高风险数据...")
    results = engine.evaluate_all(test_data)
    assessment = scorer.assess(test_data["address"], "address", results)

    # 生成告警
    triggered = [r for r in results if r.triggered]
    if triggered:
        print("\n生成告警...")
        alert = alert_manager.create_alert_from_result(
            result=triggered[0],
            subject=test_data["address"],
            subject_type="address",
            assessment=assessment,
        )

        if alert:
            print(f"\n告警已创建:")
            print(f"  Alert ID: {alert.alert_id}")
            print(f"  Priority: {alert.priority.value}")
            print(f"  Status: {alert.status.value}")

    # 统计
    stats = alert_manager.get_statistics()
    print(f"\n告警统计:")
    print(f"  Total: {stats['total']}")
    print(f"  Open: {stats['open_count']}")


def demo_rule_manager():
    """演示规则管理器（整合）"""
    print("\n" + "="*60)
    print("6. 规则管理器演示（整合所有功能）")
    print("="*60)

    # 创建规则管理器（自动加载预置规则）
    manager = RuleManager(load_preset=True)

    # 注册告警渠道
    manager.alert_manager.register_channel("console", console_channel)

    # 查看已加载规则
    rules = manager.list_rules(enabled_only=False)
    print(f"\n已加载规则: {len(rules)} 条")

    # 按分类统计
    stats = manager.get_statistics()
    print(f"\n规则分布:")
    for cat, count in stats["by_category"].items():
        print(f"  {cat}: {count}")

    # 测试场景：评估一个可疑地址
    print("\n" + "-"*40)
    print("测试：评估可疑地址")
    print("-"*40)

    suspicious_address = {
        "address": "0x8576aCC5C05DAbc82098e1B5d2f3E3b60E8Fc2D1",
        "is_sanctioned": False,
        "labels": ["TORNADO_CASH", "HIGH_VOLUME"],
        "account_age_days": 5,
        "total_volume_eth": 50.0,
        "tx_count": 15,
        "time_pattern": "concentrated",
    }

    print(f"\n地址数据:")
    for key, value in suspicious_address.items():
        print(f"  {key}: {value}")

    assessment = manager.evaluate_address(suspicious_address)

    print(f"\n评估结果:")
    print(f"  Risk Score: {assessment.total_score}/100")
    print(f"  Risk Level: {assessment.risk_level.value.upper()}")
    print(f"  Rules Evaluated: {assessment.rules_evaluated}")
    print(f"  Rules Triggered: {assessment.rules_triggered}")

    if assessment.risk_factors:
        print(f"\n风险因子:")
        for factor in assessment.risk_factors[:5]:
            print(f"  - {factor.name} (+{factor.score})")

    if assessment.category_scores:
        print(f"\n分类评分:")
        for cat, score in assessment.category_scores.items():
            print(f"  {cat}: {score}")

    print(f"\n建议动作:")
    for action in assessment.recommended_actions:
        print(f"  • {action}")

    # 快速检查接口
    print("\n" + "-"*40)
    print("快速风险检查接口")
    print("-"*40)

    quick_result = manager.quick_check(suspicious_address, "address")
    print(f"\n快速检查结果:")
    print(f"  Subject: {quick_result['subject'][:20]}...")
    print(f"  Risk Score: {quick_result['risk_score']}")
    print(f"  Risk Level: {quick_result['risk_level']}")
    print(f"  Top Factors: {quick_result['top_factors']}")


def main():
    """主函数"""
    print("\n" + "="*60)
    print("   Web3 Risk Monitor - Phase 3: 风险规则引擎")
    print("="*60)

    try:
        # 1. 规则DSL演示
        demo_rule_dsl()

        # 2. 条件评估演示
        demo_condition_evaluation()

        # 3. 规则引擎演示
        demo_rule_engine()

        # 4. 风险评分演示
        demo_risk_scorer()

        # 5. 告警系统演示
        demo_alert_system()

        # 6. 整合演示
        demo_rule_manager()

        print("\n" + "="*60)
        print("Phase 3 探索完成!")
        print("="*60)
        print("\n主要功能模块:")
        print("  1. rule_model.py     - 规则数据模型与DSL")
        print("  2. rule_engine.py    - 规则评估引擎")
        print("  3. risk_scorer.py    - 风险评分聚合")
        print("  4. alert_system.py   - 告警生成与管理")
        print("  5. rule_manager.py   - 规则管理器与预置规则库")

    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
