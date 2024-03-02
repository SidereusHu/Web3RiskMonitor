"""
Phase 4 探索脚本：智能合约风险识别

演示：
1. 字节码分析
2. 漏洞检测
3. 合约风险评估
4. 安全数据库查询
"""

import sys
sys.path.insert(0, "/Users/sidereus/Documents/FindJobs/Web3RiskMonitor")

from src.contract.contract_model import (
    ContractInfo,
    ContractType,
    VulnerabilityType,
    VulnerabilitySeverity,
)
from src.contract.bytecode_analyzer import BytecodeAnalyzer, ERC20_SELECTORS
from src.contract.vulnerability_detector import VulnerabilityDetector
from src.contract.contract_risk import ContractRiskAssessor
from src.contract.security_db import SecurityDatabase, AttackType


# 示例字节码（简化的ERC-20代币合约特征）
SAMPLE_ERC20_BYTECODE = """
6080604052348015600f57600080fd5b5060043610603c5760003560e01c806306fdde03146041
578063095ea7b31460595780631694505514607157806318160ddd146089578063313ce567146
0a157806323b872dd1460b957806370a082311460cf578063a9059cbb1460e5578063dd62ed3e
1460fb575b600080fd5b60476111565b60405180806020018281038252838181518152602001
91508051906020019080838360005b8381101560875780820151818401526020810190506
06c565b50505050905090810190601f1680156100b35780820380516001836020036101000a
031916815260200191505b509250505060405180910390f35b60c560048036038101906100
c091906101f456
"""

# 带有危险函数的代币合约示例
SAMPLE_RISKY_TOKEN_BYTECODE = """
6080604052348015600f57600080fd5b5060043610610107576000357c010000000000000000
0000000000000000000000000000000000000000000090048063715018a6116100a9578063a9
059cbb1161007e578063a9059cbb14610231578063dd62ed3e14610261578063f2fde38b1461
0291578063f9f92be4146102c157610107565b8063715018a6146101c15780638456cb59146
101cb5780638da5cb5b146101d557806395d89b411461020157610107565b806323b872dd11
6100e557806323b872dd1461016b5780633f4ba83a1461019b57806340c10f19146101a5578
06370a08231146101d557610107565b806306fdde031461010c578063095ea7b31461012a57
8063165c4a161461015a57806318160ddd14610161575b600080fd
"""

# 代理合约字节码（EIP-1167最小代理）
SAMPLE_PROXY_BYTECODE = """
363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d
91602b57fd5bf3
"""

# 带有SELFDESTRUCT的合约（简化示例）
SAMPLE_SELFDESTRUCT_BYTECODE = """
6080604052348015600f57600080fd5b506004361060285760003560e01c806341c0e1b51460
2d575b600080fd5b60336035565b005b3373ffffffffffffffffffffffffffffffffffffffff
16ff
"""


def demo_bytecode_analysis():
    """演示字节码分析"""
    print("\n" + "="*60)
    print("1. 字节码分析演示")
    print("="*60)

    analyzer = BytecodeAnalyzer()

    # 分析ERC-20合约
    print("\n[分析标准ERC-20合约]")
    bytecode = SAMPLE_ERC20_BYTECODE.replace("\n", "").replace(" ", "")
    features = analyzer.analyze(bytecode)

    print(f"  字节码大小: {features.bytecode_size} bytes")
    print(f"  字节码哈希: {features.bytecode_hash[:16]}...")
    print(f"  函数选择器数量: {len(features.function_selectors)}")
    print(f"  检测到的选择器:")
    for selector in features.function_selectors[:5]:
        func_name = ERC20_SELECTORS.get(selector, "unknown")
        print(f"    {selector}: {func_name}")
    print(f"  实现ERC-20: {features.implements_erc20}")
    print(f"  实现ERC-721: {features.implements_erc721}")

    # 分析代理合约
    print("\n[分析代理合约]")
    proxy_bytecode = SAMPLE_PROXY_BYTECODE.replace("\n", "").replace(" ", "")
    proxy_features = analyzer.analyze(proxy_bytecode)

    print(f"  字节码大小: {proxy_features.bytecode_size} bytes")
    print(f"  是最小代理 (EIP-1167): {proxy_features.is_minimal_proxy}")
    print(f"  是代理合约: {proxy_features.is_proxy}")
    print(f"  有DELEGATECALL: {proxy_features.has_delegatecall}")

    # 合约类型识别
    print("\n[合约类型识别]")
    contract_type = analyzer.identify_contract_type(features)
    print(f"  ERC-20合约类型: {contract_type.value}")

    proxy_type = analyzer.identify_contract_type(proxy_features)
    print(f"  代理合约类型: {proxy_type.value}")


def demo_vulnerability_detection():
    """演示漏洞检测"""
    print("\n" + "="*60)
    print("2. 漏洞检测演示")
    print("="*60)

    analyzer = BytecodeAnalyzer()
    detector = VulnerabilityDetector()

    print(f"\n已注册 {detector.get_pattern_count()} 种漏洞模式")

    # 检测带有危险函数的代币
    print("\n[检测风险代币合约]")
    bytecode = SAMPLE_RISKY_TOKEN_BYTECODE.replace("\n", "").replace(" ", "")

    contract = ContractInfo(
        address="0x1234567890123456789012345678901234567890",
        bytecode=bytecode,
    )
    contract = analyzer.analyze_contract(contract)

    vulnerabilities = detector.detect(contract)

    print(f"  合约类型: {contract.contract_type.value}")
    print(f"  发现漏洞: {len(vulnerabilities)} 个")

    for vuln in vulnerabilities:
        severity_icon = {
            VulnerabilitySeverity.CRITICAL: "🔴",
            VulnerabilitySeverity.HIGH: "🟠",
            VulnerabilitySeverity.MEDIUM: "🟡",
            VulnerabilitySeverity.LOW: "🟢",
            VulnerabilitySeverity.INFO: "🔵",
        }.get(vuln.severity, "⚪")

        print(f"\n  {severity_icon} [{vuln.severity.value.upper()}] {vuln.title}")
        print(f"     类型: {vuln.vuln_type.value}")
        print(f"     描述: {vuln.description[:60]}...")
        if vuln.swc_id:
            print(f"     SWC: {vuln.swc_id}")

    # 检测带有SELFDESTRUCT的合约
    print("\n[检测可销毁合约]")
    sd_bytecode = SAMPLE_SELFDESTRUCT_BYTECODE.replace("\n", "").replace(" ", "")

    contract2 = ContractInfo(
        address="0x2345678901234567890123456789012345678901",
        bytecode=sd_bytecode,
    )
    contract2 = analyzer.analyze_contract(contract2)

    vulns2 = detector.detect(contract2)

    print(f"  有SELFDESTRUCT: {contract2.features.has_selfdestruct}")
    print(f"  发现漏洞: {len(vulns2)} 个")
    for vuln in vulns2:
        print(f"    - [{vuln.severity.value}] {vuln.title}")


def demo_contract_risk_assessment():
    """演示合约风险评估"""
    print("\n" + "="*60)
    print("3. 合约风险评估演示")
    print("="*60)

    assessor = ContractRiskAssessor()

    # 评估风险代币
    print("\n[评估风险代币合约]")
    bytecode = SAMPLE_RISKY_TOKEN_BYTECODE.replace("\n", "").replace(" ", "")

    report = assessor.assess(
        address="0x1234567890123456789012345678901234567890",
        bytecode=bytecode,
        is_verified=False,
    )

    print(f"\n{'='*50}")
    print(report.summary())
    print(f"{'='*50}")

    print(f"\n详细评分:")
    print(f"  安全性评分: {report.security_score}/100")
    print(f"  中心化程度: {report.centralization_score}/100")
    print(f"  代码质量: {report.code_quality_score}/100")
    print(f"  综合风险分: {report.risk_score}/100")
    print(f"  风险等级: {report.risk_level}")
    print(f"  分析耗时: {report.analysis_time_ms:.2f}ms")

    if report.recommendations:
        print(f"\n建议:")
        for rec in report.recommendations:
            print(f"  • {rec}")

    # 快速评估
    print("\n[快速评估接口]")
    quick_result = assessor.quick_assess(
        address="0x3456789012345678901234567890123456789012",
        bytecode=bytecode,
    )
    print(f"  地址: {quick_result['address'][:20]}...")
    print(f"  风险分: {quick_result['risk_score']}")
    print(f"  风险等级: {quick_result['risk_level']}")
    print(f"  漏洞数: {quick_result['vulnerability_count']}")


def demo_security_database():
    """演示安全数据库"""
    print("\n" + "="*60)
    print("4. 安全数据库演示")
    print("="*60)

    db = SecurityDatabase()

    # 统计信息
    stats = db.get_statistics()
    print(f"\n数据库统计:")
    print(f"  攻击记录: {stats['total_attacks']} 条")
    print(f"  总损失: ${stats['total_loss_usd']:,.0f}")
    print(f"  审计报告: {stats['total_audits']} 份")
    print(f"  安全合约: {stats['safe_contracts']} 个")
    print(f"  恶意合约: {stats['malicious_contracts']} 个")

    print(f"\n攻击类型分布:")
    for attack_type, count in stats['attacks_by_type'].items():
        print(f"    {attack_type}: {count}")

    # 检查已知合约
    print("\n[检查已知合约]")

    # Uniswap V2 Router (安全)
    uniswap = db.check_contract("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")
    print(f"\nUniswap V2 Router:")
    print(f"  风险等级: {uniswap['risk_level']}")
    print(f"  标志: {uniswap['flags']}")

    # Tornado Cash (制裁)
    tornado = db.check_contract("0x722122df12d4e14e13ac3b6895a86e84145b6967")
    print(f"\nTornado Cash:")
    print(f"  风险等级: {tornado['risk_level']}")
    print(f"  标志: {tornado['flags']}")

    # WazirX (被攻击)
    wazirx = db.check_contract("0xcf0c122c6b73ff809c693db761e7baebe62b6a2e")
    print(f"\nWazirX多签钱包:")
    print(f"  风险等级: {wazirx['risk_level']}")
    print(f"  标志: {wazirx['flags']}")

    # 获取攻击详情
    attacks = db.get_attacks_by_contract("0xcf0c122c6b73ff809c693db761e7baebe62b6a2e")
    if attacks:
        attack = attacks[0]
        print(f"\n攻击详情:")
        print(f"  攻击类型: {attack.attack_type.value}")
        print(f"  损失: ${attack.loss_usd:,.0f}")
        print(f"  描述: {attack.description}")

    # 检查审计
    print("\n[审计报告查询]")
    audit = db.get_latest_audit("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")
    if audit:
        print(f"  审计方: {audit.auditor}")
        print(f"  结果: {audit.result.value}")
        print(f"  发现: Critical={audit.findings_critical}, High={audit.findings_high}")


def demo_integrated_workflow():
    """演示整合工作流"""
    print("\n" + "="*60)
    print("5. 整合工作流演示")
    print("="*60)

    assessor = ContractRiskAssessor()
    db = SecurityDatabase()

    # 模拟接收到新合约地址
    new_contract_address = "0xabcdef1234567890abcdef1234567890abcdef12"
    bytecode = SAMPLE_RISKY_TOKEN_BYTECODE.replace("\n", "").replace(" ", "")

    print(f"\n[分析新合约: {new_contract_address[:20]}...]")

    # 步骤1: 检查数据库
    db_check = db.check_contract(new_contract_address)
    print(f"\n1. 数据库检查:")
    print(f"   是否在白名单: {db_check['details']['is_safe_listed']}")
    print(f"   是否在黑名单: {db_check['details']['is_black_listed']}")
    print(f"   是否被审计: {db_check['details']['audit_count'] > 0}")

    # 步骤2: 分析字节码
    print(f"\n2. 字节码分析:")
    report = assessor.assess(new_contract_address, bytecode, is_verified=False)

    print(f"   合约类型: {report.contract_info.contract_type.value}")
    print(f"   风险评分: {report.risk_score}/100")
    print(f"   风险等级: {report.risk_level}")
    print(f"   漏洞数量: {len(report.vulnerabilities)}")

    # 步骤3: 汇总结论
    print(f"\n3. 风险评估结论:")

    if report.risk_level in ["critical", "high"]:
        print(f"   ⚠️  高风险合约，建议谨慎交互")
    elif report.risk_level == "medium":
        print(f"   ⚡ 中等风险，建议进一步审查")
    else:
        print(f"   ✅ 风险较低")

    print(f"\n   主要风险因素:")
    for factor in report.risk_factors[:3]:
        print(f"     - {factor}")

    print(f"\n   建议操作:")
    for rec in report.recommendations[:3]:
        print(f"     - {rec}")


def main():
    """主函数"""
    print("\n" + "="*60)
    print("   Web3 Risk Monitor - Phase 4: 智能合约风险识别")
    print("="*60)

    try:
        # 1. 字节码分析
        demo_bytecode_analysis()

        # 2. 漏洞检测
        demo_vulnerability_detection()

        # 3. 风险评估
        demo_contract_risk_assessment()

        # 4. 安全数据库
        demo_security_database()

        # 5. 整合工作流
        demo_integrated_workflow()

        print("\n" + "="*60)
        print("Phase 4 探索完成!")
        print("="*60)
        print("\n主要功能模块:")
        print("  1. contract_model.py      - 合约数据模型")
        print("  2. bytecode_analyzer.py   - 字节码分析器")
        print("  3. vulnerability_detector.py - 漏洞模式检测")
        print("  4. contract_risk.py       - 合约风险评估")
        print("  5. security_db.py         - 安全数据库")

    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
