"""
合约风险评估器

整合字节码分析和漏洞检测，生成综合风险报告
"""

from dataclasses import dataclass
from datetime import datetime as dt
from typing import Dict, List, Optional, Any
import time
import logging

from src.contract.contract_model import (
    ContractInfo,
    ContractType,
    BytecodeFeatures,
    Vulnerability,
    VulnerabilityType,
    VulnerabilitySeverity,
    ContractRiskReport,
)
from src.contract.bytecode_analyzer import BytecodeAnalyzer
from src.contract.vulnerability_detector import VulnerabilityDetector

logger = logging.getLogger(__name__)


# 漏洞严重程度对应的扣分
SEVERITY_SCORES = {
    VulnerabilitySeverity.CRITICAL: 40,
    VulnerabilitySeverity.HIGH: 25,
    VulnerabilitySeverity.MEDIUM: 10,
    VulnerabilitySeverity.LOW: 5,
    VulnerabilitySeverity.INFO: 0,
}

# 合约类型风险加成
CONTRACT_TYPE_RISK = {
    ContractType.UNKNOWN: 10,
    ContractType.ERC20: 0,
    ContractType.ERC721: 0,
    ContractType.ERC1155: 0,
    ContractType.PROXY: 15,
    ContractType.UPGRADEABLE: 20,
    ContractType.MULTISIG: -10,  # 多签降低风险
    ContractType.DEX_ROUTER: 10,
    ContractType.DEX_PAIR: 5,
    ContractType.LENDING: 15,
    ContractType.BRIDGE: 25,
    ContractType.STAKING: 10,
    ContractType.GOVERNANCE: 10,
    ContractType.MIXER: 50,
}


class ContractRiskAssessor:
    """合约风险评估器"""

    def __init__(self):
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.vulnerability_detector = VulnerabilityDetector()

    def assess(
        self,
        address: str,
        bytecode: str,
        source_code: Optional[str] = None,
        is_verified: bool = False,
        additional_info: Optional[Dict[str, Any]] = None
    ) -> ContractRiskReport:
        """评估合约风险

        Args:
            address: 合约地址
            bytecode: 合约字节码
            source_code: 源代码（可选）
            is_verified: 是否已验证
            additional_info: 额外信息

        Returns:
            ContractRiskReport 风险报告
        """
        start_time = time.time()

        # 创建合约信息
        contract = ContractInfo(
            address=address.lower(),
            bytecode=bytecode,
            is_verified=is_verified,
            source_code=source_code,
        )

        # 分析字节码
        contract = self.bytecode_analyzer.analyze_contract(contract)

        # 检测漏洞
        vulnerabilities = self.vulnerability_detector.detect(contract)

        # 生成报告
        report = ContractRiskReport(
            address=address.lower(),
            contract_info=contract,
            vulnerabilities=vulnerabilities,
        )

        # 计算各项评分
        self._calculate_scores(report)

        # 生成风险因素和建议
        self._generate_risk_factors(report)
        self._generate_recommendations(report)

        # 记录分析时间
        report.analysis_time_ms = (time.time() - start_time) * 1000

        logger.info(f"Contract analysis completed: {address}, score={report.risk_score}")

        return report

    def _calculate_scores(self, report: ContractRiskReport):
        """计算各项评分"""
        report.count_by_severity()

        # 1. 安全评分（从100开始扣分）
        security_score = 100
        for vuln in report.vulnerabilities:
            deduction = SEVERITY_SCORES.get(vuln.severity, 0)
            security_score -= deduction
        report.security_score = max(0, security_score)

        # 2. 中心化评分
        centralization_score = 0
        contract = report.contract_info

        if contract and contract.features:
            # 检查中心化指标
            owner_indicators = 0
            for vuln in report.vulnerabilities:
                if vuln.vuln_type in [
                    VulnerabilityType.OWNER_PRIVILEGE,
                    VulnerabilityType.HIDDEN_MINT,
                    VulnerabilityType.BLACKLIST_FUNCTION,
                    VulnerabilityType.PAUSE_FUNCTION,
                ]:
                    owner_indicators += 1

            centralization_score = min(100, owner_indicators * 25)

            # 可升级合约增加中心化分
            if contract.features.is_upgradeable:
                centralization_score = min(100, centralization_score + 30)

        report.centralization_score = centralization_score

        # 3. 代码质量评分
        code_quality_score = 100
        if contract and contract.features:
            # 未验证合约扣分
            if not contract.is_verified:
                code_quality_score -= 20

            # 使用已废弃的操作码扣分
            if contract.features.has_callcode:
                code_quality_score -= 15

            # 字节码过小（可能是简单代理或不完整）
            if contract.features.bytecode_size < 500:
                code_quality_score -= 10

        report.code_quality_score = max(0, code_quality_score)

        # 4. 综合风险评分
        # 基础分 = 100 - 安全评分
        risk_score = 100 - report.security_score

        # 加上合约类型风险
        if contract:
            type_risk = CONTRACT_TYPE_RISK.get(contract.contract_type, 0)
            risk_score += type_risk

        # 中心化程度影响
        risk_score += report.centralization_score * 0.2

        # 代码质量影响
        risk_score += (100 - report.code_quality_score) * 0.1

        report.risk_score = max(0, min(100, int(risk_score)))

        # 5. 风险等级
        if report.risk_score >= 80 or report.critical_count > 0:
            report.risk_level = "critical"
        elif report.risk_score >= 60 or report.high_count > 0:
            report.risk_level = "high"
        elif report.risk_score >= 40:
            report.risk_level = "medium"
        elif report.risk_score >= 20:
            report.risk_level = "low"
        else:
            report.risk_level = "minimal"

    def _generate_risk_factors(self, report: ContractRiskReport):
        """生成风险因素列表"""
        factors = []
        contract = report.contract_info

        # 基于漏洞
        for vuln in report.vulnerabilities:
            if vuln.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]:
                factors.append(f"[{vuln.severity.value.upper()}] {vuln.title}")

        # 基于合约类型
        if contract:
            if contract.contract_type == ContractType.MIXER:
                factors.append("合约类型: 混币器 (高风险)")
            elif contract.contract_type == ContractType.BRIDGE:
                factors.append("合约类型: 跨链桥 (历史攻击高发)")
            elif contract.contract_type == ContractType.UPGRADEABLE:
                factors.append("可升级合约: 逻辑可被修改")

            # 基于特征
            if contract.features:
                if contract.features.has_selfdestruct:
                    factors.append("包含SELFDESTRUCT操作码")
                if not contract.is_verified:
                    factors.append("合约未验证源码")

        # 基于中心化
        if report.centralization_score >= 75:
            factors.append("高度中心化: 所有者权限过大")
        elif report.centralization_score >= 50:
            factors.append("中等中心化: 存在特权函数")

        report.risk_factors = factors[:10]  # 最多10个因素

    def _generate_recommendations(self, report: ContractRiskReport):
        """生成建议"""
        recommendations = []

        # 基于风险等级
        if report.risk_level == "critical":
            recommendations.append("建议不要与此合约交互")
            recommendations.append("如已持有相关资产，建议尽快转出")
        elif report.risk_level == "high":
            recommendations.append("谨慎交互，仅投入可承受损失的资金")
            recommendations.append("密切关注合约动态和安全审计报告")

        # 基于具体漏洞
        vuln_types = set(v.vuln_type for v in report.vulnerabilities)

        if VulnerabilityType.HONEYPOT in vuln_types:
            recommendations.append("疑似蜜罐合约，强烈建议不要购买相关代币")

        if VulnerabilityType.HIDDEN_MINT in vuln_types:
            recommendations.append("代币可被增发，注意稀释风险")

        if VulnerabilityType.BLACKLIST_FUNCTION in vuln_types:
            recommendations.append("合约有黑名单功能，资产可能被冻结")

        # 基于合约类型
        contract = report.contract_info
        if contract:
            if contract.contract_type == ContractType.UPGRADEABLE:
                recommendations.append("关注升级公告，升级可能改变合约行为")

            if not contract.is_verified:
                recommendations.append("要求项目方公开并验证合约源码")

        # 基于中心化
        if report.centralization_score >= 50:
            recommendations.append("关注项目治理机制，评估去中心化程度")

        report.recommendations = list(dict.fromkeys(recommendations))[:8]  # 去重，最多8条

    def quick_assess(self, address: str, bytecode: str) -> Dict[str, Any]:
        """快速评估（返回简化结果）"""
        report = self.assess(address, bytecode)

        return {
            "address": report.address,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level,
            "vulnerability_count": len(report.vulnerabilities),
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "contract_type": report.contract_info.contract_type.value if report.contract_info else "unknown",
            "top_risks": report.risk_factors[:3],
        }

    def batch_assess(
        self,
        contracts: List[Dict[str, str]]
    ) -> List[ContractRiskReport]:
        """批量评估

        Args:
            contracts: [{"address": "0x...", "bytecode": "0x..."}, ...]

        Returns:
            报告列表
        """
        reports = []
        for contract in contracts:
            try:
                report = self.assess(
                    address=contract["address"],
                    bytecode=contract["bytecode"],
                    is_verified=contract.get("is_verified", False),
                )
                reports.append(report)
            except Exception as e:
                logger.error(f"Failed to assess {contract.get('address')}: {e}")
        return reports

    def compare_contracts(
        self,
        address1: str,
        bytecode1: str,
        address2: str,
        bytecode2: str
    ) -> Dict[str, Any]:
        """比较两个合约"""
        report1 = self.assess(address1, bytecode1)
        report2 = self.assess(address2, bytecode2)

        bytecode_comparison = self.bytecode_analyzer.compare_bytecode(bytecode1, bytecode2)

        return {
            "contract1": {
                "address": address1,
                "risk_score": report1.risk_score,
                "risk_level": report1.risk_level,
                "vulnerabilities": len(report1.vulnerabilities),
            },
            "contract2": {
                "address": address2,
                "risk_score": report2.risk_score,
                "risk_level": report2.risk_level,
                "vulnerabilities": len(report2.vulnerabilities),
            },
            "comparison": {
                "same_code": bytecode_comparison["hash_match"],
                "risk_diff": report2.risk_score - report1.risk_score,
                "bytecode_diff": bytecode_comparison,
            }
        }

    def get_assessment_stats(self) -> Dict[str, Any]:
        """获取评估器统计信息"""
        return {
            "vulnerability_patterns": self.vulnerability_detector.get_pattern_count(),
            "supported_contract_types": len(ContractType),
            "severity_weights": {k.value: v for k, v in SEVERITY_SCORES.items()},
        }
