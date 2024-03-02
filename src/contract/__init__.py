"""
智能合约风险识别

Phase 4: 合约安全分析系统

模块：
- contract_model: 合约数据模型
- bytecode_analyzer: 字节码分析器
- vulnerability_detector: 漏洞模式检测
- contract_risk: 合约风险评估
- security_db: 合约安全数据库
"""

from src.contract.contract_model import (
    ContractInfo,
    ContractType,
    BytecodeFeatures,
    VulnerabilityType,
    Vulnerability,
    ContractRiskReport,
)
from src.contract.bytecode_analyzer import BytecodeAnalyzer
from src.contract.vulnerability_detector import VulnerabilityDetector
from src.contract.contract_risk import ContractRiskAssessor
from src.contract.security_db import SecurityDatabase

__all__ = [
    "ContractInfo",
    "ContractType",
    "BytecodeFeatures",
    "VulnerabilityType",
    "Vulnerability",
    "ContractRiskReport",
    "BytecodeAnalyzer",
    "VulnerabilityDetector",
    "ContractRiskAssessor",
    "SecurityDatabase",
]
