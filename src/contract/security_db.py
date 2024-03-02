"""
合约安全数据库

存储已知的：
- 漏洞合约
- 攻击事件
- 审计报告
- 安全合约（白名单）
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt
from typing import Dict, List, Optional, Set, Any
from enum import Enum
import hashlib


class AttackType(str, Enum):
    """攻击类型"""
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    BRIDGE_EXPLOIT = "bridge_exploit"
    PRIVATE_KEY_LEAK = "private_key_leak"
    RUG_PULL = "rug_pull"
    ACCESS_CONTROL = "access_control"
    LOGIC_ERROR = "logic_error"
    FRONT_RUNNING = "front_running"
    OTHER = "other"


class AuditResult(str, Enum):
    """审计结果"""
    PASSED = "passed"                    # 通过，无严重问题
    PASSED_WITH_FINDINGS = "passed_with_findings"  # 通过，有发现
    FAILED = "failed"                    # 未通过
    PENDING = "pending"                  # 待定


@dataclass
class AttackRecord:
    """攻击记录"""
    attack_id: str
    contract_address: str
    attack_type: AttackType
    attack_date: dt
    loss_usd: float
    attacker_address: Optional[str] = None
    attack_tx: Optional[str] = None
    description: str = ""
    root_cause: str = ""
    references: List[str] = dc_field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "contract_address": self.contract_address,
            "attack_type": self.attack_type.value,
            "attack_date": self.attack_date.isoformat(),
            "loss_usd": self.loss_usd,
            "attacker_address": self.attacker_address,
            "attack_tx": self.attack_tx,
            "description": self.description,
            "root_cause": self.root_cause,
        }


@dataclass
class AuditReport:
    """审计报告"""
    report_id: str
    contract_address: str
    auditor: str
    audit_date: dt
    result: AuditResult
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    report_url: Optional[str] = None
    verified_fix: bool = False           # 问题是否已修复验证

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "contract_address": self.contract_address,
            "auditor": self.auditor,
            "audit_date": self.audit_date.isoformat(),
            "result": self.result.value,
            "findings": {
                "critical": self.findings_critical,
                "high": self.findings_high,
                "medium": self.findings_medium,
                "low": self.findings_low,
            },
            "report_url": self.report_url,
            "verified_fix": self.verified_fix,
        }


class SecurityDatabase:
    """合约安全数据库"""

    def __init__(self):
        # 已知漏洞合约
        self._vulnerable_contracts: Dict[str, Dict] = {}

        # 攻击记录
        self._attacks: Dict[str, AttackRecord] = {}
        self._attacks_by_contract: Dict[str, List[str]] = {}

        # 审计报告
        self._audits: Dict[str, AuditReport] = {}
        self._audits_by_contract: Dict[str, List[str]] = {}

        # 已知安全合约（白名单）
        self._safe_contracts: Set[str] = set()

        # 已知恶意合约（黑名单）
        self._malicious_contracts: Set[str] = set()

        # 字节码哈希索引（用于识别克隆/分叉）
        self._bytecode_hash_index: Dict[str, List[str]] = {}

        # 加载预置数据
        self._load_preset_data()

    def _load_preset_data(self):
        """加载预置的安全数据"""
        # ===== 已知攻击事件 =====

        attacks = [
            AttackRecord(
                attack_id="ATK-2024-001",
                contract_address="0x1234567890123456789012345678901234567890",  # 示例
                attack_type=AttackType.BRIDGE_EXPLOIT,
                attack_date=dt(2024, 1, 2),
                loss_usd=81_000_000,
                description="Orbit Chain跨链桥攻击",
                root_cause="跨链消息验证漏洞",
                references=["https://rekt.news/orbit-chain-rekt/"],
            ),
            AttackRecord(
                attack_id="ATK-2024-002",
                contract_address="0x2345678901234567890123456789012345678901",  # 示例
                attack_type=AttackType.PRIVATE_KEY_LEAK,
                attack_date=dt(2024, 2, 9),
                loss_usd=290_000_000,
                description="PlayDapp私钥泄露",
                root_cause="私钥管理不当",
                references=["https://rekt.news/playdapp-rekt/"],
            ),
            AttackRecord(
                attack_id="ATK-2024-003",
                contract_address="0x3456789012345678901234567890123456789012",  # 示例
                attack_type=AttackType.ACCESS_CONTROL,
                attack_date=dt(2024, 3, 26),
                loss_usd=62_500_000,
                description="Munchables攻击（后归还）",
                root_cause="内部开发者攻击",
                references=["https://rekt.news/munchables-rekt/"],
            ),
            AttackRecord(
                attack_id="ATK-2024-004",
                contract_address="0xcf0c122c6b73ff809c693db761e7baebe62b6a2e",  # WazirX
                attack_type=AttackType.ACCESS_CONTROL,
                attack_date=dt(2024, 7, 18),
                loss_usd=230_000_000,
                description="WazirX多签钱包被盗",
                root_cause="多签配置被突破",
                references=["https://rekt.news/wazirx-rekt/"],
            ),
        ]

        for attack in attacks:
            self.add_attack(attack)

        # ===== 已知恶意合约 =====

        # Tornado Cash (OFAC制裁)
        tornado_contracts = [
            "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # ETH Tornado Cash
            "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # 100 ETH pool
            "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # 10 ETH pool
            "0xa160cdab225685da1d56aa342ad8841c3b53f291",  # 1 ETH pool
            "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",  # 0.1 ETH pool
        ]
        for addr in tornado_contracts:
            self.add_malicious_contract(addr.lower(), "OFAC_SANCTIONED")

        # ===== 已知安全合约（主流协议） =====

        safe_contracts = [
            "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
            "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
            "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap V3 Router 2
            "0x1111111254fb6c44bac0bed2854e76f90643097d",  # 1inch Router V4
            "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # Aave V2 Pool
            "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  # Aave V3 Pool
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
            "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
            "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
        ]
        for addr in safe_contracts:
            self.add_safe_contract(addr.lower())

        # ===== 审计报告 =====

        audits = [
            AuditReport(
                report_id="AUDIT-2023-001",
                contract_address="0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                auditor="OpenZeppelin",
                audit_date=dt(2020, 5, 1),
                result=AuditResult.PASSED,
                findings_critical=0,
                findings_high=0,
                findings_medium=2,
                findings_low=5,
                verified_fix=True,
            ),
            AuditReport(
                report_id="AUDIT-2023-002",
                contract_address="0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
                auditor="Trail of Bits",
                audit_date=dt(2023, 3, 15),
                result=AuditResult.PASSED_WITH_FINDINGS,
                findings_critical=0,
                findings_high=1,
                findings_medium=3,
                findings_low=8,
                verified_fix=True,
            ),
        ]
        for audit in audits:
            self.add_audit(audit)

    # ===== 攻击记录管理 =====

    def add_attack(self, attack: AttackRecord):
        """添加攻击记录"""
        self._attacks[attack.attack_id] = attack

        addr = attack.contract_address.lower()
        if addr not in self._attacks_by_contract:
            self._attacks_by_contract[addr] = []
        self._attacks_by_contract[addr].append(attack.attack_id)

        # 自动加入恶意合约列表
        self.add_malicious_contract(addr, f"ATTACKED_{attack.attack_type.value}")

    def get_attacks_by_contract(self, address: str) -> List[AttackRecord]:
        """获取合约的攻击记录"""
        addr = address.lower()
        attack_ids = self._attacks_by_contract.get(addr, [])
        return [self._attacks[aid] for aid in attack_ids if aid in self._attacks]

    def has_been_attacked(self, address: str) -> bool:
        """检查合约是否被攻击过"""
        return address.lower() in self._attacks_by_contract

    # ===== 审计报告管理 =====

    def add_audit(self, audit: AuditReport):
        """添加审计报告"""
        self._audits[audit.report_id] = audit

        addr = audit.contract_address.lower()
        if addr not in self._audits_by_contract:
            self._audits_by_contract[addr] = []
        self._audits_by_contract[addr].append(audit.report_id)

    def get_audits_by_contract(self, address: str) -> List[AuditReport]:
        """获取合约的审计报告"""
        addr = address.lower()
        audit_ids = self._audits_by_contract.get(addr, [])
        return [self._audits[aid] for aid in audit_ids if aid in self._audits]

    def is_audited(self, address: str) -> bool:
        """检查合约是否被审计过"""
        return address.lower() in self._audits_by_contract

    def get_latest_audit(self, address: str) -> Optional[AuditReport]:
        """获取最新的审计报告"""
        audits = self.get_audits_by_contract(address)
        if not audits:
            return None
        return max(audits, key=lambda a: a.audit_date)

    # ===== 安全/恶意合约管理 =====

    def add_safe_contract(self, address: str):
        """添加安全合约"""
        self._safe_contracts.add(address.lower())

    def add_malicious_contract(self, address: str, reason: str = ""):
        """添加恶意合约"""
        addr = address.lower()
        self._malicious_contracts.add(addr)
        if addr not in self._vulnerable_contracts:
            self._vulnerable_contracts[addr] = {}
        self._vulnerable_contracts[addr]["reason"] = reason

    def is_safe(self, address: str) -> bool:
        """检查是否为安全合约"""
        return address.lower() in self._safe_contracts

    def is_malicious(self, address: str) -> bool:
        """检查是否为恶意合约"""
        return address.lower() in self._malicious_contracts

    def get_contract_status(self, address: str) -> Dict[str, Any]:
        """获取合约安全状态"""
        addr = address.lower()

        return {
            "address": addr,
            "is_safe": self.is_safe(addr),
            "is_malicious": self.is_malicious(addr),
            "is_audited": self.is_audited(addr),
            "has_been_attacked": self.has_been_attacked(addr),
            "attack_count": len(self._attacks_by_contract.get(addr, [])),
            "audit_count": len(self._audits_by_contract.get(addr, [])),
        }

    # ===== 字节码哈希索引 =====

    def index_bytecode(self, address: str, bytecode_hash: str):
        """索引字节码哈希"""
        if bytecode_hash not in self._bytecode_hash_index:
            self._bytecode_hash_index[bytecode_hash] = []
        if address.lower() not in self._bytecode_hash_index[bytecode_hash]:
            self._bytecode_hash_index[bytecode_hash].append(address.lower())

    def find_similar_contracts(self, bytecode_hash: str) -> List[str]:
        """查找相同字节码的合约"""
        return self._bytecode_hash_index.get(bytecode_hash, [])

    def is_known_malicious_code(self, bytecode_hash: str) -> bool:
        """检查字节码是否与已知恶意合约相同"""
        similar = self.find_similar_contracts(bytecode_hash)
        return any(self.is_malicious(addr) for addr in similar)

    # ===== 查询接口 =====

    def check_contract(self, address: str, bytecode_hash: Optional[str] = None) -> Dict[str, Any]:
        """综合检查合约

        Returns:
            {
                "address": str,
                "risk_level": str,  # safe, unknown, suspicious, dangerous
                "flags": List[str],
                "details": Dict
            }
        """
        addr = address.lower()
        flags = []
        risk_level = "unknown"

        # 检查白名单
        if self.is_safe(addr):
            risk_level = "safe"
            flags.append("WHITELISTED")

        # 检查黑名单
        if self.is_malicious(addr):
            risk_level = "dangerous"
            flags.append("BLACKLISTED")
            if addr in self._vulnerable_contracts:
                reason = self._vulnerable_contracts[addr].get("reason", "")
                if reason:
                    flags.append(reason)

        # 检查攻击历史
        attacks = self.get_attacks_by_contract(addr)
        if attacks:
            if risk_level != "dangerous":
                risk_level = "dangerous"
            flags.append(f"ATTACKED_{len(attacks)}_TIMES")
            total_loss = sum(a.loss_usd for a in attacks)
            if total_loss > 0:
                flags.append(f"TOTAL_LOSS_${total_loss:,.0f}")

        # 检查审计状态
        audits = self.get_audits_by_contract(addr)
        if audits:
            latest = max(audits, key=lambda a: a.audit_date)
            if latest.result == AuditResult.PASSED:
                flags.append("AUDIT_PASSED")
            elif latest.result == AuditResult.FAILED:
                flags.append("AUDIT_FAILED")
                if risk_level == "unknown":
                    risk_level = "suspicious"
            if latest.findings_critical > 0:
                flags.append(f"AUDIT_CRITICAL_{latest.findings_critical}")

        # 检查字节码相似性
        if bytecode_hash:
            if self.is_known_malicious_code(bytecode_hash):
                flags.append("SIMILAR_TO_MALICIOUS")
                if risk_level == "unknown":
                    risk_level = "suspicious"

        return {
            "address": addr,
            "risk_level": risk_level,
            "flags": flags,
            "details": {
                "attack_count": len(attacks),
                "audit_count": len(audits),
                "is_safe_listed": self.is_safe(addr),
                "is_black_listed": self.is_malicious(addr),
            }
        }

    def get_statistics(self) -> Dict[str, Any]:
        """获取数据库统计"""
        attack_by_type = {}
        total_loss = 0
        for attack in self._attacks.values():
            attack_by_type[attack.attack_type.value] = attack_by_type.get(attack.attack_type.value, 0) + 1
            total_loss += attack.loss_usd

        return {
            "total_attacks": len(self._attacks),
            "total_loss_usd": total_loss,
            "attacks_by_type": attack_by_type,
            "total_audits": len(self._audits),
            "safe_contracts": len(self._safe_contracts),
            "malicious_contracts": len(self._malicious_contracts),
            "indexed_bytecodes": len(self._bytecode_hash_index),
        }

    def export_blacklist(self) -> List[str]:
        """导出黑名单"""
        return list(self._malicious_contracts)

    def export_whitelist(self) -> List[str]:
        """导出白名单"""
        return list(self._safe_contracts)
