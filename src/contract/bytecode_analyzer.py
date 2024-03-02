"""
字节码分析器

分析EVM字节码，提取特征：
- 操作码统计
- 函数选择器提取
- 危险操作检测
- 合约类型识别
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set, Any
import hashlib
import re

from src.contract.contract_model import (
    BytecodeFeatures,
    ContractType,
    ContractInfo,
)


# EVM操作码定义
OPCODES = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0a: "EXP",
    0x0b: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1a: "BYTE",
    0x1b: "SHL",
    0x1c: "SHR",
    0x1d: "SAR",
    0x20: "SHA3",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3a: "GASPRICE",
    0x3b: "EXTCODESIZE",
    0x3c: "EXTCODECOPY",
    0x3d: "RETURNDATASIZE",
    0x3e: "RETURNDATACOPY",
    0x3f: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "DIFFICULTY",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5a: "GAS",
    0x5b: "JUMPDEST",
    0x5f: "PUSH0",
    0xf0: "CREATE",
    0xf1: "CALL",
    0xf2: "CALLCODE",
    0xf3: "RETURN",
    0xf4: "DELEGATECALL",
    0xf5: "CREATE2",
    0xfa: "STATICCALL",
    0xfd: "REVERT",
    0xfe: "INVALID",
    0xff: "SELFDESTRUCT",
}

# PUSH操作码范围
for i in range(32):
    OPCODES[0x60 + i] = f"PUSH{i+1}"

# DUP操作码范围
for i in range(16):
    OPCODES[0x80 + i] = f"DUP{i+1}"

# SWAP操作码范围
for i in range(16):
    OPCODES[0x90 + i] = f"SWAP{i+1}"

# LOG操作码范围
for i in range(5):
    OPCODES[0xa0 + i] = f"LOG{i}"


# ERC标准函数选择器
ERC20_SELECTORS = {
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    "0x313ce567": "decimals()",
    "0x18160ddd": "totalSupply()",
    "0x70a08231": "balanceOf(address)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0xdd62ed3e": "allowance(address,address)",
}

ERC721_SELECTORS = {
    "0x70a08231": "balanceOf(address)",
    "0x6352211e": "ownerOf(uint256)",
    "0x42842e0e": "safeTransferFrom(address,address,uint256)",
    "0xb88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0xa22cb465": "setApprovalForAll(address,bool)",
    "0x081812fc": "getApproved(uint256)",
    "0xe985e9c5": "isApprovedForAll(address,address)",
}

# 代理合约模式
MINIMAL_PROXY_PREFIX = "363d3d373d3d3d363d73"
MINIMAL_PROXY_SUFFIX = "5af43d82803e903d91602b57fd5bf3"

# 已知危险函数选择器
DANGEROUS_SELECTORS = {
    "0x715018a6": "renounceOwnership()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x8456cb59": "pause()",
    "0x3f4ba83a": "unpause()",
    "0x40c10f19": "mint(address,uint256)",
    "0x42966c68": "burn(uint256)",
    "0x79cc6790": "burnFrom(address,uint256)",
    "0x16c38b3c": "setBlacklist(address,bool)",
    "0xf9f92be4": "blacklist(address)",
}


class BytecodeAnalyzer:
    """字节码分析器"""

    def __init__(self):
        self.opcodes = OPCODES

    def analyze(self, bytecode: str) -> BytecodeFeatures:
        """分析字节码

        Args:
            bytecode: 合约字节码（0x开头的十六进制字符串）

        Returns:
            BytecodeFeatures 特征对象
        """
        features = BytecodeFeatures()

        # 清理字节码
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]

        if not bytecode or bytecode == "0x":
            return features

        # 计算哈希
        features.bytecode_hash = hashlib.sha256(bytes.fromhex(bytecode)).hexdigest()
        features.bytecode_size = len(bytecode) // 2

        # 解析操作码
        features.opcode_count = self._count_opcodes(bytecode)

        # 检测特征
        features.has_delegatecall = features.opcode_count.get("DELEGATECALL", 0) > 0
        features.has_selfdestruct = features.opcode_count.get("SELFDESTRUCT", 0) > 0
        features.has_create = features.opcode_count.get("CREATE", 0) > 0
        features.has_create2 = features.opcode_count.get("CREATE2", 0) > 0
        features.has_callcode = features.opcode_count.get("CALLCODE", 0) > 0
        features.has_staticcall = features.opcode_count.get("STATICCALL", 0) > 0

        # 存储访问
        features.storage_reads = features.opcode_count.get("SLOAD", 0)
        features.storage_writes = features.opcode_count.get("SSTORE", 0)

        # 提取函数选择器
        features.function_selectors = self._extract_selectors(bytecode)

        # 检测代理合约
        features.is_minimal_proxy = self._is_minimal_proxy(bytecode)
        features.is_proxy = features.is_minimal_proxy or features.has_delegatecall

        # 检测标准接口
        features.implements_erc20 = self._implements_erc20(features.function_selectors)
        features.implements_erc721 = self._implements_erc721(features.function_selectors)

        # 检测可升级性
        features.is_upgradeable = self._is_upgradeable(features, bytecode)

        return features

    def _count_opcodes(self, bytecode: str) -> Dict[str, int]:
        """统计操作码"""
        counts: Dict[str, int] = {}
        i = 0
        bytecode_bytes = bytes.fromhex(bytecode)
        length = len(bytecode_bytes)

        while i < length:
            opcode = bytecode_bytes[i]
            opcode_name = self.opcodes.get(opcode, f"UNKNOWN_{hex(opcode)}")

            counts[opcode_name] = counts.get(opcode_name, 0) + 1

            # 跳过PUSH数据
            if 0x60 <= opcode <= 0x7f:
                push_size = opcode - 0x5f
                i += push_size

            i += 1

        return counts

    def _extract_selectors(self, bytecode: str) -> List[str]:
        """提取函数选择器"""
        selectors: Set[str] = set()

        # 方法1: 查找PUSH4后跟的4字节
        # 函数选择器通常通过 PUSH4 selector 加载
        bytecode_bytes = bytes.fromhex(bytecode)

        for i in range(len(bytecode_bytes) - 4):
            if bytecode_bytes[i] == 0x63:  # PUSH4
                selector = bytecode_bytes[i+1:i+5].hex()
                # 过滤掉全0和全f的无效选择器
                if selector not in ("00000000", "ffffffff"):
                    selectors.add(f"0x{selector}")

        # 方法2: 查找已知模式
        # EQ操作后通常跟着选择器比较
        pattern = re.compile(r'63([0-9a-fA-F]{8})14', re.IGNORECASE)
        for match in pattern.finditer(bytecode):
            selector = match.group(1).lower()
            if selector not in ("00000000", "ffffffff"):
                selectors.add(f"0x{selector}")

        return sorted(list(selectors))

    def _is_minimal_proxy(self, bytecode: str) -> bool:
        """检测是否为EIP-1167最小代理"""
        bytecode_lower = bytecode.lower()
        return (
            bytecode_lower.startswith(MINIMAL_PROXY_PREFIX.lower()) and
            MINIMAL_PROXY_SUFFIX.lower() in bytecode_lower
        )

    def _implements_erc20(self, selectors: List[str]) -> bool:
        """检测是否实现ERC-20"""
        required = {"0x18160ddd", "0x70a08231", "0xa9059cbb", "0x23b872dd", "0x095ea7b3"}
        selector_set = set(s.lower() for s in selectors)
        return len(required & selector_set) >= 4

    def _implements_erc721(self, selectors: List[str]) -> bool:
        """检测是否实现ERC-721"""
        required = {"0x70a08231", "0x6352211e", "0x42842e0e", "0x23b872dd"}
        selector_set = set(s.lower() for s in selectors)
        return len(required & selector_set) >= 3

    def _is_upgradeable(self, features: BytecodeFeatures, bytecode: str) -> bool:
        """检测是否可升级"""
        # 可升级代理通常有DELEGATECALL和特定的升级函数
        if not features.has_delegatecall:
            return False

        # 检查是否有升级相关的函数选择器
        upgrade_selectors = {
            "0x3659cfe6",  # upgradeTo(address)
            "0x4f1ef286",  # upgradeToAndCall(address,bytes)
            "0x5c60da1b",  # implementation()
        }

        selector_set = set(s.lower() for s in features.function_selectors)
        return bool(upgrade_selectors & selector_set)

    def identify_contract_type(self, features: BytecodeFeatures) -> ContractType:
        """识别合约类型"""
        if features.is_minimal_proxy:
            return ContractType.PROXY

        if features.is_upgradeable:
            return ContractType.UPGRADEABLE

        if features.implements_erc721:
            return ContractType.ERC721

        if features.implements_erc20:
            return ContractType.ERC20

        # 检查DEX相关函数
        dex_selectors = {"0x7ff36ab5", "0x18cbafe5", "0x38ed1739"}  # Uniswap V2
        if dex_selectors & set(features.function_selectors):
            return ContractType.DEX_ROUTER

        # 检查多签特征
        multisig_selectors = {"0xc6427474", "0x20ea8d86"}  # submitTransaction, confirmTransaction
        if multisig_selectors & set(features.function_selectors):
            return ContractType.MULTISIG

        return ContractType.UNKNOWN

    def get_dangerous_operations(self, features: BytecodeFeatures) -> List[str]:
        """获取危险操作列表"""
        dangers = []

        if features.has_selfdestruct:
            dangers.append("SELFDESTRUCT: 合约可被销毁")

        if features.has_delegatecall and not features.is_proxy:
            dangers.append("DELEGATECALL: 非代理合约使用delegatecall可能存在风险")

        if features.has_callcode:
            dangers.append("CALLCODE: 已废弃的危险操作码")

        if features.has_create2:
            dangers.append("CREATE2: 可在相同地址部署不同代码")

        # 检查危险函数
        for selector in features.function_selectors:
            if selector.lower() in DANGEROUS_SELECTORS:
                func_name = DANGEROUS_SELECTORS[selector.lower()]
                dangers.append(f"危险函数: {func_name}")

        return dangers

    def analyze_contract(self, contract: ContractInfo) -> ContractInfo:
        """分析合约并更新信息"""
        if not contract.bytecode:
            return contract

        # 分析字节码
        contract.features = self.analyze(contract.bytecode)

        # 识别类型
        contract.contract_type = self.identify_contract_type(contract.features)

        # 更新标签
        if contract.features.implements_erc20:
            contract.labels.append("ERC20")
        if contract.features.implements_erc721:
            contract.labels.append("ERC721")
        if contract.features.is_proxy:
            contract.labels.append("PROXY")
        if contract.features.is_upgradeable:
            contract.labels.append("UPGRADEABLE")
        if contract.features.has_selfdestruct:
            contract.labels.append("HAS_SELFDESTRUCT")

        return contract

    def compare_bytecode(self, bytecode1: str, bytecode2: str) -> Dict[str, Any]:
        """比较两个字节码"""
        features1 = self.analyze(bytecode1)
        features2 = self.analyze(bytecode2)

        return {
            "hash_match": features1.bytecode_hash == features2.bytecode_hash,
            "size_diff": features2.bytecode_size - features1.bytecode_size,
            "selector_diff": {
                "only_in_1": set(features1.function_selectors) - set(features2.function_selectors),
                "only_in_2": set(features2.function_selectors) - set(features1.function_selectors),
                "common": set(features1.function_selectors) & set(features2.function_selectors),
            },
            "opcode_diff": {
                op: features2.opcode_count.get(op, 0) - features1.opcode_count.get(op, 0)
                for op in set(features1.opcode_count) | set(features2.opcode_count)
                if features2.opcode_count.get(op, 0) != features1.opcode_count.get(op, 0)
            },
        }
