"""
函数签名与事件签名数据库

这是风控系统的核心知识库，包含：
- 常见函数签名及其风控含义
- 常见事件签名
- 高风险地址列表
"""

from typing import Dict, List, Any
from eth_utils import keccak


def compute_selector(signature: str) -> str:
    """计算函数/事件选择器

    Args:
        signature: 如 "transfer(address,uint256)"

    Returns:
        0x开头的选择器
    """
    return "0x" + keccak(text=signature).hex()[:8]


def compute_event_topic(signature: str) -> str:
    """计算事件topic

    Args:
        signature: 如 "Transfer(address,address,uint256)"

    Returns:
        完整的topic哈希
    """
    return "0x" + keccak(text=signature).hex()


# ============================================================================
# 函数签名数据库
# ============================================================================

FUNCTION_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # ========== ERC-20 标准 ==========
    "0xa9059cbb": {
        "name": "transfer",
        "signature": "transfer(address,uint256)",
        "params": ["address", "uint256"],
        "param_names": ["to", "amount"],
        "category": "ERC20",
        "risk_level": "normal",
        "description": "ERC-20代币转账",
    },
    "0x23b872dd": {
        "name": "transferFrom",
        "signature": "transferFrom(address,address,uint256)",
        "params": ["address", "address", "uint256"],
        "param_names": ["from", "to", "amount"],
        "category": "ERC20",
        "risk_level": "normal",
        "description": "ERC-20授权转账",
    },
    "0x095ea7b3": {
        "name": "approve",
        "signature": "approve(address,uint256)",
        "params": ["address", "uint256"],
        "param_names": ["spender", "amount"],
        "category": "ERC20",
        "risk_level": "attention",
        "description": "ERC-20授权(无限授权需警惕)",
    },
    "0x70a08231": {
        "name": "balanceOf",
        "signature": "balanceOf(address)",
        "params": ["address"],
        "param_names": ["account"],
        "category": "ERC20",
        "risk_level": "normal",
        "description": "查询余额",
    },

    # ========== Uniswap V2 ==========
    "0x7ff36ab5": {
        "name": "swapExactETHForTokens",
        "signature": "swapExactETHForTokens(uint256,address[],address,uint256)",
        "params": ["uint256", "address[]", "address", "uint256"],
        "param_names": ["amountOutMin", "path", "to", "deadline"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V2: ETH换Token",
    },
    "0x18cbafe5": {
        "name": "swapExactTokensForETH",
        "signature": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
        "params": ["uint256", "uint256", "address[]", "address", "uint256"],
        "param_names": ["amountIn", "amountOutMin", "path", "to", "deadline"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V2: Token换ETH",
    },
    "0x38ed1739": {
        "name": "swapExactTokensForTokens",
        "signature": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        "params": ["uint256", "uint256", "address[]", "address", "uint256"],
        "param_names": ["amountIn", "amountOutMin", "path", "to", "deadline"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V2: Token换Token",
    },
    "0xfb3bdb41": {
        "name": "swapETHForExactTokens",
        "signature": "swapETHForExactTokens(uint256,address[],address,uint256)",
        "params": ["uint256", "address[]", "address", "uint256"],
        "param_names": ["amountOut", "path", "to", "deadline"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V2: 用ETH换指定数量Token",
    },

    # ========== Uniswap V3 ==========
    "0x04e45aaf": {
        "name": "exactInputSingle",
        "signature": "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        "params": ["tuple"],
        "param_names": ["params"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V3: 单池精确输入",
    },
    "0xb858183f": {
        "name": "exactInput",
        "signature": "exactInput((bytes,address,uint256,uint256))",
        "params": ["tuple"],
        "param_names": ["params"],
        "category": "DEX",
        "risk_level": "normal",
        "description": "Uniswap V3: 多池精确输入",
    },

    # ========== 混币器 (高风险) ==========
    "0xb214faa5": {
        "name": "deposit",
        "signature": "deposit(bytes32)",
        "params": ["bytes32"],
        "param_names": ["commitment"],
        "category": "MIXER",
        "risk_level": "high",
        "description": "[OFAC制裁] Tornado Cash存款",
    },
    "0x21a0adb6": {
        "name": "withdraw",
        "signature": "withdraw(bytes,bytes32,bytes32,address,address,uint256,uint256)",
        "params": ["bytes", "bytes32", "bytes32", "address", "address", "uint256", "uint256"],
        "param_names": ["proof", "root", "nullifierHash", "recipient", "relayer", "fee", "refund"],
        "category": "MIXER",
        "risk_level": "high",
        "description": "[OFAC制裁] Tornado Cash提款",
    },

    # ========== 跨链桥 ==========
    "0x0f5287b0": {
        "name": "depositETH",
        "signature": "depositETH(uint32,bytes)",
        "params": ["uint32", "bytes"],
        "param_names": ["destinationChainId", "recipient"],
        "category": "BRIDGE",
        "risk_level": "attention",
        "description": "跨链桥ETH存款",
    },
    "0x9a2ac6d5": {
        "name": "depositERC20",
        "signature": "depositERC20(address,address,uint256,uint32,bytes)",
        "params": ["address", "address", "uint256", "uint32", "bytes"],
        "param_names": ["l1Token", "l2Token", "amount", "l2Gas", "data"],
        "category": "BRIDGE",
        "risk_level": "attention",
        "description": "跨链桥ERC20存款",
    },

    # ========== NFT (ERC-721) ==========
    "0x42842e0e": {
        "name": "safeTransferFrom",
        "signature": "safeTransferFrom(address,address,uint256)",
        "params": ["address", "address", "uint256"],
        "param_names": ["from", "to", "tokenId"],
        "category": "NFT",
        "risk_level": "normal",
        "description": "ERC-721安全转账",
    },
    "0xb88d4fde": {
        "name": "safeTransferFrom",
        "signature": "safeTransferFrom(address,address,uint256,bytes)",
        "params": ["address", "address", "uint256", "bytes"],
        "param_names": ["from", "to", "tokenId", "data"],
        "category": "NFT",
        "risk_level": "normal",
        "description": "ERC-721安全转账(带数据)",
    },
    "0xa22cb465": {
        "name": "setApprovalForAll",
        "signature": "setApprovalForAll(address,bool)",
        "params": ["address", "bool"],
        "param_names": ["operator", "approved"],
        "category": "NFT",
        "risk_level": "attention",
        "description": "NFT批量授权(需警惕)",
    },

    # ========== 多签钱包 ==========
    "0x6a761202": {
        "name": "execTransaction",
        "signature": "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        "params": ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"],
        "param_names": ["to", "value", "data", "operation", "safeTxGas", "baseGas", "gasPrice", "gasToken", "refundReceiver", "signatures"],
        "category": "MULTISIG",
        "risk_level": "normal",
        "description": "Gnosis Safe执行交易",
    },

    # ========== DeFi借贷 ==========
    "0xe8eda9df": {
        "name": "deposit",
        "signature": "deposit(address,uint256,address,uint16)",
        "params": ["address", "uint256", "address", "uint16"],
        "param_names": ["asset", "amount", "onBehalfOf", "referralCode"],
        "category": "DEFI",
        "risk_level": "normal",
        "description": "Aave V3存款",
    },
    "0x69328dec": {
        "name": "withdraw",
        "signature": "withdraw(address,uint256,address)",
        "params": ["address", "uint256", "address"],
        "param_names": ["asset", "amount", "to"],
        "category": "DEFI",
        "risk_level": "normal",
        "description": "Aave V3提款",
    },
    "0xab9c4b5d": {
        "name": "flashLoanSimple",
        "signature": "flashLoanSimple(address,address,uint256,bytes,uint16)",
        "params": ["address", "address", "uint256", "bytes", "uint16"],
        "param_names": ["receiverAddress", "asset", "amount", "params", "referralCode"],
        "category": "DEFI",
        "risk_level": "attention",
        "description": "Aave闪电贷(常用于攻击)",
    },
}


# ============================================================================
# 事件签名数据库
# ============================================================================

EVENT_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # ERC-20 Transfer
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {
        "name": "Transfer",
        "signature": "Transfer(address,address,uint256)",
        "indexed_params": ["from", "to"],
        "data_params": ["value"],
        "category": "ERC20",
        "description": "代币转账事件",
    },
    # ERC-20 Approval
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": {
        "name": "Approval",
        "signature": "Approval(address,address,uint256)",
        "indexed_params": ["owner", "spender"],
        "data_params": ["value"],
        "category": "ERC20",
        "description": "授权事件",
    },
    # Uniswap V2 Swap
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822": {
        "name": "Swap",
        "signature": "Swap(address,uint256,uint256,uint256,uint256,address)",
        "indexed_params": ["sender", "to"],
        "data_params": ["amount0In", "amount1In", "amount0Out", "amount1Out"],
        "category": "DEX",
        "description": "Uniswap V2交换事件",
    },
    # Uniswap V3 Swap
    "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67": {
        "name": "Swap",
        "signature": "Swap(address,address,int256,int256,uint160,uint128,int24)",
        "indexed_params": ["sender", "recipient"],
        "data_params": ["amount0", "amount1", "sqrtPriceX96", "liquidity", "tick"],
        "category": "DEX",
        "description": "Uniswap V3交换事件",
    },
    # WETH Deposit/Withdrawal
    "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c": {
        "name": "Deposit",
        "signature": "Deposit(address,uint256)",
        "indexed_params": ["dst"],
        "data_params": ["wad"],
        "category": "DEFI",
        "description": "WETH存款",
    },
    "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65": {
        "name": "Withdrawal",
        "signature": "Withdrawal(address,uint256)",
        "indexed_params": ["src"],
        "data_params": ["wad"],
        "category": "DEFI",
        "description": "WETH提款",
    },
}


# ============================================================================
# 高风险地址库
# ============================================================================

# OFAC 制裁地址 (Tornado Cash)
SANCTIONED_ADDRESSES: Dict[str, Dict[str, Any]] = {
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
        "name": "Tornado Cash Router",
        "risk_level": "high",
        "sanction_type": "OFAC",
        "description": "Tornado Cash主路由合约",
    },
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": {
        "name": "Tornado Cash 0.1 ETH",
        "risk_level": "high",
        "sanction_type": "OFAC",
        "description": "Tornado Cash 0.1 ETH池",
    },
    "0xdd4c48c0b24039969fc16d1cdf626eab821d3384": {
        "name": "Tornado Cash 1 ETH",
        "risk_level": "high",
        "sanction_type": "OFAC",
        "description": "Tornado Cash 1 ETH池",
    },
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": {
        "name": "Tornado Cash 10 ETH",
        "risk_level": "high",
        "sanction_type": "OFAC",
        "description": "Tornado Cash 10 ETH池",
    },
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": {
        "name": "Tornado Cash 100 ETH",
        "risk_level": "high",
        "sanction_type": "OFAC",
        "description": "Tornado Cash 100 ETH池",
    },
}

# 已知交易所地址（用于资金流向分析）
KNOWN_EXCHANGES: Dict[str, str] = {
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance Hot Wallet",
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance Cold Wallet",
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance Cold Wallet 2",
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f": "Coinbase Hot Wallet",
    "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": "Coinbase Cold Wallet",
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": "Kraken Hot Wallet",
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe": "Gate.io",
    "0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4": "Huobi",
}

# 已知DEX路由
KNOWN_DEX_ROUTERS: Dict[str, str] = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap Universal Router",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router",
}


def get_function_info(method_id: str) -> Dict[str, Any]:
    """获取函数信息

    Args:
        method_id: 0x开头的8字符选择器

    Returns:
        函数信息字典，未找到返回空字典
    """
    return FUNCTION_SIGNATURES.get(method_id.lower(), {})


def get_event_info(topic: str) -> Dict[str, Any]:
    """获取事件信息

    Args:
        topic: 完整的topic哈希

    Returns:
        事件信息字典，未找到返回空字典
    """
    return EVENT_SIGNATURES.get(topic.lower(), {})


def check_address_risk(address: str) -> Dict[str, Any]:
    """检查地址风险

    Args:
        address: 以太坊地址

    Returns:
        风险信息字典
    """
    addr_lower = address.lower()

    # 检查制裁地址
    if addr_lower in SANCTIONED_ADDRESSES:
        info = SANCTIONED_ADDRESSES[addr_lower]
        return {
            "is_risky": True,
            "risk_level": "high",
            "risk_type": "sanctioned",
            **info
        }

    # 检查已知交易所
    if addr_lower in KNOWN_EXCHANGES:
        return {
            "is_risky": False,
            "risk_level": "normal",
            "risk_type": "exchange",
            "name": KNOWN_EXCHANGES[addr_lower]
        }

    # 检查已知DEX
    if addr_lower in KNOWN_DEX_ROUTERS:
        return {
            "is_risky": False,
            "risk_level": "normal",
            "risk_type": "dex",
            "name": KNOWN_DEX_ROUTERS[addr_lower]
        }

    return {
        "is_risky": False,
        "risk_level": "unknown",
        "risk_type": "unknown"
    }
