"""
交易解析器

负责将原始交易数据解析为结构化的风控数据
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from eth_abi import decode
from eth_abi.exceptions import DecodingError
from web3 import Web3

from src.models.ethereum import (
    Transaction, TokenTransfer, EventLog,
    TransactionType, CategoryType, RiskLevel
)
from src.parser.signatures import (
    FUNCTION_SIGNATURES, EVENT_SIGNATURES, SANCTIONED_ADDRESSES,
    get_function_info, get_event_info, check_address_risk
)


# 最大授权金额 (2^256 - 1)
MAX_UINT256 = 2**256 - 1
# 大额转账阈值 (ETH)
LARGE_TRANSFER_THRESHOLD = 100


class TransactionParser:
    """交易解析器"""

    def __init__(self, w3: Optional[Web3] = None):
        """初始化解析器

        Args:
            w3: Web3实例，用于单位转换等
        """
        self.w3 = w3 or Web3()

    def parse_transaction(
        self,
        tx: Dict[str, Any],
        receipt: Optional[Dict[str, Any]] = None
    ) -> Transaction:
        """解析单笔交易

        Args:
            tx: 原始交易数据
            receipt: 交易收据（可选）

        Returns:
            解析后的Transaction对象
        """
        # 基础数据提取
        tx_hash = tx["hash"].hex() if isinstance(tx["hash"], bytes) else tx["hash"]
        from_addr = tx["from"]
        to_addr = tx["to"]
        value = tx["value"]
        value_eth = float(self.w3.from_wei(value, "ether"))
        input_data = tx["input"].hex() if isinstance(tx["input"], bytes) else tx["input"]

        # 判断交易类型
        tx_type, category = self._determine_tx_type(tx, input_data)

        # 解析input数据
        method_id = None
        method_name = None
        method_signature = None
        decoded_params = None

        if tx_type == TransactionType.CONTRACT_CALL and len(input_data) >= 10:
            method_id = input_data[:10].lower()
            func_info = get_function_info(method_id)

            if func_info:
                method_name = func_info.get("name")
                method_signature = func_info.get("signature")
                category = CategoryType(func_info.get("category", "unknown").lower())

                # 尝试解码参数
                decoded_params = self._decode_params(
                    input_data[10:],
                    func_info.get("params", []),
                    func_info.get("param_names", [])
                )

        # 评估风险
        risk_level, risk_signals = self._assess_risk(
            tx, tx_type, category, method_id, decoded_params, to_addr, value_eth
        )

        # 从receipt提取执行结果
        status = None
        gas_used = None
        contract_address = None

        if receipt:
            status = receipt.get("status")
            gas_used = receipt.get("gasUsed")
            if receipt.get("contractAddress"):
                contract_address = receipt["contractAddress"]

        return Transaction(
            hash=tx_hash,
            block_number=tx["blockNumber"],
            block_timestamp=tx.get("blockTimestamp", 0),
            transaction_index=tx.get("transactionIndex", 0),
            from_address=from_addr,
            to_address=to_addr,
            value=value,
            value_eth=value_eth,
            gas=tx["gas"],
            gas_price=tx.get("gasPrice"),
            max_fee_per_gas=tx.get("maxFeePerGas"),
            max_priority_fee_per_gas=tx.get("maxPriorityFeePerGas"),
            gas_used=gas_used,
            effective_gas_price=receipt.get("effectiveGasPrice") if receipt else None,
            input=input_data,
            nonce=tx["nonce"],
            tx_type=tx_type,
            method_id=method_id,
            method_name=method_name,
            method_signature=method_signature,
            decoded_params=decoded_params,
            category=category,
            risk_level=risk_level,
            risk_signals=risk_signals,
            status=status,
            contract_address=contract_address,
        )

    def _determine_tx_type(
        self,
        tx: Dict[str, Any],
        input_data: str
    ) -> Tuple[TransactionType, CategoryType]:
        """判断交易类型

        Returns:
            (交易类型, 分类)
        """
        if tx["to"] is None:
            return TransactionType.CONTRACT_CREATION, CategoryType.UNKNOWN

        if not input_data or input_data == "0x":
            return TransactionType.ETH_TRANSFER, CategoryType.TRANSFER

        return TransactionType.CONTRACT_CALL, CategoryType.UNKNOWN

    def _decode_params(
        self,
        params_hex: str,
        param_types: List[str],
        param_names: List[str]
    ) -> Optional[Dict[str, Any]]:
        """解码函数参数

        Args:
            params_hex: 参数的十六进制数据
            param_types: 参数类型列表
            param_names: 参数名称列表

        Returns:
            解码后的参数字典
        """
        if not params_hex or not param_types:
            return None

        # 跳过复杂类型（tuple等）
        if "tuple" in param_types:
            return None

        try:
            decoded = decode(param_types, bytes.fromhex(params_hex))

            # 构建参数字典
            result = {}
            for i, value in enumerate(decoded):
                name = param_names[i] if i < len(param_names) else f"param{i}"

                # 转换字节类型为十六进制字符串
                if isinstance(value, bytes):
                    value = "0x" + value.hex()
                # 转换地址为校验和格式
                elif param_types[i] == "address":
                    value = Web3.to_checksum_address(value)
                # 转换地址数组
                elif param_types[i] == "address[]":
                    value = [Web3.to_checksum_address(addr) for addr in value]

                result[name] = value

            return result

        except (DecodingError, Exception):
            return None

    def _assess_risk(
        self,
        tx: Dict[str, Any],
        tx_type: TransactionType,
        category: CategoryType,
        method_id: Optional[str],
        decoded_params: Optional[Dict],
        to_addr: Optional[str],
        value_eth: float
    ) -> Tuple[RiskLevel, List[str]]:
        """评估交易风险

        Returns:
            (风险等级, 风险信号列表)
        """
        signals = []

        # 1. 检查目标地址是否在制裁名单
        if to_addr:
            addr_risk = check_address_risk(to_addr)
            if addr_risk["is_risky"]:
                signals.append(f"[HIGH] 与制裁地址交互: {addr_risk.get('name', to_addr)}")

        # 2. 检查Method ID对应的风险等级
        if method_id:
            func_info = get_function_info(method_id)
            func_risk = func_info.get("risk_level", "unknown")

            if func_risk == "high":
                signals.append(f"[HIGH] 高风险操作: {func_info.get('description', method_id)}")
            elif func_risk == "attention":
                signals.append(f"[ATTENTION] 需关注: {func_info.get('description', method_id)}")

        # 3. 检查无限授权
        if method_id == "0x095ea7b3" and decoded_params:  # approve
            amount = decoded_params.get("amount", 0)
            if amount == MAX_UINT256:
                signals.append("[ATTENTION] 无限授权: 允许spender转走所有代币")

        # 4. 检查大额ETH转账
        if value_eth >= LARGE_TRANSFER_THRESHOLD:
            signals.append(f"[MONITOR] 大额转账: {value_eth:.2f} ETH")

        # 5. 检查新账户（nonce=0）的大额操作
        if tx["nonce"] == 0 and value_eth >= 10:
            signals.append("[ATTENTION] 新账户首笔大额交易")

        # 6. 混币器分类直接标记高风险
        if category == CategoryType.MIXER:
            if "[HIGH]" not in str(signals):
                signals.append("[HIGH] 混币器操作")

        # 确定最终风险等级
        if any("[HIGH]" in s for s in signals):
            return RiskLevel.HIGH, signals
        elif any("[ATTENTION]" in s for s in signals):
            return RiskLevel.ATTENTION, signals
        elif any("[MONITOR]" in s for s in signals):
            return RiskLevel.NORMAL, signals
        else:
            return RiskLevel.NORMAL if tx_type != TransactionType.CONTRACT_CALL else RiskLevel.UNKNOWN, signals

    def parse_logs(
        self,
        logs: List[Dict[str, Any]],
        tx_hash: str,
        block_number: int
    ) -> Tuple[List[EventLog], List[TokenTransfer]]:
        """解析交易日志

        Args:
            logs: 原始日志列表
            tx_hash: 交易哈希
            block_number: 区块高度

        Returns:
            (事件日志列表, 代币转账列表)
        """
        events = []
        transfers = []

        for log in logs:
            # 解析事件
            event = self._parse_single_log(log, tx_hash, block_number)
            events.append(event)

            # 检查是否为Transfer事件
            if log["topics"] and len(log["topics"]) >= 3:
                topic0 = log["topics"][0].hex() if isinstance(log["topics"][0], bytes) else log["topics"][0]

                # ERC-20/721 Transfer
                if topic0.lower() == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef":
                    transfer = self._parse_transfer_event(log, tx_hash, block_number)
                    if transfer:
                        transfers.append(transfer)

        return events, transfers

    def _parse_single_log(
        self,
        log: Dict[str, Any],
        tx_hash: str,
        block_number: int
    ) -> EventLog:
        """解析单个日志"""
        topics = [
            t.hex() if isinstance(t, bytes) else t
            for t in log.get("topics", [])
        ]

        data = log["data"].hex() if isinstance(log["data"], bytes) else log["data"]

        # 尝试识别事件
        event_name = None
        event_signature = None
        decoded_data = None

        if topics:
            event_info = get_event_info(topics[0])
            if event_info:
                event_name = event_info.get("name")
                event_signature = event_info.get("signature")

        return EventLog(
            tx_hash=tx_hash,
            log_index=log.get("logIndex", 0),
            block_number=block_number,
            address=log["address"],
            topics=topics,
            data=data,
            event_name=event_name,
            event_signature=event_signature,
            decoded_data=decoded_data,
        )

    def _parse_transfer_event(
        self,
        log: Dict[str, Any],
        tx_hash: str,
        block_number: int
    ) -> Optional[TokenTransfer]:
        """解析Transfer事件为TokenTransfer"""
        try:
            topics = log["topics"]
            data = log["data"].hex() if isinstance(log["data"], bytes) else log["data"]

            # 从topics提取from和to
            from_addr = "0x" + (topics[1].hex() if isinstance(topics[1], bytes) else topics[1])[-40:]
            to_addr = "0x" + (topics[2].hex() if isinstance(topics[2], bytes) else topics[2])[-40:]

            # 从data提取value
            value = int(data, 16) if data and data != "0x" else 0

            # 判断是ERC-20还是ERC-721
            # ERC-721的Transfer有4个topics（包含tokenId）
            token_type = "ERC721" if len(topics) == 4 else "ERC20"
            token_id = None

            if token_type == "ERC721" and len(topics) >= 4:
                token_id = int(topics[3].hex() if isinstance(topics[3], bytes) else topics[3], 16)
                value = 1  # NFT数量固定为1

            return TokenTransfer(
                tx_hash=tx_hash,
                log_index=log.get("logIndex", 0),
                block_number=block_number,
                token_address=log["address"],
                token_type=token_type,
                from_address=Web3.to_checksum_address(from_addr),
                to_address=Web3.to_checksum_address(to_addr),
                value=value,
                token_id=token_id,
            )

        except Exception:
            return None
