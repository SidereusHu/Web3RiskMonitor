"""
SQLite 存储模块

轻量级存储方案，适合开发和测试阶段
生产环境建议迁移到PostgreSQL
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from src.models.ethereum import Block, Transaction, TokenTransfer, EventLog


class SQLiteStorage:
    """SQLite存储"""

    def __init__(self, db_path: str = "data/blockchain.db"):
        """初始化存储

        Args:
            db_path: 数据库文件路径
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        """创建数据表"""
        cursor = self.conn.cursor()

        # 区块表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                number INTEGER PRIMARY KEY,
                hash TEXT UNIQUE NOT NULL,
                parent_hash TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                datetime TEXT NOT NULL,
                miner TEXT NOT NULL,
                gas_used INTEGER NOT NULL,
                gas_limit INTEGER NOT NULL,
                base_fee_per_gas INTEGER,
                transaction_count INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 交易表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                hash TEXT PRIMARY KEY,
                block_number INTEGER NOT NULL,
                block_timestamp INTEGER NOT NULL,
                transaction_index INTEGER NOT NULL,
                from_address TEXT NOT NULL,
                to_address TEXT,
                value TEXT NOT NULL,
                value_eth REAL NOT NULL,
                gas INTEGER NOT NULL,
                gas_price INTEGER,
                gas_used INTEGER,
                input TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                tx_type TEXT NOT NULL,
                method_id TEXT,
                method_name TEXT,
                category TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_signals TEXT,
                status INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (block_number) REFERENCES blocks(number)
            )
        """)

        # 代币转账表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS token_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash TEXT NOT NULL,
                log_index INTEGER NOT NULL,
                block_number INTEGER NOT NULL,
                token_address TEXT NOT NULL,
                token_type TEXT NOT NULL,
                from_address TEXT NOT NULL,
                to_address TEXT NOT NULL,
                value TEXT NOT NULL,
                token_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tx_hash, log_index),
                FOREIGN KEY (tx_hash) REFERENCES transactions(hash)
            )
        """)

        # 事件日志表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash TEXT NOT NULL,
                log_index INTEGER NOT NULL,
                block_number INTEGER NOT NULL,
                address TEXT NOT NULL,
                topics TEXT NOT NULL,
                data TEXT NOT NULL,
                event_name TEXT,
                event_signature TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tx_hash, log_index),
                FOREIGN KEY (tx_hash) REFERENCES transactions(hash)
            )
        """)

        # 创建索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_number)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tx_risk ON transactions(risk_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transfer_token ON token_transfers(token_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transfer_from ON token_transfers(from_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transfer_to ON token_transfers(to_address)")

        self.conn.commit()

    def save_block(self, block: Block):
        """保存区块"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO blocks
            (number, hash, parent_hash, timestamp, datetime, miner,
             gas_used, gas_limit, base_fee_per_gas, transaction_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            block.number,
            block.hash,
            block.parent_hash,
            block.timestamp,
            block.datetime.isoformat(),
            block.miner,
            block.gas_used,
            block.gas_limit,
            block.base_fee_per_gas,
            block.transaction_count,
        ))
        self.conn.commit()

    def save_transaction(self, tx: Transaction):
        """保存交易"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO transactions
            (hash, block_number, block_timestamp, transaction_index,
             from_address, to_address, value, value_eth, gas, gas_price,
             gas_used, input, nonce, tx_type, method_id, method_name,
             category, risk_level, risk_signals, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tx.hash,
            tx.block_number,
            tx.block_timestamp,
            tx.transaction_index,
            tx.from_address,
            tx.to_address,
            str(tx.value),
            tx.value_eth,
            tx.gas,
            tx.gas_price,
            tx.gas_used,
            tx.input[:1000] if len(tx.input) > 1000 else tx.input,  # 限制input长度
            tx.nonce,
            tx.tx_type.value,
            tx.method_id,
            tx.method_name,
            tx.category.value,
            tx.risk_level.value,
            json.dumps(tx.risk_signals),
            tx.status,
        ))
        self.conn.commit()

    def save_token_transfer(self, transfer: TokenTransfer):
        """保存代币转账"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO token_transfers
            (tx_hash, log_index, block_number, token_address, token_type,
             from_address, to_address, value, token_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            transfer.tx_hash,
            transfer.log_index,
            transfer.block_number,
            transfer.token_address,
            transfer.token_type,
            transfer.from_address,
            transfer.to_address,
            str(transfer.value),
            transfer.token_id,
        ))
        self.conn.commit()

    def save_event(self, event: EventLog):
        """保存事件日志"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO event_logs
            (tx_hash, log_index, block_number, address, topics, data,
             event_name, event_signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.tx_hash,
            event.log_index,
            event.block_number,
            event.address,
            json.dumps(event.topics),
            event.data,
            event.event_name,
            event.event_signature,
        ))
        self.conn.commit()

    def save_batch(
        self,
        blocks: List[Block],
        transactions: List[Transaction],
        transfers: List[TokenTransfer],
        events: List[EventLog]
    ):
        """批量保存"""
        cursor = self.conn.cursor()

        # 保存区块
        for block in blocks:
            cursor.execute("""
                INSERT OR REPLACE INTO blocks
                (number, hash, parent_hash, timestamp, datetime, miner,
                 gas_used, gas_limit, base_fee_per_gas, transaction_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                block.number, block.hash, block.parent_hash, block.timestamp,
                block.datetime.isoformat(), block.miner, block.gas_used,
                block.gas_limit, block.base_fee_per_gas, block.transaction_count,
            ))

        # 保存交易
        for tx in transactions:
            cursor.execute("""
                INSERT OR REPLACE INTO transactions
                (hash, block_number, block_timestamp, transaction_index,
                 from_address, to_address, value, value_eth, gas, gas_price,
                 gas_used, input, nonce, tx_type, method_id, method_name,
                 category, risk_level, risk_signals, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tx.hash, tx.block_number, tx.block_timestamp, tx.transaction_index,
                tx.from_address, tx.to_address, str(tx.value), tx.value_eth,
                tx.gas, tx.gas_price, tx.gas_used,
                tx.input[:1000] if len(tx.input) > 1000 else tx.input,
                tx.nonce, tx.tx_type.value, tx.method_id, tx.method_name,
                tx.category.value, tx.risk_level.value, json.dumps(tx.risk_signals),
                tx.status,
            ))

        # 保存转账
        for transfer in transfers:
            cursor.execute("""
                INSERT OR REPLACE INTO token_transfers
                (tx_hash, log_index, block_number, token_address, token_type,
                 from_address, to_address, value, token_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transfer.tx_hash, transfer.log_index, transfer.block_number,
                transfer.token_address, transfer.token_type, transfer.from_address,
                transfer.to_address, str(transfer.value), transfer.token_id,
            ))

        # 保存事件
        for event in events:
            cursor.execute("""
                INSERT OR REPLACE INTO event_logs
                (tx_hash, log_index, block_number, address, topics, data,
                 event_name, event_signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.tx_hash, event.log_index, event.block_number, event.address,
                json.dumps(event.topics), event.data, event.event_name,
                event.event_signature,
            ))

        self.conn.commit()

    # ========== 查询方法 ==========

    def get_block(self, block_number: int) -> Optional[Dict]:
        """获取区块"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM blocks WHERE number = ?", (block_number,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_transaction(self, tx_hash: str) -> Optional[Dict]:
        """获取交易"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM transactions WHERE hash = ?", (tx_hash,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_transactions_by_address(
        self,
        address: str,
        limit: int = 100
    ) -> List[Dict]:
        """获取地址相关交易"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM transactions
            WHERE from_address = ? OR to_address = ?
            ORDER BY block_number DESC
            LIMIT ?
        """, (address, address, limit))
        return [dict(row) for row in cursor.fetchall()]

    def get_high_risk_transactions(self, limit: int = 100) -> List[Dict]:
        """获取高风险交易"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM transactions
            WHERE risk_level = 'high'
            ORDER BY block_number DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        cursor = self.conn.cursor()

        # 区块统计
        cursor.execute("SELECT COUNT(*), MIN(number), MAX(number) FROM blocks")
        block_count, min_block, max_block = cursor.fetchone()

        # 交易统计
        cursor.execute("SELECT COUNT(*) FROM transactions")
        tx_count = cursor.fetchone()[0]

        # 风险统计
        cursor.execute("""
            SELECT risk_level, COUNT(*)
            FROM transactions
            GROUP BY risk_level
        """)
        risk_stats = dict(cursor.fetchall())

        # 分类统计
        cursor.execute("""
            SELECT category, COUNT(*)
            FROM transactions
            GROUP BY category
        """)
        category_stats = dict(cursor.fetchall())

        return {
            "block_count": block_count,
            "min_block": min_block,
            "max_block": max_block,
            "transaction_count": tx_count,
            "risk_distribution": risk_stats,
            "category_distribution": category_stats,
        }

    def close(self):
        """关闭连接"""
        self.conn.close()
