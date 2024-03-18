"""
实时监控模块

提供:
- 实时事件监听
- WebSocket管理
- 事件分发
- 监控指标收集
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt, timedelta
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum
from collections import deque
import asyncio
import logging
import json
import time
import threading

logger = logging.getLogger(__name__)


class EventType(Enum):
    """事件类型"""
    # 交易相关
    TRANSACTION_DETECTED = "transaction_detected"
    HIGH_VALUE_TRANSFER = "high_value_transfer"
    SUSPICIOUS_PATTERN = "suspicious_pattern"

    # 风险相关
    RISK_SCORE_CHANGE = "risk_score_change"
    NEW_HIGH_RISK = "new_high_risk"
    RISK_THRESHOLD_BREACH = "risk_threshold_breach"

    # 告警相关
    ALERT_CREATED = "alert_created"
    ALERT_ESCALATED = "alert_escalated"
    ALERT_RESOLVED = "alert_resolved"

    # 合约相关
    CONTRACT_DEPLOYED = "contract_deployed"
    CONTRACT_VULNERABILITY = "contract_vulnerability"
    PROXY_UPGRADED = "proxy_upgraded"

    # 系统相关
    SYSTEM_STATUS = "system_status"
    CONNECTION_STATUS = "connection_status"
    ERROR = "error"


class EventPriority(Enum):
    """事件优先级"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass
class MonitorEvent:
    """监控事件"""
    event_type: EventType
    data: Dict[str, Any]
    priority: EventPriority = EventPriority.MEDIUM
    timestamp: dt = dc_field(default_factory=dt.now)
    event_id: str = ""
    source: str = "monitor"
    tags: List[str] = dc_field(default_factory=list)

    def __post_init__(self):
        if not self.event_id:
            import uuid
            self.event_id = str(uuid.uuid4())[:8]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "priority": self.priority.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "tags": self.tags,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class Subscription:
    """订阅信息"""
    client_id: str
    event_types: Set[EventType] = dc_field(default_factory=set)
    filters: Dict[str, Any] = dc_field(default_factory=dict)
    priority_threshold: EventPriority = EventPriority.INFO
    created_at: dt = dc_field(default_factory=dt.now)


class WebSocketManager:
    """WebSocket连接管理器"""

    def __init__(self, heartbeat_interval: int = 30):
        self._clients: Dict[str, Any] = {}  # client_id -> connection
        self._subscriptions: Dict[str, Subscription] = {}
        self._heartbeat_interval = heartbeat_interval
        self._running = False
        self._message_queue: deque = deque(maxlen=10000)
        self._stats = {
            "connections": 0,
            "messages_sent": 0,
            "messages_failed": 0,
        }

    def connect(self, client_id: str, connection: Any) -> bool:
        """客户端连接"""
        if client_id in self._clients:
            logger.warning(f"Client {client_id} already connected, replacing")

        self._clients[client_id] = connection
        self._subscriptions[client_id] = Subscription(client_id=client_id)
        self._stats["connections"] += 1

        logger.info(f"Client connected: {client_id}, total: {len(self._clients)}")
        return True

    def disconnect(self, client_id: str):
        """客户端断开"""
        self._clients.pop(client_id, None)
        self._subscriptions.pop(client_id, None)
        logger.info(f"Client disconnected: {client_id}, remaining: {len(self._clients)}")

    def subscribe(
        self,
        client_id: str,
        event_types: List[EventType],
        filters: Optional[Dict[str, Any]] = None,
        priority_threshold: EventPriority = EventPriority.INFO
    ):
        """订阅事件"""
        if client_id not in self._subscriptions:
            self._subscriptions[client_id] = Subscription(client_id=client_id)

        sub = self._subscriptions[client_id]
        sub.event_types.update(event_types)
        if filters:
            sub.filters.update(filters)
        sub.priority_threshold = priority_threshold

        logger.debug(f"Client {client_id} subscribed to {len(event_types)} event types")

    def unsubscribe(self, client_id: str, event_types: List[EventType]):
        """取消订阅"""
        if client_id in self._subscriptions:
            sub = self._subscriptions[client_id]
            sub.event_types -= set(event_types)

    async def broadcast(self, event: MonitorEvent):
        """广播事件"""
        for client_id, connection in list(self._clients.items()):
            if self._should_send(client_id, event):
                await self._send_to_client(client_id, connection, event)

    def _should_send(self, client_id: str, event: MonitorEvent) -> bool:
        """检查是否应发送给客户端"""
        if client_id not in self._subscriptions:
            return False

        sub = self._subscriptions[client_id]

        # 检查事件类型
        if sub.event_types and event.event_type not in sub.event_types:
            return False

        # 检查优先级
        if event.priority.value > sub.priority_threshold.value:
            return False

        # 检查过滤器
        for key, value in sub.filters.items():
            if key in event.data and event.data[key] != value:
                return False

        return True

    async def _send_to_client(
        self,
        client_id: str,
        connection: Any,
        event: MonitorEvent
    ):
        """发送消息给客户端"""
        try:
            # 实际发送逻辑取决于WebSocket库
            # 这里模拟发送
            message = event.to_json()
            self._stats["messages_sent"] += 1
            logger.debug(f"Sent to {client_id}: {event.event_type.value}")
        except Exception as e:
            self._stats["messages_failed"] += 1
            logger.error(f"Failed to send to {client_id}: {e}")
            self.disconnect(client_id)

    async def send_heartbeat(self):
        """发送心跳"""
        heartbeat = MonitorEvent(
            event_type=EventType.SYSTEM_STATUS,
            data={"status": "alive", "timestamp": dt.now().isoformat()},
            priority=EventPriority.INFO,
        )
        await self.broadcast(heartbeat)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            "active_clients": len(self._clients),
            "subscriptions": len(self._subscriptions),
        }

    def get_clients(self) -> List[str]:
        """获取所有客户端ID"""
        return list(self._clients.keys())


class EventBuffer:
    """事件缓冲区"""

    def __init__(self, max_size: int = 1000, flush_interval: float = 1.0):
        self._buffer: deque = deque(maxlen=max_size)
        self._flush_interval = flush_interval
        self._last_flush = time.time()
        self._lock = threading.Lock()

    def add(self, event: MonitorEvent):
        """添加事件"""
        with self._lock:
            self._buffer.append(event)

    def get_pending(self) -> List[MonitorEvent]:
        """获取待处理事件"""
        with self._lock:
            events = list(self._buffer)
            self._buffer.clear()
            self._last_flush = time.time()
            return events

    def should_flush(self) -> bool:
        """是否应刷新"""
        return (
            time.time() - self._last_flush >= self._flush_interval
            or len(self._buffer) >= self._buffer.maxlen // 2
        )

    def size(self) -> int:
        """缓冲区大小"""
        return len(self._buffer)


class RealtimeMonitor:
    """实时监控器"""

    def __init__(
        self,
        buffer_size: int = 1000,
        flush_interval: float = 1.0,
        heartbeat_interval: int = 30
    ):
        self.ws_manager = WebSocketManager(heartbeat_interval)
        self._buffer = EventBuffer(buffer_size, flush_interval)
        self._handlers: Dict[EventType, List[Callable]] = {}
        self._running = False
        self._event_count = 0
        self._start_time: Optional[dt] = None

        # 监控指标
        self._metrics = {
            "events_processed": 0,
            "events_by_type": {},
            "events_by_priority": {},
            "avg_processing_time_ms": 0,
        }

    def register_handler(
        self,
        event_type: EventType,
        handler: Callable[[MonitorEvent], None]
    ):
        """注册事件处理器"""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        logger.debug(f"Registered handler for {event_type.value}")

    def unregister_handler(
        self,
        event_type: EventType,
        handler: Callable[[MonitorEvent], None]
    ):
        """取消注册处理器"""
        if event_type in self._handlers:
            self._handlers[event_type] = [
                h for h in self._handlers[event_type] if h != handler
            ]

    def emit(self, event: MonitorEvent):
        """发出事件"""
        self._buffer.add(event)
        self._update_metrics(event)

    def emit_transaction(
        self,
        tx_hash: str,
        from_addr: str,
        to_addr: str,
        value: float,
        risk_score: int = 0
    ):
        """发出交易事件"""
        event_type = (
            EventType.HIGH_VALUE_TRANSFER
            if value > 100
            else EventType.TRANSACTION_DETECTED
        )
        priority = EventPriority.HIGH if risk_score > 70 else EventPriority.MEDIUM

        self.emit(MonitorEvent(
            event_type=event_type,
            priority=priority,
            data={
                "tx_hash": tx_hash,
                "from": from_addr,
                "to": to_addr,
                "value": value,
                "risk_score": risk_score,
            },
            tags=["transaction"],
        ))

    def emit_alert(
        self,
        alert_id: str,
        alert_type: str,
        severity: str,
        details: Dict[str, Any]
    ):
        """发出告警事件"""
        priority_map = {
            "critical": EventPriority.CRITICAL,
            "high": EventPriority.HIGH,
            "medium": EventPriority.MEDIUM,
            "low": EventPriority.LOW,
        }

        self.emit(MonitorEvent(
            event_type=EventType.ALERT_CREATED,
            priority=priority_map.get(severity, EventPriority.MEDIUM),
            data={
                "alert_id": alert_id,
                "type": alert_type,
                "severity": severity,
                **details,
            },
            tags=["alert", severity],
        ))

    def emit_risk_change(
        self,
        address: str,
        old_score: int,
        new_score: int,
        risk_level: str
    ):
        """发出风险变化事件"""
        event_type = (
            EventType.NEW_HIGH_RISK
            if new_score >= 80 and old_score < 80
            else EventType.RISK_SCORE_CHANGE
        )
        priority = (
            EventPriority.HIGH
            if new_score >= 80
            else EventPriority.MEDIUM
        )

        self.emit(MonitorEvent(
            event_type=event_type,
            priority=priority,
            data={
                "address": address,
                "old_score": old_score,
                "new_score": new_score,
                "change": new_score - old_score,
                "risk_level": risk_level,
            },
            tags=["risk", risk_level],
        ))

    def emit_contract_event(
        self,
        address: str,
        event_type: EventType,
        details: Dict[str, Any]
    ):
        """发出合约事件"""
        priority = (
            EventPriority.HIGH
            if event_type == EventType.CONTRACT_VULNERABILITY
            else EventPriority.MEDIUM
        )

        self.emit(MonitorEvent(
            event_type=event_type,
            priority=priority,
            data={"address": address, **details},
            tags=["contract"],
        ))

    def _update_metrics(self, event: MonitorEvent):
        """更新指标"""
        self._metrics["events_processed"] += 1

        event_type = event.event_type.value
        if event_type not in self._metrics["events_by_type"]:
            self._metrics["events_by_type"][event_type] = 0
        self._metrics["events_by_type"][event_type] += 1

        priority = event.priority.name
        if priority not in self._metrics["events_by_priority"]:
            self._metrics["events_by_priority"][priority] = 0
        self._metrics["events_by_priority"][priority] += 1

    async def process_events(self):
        """处理事件"""
        events = self._buffer.get_pending()

        for event in events:
            # 调用处理器
            handlers = self._handlers.get(event.event_type, [])
            for handler in handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Handler error: {e}")

            # 广播到WebSocket
            await self.ws_manager.broadcast(event)

    async def run(self):
        """运行监控循环"""
        self._running = True
        self._start_time = dt.now()
        logger.info("Realtime monitor started")

        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            while self._running:
                if self._buffer.should_flush():
                    await self.process_events()
                await asyncio.sleep(0.1)
        finally:
            heartbeat_task.cancel()
            logger.info("Realtime monitor stopped")

    async def _heartbeat_loop(self):
        """心跳循环"""
        while self._running:
            await self.ws_manager.send_heartbeat()
            await asyncio.sleep(self.ws_manager._heartbeat_interval)

    def stop(self):
        """停止监控"""
        self._running = False

    def get_metrics(self) -> Dict[str, Any]:
        """获取监控指标"""
        uptime = (
            (dt.now() - self._start_time).total_seconds()
            if self._start_time else 0
        )

        return {
            **self._metrics,
            "buffer_size": self._buffer.size(),
            "ws_stats": self.ws_manager.get_stats(),
            "uptime_seconds": uptime,
            "running": self._running,
        }

    def get_recent_events(
        self,
        event_type: Optional[EventType] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """获取最近事件（从缓冲区）"""
        events = list(self._buffer._buffer)

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        return [e.to_dict() for e in events[-limit:]]


class MonitoringDashboard:
    """监控仪表盘"""

    def __init__(self, monitor: RealtimeMonitor):
        self.monitor = monitor
        self._thresholds = {
            "high_risk_score": 80,
            "high_value_transfer": 100,
            "alert_rate_per_hour": 50,
        }

    def set_threshold(self, name: str, value: float):
        """设置阈值"""
        self._thresholds[name] = value

    def get_status(self) -> Dict[str, Any]:
        """获取系统状态"""
        metrics = self.monitor.get_metrics()

        return {
            "status": "running" if self.monitor._running else "stopped",
            "health": self._calculate_health(metrics),
            "metrics": metrics,
            "thresholds": self._thresholds,
            "clients": self.monitor.ws_manager.get_clients(),
        }

    def _calculate_health(self, metrics: Dict[str, Any]) -> str:
        """计算健康状态"""
        ws_stats = metrics.get("ws_stats", {})
        failed = ws_stats.get("messages_failed", 0)
        sent = ws_stats.get("messages_sent", 1)

        error_rate = failed / sent if sent > 0 else 0

        if error_rate > 0.1:
            return "degraded"
        elif not metrics.get("running", False):
            return "stopped"
        return "healthy"

    def get_summary(self) -> str:
        """获取摘要"""
        status = self.get_status()
        metrics = status["metrics"]

        lines = [
            "=== Realtime Monitor Status ===",
            f"Status: {status['status']}",
            f"Health: {status['health']}",
            f"Events Processed: {metrics['events_processed']}",
            f"Active Clients: {metrics['ws_stats']['active_clients']}",
            f"Buffer Size: {metrics['buffer_size']}",
            f"Uptime: {metrics['uptime_seconds']:.0f}s",
        ]

        return "\n".join(lines)
