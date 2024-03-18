"""
API服务器

基于FastAPI构建RESTful API，提供:
- 风险查询接口
- 仪表盘数据接口
- 告警管理接口
- WebSocket实时推送
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import json
import logging
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class APIConfig:
    """API配置"""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: List[str] = dc_field(default_factory=lambda: ["*"])
    api_prefix: str = "/api/v1"
    rate_limit: int = 100  # 每分钟请求数
    enable_docs: bool = True
    auth_enabled: bool = False
    api_key: Optional[str] = None


class ResponseStatus(Enum):
    """响应状态"""
    SUCCESS = "success"
    ERROR = "error"
    PARTIAL = "partial"


@dataclass
class APIResponse:
    """API响应"""
    status: ResponseStatus
    data: Any = None
    message: str = ""
    timestamp: str = dc_field(default_factory=lambda: dt.now().isoformat())
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "data": self.data,
            "message": self.message,
            "timestamp": self.timestamp,
            "request_id": self.request_id,
        }


class RateLimiter:
    """简易速率限制器"""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}

    def is_allowed(self, client_id: str) -> bool:
        """检查是否允许请求"""
        import time
        now = time.time()
        cutoff = now - self.window_seconds

        if client_id not in self._requests:
            self._requests[client_id] = []

        # 清理过期记录
        self._requests[client_id] = [
            t for t in self._requests[client_id] if t > cutoff
        ]

        if len(self._requests[client_id]) >= self.max_requests:
            return False

        self._requests[client_id].append(now)
        return True

    def reset(self, client_id: str):
        """重置客户端限制"""
        self._requests.pop(client_id, None)


class APIRouter:
    """API路由器（模拟FastAPI路由）"""

    def __init__(self, prefix: str = ""):
        self.prefix = prefix
        self.routes: Dict[str, Dict[str, Callable]] = {}

    def get(self, path: str):
        """GET路由装饰器"""
        def decorator(func: Callable):
            full_path = f"{self.prefix}{path}"
            if full_path not in self.routes:
                self.routes[full_path] = {}
            self.routes[full_path]["GET"] = func
            return func
        return decorator

    def post(self, path: str):
        """POST路由装饰器"""
        def decorator(func: Callable):
            full_path = f"{self.prefix}{path}"
            if full_path not in self.routes:
                self.routes[full_path] = {}
            self.routes[full_path]["POST"] = func
            return func
        return decorator

    def delete(self, path: str):
        """DELETE路由装饰器"""
        def decorator(func: Callable):
            full_path = f"{self.prefix}{path}"
            if full_path not in self.routes:
                self.routes[full_path] = {}
            self.routes[full_path]["DELETE"] = func
            return func
        return decorator


class APIServer:
    """API服务器"""

    def __init__(self, config: Optional[APIConfig] = None):
        self.config = config or APIConfig()
        self.rate_limiter = RateLimiter(
            max_requests=self.config.rate_limit
        )
        self.router = APIRouter(prefix=self.config.api_prefix)
        self._setup_routes()

        # 数据存储（实际应用中应注入依赖）
        self._data_aggregator = None
        self._alert_dashboard = None

    def set_data_aggregator(self, aggregator):
        """设置数据聚合器"""
        self._data_aggregator = aggregator

    def set_alert_dashboard(self, dashboard):
        """设置告警仪表盘"""
        self._alert_dashboard = dashboard

    def _setup_routes(self):
        """设置路由"""
        router = self.router

        # ===== 健康检查 =====
        @router.get("/health")
        def health_check() -> Dict[str, Any]:
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data={"status": "healthy", "version": "1.0.0"},
                message="Service is running"
            ).to_dict()

        # ===== 仪表盘数据 =====
        @router.get("/dashboard/metrics")
        def get_dashboard_metrics() -> Dict[str, Any]:
            if not self._data_aggregator:
                return APIResponse(
                    status=ResponseStatus.ERROR,
                    message="Data aggregator not initialized"
                ).to_dict()

            metrics = self._data_aggregator.get_metrics()
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data=metrics.to_dict()
            ).to_dict()

        @router.get("/dashboard/top-risks")
        def get_top_risks(category: str = "all", limit: int = 10) -> Dict[str, Any]:
            if not self._data_aggregator:
                return APIResponse(
                    status=ResponseStatus.ERROR,
                    message="Data aggregator not initialized"
                ).to_dict()

            risks = self._data_aggregator.get_top_risks(category, limit)
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data=[{
                    "identifier": r.identifier,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "category": r.category,
                    "alert_count": r.alert_count,
                } for r in risks]
            ).to_dict()

        @router.get("/dashboard/snapshot")
        def get_snapshot() -> Dict[str, Any]:
            if not self._data_aggregator:
                return APIResponse(
                    status=ResponseStatus.ERROR,
                    message="Data aggregator not initialized"
                ).to_dict()

            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data=self._data_aggregator.export_snapshot()
            ).to_dict()

        # ===== 风险查询 =====
        @router.get("/risk/address/{address}")
        def get_address_risk(address: str) -> Dict[str, Any]:
            # 实际应调用风险评估模块
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data={
                    "address": address,
                    "risk_score": 45,
                    "risk_level": "medium",
                    "labels": ["defi_user"],
                    "last_activity": dt.now().isoformat(),
                }
            ).to_dict()

        @router.get("/risk/contract/{address}")
        def get_contract_risk(address: str) -> Dict[str, Any]:
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data={
                    "address": address,
                    "risk_score": 30,
                    "risk_level": "low",
                    "contract_type": "erc20",
                    "vulnerabilities": [],
                }
            ).to_dict()

        @router.post("/risk/batch")
        def batch_risk_check(addresses: List[str]) -> Dict[str, Any]:
            results = []
            for addr in addresses[:100]:  # 限制批量数量
                results.append({
                    "address": addr,
                    "risk_score": 50,
                    "risk_level": "medium",
                })
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data=results
            ).to_dict()

        # ===== 告警管理 =====
        @router.get("/alerts")
        def get_alerts(
            status: str = "all",
            severity: str = "all",
            limit: int = 50
        ) -> Dict[str, Any]:
            if self._alert_dashboard:
                alerts = self._alert_dashboard.get_alerts(
                    status=status,
                    severity=severity,
                    limit=limit
                )
                return APIResponse(
                    status=ResponseStatus.SUCCESS,
                    data=alerts
                ).to_dict()

            # 模拟数据
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data=[]
            ).to_dict()

        @router.get("/alerts/{alert_id}")
        def get_alert(alert_id: str) -> Dict[str, Any]:
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data={
                    "id": alert_id,
                    "type": "high_risk_transaction",
                    "severity": "high",
                    "status": "pending",
                    "created_at": dt.now().isoformat(),
                }
            ).to_dict()

        @router.post("/alerts/{alert_id}/resolve")
        def resolve_alert(alert_id: str, resolution: str = "") -> Dict[str, Any]:
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                message=f"Alert {alert_id} resolved",
                data={"alert_id": alert_id, "resolution": resolution}
            ).to_dict()

        @router.get("/alerts/statistics")
        def get_alert_statistics() -> Dict[str, Any]:
            if self._data_aggregator:
                return APIResponse(
                    status=ResponseStatus.SUCCESS,
                    data=self._data_aggregator.get_alert_summary()
                ).to_dict()
            return APIResponse(
                status=ResponseStatus.SUCCESS,
                data={}
            ).to_dict()

        # ===== 时间序列 =====
        @router.get("/timeseries/{metric}")
        def get_timeseries(
            metric: str,
            period: str = "hour",
            hours: int = 24
        ) -> Dict[str, Any]:
            if self._data_aggregator:
                from src.dashboard.dashboard_data import AggregationPeriod
                period_enum = AggregationPeriod(period)
                series = self._data_aggregator.get_time_series(
                    metric, period_enum, hours
                )
                return APIResponse(
                    status=ResponseStatus.SUCCESS,
                    data=series.to_dict()
                ).to_dict()
            return APIResponse(
                status=ResponseStatus.ERROR,
                message="Data not available"
            ).to_dict()

    def handle_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        client_id: str = "default"
    ) -> Dict[str, Any]:
        """处理请求"""
        # 速率限制
        if not self.rate_limiter.is_allowed(client_id):
            return APIResponse(
                status=ResponseStatus.ERROR,
                message="Rate limit exceeded"
            ).to_dict()

        # 查找路由
        handler = None
        route_params = {}

        for route_path, handlers in self.router.routes.items():
            if method in handlers:
                # 简单路径匹配（支持{param}格式）
                if self._match_path(route_path, path, route_params):
                    handler = handlers[method]
                    break

        if not handler:
            return APIResponse(
                status=ResponseStatus.ERROR,
                message=f"Route not found: {method} {path}"
            ).to_dict()

        try:
            # 合并参数
            all_params = {**(params or {}), **route_params}
            if body:
                all_params.update(body)

            # 调用处理器
            result = handler(**all_params) if all_params else handler()
            return result
        except Exception as e:
            logger.error(f"Request error: {e}")
            return APIResponse(
                status=ResponseStatus.ERROR,
                message=str(e)
            ).to_dict()

    def _match_path(
        self,
        template: str,
        path: str,
        params: Dict[str, str]
    ) -> bool:
        """匹配路径模板"""
        template_parts = template.split("/")
        path_parts = path.split("/")

        if len(template_parts) != len(path_parts):
            return False

        for t, p in zip(template_parts, path_parts):
            if t.startswith("{") and t.endswith("}"):
                param_name = t[1:-1]
                params[param_name] = p
            elif t != p:
                return False

        return True

    def get_routes(self) -> List[Dict[str, str]]:
        """获取所有路由"""
        routes = []
        for path, methods in self.router.routes.items():
            for method in methods:
                routes.append({"method": method, "path": path})
        return routes


def create_app(config: Optional[APIConfig] = None) -> APIServer:
    """创建API应用"""
    return APIServer(config)


# WebSocket消息类型
class WSMessageType(Enum):
    """WebSocket消息类型"""
    ALERT = "alert"
    RISK_UPDATE = "risk_update"
    TRANSACTION = "transaction"
    SYSTEM = "system"
    HEARTBEAT = "heartbeat"


@dataclass
class WSMessage:
    """WebSocket消息"""
    type: WSMessageType
    data: Any
    timestamp: str = dc_field(default_factory=lambda: dt.now().isoformat())

    def to_json(self) -> str:
        return json.dumps({
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp,
        })


class WebSocketHandler:
    """WebSocket处理器"""

    def __init__(self):
        self._clients: Dict[str, Any] = {}
        self._subscriptions: Dict[str, List[str]] = {}  # client_id -> topics

    def connect(self, client_id: str, client: Any):
        """客户端连接"""
        self._clients[client_id] = client
        self._subscriptions[client_id] = []
        logger.info(f"WebSocket client connected: {client_id}")

    def disconnect(self, client_id: str):
        """客户端断开"""
        self._clients.pop(client_id, None)
        self._subscriptions.pop(client_id, None)
        logger.info(f"WebSocket client disconnected: {client_id}")

    def subscribe(self, client_id: str, topics: List[str]):
        """订阅主题"""
        if client_id in self._subscriptions:
            self._subscriptions[client_id].extend(topics)

    def unsubscribe(self, client_id: str, topics: List[str]):
        """取消订阅"""
        if client_id in self._subscriptions:
            self._subscriptions[client_id] = [
                t for t in self._subscriptions[client_id]
                if t not in topics
            ]

    async def broadcast(self, message: WSMessage, topic: Optional[str] = None):
        """广播消息"""
        for client_id, client in list(self._clients.items()):
            if topic and topic not in self._subscriptions.get(client_id, []):
                continue
            try:
                await self._send_to_client(client, message)
            except Exception as e:
                logger.error(f"Failed to send to {client_id}: {e}")
                self.disconnect(client_id)

    async def _send_to_client(self, client: Any, message: WSMessage):
        """发送消息到客户端"""
        # 实际实现取决于WebSocket库
        pass

    def get_client_count(self) -> int:
        """获取客户端数量"""
        return len(self._clients)

    def get_subscriptions(self, client_id: str) -> List[str]:
        """获取客户端订阅"""
        return self._subscriptions.get(client_id, [])
