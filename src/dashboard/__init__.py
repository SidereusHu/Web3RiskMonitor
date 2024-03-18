"""
Dashboard & Visualization Module

Phase 5: 可视化仪表盘与API服务

提供:
- RESTful API服务
- 实时监控WebSocket
- 风险仪表盘数据聚合
- 报告生成
- 告警管理界面
"""

from src.dashboard.dashboard_data import (
    DashboardDataAggregator,
    DashboardMetrics,
    TimeSeriesData,
    RiskDistribution,
)
from src.dashboard.api_server import (
    create_app,
    APIConfig,
)
from src.dashboard.realtime_monitor import (
    RealtimeMonitor,
    WebSocketManager,
    MonitorEvent,
    EventType,
)
from src.dashboard.report_generator import (
    ReportGenerator,
    ReportConfig,
    ReportFormat,
)
from src.dashboard.alert_dashboard import (
    AlertDashboard,
    AlertFilter,
    AlertStatistics,
)

__all__ = [
    # Data Aggregation
    "DashboardDataAggregator",
    "DashboardMetrics",
    "TimeSeriesData",
    "RiskDistribution",
    # API Server
    "create_app",
    "APIConfig",
    # Realtime Monitor
    "RealtimeMonitor",
    "WebSocketManager",
    "MonitorEvent",
    "EventType",
    # Report Generator
    "ReportGenerator",
    "ReportConfig",
    "ReportFormat",
    # Alert Dashboard
    "AlertDashboard",
    "AlertFilter",
    "AlertStatistics",
]
