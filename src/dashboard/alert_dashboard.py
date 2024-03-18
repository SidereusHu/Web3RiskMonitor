"""
告警仪表盘

告警管理与可视化:
- 告警列表与筛选
- 告警统计
- 告警处理流程
- 告警趋势分析
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class AlertStatus(Enum):
    """告警状态"""
    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class AlertSeverity(Enum):
    """告警严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(Enum):
    """告警分类"""
    TRANSACTION = "transaction"
    ADDRESS = "address"
    CONTRACT = "contract"
    COMPLIANCE = "compliance"
    SYSTEM = "system"


@dataclass
class AlertFilter:
    """告警筛选器"""
    status: Optional[List[AlertStatus]] = None
    severity: Optional[List[AlertSeverity]] = None
    category: Optional[List[AlertCategory]] = None
    start_time: Optional[dt] = None
    end_time: Optional[dt] = None
    search_text: Optional[str] = None
    address: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None

    def matches(self, alert: "AlertRecord") -> bool:
        """检查告警是否匹配筛选条件"""
        if self.status and alert.status not in self.status:
            return False
        if self.severity and alert.severity not in self.severity:
            return False
        if self.category and alert.category not in self.category:
            return False
        if self.start_time and alert.created_at < self.start_time:
            return False
        if self.end_time and alert.created_at > self.end_time:
            return False
        if self.search_text:
            search_lower = self.search_text.lower()
            if (search_lower not in alert.title.lower() and
                search_lower not in alert.description.lower()):
                return False
        if self.address and alert.related_address != self.address:
            return False
        if self.assigned_to and alert.assigned_to != self.assigned_to:
            return False
        if self.tags:
            if not set(self.tags) & set(alert.tags):
                return False
        return True


@dataclass
class AlertRecord:
    """告警记录"""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    category: AlertCategory
    status: AlertStatus = AlertStatus.PENDING
    created_at: dt = dc_field(default_factory=dt.now)
    updated_at: dt = dc_field(default_factory=dt.now)
    resolved_at: Optional[dt] = None
    related_address: Optional[str] = None
    related_tx: Optional[str] = None
    related_contract: Optional[str] = None
    risk_score: int = 0
    assigned_to: Optional[str] = None
    tags: List[str] = dc_field(default_factory=list)
    metadata: Dict[str, Any] = dc_field(default_factory=dict)
    comments: List[Dict[str, Any]] = dc_field(default_factory=list)
    history: List[Dict[str, Any]] = dc_field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "related_address": self.related_address,
            "related_tx": self.related_tx,
            "related_contract": self.related_contract,
            "risk_score": self.risk_score,
            "assigned_to": self.assigned_to,
            "tags": self.tags,
            "metadata": self.metadata,
            "comments_count": len(self.comments),
        }


@dataclass
class AlertStatistics:
    """告警统计"""
    total: int = 0
    by_status: Dict[str, int] = dc_field(default_factory=dict)
    by_severity: Dict[str, int] = dc_field(default_factory=dict)
    by_category: Dict[str, int] = dc_field(default_factory=dict)
    avg_resolution_time_hours: float = 0.0
    false_positive_rate: float = 0.0
    escalation_rate: float = 0.0
    pending_critical: int = 0
    pending_high: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "by_status": self.by_status,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "avg_resolution_time_hours": round(self.avg_resolution_time_hours, 2),
            "false_positive_rate": round(self.false_positive_rate, 2),
            "escalation_rate": round(self.escalation_rate, 2),
            "pending_critical": self.pending_critical,
            "pending_high": self.pending_high,
        }


class AlertDashboard:
    """告警仪表盘"""

    def __init__(self):
        self._alerts: Dict[str, AlertRecord] = {}
        self._handlers: Dict[str, List[Callable]] = {}
        self._auto_rules: List[Dict[str, Any]] = []

        # 配置
        self._sla_config = {
            AlertSeverity.CRITICAL: 1,  # 1小时内响应
            AlertSeverity.HIGH: 4,       # 4小时内响应
            AlertSeverity.MEDIUM: 24,    # 24小时内响应
            AlertSeverity.LOW: 72,       # 72小时内响应
            AlertSeverity.INFO: 168,     # 一周内响应
        }

    def add_alert(self, alert: AlertRecord) -> str:
        """添加告警"""
        self._alerts[alert.alert_id] = alert
        self._apply_auto_rules(alert)
        self._trigger_handlers("alert_created", alert)
        logger.info(f"Alert created: {alert.alert_id} - {alert.title}")
        return alert.alert_id

    def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        category: AlertCategory,
        **kwargs
    ) -> AlertRecord:
        """创建告警"""
        import uuid
        alert_id = f"ALT-{str(uuid.uuid4())[:8].upper()}"

        alert = AlertRecord(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            **kwargs
        )

        self.add_alert(alert)
        return alert

    def get_alert(self, alert_id: str) -> Optional[AlertRecord]:
        """获取告警"""
        return self._alerts.get(alert_id)

    def get_alerts(
        self,
        filter: Optional[AlertFilter] = None,
        status: str = "all",
        severity: str = "all",
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "created_at",
        sort_order: str = "desc"
    ) -> List[Dict[str, Any]]:
        """获取告警列表"""
        alerts = list(self._alerts.values())

        # 应用简单筛选
        if status != "all":
            try:
                status_enum = AlertStatus(status)
                alerts = [a for a in alerts if a.status == status_enum]
            except ValueError:
                pass

        if severity != "all":
            try:
                severity_enum = AlertSeverity(severity)
                alerts = [a for a in alerts if a.severity == severity_enum]
            except ValueError:
                pass

        # 应用复杂筛选
        if filter:
            alerts = [a for a in alerts if filter.matches(a)]

        # 排序
        reverse = sort_order == "desc"
        if sort_by == "created_at":
            alerts.sort(key=lambda a: a.created_at, reverse=reverse)
        elif sort_by == "severity":
            severity_order = {s: i for i, s in enumerate(AlertSeverity)}
            alerts.sort(key=lambda a: severity_order.get(a.severity, 99), reverse=reverse)
        elif sort_by == "risk_score":
            alerts.sort(key=lambda a: a.risk_score, reverse=reverse)

        # 分页
        alerts = alerts[offset:offset + limit]

        return [a.to_dict() for a in alerts]

    def update_alert(
        self,
        alert_id: str,
        updates: Dict[str, Any]
    ) -> Optional[AlertRecord]:
        """更新告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None

        old_status = alert.status

        for key, value in updates.items():
            if hasattr(alert, key):
                if key == "status" and isinstance(value, str):
                    value = AlertStatus(value)
                setattr(alert, key, value)

        alert.updated_at = dt.now()

        # 记录历史
        alert.history.append({
            "timestamp": dt.now().isoformat(),
            "action": "updated",
            "changes": updates,
        })

        # 状态变更触发
        if "status" in updates and old_status != alert.status:
            if alert.status == AlertStatus.RESOLVED:
                alert.resolved_at = dt.now()
                self._trigger_handlers("alert_resolved", alert)
            elif alert.status == AlertStatus.ESCALATED:
                self._trigger_handlers("alert_escalated", alert)

        logger.info(f"Alert updated: {alert_id}")
        return alert

    def acknowledge_alert(
        self,
        alert_id: str,
        user: str = "system"
    ) -> bool:
        """确认告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False

        alert.status = AlertStatus.ACKNOWLEDGED
        alert.assigned_to = user
        alert.updated_at = dt.now()
        alert.history.append({
            "timestamp": dt.now().isoformat(),
            "action": "acknowledged",
            "user": user,
        })

        self._trigger_handlers("alert_acknowledged", alert)
        return True

    def resolve_alert(
        self,
        alert_id: str,
        resolution: str = "",
        is_false_positive: bool = False
    ) -> bool:
        """解决告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False

        alert.status = (
            AlertStatus.FALSE_POSITIVE if is_false_positive
            else AlertStatus.RESOLVED
        )
        alert.resolved_at = dt.now()
        alert.updated_at = dt.now()
        alert.metadata["resolution"] = resolution
        alert.history.append({
            "timestamp": dt.now().isoformat(),
            "action": "resolved",
            "resolution": resolution,
            "is_false_positive": is_false_positive,
        })

        self._trigger_handlers("alert_resolved", alert)
        logger.info(f"Alert resolved: {alert_id}")
        return True

    def escalate_alert(
        self,
        alert_id: str,
        reason: str = "",
        escalate_to: Optional[str] = None
    ) -> bool:
        """升级告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False

        alert.status = AlertStatus.ESCALATED
        alert.updated_at = dt.now()
        if escalate_to:
            alert.assigned_to = escalate_to
        alert.metadata["escalation_reason"] = reason
        alert.history.append({
            "timestamp": dt.now().isoformat(),
            "action": "escalated",
            "reason": reason,
            "escalate_to": escalate_to,
        })

        self._trigger_handlers("alert_escalated", alert)
        logger.info(f"Alert escalated: {alert_id}")
        return True

    def add_comment(
        self,
        alert_id: str,
        comment: str,
        user: str = "system"
    ) -> bool:
        """添加评论"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False

        alert.comments.append({
            "timestamp": dt.now().isoformat(),
            "user": user,
            "comment": comment,
        })
        alert.updated_at = dt.now()
        return True

    def get_statistics(
        self,
        time_range_hours: int = 24
    ) -> AlertStatistics:
        """获取统计信息"""
        stats = AlertStatistics()
        cutoff = dt.now() - timedelta(hours=time_range_hours)

        relevant_alerts = [
            a for a in self._alerts.values()
            if a.created_at >= cutoff
        ]

        stats.total = len(relevant_alerts)

        # 按状态统计
        for status in AlertStatus:
            count = sum(1 for a in relevant_alerts if a.status == status)
            stats.by_status[status.value] = count

        # 按严重程度统计
        for severity in AlertSeverity:
            count = sum(1 for a in relevant_alerts if a.severity == severity)
            stats.by_severity[severity.value] = count

        # 按分类统计
        for category in AlertCategory:
            count = sum(1 for a in relevant_alerts if a.category == category)
            stats.by_category[category.value] = count

        # 计算平均解决时间
        resolved = [
            a for a in relevant_alerts
            if a.resolved_at and a.status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]
        ]
        if resolved:
            total_hours = sum(
                (a.resolved_at - a.created_at).total_seconds() / 3600
                for a in resolved
            )
            stats.avg_resolution_time_hours = total_hours / len(resolved)

        # 误报率
        false_positives = sum(
            1 for a in relevant_alerts if a.status == AlertStatus.FALSE_POSITIVE
        )
        if stats.total > 0:
            stats.false_positive_rate = false_positives / stats.total * 100

        # 升级率
        escalated = sum(
            1 for a in relevant_alerts if a.status == AlertStatus.ESCALATED
        )
        if stats.total > 0:
            stats.escalation_rate = escalated / stats.total * 100

        # 待处理的紧急告警
        pending_statuses = [AlertStatus.PENDING, AlertStatus.ACKNOWLEDGED]
        stats.pending_critical = sum(
            1 for a in self._alerts.values()
            if a.severity == AlertSeverity.CRITICAL and a.status in pending_statuses
        )
        stats.pending_high = sum(
            1 for a in self._alerts.values()
            if a.severity == AlertSeverity.HIGH and a.status in pending_statuses
        )

        return stats

    def get_trend(
        self,
        hours: int = 24,
        interval_hours: int = 1
    ) -> List[Dict[str, Any]]:
        """获取告警趋势"""
        now = dt.now()
        trend = []

        for i in range(hours // interval_hours, 0, -1):
            start = now - timedelta(hours=i * interval_hours)
            end = now - timedelta(hours=(i - 1) * interval_hours)

            count = sum(
                1 for a in self._alerts.values()
                if start <= a.created_at < end
            )

            trend.append({
                "timestamp": start.isoformat(),
                "count": count,
            })

        return trend

    def get_sla_status(self) -> List[Dict[str, Any]]:
        """获取SLA状态"""
        now = dt.now()
        results = []

        for alert in self._alerts.values():
            if alert.status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]:
                continue

            sla_hours = self._sla_config.get(alert.severity, 24)
            deadline = alert.created_at + timedelta(hours=sla_hours)
            remaining = (deadline - now).total_seconds() / 3600

            if remaining < 0:
                status = "breached"
            elif remaining < 1:
                status = "critical"
            elif remaining < sla_hours * 0.25:
                status = "warning"
            else:
                status = "ok"

            results.append({
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
                "sla_hours": sla_hours,
                "remaining_hours": max(0, remaining),
                "status": status,
            })

        # 按紧急程度排序
        status_order = {"breached": 0, "critical": 1, "warning": 2, "ok": 3}
        results.sort(key=lambda x: status_order.get(x["status"], 99))

        return results

    def register_handler(self, event: str, handler: Callable):
        """注册事件处理器"""
        if event not in self._handlers:
            self._handlers[event] = []
        self._handlers[event].append(handler)

    def _trigger_handlers(self, event: str, alert: AlertRecord):
        """触发事件处理器"""
        for handler in self._handlers.get(event, []):
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Handler error: {e}")

    def add_auto_rule(
        self,
        name: str,
        condition: Callable[[AlertRecord], bool],
        action: Callable[[AlertRecord], None]
    ):
        """添加自动化规则"""
        self._auto_rules.append({
            "name": name,
            "condition": condition,
            "action": action,
        })

    def _apply_auto_rules(self, alert: AlertRecord):
        """应用自动化规则"""
        for rule in self._auto_rules:
            try:
                if rule["condition"](alert):
                    rule["action"](alert)
                    logger.debug(f"Auto rule applied: {rule['name']}")
            except Exception as e:
                logger.error(f"Auto rule error: {e}")

    def get_dashboard_data(self) -> Dict[str, Any]:
        """获取仪表盘数据"""
        stats = self.get_statistics()

        return {
            "statistics": stats.to_dict(),
            "sla_status": self.get_sla_status()[:10],
            "recent_alerts": self.get_alerts(limit=10),
            "trend_24h": self.get_trend(hours=24),
            "critical_pending": stats.pending_critical,
            "high_pending": stats.pending_high,
        }

    def export_alerts(
        self,
        filter: Optional[AlertFilter] = None,
        format: str = "json"
    ) -> str:
        """导出告警"""
        import json

        alerts = self.get_alerts(filter=filter, limit=10000)

        if format == "json":
            return json.dumps(alerts, indent=2, ensure_ascii=False)
        elif format == "csv":
            if not alerts:
                return ""
            headers = list(alerts[0].keys())
            lines = [",".join(headers)]
            for alert in alerts:
                row = [str(alert.get(h, "")) for h in headers]
                lines.append(",".join(row))
            return "\n".join(lines)

        return ""

    def bulk_update(
        self,
        alert_ids: List[str],
        updates: Dict[str, Any]
    ) -> int:
        """批量更新告警"""
        updated = 0
        for alert_id in alert_ids:
            if self.update_alert(alert_id, updates):
                updated += 1
        return updated

    def get_related_alerts(
        self,
        alert_id: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """获取相关告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return []

        related = []
        for a in self._alerts.values():
            if a.alert_id == alert_id:
                continue

            # 相同地址
            if alert.related_address and a.related_address == alert.related_address:
                related.append(a)
            # 相同合约
            elif alert.related_contract and a.related_contract == alert.related_contract:
                related.append(a)
            # 相同分类和时间接近
            elif (a.category == alert.category and
                  abs((a.created_at - alert.created_at).total_seconds()) < 3600):
                related.append(a)

        related.sort(key=lambda x: x.created_at, reverse=True)
        return [a.to_dict() for a in related[:limit]]

    def clear_resolved(self, days_old: int = 30) -> int:
        """清理已解决的旧告警"""
        cutoff = dt.now() - timedelta(days=days_old)
        to_remove = [
            alert_id for alert_id, alert in self._alerts.items()
            if alert.status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]
            and alert.resolved_at and alert.resolved_at < cutoff
        ]

        for alert_id in to_remove:
            del self._alerts[alert_id]

        logger.info(f"Cleared {len(to_remove)} old resolved alerts")
        return len(to_remove)
