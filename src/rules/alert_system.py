"""
告警生成与管理系统

功能：
- 告警生成
- 告警状态管理
- 告警分发（多渠道）
- 告警去重与聚合
"""

from dataclasses import dataclass, field
from datetime import datetime as dt, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from collections import defaultdict
import hashlib
import json
import logging

from src.rules.rule_model import RuleSeverity
from src.rules.rule_engine import RuleResult
from src.rules.risk_scorer import RiskAssessment, RiskLevel

logger = logging.getLogger(__name__)


class AlertStatus(str, Enum):
    """告警状态"""
    OPEN = "open"                    # 新告警
    ACKNOWLEDGED = "acknowledged"    # 已确认
    INVESTIGATING = "investigating"  # 调查中
    RESOLVED = "resolved"            # 已解决
    DISMISSED = "dismissed"          # 已忽略
    ESCALATED = "escalated"          # 已升级


class AlertPriority(str, Enum):
    """告警优先级"""
    P1 = "P1"                        # 最高优先级，需立即处理
    P2 = "P2"                        # 高优先级，4小时内处理
    P3 = "P3"                        # 中优先级，24小时内处理
    P4 = "P4"                        # 低优先级，48小时内处理


@dataclass
class Alert:
    """告警"""
    alert_id: str
    title: str
    description: str

    # 关联信息
    subject: str                     # 告警主体（地址/交易哈希）
    subject_type: str                # 主体类型
    rule_id: str                     # 触发规则ID
    rule_name: str                   # 触发规则名称

    # 优先级与状态
    priority: AlertPriority = AlertPriority.P3
    status: AlertStatus = AlertStatus.OPEN

    # 风险信息
    risk_score: int = 0
    risk_level: str = "unknown"
    severity: str = "medium"

    # 证据
    evidence: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

    # 时间
    created_at: dt = field(default_factory=dt.now)
    updated_at: dt = field(default_factory=dt.now)
    acknowledged_at: Optional[dt] = None
    resolved_at: Optional[dt] = None

    # 处理人
    assignee: Optional[str] = None
    acknowledger: Optional[str] = None

    # 备注
    notes: List[Dict[str, Any]] = field(default_factory=list)

    # 聚合
    occurrence_count: int = 1        # 出现次数（聚合后）
    related_alerts: List[str] = field(default_factory=list)

    # 标签
    tags: List[str] = field(default_factory=list)

    def acknowledge(self, user: str, note: Optional[str] = None):
        """确认告警"""
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_at = dt.now()
        self.acknowledger = user
        self.updated_at = dt.now()
        if note:
            self.add_note(user, note)

    def resolve(self, user: str, note: Optional[str] = None):
        """解决告警"""
        self.status = AlertStatus.RESOLVED
        self.resolved_at = dt.now()
        self.updated_at = dt.now()
        if note:
            self.add_note(user, f"Resolved: {note}")

    def dismiss(self, user: str, reason: str):
        """忽略告警"""
        self.status = AlertStatus.DISMISSED
        self.updated_at = dt.now()
        self.add_note(user, f"Dismissed: {reason}")

    def escalate(self, user: str, reason: str):
        """升级告警"""
        self.status = AlertStatus.ESCALATED
        self.updated_at = dt.now()
        self.add_note(user, f"Escalated: {reason}")
        # 提升优先级
        if self.priority == AlertPriority.P4:
            self.priority = AlertPriority.P3
        elif self.priority == AlertPriority.P3:
            self.priority = AlertPriority.P2
        elif self.priority == AlertPriority.P2:
            self.priority = AlertPriority.P1

    def add_note(self, user: str, content: str):
        """添加备注"""
        self.notes.append({
            "user": user,
            "content": content,
            "timestamp": dt.now().isoformat(),
        })

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "subject": self.subject,
            "subject_type": self.subject_type,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "priority": self.priority.value,
            "status": self.status.value,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "severity": self.severity,
            "evidence": self.evidence,
            "context": self.context,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "assignee": self.assignee,
            "acknowledger": self.acknowledger,
            "notes": self.notes,
            "occurrence_count": self.occurrence_count,
            "tags": self.tags,
        }


class AlertManager:
    """告警管理器"""

    def __init__(
        self,
        dedup_window_minutes: int = 60,
        auto_escalate_hours: int = 4
    ):
        """初始化告警管理器

        Args:
            dedup_window_minutes: 去重时间窗口（分钟）
            auto_escalate_hours: 未处理自动升级时间（小时）
        """
        self.dedup_window = timedelta(minutes=dedup_window_minutes)
        self.auto_escalate_hours = auto_escalate_hours

        # 告警存储
        self._alerts: Dict[str, Alert] = {}

        # 去重索引：fingerprint -> alert_id
        self._dedup_index: Dict[str, str] = {}

        # 通知渠道
        self._channels: Dict[str, Callable[[Alert], bool]] = {}

        # 计数器
        self._alert_counter = 0

    def register_channel(self, name: str, handler: Callable[[Alert], bool]):
        """注册通知渠道

        Args:
            name: 渠道名称
            handler: 处理函数，接收Alert，返回是否发送成功
        """
        self._channels[name] = handler
        logger.info(f"Alert channel registered: {name}")

    def create_alert_from_result(
        self,
        result: RuleResult,
        subject: str,
        subject_type: str,
        assessment: Optional[RiskAssessment] = None
    ) -> Optional[Alert]:
        """从规则评估结果创建告警

        Args:
            result: 规则评估结果
            subject: 主体
            subject_type: 主体类型
            assessment: 风险评估结果（可选）

        Returns:
            Alert 或 None（如果被去重）
        """
        if not result.triggered:
            return None

        # 生成指纹用于去重
        fingerprint = self._generate_fingerprint(result, subject)

        # 检查去重
        existing_alert = self._check_dedup(fingerprint)
        if existing_alert:
            existing_alert.occurrence_count += 1
            existing_alert.updated_at = dt.now()
            logger.debug(f"Alert deduplicated: {existing_alert.alert_id}")
            return None

        # 生成告警ID
        self._alert_counter += 1
        alert_id = f"ALT-{dt.now().strftime('%Y%m%d')}-{self._alert_counter:05d}"

        # 确定优先级
        priority = self._determine_priority(result, assessment)

        # 创建告警
        alert = Alert(
            alert_id=alert_id,
            title=f"[{result.rule_name}] Risk detected for {subject_type}: {subject[:16]}...",
            description=self._generate_description(result, assessment),
            subject=subject,
            subject_type=subject_type,
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            priority=priority,
            risk_score=result.risk_score,
            risk_level=assessment.risk_level.value if assessment else "unknown",
            severity=self._get_rule_severity(result),
            evidence=result.matched_conditions,
            context=result.context,
        )

        # 存储
        self._alerts[alert_id] = alert
        self._dedup_index[fingerprint] = alert_id

        logger.info(f"Alert created: {alert_id} - {alert.title}")

        # 发送通知
        self._dispatch_alert(alert)

        return alert

    def create_alert_from_assessment(
        self,
        assessment: RiskAssessment
    ) -> Optional[Alert]:
        """从风险评估结果创建告警"""
        if assessment.risk_level == RiskLevel.NONE:
            return None

        # 生成指纹
        fingerprint = hashlib.md5(
            f"{assessment.subject}:{assessment.risk_level.value}".encode()
        ).hexdigest()

        # 检查去重
        existing_alert = self._check_dedup(fingerprint)
        if existing_alert:
            existing_alert.occurrence_count += 1
            existing_alert.updated_at = dt.now()
            return None

        # 生成告警ID
        self._alert_counter += 1
        alert_id = f"ALT-{dt.now().strftime('%Y%m%d')}-{self._alert_counter:05d}"

        # 确定优先级
        priority = self._level_to_priority(assessment.risk_level)

        # 汇总风险因子
        factors_summary = ", ".join(f.name for f in assessment.risk_factors[:3])
        if len(assessment.risk_factors) > 3:
            factors_summary += f" (+{len(assessment.risk_factors) - 3} more)"

        alert = Alert(
            alert_id=alert_id,
            title=f"[{assessment.risk_level.value.upper()}] Risk assessment for {assessment.subject_type}: {assessment.subject[:16]}...",
            description=f"Risk Score: {assessment.total_score}/100\n"
                       f"Risk Factors: {factors_summary}\n"
                       f"Recommendations: {', '.join(assessment.recommended_actions[:2])}",
            subject=assessment.subject,
            subject_type=assessment.subject_type,
            rule_id="risk_assessment",
            rule_name="Comprehensive Risk Assessment",
            priority=priority,
            risk_score=assessment.total_score,
            risk_level=assessment.risk_level.value,
            severity=assessment.risk_level.value,
            evidence=[f.description for f in assessment.risk_factors],
            context={"category_scores": assessment.category_scores},
            tags=["assessment"],
        )

        self._alerts[alert_id] = alert
        self._dedup_index[fingerprint] = alert_id

        logger.info(f"Assessment alert created: {alert_id}")
        self._dispatch_alert(alert)

        return alert

    def _generate_fingerprint(self, result: RuleResult, subject: str) -> str:
        """生成告警指纹用于去重"""
        content = f"{result.rule_id}:{subject}"
        return hashlib.md5(content.encode()).hexdigest()

    def _check_dedup(self, fingerprint: str) -> Optional[Alert]:
        """检查去重"""
        if fingerprint not in self._dedup_index:
            return None

        alert_id = self._dedup_index[fingerprint]
        alert = self._alerts.get(alert_id)

        if not alert:
            del self._dedup_index[fingerprint]
            return None

        # 检查是否在去重窗口内
        if dt.now() - alert.created_at > self.dedup_window:
            del self._dedup_index[fingerprint]
            return None

        # 检查是否已关闭
        if alert.status in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]:
            del self._dedup_index[fingerprint]
            return None

        return alert

    def _determine_priority(
        self,
        result: RuleResult,
        assessment: Optional[RiskAssessment]
    ) -> AlertPriority:
        """确定告警优先级"""
        # 基于评估结果
        if assessment:
            return self._level_to_priority(assessment.risk_level)

        # 基于规则分数
        if result.risk_score >= 80:
            return AlertPriority.P1
        elif result.risk_score >= 50:
            return AlertPriority.P2
        elif result.risk_score >= 30:
            return AlertPriority.P3
        else:
            return AlertPriority.P4

    def _level_to_priority(self, level: RiskLevel) -> AlertPriority:
        """风险等级转优先级"""
        mapping = {
            RiskLevel.CRITICAL: AlertPriority.P1,
            RiskLevel.HIGH: AlertPriority.P2,
            RiskLevel.MEDIUM: AlertPriority.P3,
            RiskLevel.LOW: AlertPriority.P4,
            RiskLevel.MINIMAL: AlertPriority.P4,
            RiskLevel.NONE: AlertPriority.P4,
        }
        return mapping.get(level, AlertPriority.P3)

    def _generate_description(
        self,
        result: RuleResult,
        assessment: Optional[RiskAssessment]
    ) -> str:
        """生成告警描述"""
        lines = [
            f"Rule: {result.rule_name} ({result.rule_id})",
            f"Risk Score: {result.risk_score}",
        ]

        if result.matched_conditions:
            lines.append("Matched Conditions:")
            for cond in result.matched_conditions[:5]:
                lines.append(f"  - {cond}")

        if assessment:
            lines.append(f"Overall Risk Level: {assessment.risk_level.value}")
            if assessment.recommended_actions:
                lines.append("Recommendations:")
                for action in assessment.recommended_actions[:3]:
                    lines.append(f"  - {action}")

        return "\n".join(lines)

    def _get_rule_severity(self, result: RuleResult) -> str:
        """获取规则严重程度"""
        # 从上下文获取
        if "severity" in result.context:
            return result.context["severity"]
        # 根据分数推断
        if result.risk_score >= 80:
            return "critical"
        elif result.risk_score >= 50:
            return "high"
        elif result.risk_score >= 30:
            return "medium"
        else:
            return "low"

    def _dispatch_alert(self, alert: Alert):
        """分发告警到各渠道"""
        if not self._channels:
            logger.debug("No alert channels registered")
            return

        for channel_name, handler in self._channels.items():
            try:
                success = handler(alert)
                if success:
                    logger.debug(f"Alert dispatched to {channel_name}: {alert.alert_id}")
                else:
                    logger.warning(f"Alert dispatch failed for {channel_name}: {alert.alert_id}")
            except Exception as e:
                logger.error(f"Alert dispatch error for {channel_name}: {e}")

    # ===== 告警查询 =====

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """获取告警"""
        return self._alerts.get(alert_id)

    def list_alerts(
        self,
        status: Optional[AlertStatus] = None,
        priority: Optional[AlertPriority] = None,
        subject: Optional[str] = None,
        limit: int = 100
    ) -> List[Alert]:
        """列出告警"""
        alerts = list(self._alerts.values())

        if status:
            alerts = [a for a in alerts if a.status == status]
        if priority:
            alerts = [a for a in alerts if a.priority == priority]
        if subject:
            alerts = [a for a in alerts if a.subject == subject]

        # 按创建时间倒序
        alerts.sort(key=lambda a: a.created_at, reverse=True)

        return alerts[:limit]

    def get_open_alerts(self) -> List[Alert]:
        """获取所有未处理告警"""
        return self.list_alerts(status=AlertStatus.OPEN)

    def get_alerts_by_subject(self, subject: str) -> List[Alert]:
        """获取某主体的所有告警"""
        return self.list_alerts(subject=subject)

    # ===== 告警操作 =====

    def acknowledge_alert(self, alert_id: str, user: str, note: Optional[str] = None) -> bool:
        """确认告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.acknowledge(user, note)
        return True

    def resolve_alert(self, alert_id: str, user: str, note: Optional[str] = None) -> bool:
        """解决告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.resolve(user, note)
        return True

    def dismiss_alert(self, alert_id: str, user: str, reason: str) -> bool:
        """忽略告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.dismiss(user, reason)
        return True

    def escalate_alert(self, alert_id: str, user: str, reason: str) -> bool:
        """升级告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.escalate(user, reason)
        self._dispatch_alert(alert)  # 重新分发
        return True

    def assign_alert(self, alert_id: str, assignee: str) -> bool:
        """分配告警"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.assignee = assignee
        alert.updated_at = dt.now()
        return True

    # ===== 统计 =====

    def get_statistics(self) -> Dict[str, Any]:
        """获取告警统计"""
        alerts = list(self._alerts.values())

        status_counts = defaultdict(int)
        priority_counts = defaultdict(int)

        for alert in alerts:
            status_counts[alert.status.value] += 1
            priority_counts[alert.priority.value] += 1

        return {
            "total": len(alerts),
            "by_status": dict(status_counts),
            "by_priority": dict(priority_counts),
            "open_count": status_counts.get("open", 0),
            "acknowledged_count": status_counts.get("acknowledged", 0),
            "resolved_count": status_counts.get("resolved", 0),
        }

    def cleanup_old_alerts(self, days: int = 30) -> int:
        """清理旧告警"""
        cutoff = dt.now() - timedelta(days=days)
        to_remove = []

        for alert_id, alert in self._alerts.items():
            if alert.status in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]:
                if alert.updated_at < cutoff:
                    to_remove.append(alert_id)

        for alert_id in to_remove:
            del self._alerts[alert_id]

        logger.info(f"Cleaned up {len(to_remove)} old alerts")
        return len(to_remove)


# ===== 预置通知渠道 =====

def console_channel(alert: Alert) -> bool:
    """控制台输出渠道"""
    print(f"\n{'='*60}")
    print(f"🚨 ALERT [{alert.priority.value}] - {alert.alert_id}")
    print(f"{'='*60}")
    print(f"Title: {alert.title}")
    print(f"Status: {alert.status.value}")
    print(f"Risk Score: {alert.risk_score}")
    print(f"Created: {alert.created_at}")
    print(f"\nDescription:\n{alert.description}")
    print(f"{'='*60}\n")
    return True


def log_channel(alert: Alert) -> bool:
    """日志渠道"""
    logger.warning(
        f"ALERT [{alert.priority.value}] {alert.alert_id}: {alert.title} "
        f"(score={alert.risk_score}, status={alert.status.value})"
    )
    return True
