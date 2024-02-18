"""
规则数据模型

定义风险规则的数据结构：
- 规则条件 (Condition)
- 规则动作 (Action)
- 规则本身 (Rule)
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import json
import re


class ConditionOperator(str, Enum):
    """条件操作符"""
    # 比较操作符
    EQ = "eq"                    # 等于
    NE = "ne"                    # 不等于
    GT = "gt"                    # 大于
    GTE = "gte"                  # 大于等于
    LT = "lt"                    # 小于
    LTE = "lte"                  # 小于等于

    # 集合操作符
    IN = "in"                    # 在列表中
    NOT_IN = "not_in"            # 不在列表中
    CONTAINS = "contains"        # 包含
    NOT_CONTAINS = "not_contains"  # 不包含

    # 字符串操作符
    STARTS_WITH = "starts_with"  # 以...开头
    ENDS_WITH = "ends_with"      # 以...结尾
    REGEX = "regex"              # 正则匹配

    # 存在性操作符
    EXISTS = "exists"            # 字段存在
    NOT_EXISTS = "not_exists"    # 字段不存在
    IS_NULL = "is_null"          # 为空
    NOT_NULL = "not_null"        # 不为空

    # 逻辑操作符
    AND = "and"                  # 与
    OR = "or"                    # 或
    NOT = "not"                  # 非


class RuleSeverity(str, Enum):
    """规则严重程度"""
    CRITICAL = "critical"        # 严重 - 需要立即处理
    HIGH = "high"                # 高 - 需要优先关注
    MEDIUM = "medium"            # 中 - 需要审核
    LOW = "low"                  # 低 - 仅记录
    INFO = "info"                # 信息 - 仅供参考


class RuleCategory(str, Enum):
    """规则类别"""
    SANCTION = "sanction"        # 制裁相关
    AML = "aml"                  # 反洗钱
    FRAUD = "fraud"              # 欺诈检测
    COMPLIANCE = "compliance"    # 合规检查
    BEHAVIOR = "behavior"        # 行为异常
    SECURITY = "security"        # 安全风险
    CUSTOM = "custom"            # 自定义


class ActionType(str, Enum):
    """动作类型"""
    ALERT = "alert"              # 生成告警
    BLOCK = "block"              # 阻断交易
    FLAG = "flag"                # 标记地址
    LOG = "log"                  # 记录日志
    NOTIFY = "notify"            # 发送通知
    SCORE = "score"              # 调整风险分
    WEBHOOK = "webhook"          # 调用webhook


@dataclass
class RuleCondition:
    """规则条件

    支持简单条件和嵌套条件：
    - 简单条件: field + operator + value
    - 嵌套条件: operator(AND/OR/NOT) + conditions(子条件列表)
    """
    operator: ConditionOperator

    # 简单条件的字段
    field: Optional[str] = None
    value: Optional[Any] = None

    # 嵌套条件的子条件
    conditions: List['RuleCondition'] = dc_field(default_factory=list)

    def is_logical(self) -> bool:
        """是否为逻辑条件（AND/OR/NOT）"""
        return self.operator in [ConditionOperator.AND, ConditionOperator.OR, ConditionOperator.NOT]

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {"operator": self.operator.value}
        if self.field:
            result["field"] = self.field
        if self.value is not None:
            result["value"] = self.value
        if self.conditions:
            result["conditions"] = [c.to_dict() for c in self.conditions]
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RuleCondition':
        """从字典创建"""
        conditions = []
        if "conditions" in data:
            conditions = [cls.from_dict(c) for c in data["conditions"]]

        return cls(
            operator=ConditionOperator(data["operator"]),
            field=data.get("field"),
            value=data.get("value"),
            conditions=conditions,
        )

    # 便捷的静态工厂方法
    @staticmethod
    def eq(field_name: str, value: Any) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.EQ, field=field_name, value=value)

    @staticmethod
    def gt(field_name: str, value: Any) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.GT, field=field_name, value=value)

    @staticmethod
    def gte(field_name: str, value: Any) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.GTE, field=field_name, value=value)

    @staticmethod
    def lt(field_name: str, value: Any) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.LT, field=field_name, value=value)

    @staticmethod
    def lte(field_name: str, value: Any) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.LTE, field=field_name, value=value)

    @staticmethod
    def in_list(field_name: str, values: List[Any]) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.IN, field=field_name, value=values)

    @staticmethod
    def contains(field_name: str, value: str) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.CONTAINS, field=field_name, value=value)

    @staticmethod
    def regex_match(field_name: str, pattern: str) -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.REGEX, field=field_name, value=pattern)

    @staticmethod
    def and_(*conditions: 'RuleCondition') -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.AND, conditions=list(conditions))

    @staticmethod
    def or_(*conditions: 'RuleCondition') -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.OR, conditions=list(conditions))

    @staticmethod
    def not_(condition: 'RuleCondition') -> 'RuleCondition':
        return RuleCondition(operator=ConditionOperator.NOT, conditions=[condition])


@dataclass
class RuleAction:
    """规则动作"""
    action_type: ActionType
    params: Dict[str, Any] = dc_field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "params": self.params,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RuleAction':
        return cls(
            action_type=ActionType(data["action_type"]),
            params=data.get("params", {}),
        )

    # 便捷工厂方法
    @staticmethod
    def alert(message: str, channels: Optional[List[str]] = None) -> 'RuleAction':
        return RuleAction(
            action_type=ActionType.ALERT,
            params={"message": message, "channels": channels or ["default"]}
        )

    @staticmethod
    def add_score(points: int, reason: str) -> 'RuleAction':
        return RuleAction(
            action_type=ActionType.SCORE,
            params={"points": points, "reason": reason}
        )

    @staticmethod
    def flag_address(label: str, ttl_days: Optional[int] = None) -> 'RuleAction':
        return RuleAction(
            action_type=ActionType.FLAG,
            params={"label": label, "ttl_days": ttl_days}
        )

    @staticmethod
    def webhook(url: str, payload_template: Optional[Dict] = None) -> 'RuleAction':
        return RuleAction(
            action_type=ActionType.WEBHOOK,
            params={"url": url, "payload_template": payload_template or {}}
        )


@dataclass
class Rule:
    """风险规则

    一条完整的规则包含：
    - 基本信息（ID、名称、描述）
    - 条件（触发条件）
    - 动作（触发后执行的动作）
    - 元数据（严重程度、分类、启用状态等）
    """
    rule_id: str
    name: str
    description: str
    condition: RuleCondition
    actions: List[RuleAction]

    # 元数据
    severity: RuleSeverity = RuleSeverity.MEDIUM
    category: RuleCategory = RuleCategory.CUSTOM
    enabled: bool = True

    # 风险分数
    risk_score: int = 0                    # 触发时增加的风险分

    # 适用范围
    applies_to: List[str] = dc_field(default_factory=list)  # 适用的数据类型: transaction, address, etc.

    # 时间控制
    created_at: dt = dc_field(default_factory=dt.now)
    updated_at: dt = dc_field(default_factory=dt.now)
    effective_from: Optional[dt] = None    # 生效开始时间
    effective_until: Optional[dt] = None   # 生效结束时间

    # 统计信息
    trigger_count: int = 0                 # 触发次数
    last_triggered: Optional[dt] = None    # 最后触发时间

    # 标签
    tags: List[str] = dc_field(default_factory=list)

    def is_active(self) -> bool:
        """规则是否当前有效"""
        if not self.enabled:
            return False

        now = dt.now()
        if self.effective_from and now < self.effective_from:
            return False
        if self.effective_until and now > self.effective_until:
            return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于序列化）"""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "condition": self.condition.to_dict(),
            "actions": [a.to_dict() for a in self.actions],
            "severity": self.severity.value,
            "category": self.category.value,
            "enabled": self.enabled,
            "risk_score": self.risk_score,
            "applies_to": self.applies_to,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "effective_from": self.effective_from.isoformat() if self.effective_from else None,
            "effective_until": self.effective_until.isoformat() if self.effective_until else None,
            "trigger_count": self.trigger_count,
            "last_triggered": self.last_triggered.isoformat() if self.last_triggered else None,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        """从字典创建规则"""
        return cls(
            rule_id=data["rule_id"],
            name=data["name"],
            description=data["description"],
            condition=RuleCondition.from_dict(data["condition"]),
            actions=[RuleAction.from_dict(a) for a in data["actions"]],
            severity=RuleSeverity(data.get("severity", "medium")),
            category=RuleCategory(data.get("category", "custom")),
            enabled=data.get("enabled", True),
            risk_score=data.get("risk_score", 0),
            applies_to=data.get("applies_to", []),
            created_at=dt.fromisoformat(data["created_at"]) if data.get("created_at") else dt.now(),
            updated_at=dt.fromisoformat(data["updated_at"]) if data.get("updated_at") else dt.now(),
            effective_from=dt.fromisoformat(data["effective_from"]) if data.get("effective_from") else None,
            effective_until=dt.fromisoformat(data["effective_until"]) if data.get("effective_until") else None,
            trigger_count=data.get("trigger_count", 0),
            last_triggered=dt.fromisoformat(data["last_triggered"]) if data.get("last_triggered") else None,
            tags=data.get("tags", []),
        )

    def to_json(self) -> str:
        """序列化为JSON"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> 'Rule':
        """从JSON反序列化"""
        return cls.from_dict(json.loads(json_str))


# 规则构建器（流畅API）
class RuleBuilder:
    """规则构建器 - 流畅API"""

    def __init__(self, rule_id: str):
        self._rule_id = rule_id
        self._name = ""
        self._description = ""
        self._condition: Optional[RuleCondition] = None
        self._actions: List[RuleAction] = []
        self._severity = RuleSeverity.MEDIUM
        self._category = RuleCategory.CUSTOM
        self._risk_score = 0
        self._applies_to: List[str] = []
        self._tags: List[str] = []

    def name(self, name: str) -> 'RuleBuilder':
        self._name = name
        return self

    def description(self, desc: str) -> 'RuleBuilder':
        self._description = desc
        return self

    def when(self, condition: RuleCondition) -> 'RuleBuilder':
        self._condition = condition
        return self

    def then(self, action: RuleAction) -> 'RuleBuilder':
        self._actions.append(action)
        return self

    def severity(self, severity: RuleSeverity) -> 'RuleBuilder':
        self._severity = severity
        return self

    def category(self, category: RuleCategory) -> 'RuleBuilder':
        self._category = category
        return self

    def risk_score(self, score: int) -> 'RuleBuilder':
        self._risk_score = score
        return self

    def applies_to(self, *types: str) -> 'RuleBuilder':
        self._applies_to.extend(types)
        return self

    def tags(self, *tags: str) -> 'RuleBuilder':
        self._tags.extend(tags)
        return self

    def build(self) -> Rule:
        if not self._condition:
            raise ValueError("Rule must have a condition")
        if not self._actions:
            raise ValueError("Rule must have at least one action")

        return Rule(
            rule_id=self._rule_id,
            name=self._name,
            description=self._description,
            condition=self._condition,
            actions=self._actions,
            severity=self._severity,
            category=self._category,
            risk_score=self._risk_score,
            applies_to=self._applies_to,
            tags=self._tags,
        )
