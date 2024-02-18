"""
规则评估引擎

负责执行规则条件判断，核心功能：
- 条件评估（支持嵌套逻辑）
- 字段提取（支持嵌套字段访问）
- 规则执行与结果收集
"""

from dataclasses import dataclass, field
from datetime import datetime as dt
from typing import Dict, List, Optional, Any, Callable
import re
import logging

from src.rules.rule_model import (
    Rule,
    RuleCondition,
    ConditionOperator,
    RuleAction,
    ActionType,
)

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
    """规则执行结果"""
    rule_id: str
    rule_name: str
    triggered: bool                         # 是否触发
    risk_score: int = 0                     # 触发贡献的风险分
    matched_conditions: List[str] = field(default_factory=list)  # 匹配的条件描述
    actions_to_execute: List[RuleAction] = field(default_factory=list)
    evaluated_at: dt = field(default_factory=dt.now)
    evaluation_time_ms: float = 0.0         # 评估耗时（毫秒）
    context: Dict[str, Any] = field(default_factory=dict)  # 额外上下文


class ConditionEvaluator:
    """条件评估器"""

    def __init__(self):
        # 注册操作符处理函数
        self._operators: Dict[ConditionOperator, Callable] = {
            # 比较操作符
            ConditionOperator.EQ: self._eval_eq,
            ConditionOperator.NE: self._eval_ne,
            ConditionOperator.GT: self._eval_gt,
            ConditionOperator.GTE: self._eval_gte,
            ConditionOperator.LT: self._eval_lt,
            ConditionOperator.LTE: self._eval_lte,

            # 集合操作符
            ConditionOperator.IN: self._eval_in,
            ConditionOperator.NOT_IN: self._eval_not_in,
            ConditionOperator.CONTAINS: self._eval_contains,
            ConditionOperator.NOT_CONTAINS: self._eval_not_contains,

            # 字符串操作符
            ConditionOperator.STARTS_WITH: self._eval_starts_with,
            ConditionOperator.ENDS_WITH: self._eval_ends_with,
            ConditionOperator.REGEX: self._eval_regex,

            # 存在性操作符
            ConditionOperator.EXISTS: self._eval_exists,
            ConditionOperator.NOT_EXISTS: self._eval_not_exists,
            ConditionOperator.IS_NULL: self._eval_is_null,
            ConditionOperator.NOT_NULL: self._eval_not_null,

            # 逻辑操作符
            ConditionOperator.AND: self._eval_and,
            ConditionOperator.OR: self._eval_or,
            ConditionOperator.NOT: self._eval_not,
        }

    def evaluate(
        self,
        condition: RuleCondition,
        data: Dict[str, Any],
        matched_conditions: Optional[List[str]] = None
    ) -> bool:
        """评估条件

        Args:
            condition: 要评估的条件
            data: 数据上下文
            matched_conditions: 用于收集匹配条件描述的列表

        Returns:
            是否匹配
        """
        if matched_conditions is None:
            matched_conditions = []

        handler = self._operators.get(condition.operator)
        if not handler:
            logger.warning(f"Unknown operator: {condition.operator}")
            return False

        result = handler(condition, data, matched_conditions)
        return result

    def _get_field_value(self, data: Dict[str, Any], field_path: str) -> Any:
        """获取嵌套字段值

        支持点分隔的路径，如 "transaction.value_eth"
        支持数组索引，如 "labels[0]"
        """
        if not field_path:
            return None

        parts = field_path.replace("[", ".[").split(".")
        value = data

        for part in parts:
            if not part:
                continue

            if value is None:
                return None

            # 处理数组索引
            if part.startswith("[") and part.endswith("]"):
                try:
                    index = int(part[1:-1])
                    if isinstance(value, (list, tuple)) and 0 <= index < len(value):
                        value = value[index]
                    else:
                        return None
                except (ValueError, IndexError):
                    return None
            elif isinstance(value, dict):
                value = value.get(part)
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return None

        return value

    def _field_exists(self, data: Dict[str, Any], field_path: str) -> bool:
        """检查字段是否存在"""
        parts = field_path.replace("[", ".[").split(".")
        value = data

        for part in parts:
            if not part:
                continue

            if part.startswith("[") and part.endswith("]"):
                try:
                    index = int(part[1:-1])
                    if isinstance(value, (list, tuple)) and 0 <= index < len(value):
                        value = value[index]
                    else:
                        return False
                except (ValueError, IndexError):
                    return False
            elif isinstance(value, dict):
                if part not in value:
                    return False
                value = value[part]
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return False

        return True

    # ===== 比较操作符实现 =====

    def _eval_eq(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        result = value == cond.value
        if result:
            matched.append(f"{cond.field} == {cond.value}")
        return result

    def _eval_ne(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        result = value != cond.value
        if result:
            matched.append(f"{cond.field} != {cond.value}")
        return result

    def _eval_gt(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if value is None:
            return False
        try:
            result = float(value) > float(cond.value)
            if result:
                matched.append(f"{cond.field}({value}) > {cond.value}")
            return result
        except (TypeError, ValueError):
            return False

    def _eval_gte(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if value is None:
            return False
        try:
            result = float(value) >= float(cond.value)
            if result:
                matched.append(f"{cond.field}({value}) >= {cond.value}")
            return result
        except (TypeError, ValueError):
            return False

    def _eval_lt(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if value is None:
            return False
        try:
            result = float(value) < float(cond.value)
            if result:
                matched.append(f"{cond.field}({value}) < {cond.value}")
            return result
        except (TypeError, ValueError):
            return False

    def _eval_lte(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if value is None:
            return False
        try:
            result = float(value) <= float(cond.value)
            if result:
                matched.append(f"{cond.field}({value}) <= {cond.value}")
            return result
        except (TypeError, ValueError):
            return False

    # ===== 集合操作符实现 =====

    def _eval_in(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if not isinstance(cond.value, (list, tuple, set)):
            return False
        # 忽略大小写比较（如果是字符串）
        if isinstance(value, str):
            result = value.lower() in [v.lower() if isinstance(v, str) else v for v in cond.value]
        else:
            result = value in cond.value
        if result:
            matched.append(f"{cond.field}({value}) in list[{len(cond.value)} items]")
        return result

    def _eval_not_in(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if not isinstance(cond.value, (list, tuple, set)):
            return True
        if isinstance(value, str):
            result = value.lower() not in [v.lower() if isinstance(v, str) else v for v in cond.value]
        else:
            result = value not in cond.value
        if result:
            matched.append(f"{cond.field}({value}) not in list[{len(cond.value)} items]")
        return result

    def _eval_contains(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if value is None:
            return False

        # 列表/集合包含
        if isinstance(value, (list, tuple, set)):
            result = cond.value in value
        # 字符串包含
        elif isinstance(value, str):
            result = str(cond.value).lower() in value.lower()
        else:
            return False

        if result:
            matched.append(f"{cond.field} contains {cond.value}")
        return result

    def _eval_not_contains(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if value is None:
            return True

        if isinstance(value, (list, tuple, set)):
            result = cond.value not in value
        elif isinstance(value, str):
            result = str(cond.value).lower() not in value.lower()
        else:
            return True

        if result:
            matched.append(f"{cond.field} not contains {cond.value}")
        return result

    # ===== 字符串操作符实现 =====

    def _eval_starts_with(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if not isinstance(value, str):
            return False
        result = value.lower().startswith(str(cond.value).lower())
        if result:
            matched.append(f"{cond.field} starts with {cond.value}")
        return result

    def _eval_ends_with(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if not isinstance(value, str):
            return False
        result = value.lower().endswith(str(cond.value).lower())
        if result:
            matched.append(f"{cond.field} ends with {cond.value}")
        return result

    def _eval_regex(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        if not isinstance(value, str):
            return False
        try:
            pattern = re.compile(str(cond.value), re.IGNORECASE)
            result = bool(pattern.search(value))
            if result:
                matched.append(f"{cond.field} matches /{cond.value}/")
            return result
        except re.error:
            logger.warning(f"Invalid regex pattern: {cond.value}")
            return False

    # ===== 存在性操作符实现 =====

    def _eval_exists(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        result = self._field_exists(data, cond.field)
        if result:
            matched.append(f"{cond.field} exists")
        return result

    def _eval_not_exists(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        result = not self._field_exists(data, cond.field)
        if result:
            matched.append(f"{cond.field} not exists")
        return result

    def _eval_is_null(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        result = value is None
        if result:
            matched.append(f"{cond.field} is null")
        return result

    def _eval_not_null(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        value = self._get_field_value(data, cond.field)
        result = value is not None
        if result:
            matched.append(f"{cond.field} is not null")
        return result

    # ===== 逻辑操作符实现 =====

    def _eval_and(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        if not cond.conditions:
            return True
        results = []
        for sub_cond in cond.conditions:
            sub_matched = []
            result = self.evaluate(sub_cond, data, sub_matched)
            results.append(result)
            if result:
                matched.extend(sub_matched)
            if not result:  # 短路评估
                return False
        return all(results)

    def _eval_or(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        if not cond.conditions:
            return False
        for sub_cond in cond.conditions:
            sub_matched = []
            result = self.evaluate(sub_cond, data, sub_matched)
            if result:
                matched.extend(sub_matched)
                return True  # 短路评估
        return False

    def _eval_not(self, cond: RuleCondition, data: Dict, matched: List[str]) -> bool:
        if not cond.conditions:
            return True
        sub_matched = []
        result = not self.evaluate(cond.conditions[0], data, sub_matched)
        if result:
            matched.append(f"NOT({', '.join(sub_matched) if sub_matched else 'condition'})")
        return result


class RuleEngine:
    """规则引擎"""

    def __init__(self):
        self.evaluator = ConditionEvaluator()
        self._rules: Dict[str, Rule] = {}

    def add_rule(self, rule: Rule):
        """添加规则"""
        self._rules[rule.rule_id] = rule
        logger.info(f"Rule added: {rule.rule_id} - {rule.name}")

    def remove_rule(self, rule_id: str):
        """移除规则"""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Rule removed: {rule_id}")

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """获取规则"""
        return self._rules.get(rule_id)

    def list_rules(self, category: Optional[str] = None, enabled_only: bool = True) -> List[Rule]:
        """列出规则"""
        rules = list(self._rules.values())

        if category:
            rules = [r for r in rules if r.category.value == category]

        if enabled_only:
            rules = [r for r in rules if r.is_active()]

        return rules

    def evaluate_rule(self, rule: Rule, data: Dict[str, Any]) -> RuleResult:
        """评估单条规则

        Args:
            rule: 要评估的规则
            data: 数据上下文

        Returns:
            RuleResult 评估结果
        """
        import time
        start_time = time.time()

        matched_conditions: List[str] = []

        # 检查规则是否有效
        if not rule.is_active():
            return RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                triggered=False,
                context={"reason": "rule_inactive"}
            )

        # 评估条件
        triggered = self.evaluator.evaluate(rule.condition, data, matched_conditions)

        # 构建结果
        result = RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            triggered=triggered,
            risk_score=rule.risk_score if triggered else 0,
            matched_conditions=matched_conditions,
            actions_to_execute=rule.actions if triggered else [],
            evaluation_time_ms=(time.time() - start_time) * 1000,
        )

        # 更新规则统计
        if triggered:
            rule.trigger_count += 1
            rule.last_triggered = dt.now()
            logger.info(f"Rule triggered: {rule.rule_id} - {rule.name}")

        return result

    def evaluate_all(
        self,
        data: Dict[str, Any],
        data_type: Optional[str] = None,
        stop_on_critical: bool = False
    ) -> List[RuleResult]:
        """评估所有适用规则

        Args:
            data: 数据上下文
            data_type: 数据类型（用于过滤适用规则）
            stop_on_critical: 遇到严重规则触发时是否停止

        Returns:
            所有评估结果列表
        """
        results = []

        for rule in self._rules.values():
            # 检查适用性
            if data_type and rule.applies_to and data_type not in rule.applies_to:
                continue

            # 评估规则
            result = self.evaluate_rule(rule, data)
            results.append(result)

            # 严重规则触发时停止
            if stop_on_critical and result.triggered:
                if rule.severity.value == "critical":
                    logger.warning(f"Critical rule triggered, stopping evaluation: {rule.rule_id}")
                    break

        return results

    def evaluate_transaction(self, tx_data: Dict[str, Any]) -> List[RuleResult]:
        """评估交易数据"""
        return self.evaluate_all(tx_data, data_type="transaction")

    def evaluate_address(self, address_data: Dict[str, Any]) -> List[RuleResult]:
        """评估地址数据"""
        return self.evaluate_all(address_data, data_type="address")

    def get_triggered_rules(self, results: List[RuleResult]) -> List[RuleResult]:
        """获取触发的规则"""
        return [r for r in results if r.triggered]

    def calculate_total_risk_score(self, results: List[RuleResult]) -> int:
        """计算总风险分"""
        return sum(r.risk_score for r in results if r.triggered)
