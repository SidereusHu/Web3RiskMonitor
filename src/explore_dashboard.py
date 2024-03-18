"""
Phase 5 探索脚本：可视化仪表盘与API服务

演示：
1. 仪表盘数据聚合
2. API服务接口
3. 实时监控
4. 报告生成
5. 告警仪表盘
"""

import sys
sys.path.insert(0, "/Users/sidereus/Documents/FindJobs/Web3RiskMonitor")

from datetime import datetime as dt, timedelta
import json

from src.dashboard.dashboard_data import (
    DashboardDataAggregator,
    DashboardMetrics,
    TimeSeriesData,
    RiskDistribution,
)
from src.dashboard.api_server import (
    create_app,
    APIConfig,
    APIResponse,
    ResponseStatus,
)
from src.dashboard.realtime_monitor import (
    RealtimeMonitor,
    MonitorEvent,
    EventType,
    EventPriority,
    MonitoringDashboard,
)
from src.dashboard.report_generator import (
    ReportGenerator,
    ReportConfig,
    ReportFormat,
    ReportType,
)
from src.dashboard.alert_dashboard import (
    AlertDashboard,
    AlertFilter,
    AlertStatistics,
    AlertSeverity,
    AlertCategory,
    AlertStatus,
)


def demo_dashboard_data():
    """演示仪表盘数据聚合"""
    print("\n" + "="*60)
    print("1. 仪表盘数据聚合演示")
    print("="*60)

    aggregator = DashboardDataAggregator()

    # 模拟数据录入
    print("\n[录入模拟数据]")

    # 地址风险
    addresses = [
        ("0x1234567890123456789012345678901234567890", 85, "critical"),
        ("0x2345678901234567890123456789012345678901", 65, "high"),
        ("0x3456789012345678901234567890123456789012", 45, "medium"),
        ("0x4567890123456789012345678901234567890123", 25, "low"),
        ("0x5678901234567890123456789012345678901234", 15, "minimal"),
    ]

    for addr, score, level in addresses:
        aggregator.record_address_risk(addr, score, level)

    print(f"  录入 {len(addresses)} 个地址风险数据")

    # 合约风险
    contracts = [
        ("0xcontract1", 75, "high"),
        ("0xcontract2", 55, "medium"),
        ("0xcontract3", 35, "low"),
    ]

    for addr, score, level in contracts:
        aggregator.record_contract_risk(addr, score, level)

    print(f"  录入 {len(contracts)} 个合约风险数据")

    # 告警
    for i in range(10):
        aggregator.record_alert({
            "id": f"alert_{i}",
            "severity": "high" if i < 3 else "medium",
            "type": "suspicious_transaction",
            "status": "resolved" if i < 5 else "pending",
        })

    print(f"  录入 10 条告警")

    # 获取指标
    print("\n[获取仪表盘指标]")
    metrics = aggregator.get_metrics()

    print(f"\n总览:")
    print(f"  监控地址: {metrics.total_addresses_monitored}")
    print(f"  扫描合约: {metrics.total_contracts_scanned}")
    print(f"  生成告警: {metrics.total_alerts_generated}")

    print(f"\n地址风险分布:")
    addr_dist = metrics.address_risk_distribution
    print(f"  Critical: {addr_dist.critical}")
    print(f"  High: {addr_dist.high}")
    print(f"  Medium: {addr_dist.medium}")
    print(f"  Low: {addr_dist.low}")
    print(f"  Minimal: {addr_dist.minimal}")

    print(f"\n告警统计:")
    print(f"  活跃: {metrics.active_alerts}")
    print(f"  已解决: {metrics.resolved_alerts}")

    # 高风险项目
    print("\n[高风险项目 Top 3]")
    top_risks = aggregator.get_top_risks(limit=3)
    for risk in top_risks:
        print(f"  {risk.identifier[:20]}... Score: {risk.risk_score} Level: {risk.risk_level}")


def demo_api_server():
    """演示API服务"""
    print("\n" + "="*60)
    print("2. API服务演示")
    print("="*60)

    # 创建应用
    config = APIConfig(
        host="0.0.0.0",
        port=8000,
        api_prefix="/api/v1",
        rate_limit=100,
    )
    app = create_app(config)

    # 设置数据聚合器
    aggregator = DashboardDataAggregator()
    aggregator.record_address_risk("0x1234", 75, "high")
    aggregator.record_contract_risk("0xabcd", 45, "medium")
    app.set_data_aggregator(aggregator)

    print("\n[可用API端点]")
    routes = app.get_routes()
    for route in routes[:10]:
        print(f"  {route['method']:6} {route['path']}")

    # 模拟请求
    print("\n[模拟API请求]")

    # 健康检查
    response = app.handle_request("GET", "/api/v1/health")
    print(f"\nGET /api/v1/health:")
    print(f"  Status: {response['status']}")
    print(f"  Data: {response['data']}")

    # 获取仪表盘指标
    response = app.handle_request("GET", "/api/v1/dashboard/metrics")
    print(f"\nGET /api/v1/dashboard/metrics:")
    print(f"  Status: {response['status']}")
    if response['data']:
        overview = response['data'].get('overview', {})
        print(f"  Addresses: {overview.get('addresses_monitored', 0)}")

    # 获取地址风险
    response = app.handle_request(
        "GET",
        "/api/v1/risk/address/0x1234567890123456789012345678901234567890"
    )
    print(f"\nGET /api/v1/risk/address/0x1234...:")
    print(f"  Status: {response['status']}")
    if response['data']:
        print(f"  Risk Score: {response['data'].get('risk_score')}")
        print(f"  Risk Level: {response['data'].get('risk_level')}")


def demo_realtime_monitor():
    """演示实时监控"""
    print("\n" + "="*60)
    print("3. 实时监控演示")
    print("="*60)

    monitor = RealtimeMonitor()

    # 注册事件处理器
    def on_high_risk(event: MonitorEvent):
        print(f"  [Handler] 高风险事件: {event.event_type.value}")

    monitor.register_handler(EventType.NEW_HIGH_RISK, on_high_risk)

    print("\n[发送监控事件]")

    # 发送交易事件
    monitor.emit_transaction(
        tx_hash="0xabc123...",
        from_addr="0x1234...",
        to_addr="0x5678...",
        value=50.0,
        risk_score=45
    )
    print("  发送交易事件 (普通)")

    # 发送高价值交易
    monitor.emit_transaction(
        tx_hash="0xdef456...",
        from_addr="0x9999...",
        to_addr="0x8888...",
        value=500.0,
        risk_score=80
    )
    print("  发送交易事件 (高价值)")

    # 发送告警事件
    monitor.emit_alert(
        alert_id="ALT-001",
        alert_type="suspicious_pattern",
        severity="high",
        details={"description": "可疑交易模式"}
    )
    print("  发送告警事件")

    # 发送风险变化事件
    monitor.emit_risk_change(
        address="0xaaaa...",
        old_score=50,
        new_score=85,
        risk_level="critical"
    )
    print("  发送风险变化事件")

    # 获取监控指标
    print("\n[监控指标]")
    metrics = monitor.get_metrics()
    print(f"  处理事件: {metrics['events_processed']}")
    print(f"  缓冲区大小: {metrics['buffer_size']}")
    print(f"  事件类型分布: {metrics['events_by_type']}")

    # 监控仪表盘
    print("\n[监控仪表盘状态]")
    dashboard = MonitoringDashboard(monitor)
    print(dashboard.get_summary())


def demo_report_generator():
    """演示报告生成"""
    print("\n" + "="*60)
    print("4. 报告生成演示")
    print("="*60)

    generator = ReportGenerator()

    # 准备数据
    data = {
        "metrics": {
            "overview": {
                "addresses_monitored": 1250,
                "transactions_analyzed": 45000,
                "contracts_scanned": 380,
                "alerts_generated": 156,
            },
            "risk_distribution": {
                "addresses": {"critical": 12, "high": 45, "medium": 180, "low": 500, "minimal": 513},
                "contracts": {"critical": 5, "high": 20, "medium": 80, "low": 150, "minimal": 125},
            },
            "alerts": {
                "active": 23,
                "resolved": 133,
                "false_positive_rate": 8.5,
            },
        },
        "top_risks": [
            {"identifier": "0x1234...", "risk_score": 92, "risk_level": "critical", "category": "address"},
            {"identifier": "0x5678...", "risk_score": 88, "risk_level": "critical", "category": "contract"},
            {"identifier": "0x9abc...", "risk_score": 75, "risk_level": "high", "category": "address"},
        ],
    }

    # 生成日报
    print("\n[生成日报]")
    config = ReportConfig(
        report_type=ReportType.DAILY_SUMMARY,
        format=ReportFormat.HTML,
        time_range_hours=24,
    )

    report = generator.generate(data, config)

    print(f"  报告ID: {report.report_id}")
    print(f"  报告类型: {report.report_type.value}")
    print(f"  章节数: {len(report.sections)}")
    for section in report.sections:
        print(f"    - {section.title}")

    # 渲染不同格式
    print("\n[渲染报告]")

    # 文本格式
    text_output = generator.render(report, ReportFormat.TEXT)
    print(f"\n文本格式预览 (前500字符):")
    print(text_output[:500])

    # Markdown格式
    md_output = generator.render(report, ReportFormat.MARKDOWN)
    print(f"\nMarkdown格式预览 (前300字符):")
    print(md_output[:300])

    # JSON格式
    json_output = generator.render(report, ReportFormat.JSON)
    print(f"\nJSON格式预览 (前200字符):")
    print(json_output[:200])


def demo_alert_dashboard():
    """演示告警仪表盘"""
    print("\n" + "="*60)
    print("5. 告警仪表盘演示")
    print("="*60)

    dashboard = AlertDashboard()

    # 创建告警
    print("\n[创建告警]")

    alerts_data = [
        ("高风险交易检测", "检测到大额可疑转账", AlertSeverity.CRITICAL, AlertCategory.TRANSACTION),
        ("制裁地址交互", "与OFAC制裁地址有资金往来", AlertSeverity.HIGH, AlertCategory.COMPLIANCE),
        ("合约漏洞警告", "检测到重入漏洞风险", AlertSeverity.HIGH, AlertCategory.CONTRACT),
        ("异常交易频率", "24小时内交易量异常增加", AlertSeverity.MEDIUM, AlertCategory.TRANSACTION),
        ("新部署风险合约", "新合约包含可疑函数", AlertSeverity.MEDIUM, AlertCategory.CONTRACT),
    ]

    created_alerts = []
    for title, desc, severity, category in alerts_data:
        alert = dashboard.create_alert(
            title=title,
            description=desc,
            severity=severity,
            category=category,
            risk_score=80 if severity == AlertSeverity.CRITICAL else 60,
        )
        created_alerts.append(alert)
        print(f"  创建: {alert.alert_id} - {title}")

    # 处理告警
    print("\n[处理告警]")

    # 确认第一个告警
    dashboard.acknowledge_alert(created_alerts[0].alert_id, user="analyst_1")
    print(f"  确认告警: {created_alerts[0].alert_id}")

    # 解决第二个告警
    dashboard.resolve_alert(
        created_alerts[1].alert_id,
        resolution="经核实为正常业务往来",
        is_false_positive=True
    )
    print(f"  解决告警 (误报): {created_alerts[1].alert_id}")

    # 升级第三个告警
    dashboard.escalate_alert(
        created_alerts[2].alert_id,
        reason="需要安全专家介入",
        escalate_to="security_team"
    )
    print(f"  升级告警: {created_alerts[2].alert_id}")

    # 添加评论
    dashboard.add_comment(
        created_alerts[3].alert_id,
        comment="正在调查中，初步判断为套利机器人行为",
        user="analyst_2"
    )
    print(f"  添加评论: {created_alerts[3].alert_id}")

    # 获取统计
    print("\n[告警统计]")
    stats = dashboard.get_statistics()
    print(f"  总告警: {stats.total}")
    print(f"  按状态: {stats.by_status}")
    print(f"  按严重程度: {stats.by_severity}")
    print(f"  误报率: {stats.false_positive_rate:.1f}%")
    print(f"  待处理Critical: {stats.pending_critical}")
    print(f"  待处理High: {stats.pending_high}")

    # SLA状态
    print("\n[SLA状态]")
    sla_status = dashboard.get_sla_status()
    for sla in sla_status[:3]:
        print(f"  {sla['alert_id']}: {sla['status']} (剩余 {sla['remaining_hours']:.1f} 小时)")

    # 筛选告警
    print("\n[筛选告警]")
    filter = AlertFilter(
        severity=[AlertSeverity.CRITICAL, AlertSeverity.HIGH],
        status=[AlertStatus.PENDING, AlertStatus.ACKNOWLEDGED],
    )
    filtered = dashboard.get_alerts(filter=filter)
    print(f"  高优先级待处理告警: {len(filtered)} 条")

    # 获取仪表盘数据
    print("\n[仪表盘数据]")
    dashboard_data = dashboard.get_dashboard_data()
    print(f"  统计: {json.dumps(dashboard_data['statistics'], indent=2, ensure_ascii=False)[:200]}...")


def demo_integrated_workflow():
    """演示整合工作流"""
    print("\n" + "="*60)
    print("6. 整合工作流演示")
    print("="*60)

    # 初始化组件
    aggregator = DashboardDataAggregator()
    monitor = RealtimeMonitor()
    alert_dashboard = AlertDashboard()
    report_generator = ReportGenerator()

    # 连接组件
    api = create_app()
    api.set_data_aggregator(aggregator)
    api.set_alert_dashboard(alert_dashboard)

    print("\n[模拟风险监控流程]")

    # 1. 检测到风险地址
    print("\n步骤1: 检测到风险地址")
    address = "0xsuspicious123..."
    risk_score = 85
    aggregator.record_address_risk(address, risk_score, "critical")
    print(f"  记录地址风险: {address[:20]}... Score: {risk_score}")

    # 2. 发送监控事件
    print("\n步骤2: 发送监控事件")
    monitor.emit_risk_change(address, 0, risk_score, "critical")
    print(f"  发送风险变化事件")

    # 3. 创建告警
    print("\n步骤3: 创建告警")
    alert = alert_dashboard.create_alert(
        title="高风险地址发现",
        description=f"地址 {address} 风险评分达到 {risk_score}",
        severity=AlertSeverity.CRITICAL,
        category=AlertCategory.ADDRESS,
        related_address=address,
        risk_score=risk_score,
    )
    print(f"  创建告警: {alert.alert_id}")

    # 记录告警到聚合器
    aggregator.record_alert({
        "id": alert.alert_id,
        "severity": "critical",
        "type": "high_risk_address",
        "status": "pending",
    })

    # 4. 通过API查询
    print("\n步骤4: API查询")
    response = api.handle_request("GET", "/api/v1/dashboard/metrics")
    overview = response['data']['overview']
    print(f"  监控地址: {overview['addresses_monitored']}")
    print(f"  生成告警: {overview['alerts_generated']}")

    # 5. 生成报告
    print("\n步骤5: 生成风险报告")
    report_data = aggregator.export_snapshot()
    config = ReportConfig(report_type=ReportType.DAILY_SUMMARY)
    report = report_generator.generate(report_data, config)
    print(f"  报告ID: {report.report_id}")
    print(f"  报告摘要: {report.summary[:100]}...")

    print("\n" + "="*60)
    print("整合工作流演示完成!")
    print("="*60)


def main():
    """主函数"""
    print("\n" + "="*60)
    print("   Web3 Risk Monitor - Phase 5: 可视化仪表盘与API服务")
    print("="*60)

    try:
        # 1. 仪表盘数据聚合
        demo_dashboard_data()

        # 2. API服务
        demo_api_server()

        # 3. 实时监控
        demo_realtime_monitor()

        # 4. 报告生成
        demo_report_generator()

        # 5. 告警仪表盘
        demo_alert_dashboard()

        # 6. 整合工作流
        demo_integrated_workflow()

        print("\n" + "="*60)
        print("Phase 5 探索完成!")
        print("="*60)
        print("\n主要功能模块:")
        print("  1. dashboard_data.py     - 仪表盘数据聚合")
        print("  2. api_server.py         - RESTful API服务")
        print("  3. realtime_monitor.py   - 实时监控与WebSocket")
        print("  4. report_generator.py   - 多格式报告生成")
        print("  5. alert_dashboard.py    - 告警管理仪表盘")

    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
