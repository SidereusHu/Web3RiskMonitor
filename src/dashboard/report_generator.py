"""
报告生成器

生成多种格式的风险报告:
- HTML报告
- JSON报告
- 文本摘要
- Markdown报告
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """报告格式"""
    HTML = "html"
    JSON = "json"
    TEXT = "text"
    MARKDOWN = "markdown"


class ReportType(Enum):
    """报告类型"""
    DAILY_SUMMARY = "daily_summary"
    RISK_ASSESSMENT = "risk_assessment"
    ALERT_REPORT = "alert_report"
    CONTRACT_ANALYSIS = "contract_analysis"
    ADDRESS_PROFILE = "address_profile"
    COMPLIANCE_REPORT = "compliance_report"


@dataclass
class ReportConfig:
    """报告配置"""
    report_type: ReportType = ReportType.DAILY_SUMMARY
    format: ReportFormat = ReportFormat.HTML
    include_charts: bool = True
    include_raw_data: bool = False
    time_range_hours: int = 24
    language: str = "zh"  # zh, en
    template_name: Optional[str] = None
    custom_header: Optional[str] = None
    custom_footer: Optional[str] = None


@dataclass
class ReportSection:
    """报告章节"""
    title: str
    content: str
    data: Optional[Dict[str, Any]] = None
    chart_type: Optional[str] = None  # bar, line, pie, table
    order: int = 0


@dataclass
class Report:
    """报告"""
    report_id: str
    report_type: ReportType
    title: str
    generated_at: dt = dc_field(default_factory=dt.now)
    time_range_start: Optional[dt] = None
    time_range_end: Optional[dt] = None
    sections: List[ReportSection] = dc_field(default_factory=list)
    metadata: Dict[str, Any] = dc_field(default_factory=dict)
    summary: str = ""

    def add_section(self, section: ReportSection):
        """添加章节"""
        self.sections.append(section)
        self.sections.sort(key=lambda s: s.order)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "title": self.title,
            "generated_at": self.generated_at.isoformat(),
            "time_range": {
                "start": self.time_range_start.isoformat() if self.time_range_start else None,
                "end": self.time_range_end.isoformat() if self.time_range_end else None,
            },
            "summary": self.summary,
            "sections": [
                {
                    "title": s.title,
                    "content": s.content,
                    "data": s.data,
                    "chart_type": s.chart_type,
                }
                for s in self.sections
            ],
            "metadata": self.metadata,
        }


class ReportGenerator:
    """报告生成器"""

    def __init__(self):
        self._templates: Dict[str, str] = {}
        self._load_default_templates()

    def _load_default_templates(self):
        """加载默认模板"""
        self._templates["html_base"] = """
<!DOCTYPE html>
<html lang="{language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .report-header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                         color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .report-header h1 {{ margin: 0 0 10px 0; }}
        .report-header .meta {{ opacity: 0.9; font-size: 14px; }}
        .section {{ background: white; padding: 20px; border-radius: 8px;
                   margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .risk-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px;
                      font-size: 12px; font-weight: bold; }}
        .risk-critical {{ background: #ff4757; color: white; }}
        .risk-high {{ background: #ff6b35; color: white; }}
        .risk-medium {{ background: #ffa502; color: white; }}
        .risk-low {{ background: #2ed573; color: white; }}
        .risk-minimal {{ background: #a4b0be; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .metric-card {{ display: inline-block; background: #f8f9fa; padding: 15px 25px;
                       border-radius: 8px; margin: 5px; text-align: center; }}
        .metric-value {{ font-size: 28px; font-weight: bold; color: #667eea; }}
        .metric-label {{ font-size: 12px; color: #666; margin-top: 5px; }}
        .chart-placeholder {{ background: #f8f9fa; padding: 40px; text-align: center;
                             border-radius: 8px; color: #999; }}
        .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>{title}</h1>
        <div class="meta">
            生成时间: {generated_at}<br>
            数据范围: {time_range}
        </div>
    </div>
    <div class="summary section">
        <h2>摘要</h2>
        <p>{summary}</p>
    </div>
    {sections}
    <div class="footer">
        {footer}
    </div>
</body>
</html>
"""

        self._templates["markdown_base"] = """
# {title}

**生成时间**: {generated_at}
**数据范围**: {time_range}

---

## 摘要

{summary}

{sections}

---

*{footer}*
"""

    def generate(
        self,
        data: Dict[str, Any],
        config: Optional[ReportConfig] = None
    ) -> Report:
        """生成报告"""
        config = config or ReportConfig()
        import uuid

        report = Report(
            report_id=str(uuid.uuid4())[:8],
            report_type=config.report_type,
            title=self._get_title(config.report_type),
            time_range_start=dt.now() - timedelta(hours=config.time_range_hours),
            time_range_end=dt.now(),
        )

        # 根据报告类型生成内容
        if config.report_type == ReportType.DAILY_SUMMARY:
            self._generate_daily_summary(report, data, config)
        elif config.report_type == ReportType.RISK_ASSESSMENT:
            self._generate_risk_assessment(report, data, config)
        elif config.report_type == ReportType.ALERT_REPORT:
            self._generate_alert_report(report, data, config)
        elif config.report_type == ReportType.CONTRACT_ANALYSIS:
            self._generate_contract_analysis(report, data, config)
        elif config.report_type == ReportType.ADDRESS_PROFILE:
            self._generate_address_profile(report, data, config)
        elif config.report_type == ReportType.COMPLIANCE_REPORT:
            self._generate_compliance_report(report, data, config)

        return report

    def _get_title(self, report_type: ReportType) -> str:
        """获取报告标题"""
        titles = {
            ReportType.DAILY_SUMMARY: "Web3风险监控日报",
            ReportType.RISK_ASSESSMENT: "风险评估报告",
            ReportType.ALERT_REPORT: "告警分析报告",
            ReportType.CONTRACT_ANALYSIS: "智能合约分析报告",
            ReportType.ADDRESS_PROFILE: "地址画像报告",
            ReportType.COMPLIANCE_REPORT: "合规审计报告",
        }
        return titles.get(report_type, "风险报告")

    def _generate_daily_summary(
        self,
        report: Report,
        data: Dict[str, Any],
        config: ReportConfig
    ):
        """生成日报"""
        metrics = data.get("metrics", {})
        overview = metrics.get("overview", {})

        # 摘要
        report.summary = f"""
过去{config.time_range_hours}小时内，系统共监控 {overview.get('addresses_monitored', 0)} 个地址，
分析 {overview.get('transactions_analyzed', 0)} 笔交易，
扫描 {overview.get('contracts_scanned', 0)} 个合约，
生成 {overview.get('alerts_generated', 0)} 条告警。
"""

        # 核心指标
        report.add_section(ReportSection(
            title="核心指标",
            content="",
            data={
                "metrics": [
                    {"label": "监控地址", "value": overview.get('addresses_monitored', 0)},
                    {"label": "分析交易", "value": overview.get('transactions_analyzed', 0)},
                    {"label": "扫描合约", "value": overview.get('contracts_scanned', 0)},
                    {"label": "生成告警", "value": overview.get('alerts_generated', 0)},
                ]
            },
            chart_type="metric_cards",
            order=1,
        ))

        # 风险分布
        risk_dist = metrics.get("risk_distribution", {})
        report.add_section(ReportSection(
            title="风险分布",
            content="地址和合约的风险等级分布情况",
            data={
                "addresses": risk_dist.get("addresses", {}),
                "contracts": risk_dist.get("contracts", {}),
            },
            chart_type="pie",
            order=2,
        ))

        # 告警统计
        alerts = metrics.get("alerts", {})
        report.add_section(ReportSection(
            title="告警统计",
            content=f"活跃告警: {alerts.get('active', 0)}, 已解决: {alerts.get('resolved', 0)}",
            data=alerts,
            chart_type="bar",
            order=3,
        ))

        # 高风险项目
        top_risks = data.get("top_risks", [])
        if top_risks:
            report.add_section(ReportSection(
                title="高风险项目",
                content="风险评分最高的地址和合约",
                data={"items": top_risks[:10]},
                chart_type="table",
                order=4,
            ))

    def _generate_risk_assessment(
        self,
        report: Report,
        data: Dict[str, Any],
        config: ReportConfig
    ):
        """生成风险评估报告"""
        target = data.get("target", {})
        risk_score = data.get("risk_score", 0)
        risk_level = data.get("risk_level", "unknown")

        report.summary = f"""
目标: {target.get('address', 'N/A')}
风险评分: {risk_score}/100
风险等级: {risk_level}
"""

        # 风险概览
        report.add_section(ReportSection(
            title="风险概览",
            content="",
            data={
                "score": risk_score,
                "level": risk_level,
                "factors": data.get("risk_factors", []),
            },
            order=1,
        ))

        # 漏洞详情
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            report.add_section(ReportSection(
                title="发现的漏洞",
                content=f"共发现 {len(vulnerabilities)} 个漏洞",
                data={"vulnerabilities": vulnerabilities},
                chart_type="table",
                order=2,
            ))

        # 建议
        recommendations = data.get("recommendations", [])
        if recommendations:
            report.add_section(ReportSection(
                title="建议",
                content="\n".join(f"- {r}" for r in recommendations),
                order=3,
            ))

    def _generate_alert_report(
        self,
        report: Report,
        data: Dict[str, Any],
        config: ReportConfig
    ):
        """生成告警报告"""
        summary = data.get("summary", {})
        total = summary.get("total", 0)

        report.summary = f"报告期间共生成 {total} 条告警"

        # 告警概览
        report.add_section(ReportSection(
            title="告警概览",
            content="",
            data=summary,
            chart_type="bar",
            order=1,
        ))

        # 按严重程度
        by_severity = summary.get("by_severity", {})
        report.add_section(ReportSection(
            title="严重程度分布",
            content="",
            data=by_severity,
            chart_type="pie",
            order=2,
        ))

        # 告警列表
        alerts = data.get("alerts", [])
        if alerts:
            report.add_section(ReportSection(
                title="告警详情",
                content="",
                data={"alerts": alerts[:50]},
                chart_type="table",
                order=3,
            ))

    def _generate_contract_analysis(
        self,
        report: Report,
        data: Dict[str, Any],
        config: ReportConfig
    ):
        """生成合约分析报告"""
        contract = data.get("contract", {})
        address = contract.get("address", "N/A")
        contract_type = contract.get("type", "unknown")

        report.summary = f"合约地址: {address}\n合约类型: {contract_type}"

        # 基本信息
        report.add_section(ReportSection(
            title="合约信息",
            content="",
            data={
                "address": address,
                "type": contract_type,
                "verified": contract.get("verified", False),
                "bytecode_size": contract.get("bytecode_size", 0),
            },
            order=1,
        ))

        # 功能分析
        features = contract.get("features", {})
        report.add_section(ReportSection(
            title="功能分析",
            content="",
            data=features,
            chart_type="table",
            order=2,
        ))

        # 安全分析
        security = data.get("security", {})
        report.add_section(ReportSection(
            title="安全分析",
            content="",
            data=security,
            order=3,
        ))

    def _generate_address_profile(
        self,
        report: Report,
        data: Dict[str, Any],
        config: ReportConfig
    ):
        """生成地址画像报告"""
        address = data.get("address", "N/A")
        profile = data.get("profile", {})

        report.summary = f"地址: {address}"

        # 基本画像
        report.add_section(ReportSection(
            title="地址画像",
            content="",
            data=profile,
            order=1,
        ))

        # 交易统计
        tx_stats = data.get("transaction_stats", {})
        report.add_section(ReportSection(
            title="交易统计",
            content="",
            data=tx_stats,
            chart_type="bar",
            order=2,
        ))

        # 关联分析
        relations = data.get("relations", {})
        report.add_section(ReportSection(
            title="关联分析",
            content="",
            data=relations,
            chart_type="network",
            order=3,
        ))

    def _generate_compliance_report(
        self,
        report: Report,
        data: Dict[str, Any],
        config: ReportConfig
    ):
        """生成合规报告"""
        report.summary = "合规审计报告"

        # 合规检查
        checks = data.get("compliance_checks", [])
        report.add_section(ReportSection(
            title="合规检查项",
            content="",
            data={"checks": checks},
            chart_type="table",
            order=1,
        ))

        # 风险标记
        flags = data.get("risk_flags", [])
        report.add_section(ReportSection(
            title="风险标记",
            content="",
            data={"flags": flags},
            order=2,
        ))

    def render(
        self,
        report: Report,
        format: ReportFormat = ReportFormat.HTML
    ) -> str:
        """渲染报告"""
        if format == ReportFormat.HTML:
            return self._render_html(report)
        elif format == ReportFormat.JSON:
            return self._render_json(report)
        elif format == ReportFormat.MARKDOWN:
            return self._render_markdown(report)
        elif format == ReportFormat.TEXT:
            return self._render_text(report)
        return ""

    def _render_html(self, report: Report) -> str:
        """渲染HTML"""
        sections_html = ""

        for section in report.sections:
            section_content = f"""
    <div class="section">
        <h2>{section.title}</h2>
        <div class="content">{section.content}</div>
        {self._render_html_data(section)}
    </div>
"""
            sections_html += section_content

        time_range = f"{report.time_range_start.strftime('%Y-%m-%d %H:%M') if report.time_range_start else 'N/A'} - {report.time_range_end.strftime('%Y-%m-%d %H:%M') if report.time_range_end else 'N/A'}"

        html = self._templates["html_base"].format(
            language="zh",
            title=report.title,
            generated_at=report.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
            time_range=time_range,
            summary=report.summary.replace("\n", "<br>"),
            sections=sections_html,
            footer="Web3 Risk Monitor - Generated Report",
        )

        return html

    def _render_html_data(self, section: ReportSection) -> str:
        """渲染章节数据"""
        if not section.data:
            return ""

        if section.chart_type == "table":
            return self._render_html_table(section.data)
        elif section.chart_type == "metric_cards":
            return self._render_html_metrics(section.data)
        elif section.chart_type in ("bar", "pie", "line"):
            return f'<div class="chart-placeholder">[{section.chart_type.upper()} Chart: {json.dumps(section.data)}]</div>'

        return f"<pre>{json.dumps(section.data, indent=2, ensure_ascii=False)}</pre>"

    def _render_html_table(self, data: Dict[str, Any]) -> str:
        """渲染HTML表格"""
        items = data.get("items", data.get("vulnerabilities", data.get("alerts", [])))
        if not items:
            return ""

        if not items:
            return "<p>无数据</p>"

        # 获取表头
        headers = list(items[0].keys()) if items else []

        html = "<table><thead><tr>"
        for h in headers:
            html += f"<th>{h}</th>"
        html += "</tr></thead><tbody>"

        for item in items[:20]:  # 限制行数
            html += "<tr>"
            for h in headers:
                value = item.get(h, "")
                if h == "risk_level":
                    html += f'<td><span class="risk-badge risk-{value}">{value}</span></td>'
                else:
                    html += f"<td>{value}</td>"
            html += "</tr>"

        html += "</tbody></table>"
        return html

    def _render_html_metrics(self, data: Dict[str, Any]) -> str:
        """渲染指标卡片"""
        metrics = data.get("metrics", [])
        html = '<div class="metrics">'

        for m in metrics:
            html += f"""
        <div class="metric-card">
            <div class="metric-value">{m['value']}</div>
            <div class="metric-label">{m['label']}</div>
        </div>
"""

        html += "</div>"
        return html

    def _render_json(self, report: Report) -> str:
        """渲染JSON"""
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)

    def _render_markdown(self, report: Report) -> str:
        """渲染Markdown"""
        sections_md = ""

        for section in report.sections:
            section_md = f"\n## {section.title}\n\n{section.content}\n"
            if section.data:
                section_md += f"\n```json\n{json.dumps(section.data, indent=2, ensure_ascii=False)}\n```\n"
            sections_md += section_md

        time_range = f"{report.time_range_start.strftime('%Y-%m-%d %H:%M') if report.time_range_start else 'N/A'} - {report.time_range_end.strftime('%Y-%m-%d %H:%M') if report.time_range_end else 'N/A'}"

        md = self._templates["markdown_base"].format(
            title=report.title,
            generated_at=report.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
            time_range=time_range,
            summary=report.summary,
            sections=sections_md,
            footer="Web3 Risk Monitor - Generated Report",
        )

        return md

    def _render_text(self, report: Report) -> str:
        """渲染纯文本"""
        lines = [
            "=" * 60,
            report.title.center(60),
            "=" * 60,
            f"生成时间: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "摘要:",
            report.summary,
            "",
        ]

        for section in report.sections:
            lines.append("-" * 40)
            lines.append(section.title)
            lines.append("-" * 40)
            lines.append(section.content)
            if section.data:
                lines.append(json.dumps(section.data, indent=2, ensure_ascii=False))
            lines.append("")

        lines.append("=" * 60)

        return "\n".join(lines)

    def export_to_file(
        self,
        report: Report,
        filepath: str,
        format: ReportFormat = ReportFormat.HTML
    ):
        """导出报告到文件"""
        content = self.render(report, format)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Report exported to {filepath}")
