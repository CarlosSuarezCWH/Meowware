"""
Executive Reporting System
Executive summary, risk assessment, business impact, remediation roadmap, visualizations

Meowware v17.0 - Developed by Carlos Mancera
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from ..core.models import ScanResult, Finding, Severity, Host

@dataclass
class RiskAssessment:
    """Risk assessment for findings"""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_risk_score: float = 0.0
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL

@dataclass
class BusinessImpact:
    """Business impact analysis"""
    data_breach_risk: float = 0.0
    service_disruption_risk: float = 0.0
    reputation_risk: float = 0.0
    compliance_risk: float = 0.0
    financial_impact: float = 0.0
    overall_impact: str = "LOW"

@dataclass
class RemediationItem:
    """Remediation item"""
    finding_title: str
    severity: Severity
    priority: int  # 1-5, 1 is highest
    effort: str  # LOW, MEDIUM, HIGH
    estimated_time: str
    recommendation: str
    affected_assets: List[str] = field(default_factory=list)

@dataclass
class RemediationRoadmap:
    """Remediation roadmap"""
    immediate: List[RemediationItem] = field(default_factory=list)  # 0-7 days
    short_term: List[RemediationItem] = field(default_factory=list)  # 1-4 weeks
    medium_term: List[RemediationItem] = field(default_factory=list)  # 1-3 months
    long_term: List[RemediationItem] = field(default_factory=list)  # 3+ months

class ExecutiveReporter:
    """
    Generates executive reports with:
    - Executive summary
    - Risk assessment
    - Business impact
    - Remediation roadmap
    - Visualizations
    """
    
    def generate_executive_report(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Generate complete executive report.
        """
        # 1. Executive Summary
        exec_summary = self._generate_executive_summary(scan_result)
        
        # 2. Risk Assessment
        risk_assessment = self._assess_risks(scan_result)
        
        # 3. Business Impact
        business_impact = self._calculate_business_impact(scan_result, risk_assessment)
        
        # 4. Remediation Roadmap
        remediation_roadmap = self._generate_remediation_roadmap(scan_result)
        
        # 5. Visualizations Data
        visualizations = self._generate_visualization_data(scan_result, risk_assessment)
        
        # Convert RemediationRoadmap to dict for JSON serialization
        roadmap_dict = {
            "immediate": [self._remediation_item_to_dict(item) for item in remediation_roadmap.immediate],
            "short_term": [self._remediation_item_to_dict(item) for item in remediation_roadmap.short_term],
            "medium_term": [self._remediation_item_to_dict(item) for item in remediation_roadmap.medium_term],
            "long_term": [self._remediation_item_to_dict(item) for item in remediation_roadmap.long_term]
        }
        
        return {
            "executive_summary": exec_summary,
            "risk_assessment": {
                "critical_count": risk_assessment.critical_count,
                "high_count": risk_assessment.high_count,
                "medium_count": risk_assessment.medium_count,
                "low_count": risk_assessment.low_count,
                "info_count": risk_assessment.info_count,
                "total_risk_score": risk_assessment.total_risk_score,
                "risk_level": risk_assessment.risk_level
            },
            "business_impact": {
                "data_breach_risk": business_impact.data_breach_risk,
                "service_disruption_risk": business_impact.service_disruption_risk,
                "reputation_risk": business_impact.reputation_risk,
                "compliance_risk": business_impact.compliance_risk,
                "financial_impact": business_impact.financial_impact,
                "overall_impact": business_impact.overall_impact
            },
            "remediation_roadmap": roadmap_dict,
            "visualizations": visualizations,
            "generated_at": datetime.now().isoformat()
        }
    
    def _remediation_item_to_dict(self, item: RemediationItem) -> Dict[str, Any]:
        """Convert RemediationItem to dict"""
        return {
            "finding_title": item.finding_title,
            "severity": item.severity.value if hasattr(item.severity, 'value') else str(item.severity),
            "priority": item.priority,
            "effort": item.effort,
            "estimated_time": item.estimated_time,
            "recommendation": item.recommendation,
            "affected_assets": item.affected_assets
        }
    
    def _generate_executive_summary(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Generate executive summary"""
        total_findings = len(scan_result.findings)
        critical_findings = [f for f in scan_result.findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in scan_result.findings if f.severity == Severity.HIGH]
        
        # Handle timestamp - it's already a string in ScanResult
        scan_date = scan_result.timestamp if scan_result.timestamp else datetime.now().isoformat()
        if isinstance(scan_date, str) and 'T' in scan_date:
            # Already in ISO format
            pass
        elif isinstance(scan_date, str):
            # Try to parse and convert
            try:
                from datetime import datetime as dt
                scan_date = dt.fromisoformat(scan_date.replace('Z', '+00:00')).isoformat()
            except:
                scan_date = datetime.now().isoformat()
        
        summary = {
            "target": scan_result.target.input,
            "scan_date": scan_date,
            "total_findings": total_findings,
            "critical_findings": len(critical_findings),
            "high_findings": len(high_findings),
            "hosts_scanned": len(scan_result.hosts),
            "key_findings": [f.title for f in critical_findings[:5]],
            "overall_risk": "CRITICAL" if critical_findings else ("HIGH" if high_findings else "MEDIUM"),
            "recommendation": self._generate_overall_recommendation(scan_result)
        }
        
        return summary
    
    def _generate_overall_recommendation(self, scan_result: ScanResult) -> str:
        """Generate overall recommendation"""
        critical = len([f for f in scan_result.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in scan_result.findings if f.severity == Severity.HIGH])
        
        if critical > 0:
            return f"Immediate action required: {critical} critical vulnerabilities detected. Prioritize remediation of these issues to prevent potential security breaches."
        elif high > 5:
            return f"High priority: {high} high-severity vulnerabilities require attention. Develop a remediation plan to address these issues within 30 days."
        elif high > 0:
            return f"Moderate risk: {high} high-severity vulnerabilities detected. Address these issues in the next security update cycle."
        else:
            return "Low to moderate risk profile. Continue regular security assessments and maintain current security posture."
    
    def _assess_risks(self, scan_result: ScanResult) -> RiskAssessment:
        """Assess risks from findings"""
        assessment = RiskAssessment()
        
        for finding in scan_result.findings:
            if finding.severity == Severity.CRITICAL:
                assessment.critical_count += 1
                assessment.total_risk_score += 10.0
            elif finding.severity == Severity.HIGH:
                assessment.high_count += 1
                assessment.total_risk_score += 7.0
            elif finding.severity == Severity.MEDIUM:
                assessment.medium_count += 1
                assessment.total_risk_score += 4.0
            elif finding.severity == Severity.LOW:
                assessment.low_count += 1
                assessment.total_risk_score += 1.0
            else:
                assessment.info_count += 1
        
        # Determine overall risk level
        if assessment.critical_count > 0:
            assessment.risk_level = "CRITICAL"
        elif assessment.high_count > 5:
            assessment.risk_level = "HIGH"
        elif assessment.high_count > 0:
            assessment.risk_level = "MEDIUM"
        else:
            assessment.risk_level = "LOW"
        
        return assessment
    
    def _calculate_business_impact(self, scan_result: ScanResult, 
                                   risk_assessment: RiskAssessment) -> BusinessImpact:
        """Calculate business impact"""
        impact = BusinessImpact()
        
        # Data breach risk (based on critical/high findings)
        critical_high = risk_assessment.critical_count + risk_assessment.high_count
        impact.data_breach_risk = min(10.0, critical_high * 2.0)
        
        # Service disruption risk
        service_related = [f for f in scan_result.findings 
                          if any(keyword in f.title.lower() 
                                for keyword in ['dos', 'denial', 'service', 'availability'])]
        impact.service_disruption_risk = min(10.0, len(service_related) * 3.0)
        
        # Reputation risk
        public_exposure = [f for f in scan_result.findings 
                          if 'exposure' in f.title.lower() or 'exposed' in f.description.lower()]
        impact.reputation_risk = min(10.0, len(public_exposure) * 2.5)
        
        # Compliance risk
        compliance_keywords = ['pii', 'gdpr', 'pci', 'hipaa', 'data', 'personal']
        compliance_related = [f for f in scan_result.findings 
                             if any(keyword in f.title.lower() or keyword in f.description.lower() 
                                   for keyword in compliance_keywords)]
        impact.compliance_risk = min(10.0, len(compliance_related) * 2.0)
        
        # Financial impact (estimated)
        impact.financial_impact = (
            impact.data_breach_risk * 10000 +
            impact.service_disruption_risk * 5000 +
            impact.reputation_risk * 3000 +
            impact.compliance_risk * 15000
        )
        
        # Overall impact
        avg_impact = (impact.data_breach_risk + impact.service_disruption_risk + 
                     impact.reputation_risk + impact.compliance_risk) / 4.0
        
        if avg_impact >= 7.5:
            impact.overall_impact = "CRITICAL"
        elif avg_impact >= 5.0:
            impact.overall_impact = "HIGH"
        elif avg_impact >= 2.5:
            impact.overall_impact = "MEDIUM"
        else:
            impact.overall_impact = "LOW"
        
        return impact
    
    def _generate_remediation_roadmap(self, scan_result: ScanResult) -> RemediationRoadmap:
        """Generate remediation roadmap"""
        roadmap = RemediationRoadmap()
        
        # Sort findings by severity and priority
        sorted_findings = sorted(scan_result.findings, 
                                key=lambda f: (f.severity.value if hasattr(f.severity, 'value') else str(f.severity), 
                                              -getattr(f, 'confidence_score', 0.5)),
                                reverse=True)
        
        for finding in sorted_findings:
            # Find affected hosts by checking if finding title contains host IP or hostname
            affected_assets = []
            for host in scan_result.hosts:
                # Check if finding title or description mentions this host
                host_identifiers = [host.ip, host.hostname] + (host.aliases or [])
                if any(identifier and identifier in finding.title for identifier in host_identifiers if identifier):
                    affected_assets.append(host.hostname or host.ip)
            
            # If no specific host found, use "Multiple" or target
            if not affected_assets:
                affected_assets = [scan_result.target.input]
            
            item = RemediationItem(
                finding_title=finding.title,
                severity=finding.severity,
                priority=self._calculate_priority(finding),
                effort=self._estimate_effort(finding),
                estimated_time=self._estimate_time(finding),
                recommendation=finding.recommendation or "Review and remediate",
                affected_assets=affected_assets
            )
            
            # Categorize by timeline
            if finding.severity == Severity.CRITICAL:
                roadmap.immediate.append(item)
            elif finding.severity == Severity.HIGH:
                roadmap.short_term.append(item)
            elif finding.severity == Severity.MEDIUM:
                roadmap.medium_term.append(item)
            else:
                roadmap.long_term.append(item)
        
        return roadmap
    
    def _calculate_priority(self, finding: Finding) -> int:
        """Calculate priority (1-5, 1 is highest)"""
        if finding.severity == Severity.CRITICAL:
            return 1
        elif finding.severity == Severity.HIGH:
            return 2
        elif finding.severity == Severity.MEDIUM:
            return 3
        elif finding.severity == Severity.LOW:
            return 4
        else:
            return 5
    
    def _estimate_effort(self, finding: Finding) -> str:
        """Estimate remediation effort"""
        finding_lower = finding.title.lower() + " " + finding.description.lower()
        
        if any(keyword in finding_lower for keyword in ['patch', 'update', 'upgrade']):
            return "MEDIUM"
        elif any(keyword in finding_lower for keyword in ['configuration', 'misconfiguration']):
            return "LOW"
        elif any(keyword in finding_lower for keyword in ['code', 'development', 'refactor']):
            return "HIGH"
        else:
            return "MEDIUM"
    
    def _estimate_time(self, finding: Finding) -> str:
        """Estimate remediation time"""
        effort = self._estimate_effort(finding)
        
        if effort == "LOW":
            return "1-3 days"
        elif effort == "MEDIUM":
            return "1-2 weeks"
        else:
            return "2-4 weeks"
    
    def _generate_visualization_data(self, scan_result: ScanResult, 
                                    risk_assessment: RiskAssessment) -> Dict[str, Any]:
        """Generate data for visualizations"""
        # Severity distribution
        severity_distribution = {
            "Critical": risk_assessment.critical_count,
            "High": risk_assessment.high_count,
            "Medium": risk_assessment.medium_count,
            "Low": risk_assessment.low_count,
            "Info": risk_assessment.info_count
        }
        
        # Category distribution
        category_distribution = {}
        for finding in scan_result.findings:
            category = finding.category
            category_distribution[category] = category_distribution.get(category, 0) + 1
        
        # Timeline data (findings over time - if available)
        timeline_data = {
            "scan_date": scan_result.timestamp if scan_result.timestamp else datetime.now().isoformat(),
            "total_findings": len(scan_result.findings)
        }
        
        # Risk score over time (placeholder for historical data)
        risk_trend = {
            "current": risk_assessment.total_risk_score,
            "trend": "increasing" if risk_assessment.total_risk_score > 50 else "stable"
        }
        
        return {
            "severity_distribution": severity_distribution,
            "category_distribution": category_distribution,
            "timeline": timeline_data,
            "risk_trend": risk_trend,
            "hosts_affected": len(scan_result.hosts),
            "total_risk_score": risk_assessment.total_risk_score
        }
    
    def generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML executive report in Spanish"""
        # Logo SVG
        logo_svg = """<svg width="80" height="80" viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <radialGradient id="aura">
      <stop offset="0%" stop-color="#7000ff" stop-opacity="0.6"/>
      <stop offset="100%" stop-color="#00d4ff" stop-opacity="0.2"/>
    </radialGradient>
    <linearGradient id="tulipGrad">
      <stop offset="0%" stop-color="#ff00ff"/>
      <stop offset="100%" stop-color="#7000ff"/>
    </linearGradient>
  </defs>
  <circle cx="60" cy="60" r="55" fill="url(#aura)"/>
  <path d="M 30 80 Q 20 60 25 45" stroke="#00cc66" stroke-width="3" fill="none" opacity="0.8"/>
  <path d="M 90 80 Q 100 60 95 45" stroke="#00cc66" stroke-width="3" fill="none" opacity="0.8"/>
  <ellipse cx="60" cy="70" rx="25" ry="20" fill="#ffffff" opacity="0.95"/>
  <circle cx="60" cy="50" r="22" fill="#ffffff" opacity="0.95"/>
  <path d="M 45 35 L 50 20 L 55 35 Z" fill="#e0b0ff" opacity="0.9"/>
  <path d="M 65 35 L 70 20 L 75 35 Z" fill="#e0b0ff" opacity="0.9"/>
  <circle cx="52" cy="48" r="6" fill="#00d4ff"/>
  <circle cx="68" cy="48" r="6" fill="#00d4ff"/>
  <circle cx="52" cy="48" r="3" fill="#000080"/>
  <circle cx="68" cy="48" r="3" fill="#000080"/>
  <circle cx="53" cy="47" r="1.5" fill="#ffffff"/>
  <circle cx="69" cy="47" r="1.5" fill="#ffffff"/>
  <path d="M 60 55 L 58 58 L 60 60 L 62 58 Z" fill="#00d4ff"/>
  <path d="M 60 28 Q 58 20 60 15 Q 62 20 60 28" fill="url(#tulipGrad)"/>
  <ellipse cx="50" cy="85" rx="8" ry="6" fill="#ffffff" opacity="0.95"/>
  <ellipse cx="70" cy="85" rx="8" ry="6" fill="#ffffff" opacity="0.95"/>
</svg>"""
        
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe Ejecutivo de Seguridad - {report_data['executive_summary']['target']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Helvetica Neue', Arial, sans-serif; 
            margin: 0; 
            padding: 0; 
            background: #ffffff; 
            color: #1a1a1a; 
            line-height: 1.7;
        }}
        header {{
            background: #ffffff;
            padding: 30px 20px;
            border-bottom: 2px solid #e0e0e0;
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        .logo-svg {{ width: 80px; height: 80px; }}
        h1 {{ 
            color: #1a1a1a; 
            font-size: 2em;
            font-weight: 600;
        }}
        h2 {{ 
            color: #1a1a1a; 
            border-bottom: 2px solid #e0e0e0; 
            padding-bottom: 10px; 
            margin-top: 30px;
            font-weight: 600;
        }}
        .summary-box {{ 
            background: #fafafa; 
            padding: 25px; 
            border: 1px solid #e0e0e0;
            border-radius: 4px; 
            margin: 20px 0; 
        }}
        .risk-critical {{ color: #c0392b; font-weight: bold; }}
        .risk-high {{ color: #e74c3c; font-weight: bold; }}
        .risk-medium {{ color: #e67e22; font-weight: bold; }}
        .risk-low {{ color: #27ae60; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #1a1a1a; color: white; font-weight: 600; text-transform: uppercase; font-size: 0.85em; }}
        .chart {{ margin: 20px 0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
    </style>
</head>
<body>
    <header>
        <div class="logo-svg">{logo_svg}</div>
        <div>
            <h1>ME<span style="color: #7000ff;">O</span>WARE v1.0 "Tulipán"</h1>
            <p style="color: #666; margin-top: 5px;">Informe Ejecutivo de Seguridad</p>
        </div>
    </header>
    
    <div class="container">
    <div class="summary-box">
        <h2>Resumen Ejecutivo</h2>
        <p><strong>Objetivo:</strong> {report_data['executive_summary']['target']}</p>
        <p><strong>Fecha de Escaneo:</strong> {report_data['executive_summary']['scan_date']}</p>
        <p><strong>Total de Hallazgos:</strong> {report_data['executive_summary']['total_findings']}</p>
        <p><strong>Hallazgos Críticos:</strong> <span class="risk-critical">{report_data['executive_summary']['critical_findings']}</span></p>
        <p><strong>Hallazgos Altos:</strong> <span class="risk-high">{report_data['executive_summary']['high_findings']}</span></p>
        <p><strong>Riesgo General:</strong> <span class="risk-{report_data['executive_summary']['overall_risk'].lower()}">{report_data['executive_summary']['overall_risk']}</span></p>
        <p><strong>Recomendación:</strong> {report_data['executive_summary']['recommendation']}</p>
    </div>
    
    <h2>Evaluación de Riesgos</h2>
    <table>
        <tr>
            <th>Severidad</th>
            <th>Cantidad</th>
            <th>Puntuación de Riesgo</th>
        </tr>
        <tr>
            <td class="risk-critical">Crítico</td>
            <td>{report_data['risk_assessment']['critical_count']}</td>
            <td>{report_data['risk_assessment']['critical_count'] * 10}</td>
        </tr>
        <tr>
            <td class="risk-high">Alto</td>
            <td>{report_data['risk_assessment']['high_count']}</td>
            <td>{report_data['risk_assessment']['high_count'] * 7}</td>
        </tr>
        <tr>
            <td class="risk-medium">Medio</td>
            <td>{report_data['risk_assessment']['medium_count']}</td>
            <td>{report_data['risk_assessment']['medium_count'] * 4}</td>
        </tr>
        <tr>
            <td class="risk-low">Bajo</td>
            <td>{report_data['risk_assessment']['low_count']}</td>
            <td>{report_data['risk_assessment']['low_count'] * 1}</td>
        </tr>
        <tr>
            <th>Puntuación Total de Riesgo</th>
            <th colspan="2">{report_data['risk_assessment']['total_risk_score']:.2f}</th>
        </tr>
    </table>
    
    <h2>Impacto en el Negocio</h2>
    <table>
        <tr>
            <th>Tipo de Impacto</th>
            <th>Puntuación de Riesgo</th>
            <th>Impacto Financiero Estimado</th>
        </tr>
        <tr>
            <td>Riesgo de Fuga de Datos</td>
            <td>{report_data['business_impact']['data_breach_risk']:.2f}/10</td>
            <td>${report_data['business_impact']['data_breach_risk'] * 10000:,.0f}</td>
        </tr>
        <tr>
            <td>Riesgo de Interrupción del Servicio</td>
            <td>{report_data['business_impact']['service_disruption_risk']:.2f}/10</td>
            <td>${report_data['business_impact']['service_disruption_risk'] * 5000:,.0f}</td>
        </tr>
        <tr>
            <td>Riesgo Reputacional</td>
            <td>{report_data['business_impact']['reputation_risk']:.2f}/10</td>
            <td>${report_data['business_impact']['reputation_risk'] * 3000:,.0f}</td>
        </tr>
        <tr>
            <td>Riesgo de Cumplimiento Normativo</td>
            <td>{report_data['business_impact']['compliance_risk']:.2f}/10</td>
            <td>${report_data['business_impact']['compliance_risk'] * 15000:,.0f}</td>
        </tr>
        <tr>
            <th>Impacto General Estimado</th>
            <th colspan="2">${report_data['business_impact']['financial_impact']:,.0f}</th>
        </tr>
    </table>
    
    <h2>Remediation Roadmap</h2>
    <h3>Immediate (0-7 days)</h3>
    {self._generate_remediation_table_html(report_data['remediation_roadmap'].get('immediate', []))}
    
    <h3>Short Term (1-4 weeks)</h3>
    {self._generate_remediation_table_html(report_data['remediation_roadmap'].get('short_term', []))}
    
    <h3>Mediano Plazo (1-3 meses)</h3>
    {self._generate_remediation_table_html(report_data['remediation_roadmap'].get('medium_term', []))}
    
    <h3>Largo Plazo (3+ meses)</h3>
    {self._generate_remediation_table_html(report_data['remediation_roadmap'].get('long_term', []))}
    
    <h2>Visualizations</h2>
    <div class="chart">
        <h3>Severity Distribution</h3>
        <p>Critical: {report_data['visualizations']['severity_distribution']['Critical']}</p>
        <p>High: {report_data['visualizations']['severity_distribution']['High']}</p>
        <p>Medium: {report_data['visualizations']['severity_distribution']['Medium']}</p>
        <p>Low: {report_data['visualizations']['severity_distribution']['Low']}</p>
        <p>Info: {report_data['visualizations']['severity_distribution']['Info']}</p>
    </div>
    
    <p><em>Informe generado el {report_data['generated_at']}</em></p>
</body>
</html>
"""
        return html
    
    def _generate_remediation_table_html(self, items: List[Dict[str, Any]]) -> str:
        """Generate HTML table for remediation items (from dict)"""
        if not items:
            return "<p>No hay elementos en esta categoría.</p>"
        
        html = "<table><tr><th>Hallazgo</th><th>Prioridad</th><th>Esfuerzo</th><th>Tiempo</th><th>Recomendación</th></tr>"
        for item in items[:10]:  # Limit to top 10
            finding_title = item.get('finding_title', '')[:50] + "..." if len(item.get('finding_title', '')) > 50 else item.get('finding_title', '')
            recommendation = item.get('recommendation', '')[:100] + "..." if len(item.get('recommendation', '')) > 100 else item.get('recommendation', '')
            html += f"""
            <tr>
                <td>{finding_title}</td>
                <td>{item.get('priority', 'N/A')}</td>
                <td>{item.get('effort', 'N/A')}</td>
                <td>{item.get('estimated_time', 'N/A')}</td>
                <td>{recommendation}</td>
            </tr>
            """
        html += "</table>"
        return html
    
    def _generate_remediation_table(self, items: List[RemediationItem]) -> str:
        """Generate HTML table for remediation items"""
        if not items:
            return "<p>No hay elementos en esta categoría.</p>"
        
        html = "<table><tr><th>Hallazgo</th><th>Prioridad</th><th>Esfuerzo</th><th>Tiempo</th><th>Recomendación</th></tr>"
        for item in items[:10]:  # Limit to top 10
            finding_title = item.finding_title[:50] + "..." if len(item.finding_title) > 50 else item.finding_title
            recommendation = item.recommendation[:100] + "..." if len(item.recommendation) > 100 else item.recommendation
            html += f"""
            <tr>
                <td>{finding_title}</td>
                <td>{item.priority}</td>
                <td>{item.effort}</td>
                <td>{item.estimated_time}</td>
                <td>{recommendation}</td>
            </tr>
            """
        html += "</table>"
        return html

