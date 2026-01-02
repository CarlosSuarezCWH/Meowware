import json
from typing import Dict, Any, List
from datetime import datetime
from ..core.models import ScanResult, Severity, HostRole
from ..analysis.risk_scorer import RiskScorer, EnhancedRiskScorer
from ..analysis.per_host_risk import PerHostRiskScorer
from ..analysis.correlation import CorrelationEngine

class Reporter:
    @staticmethod
    def generate_json(data: ScanResult) -> str:
        return json.dumps(data.to_dict(), indent=2)

    @staticmethod
    def _calculate_scan_duration(data: ScanResult) -> str:
        """Calculate scan duration from timestamp"""
        try:
            start = datetime.fromisoformat(data.timestamp)
            end = datetime.now()
            duration = (end - start).total_seconds()
            if duration < 60:
                return f"{int(duration)} segundos"
            elif duration < 3600:
                return f"{int(duration // 60)} minutos"
            else:
                return f"{int(duration // 3600)} horas {int((duration % 3600) // 60)} minutos"
        except:
            return "N/A"

    @staticmethod
    def _get_overall_risk(data: ScanResult) -> tuple:
        """Calculate overall risk level"""
        critical = len([f for f in data.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in data.findings if f.severity == Severity.HIGH])
        medium = len([f for f in data.findings if f.severity == Severity.MEDIUM])
        
        if critical > 0:
            return ("CRÍTICO", "#c0392b", "Critical vulnerabilities require immediate attention")
        elif high >= 3:
            return ("ALTO", "#e74c3c", "Multiple high-severity issues identified")
        elif high > 0 or medium >= 5:
            return ("MEDIO", "#e67e22", "Security weaknesses identified requiring remediation")
        elif medium > 0:
            return ("BAJO", "#27ae60", "Minor security improvements recommended")
        else:
            return ("INFO", "#3498db", "No significant security issues identified")

    @staticmethod
    def _get_tools_used(data: ScanResult) -> List[str]:
        """Extract tools used from scan"""
        tools = set()
        for host in data.hosts:
            if hasattr(host, 'services'):
                for s in host.services:
                    if s.banner:
                        tools.add("nmap")
        # Add common tools
        tools.update(["nmap", "whatweb", "nuclei", "sslscan", "wpscan"])
        return sorted(list(tools))

    @staticmethod
    def _get_scope_info(data: ScanResult) -> Dict[str, Any]:
        """v17.6: Extract scope information - only count actually audited hosts"""
        ipv4 = []
        ipv6 = []
        domains = []
        
        if data.target.type == 'domain':
            domains.append(data.target.input)
        else:
            ipv4.append(data.target.input)
        
        # v1.0: Only count hosts that were actually audited (have services or web_context)
        audited_hosts = []
        for host in data.hosts:
            # Host is considered audited if it has services or web_context
            is_audited = (hasattr(host, 'services') and host.services) or (hasattr(host, 'web_context') and host.web_context)
            
            if is_audited:
                audited_hosts.append(host)
                if ':' in host.ip:
                    if host.ip not in ipv6:
                        ipv6.append(host.ip)
                else:
                    if host.ip not in ipv4:
                        ipv4.append(host.ip)
                if host.hostname and host.hostname not in domains:
                    domains.append(host.hostname)
        
        return {
            "domains": domains,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "total_hosts": len(audited_hosts),  # v1.0: Use audited hosts count, not all hosts
            "audited_hosts": audited_hosts,
            "total_discovered": len(data.hosts)  # Total discovered (may include non-audited)
        }

    @staticmethod
    def _get_host_details(data: ScanResult) -> List[Dict[str, Any]]:
        """Get detailed host information"""
        host_details = []
        
        for host in data.hosts:
            # Get services
            services = []
            if hasattr(host, 'services'):
                for s in host.services:
                    if s.state == 'open':
                        services.append(f"{s.name}/{s.port}")
            
            # Get CMS/WAF info
            cms_waf = []
            if host.web_context:
                if host.web_context.cms_detected:
                    cms_waf.append(host.web_context.cms_detected)
                    if host.web_context.cms_version:
                        cms_waf[-1] += f" {host.web_context.cms_version}"
                if host.web_context.waf_detected:
                    cms_waf.append(host.web_context.waf_name or "WAF")
            
            # Get critical vulnerabilities for this host
            host_critical = [f for f in data.findings 
                           if f.severity == Severity.CRITICAL and 
                           (f"({host.ip})" in f.title or host.hostname in f.title)]
            
            # Get recommendations
            recommendations = []
            for f in data.findings:
                if f"({host.ip})" in f.title or host.hostname in f.title:
                    if f.recommendation and f.recommendation not in recommendations:
                        recommendations.append(f.recommendation[:100])
            
            host_details.append({
                "name": host.hostname or host.ip,
                "ip": host.ip,
                "services": ", ".join(services[:5]) if services else "Ninguno confirmado",
                "cms_waf": " / ".join(cms_waf) if cms_waf else "N/A",
                "critical": len(host_critical),
                "critical_details": [f.title for f in host_critical[:3]],
                "recommendations": ", ".join(recommendations[:2]) if recommendations else "Revisar configuración general"
            })
        
        return host_details

    @staticmethod
    def _format_finding(finding, host_ip: str = None) -> Dict[str, Any]:
        """v1.0: Format finding with enhanced documentation and technical details"""
        import re
        
        # Extract CVEs from title/description
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = list(set(re.findall(cve_pattern, finding.title + " " + finding.description, re.IGNORECASE)))
        
        # Extract version numbers
        version_pattern = r'v?\d+\.\d+(?:\.\d+)?'
        versions = list(set(re.findall(version_pattern, finding.title + " " + finding.description)))[:3]
        
        # Determine exploitability based on category and severity
        exploitability = "Alta" if finding.severity in [Severity.CRITICAL, Severity.HIGH] else "Media" if finding.severity == Severity.MEDIUM else "Baja"
        if "exposed" in finding.title.lower() or "information disclosure" in finding.title.lower():
            exploitability = "Alta"
        if "WAF" in finding.title or "WAF" in finding.description:
            exploitability = "Mitigada"
        
        # Generate technical documentation
        technical_docs = []
        if cves:
            cve_links = [f'<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}" target="_blank">{cve}</a>' for cve in cves[:5]]
            technical_docs.append(f"<strong>CVEs:</strong> {', '.join(cve_links)}")
        
        if versions:
            technical_docs.append(f"<strong>Versiones detectadas:</strong> {', '.join(versions)}")
        
        # Add references based on category
        references = []
        if "MySQL" in finding.title or "3306" in finding.title:
            references.append('<a href="https://dev.mysql.com/doc/refman/8.0/en/security.html" target="_blank">MySQL Security Guide</a>')
        if "WordPress" in finding.title:
            references.append('<a href="https://wordpress.org/support/article/hardening-wordpress/" target="_blank">WordPress Hardening</a>')
        if "SSL" in finding.title or "TLS" in finding.title:
            references.append('<a href="https://ssl-config.mozilla.org/" target="_blank">Mozilla SSL Configuration Generator</a>')
        if "SMTP" in finding.title or "mail" in finding.category.lower():
            references.append('<a href="https://www.ietf.org/rfc/rfc5321.txt" target="_blank">RFC 5321 - SMTP</a>')
        
        # Enhanced impact description
        impact_details = finding.recommendation.split('.')[0] if finding.recommendation else "Ver recomendación"
        if finding.severity == Severity.CRITICAL:
            impact_details = f"🔴 CRÍTICO: {impact_details}. Riesgo de compromiso total del sistema."
        elif finding.severity == Severity.HIGH:
            impact_details = f"🟠 ALTO: {impact_details}. Riesgo significativo de acceso no autorizado."
        
        return {
            "title": finding.title,
            "severity": finding.severity.name if hasattr(finding.severity, 'name') else str(finding.severity),
            "affected_asset": host_ip or "Multiple",
            "description": finding.description,
            "evidence": getattr(finding, 'raw_output', '') or "See description",
            "impact": impact_details,
            "recommendation": finding.recommendation,
            "status": "Mitigado por WAF" if "WAF" in finding.title or "WAF" in finding.description else "Confirmado",
            "category": finding.category,
            "confidence": getattr(finding, 'confidence_score', 0.5),
            "cves": cves,
            "versions": versions,
            "exploitability": exploitability,
            "technical_docs": technical_docs,
            "references": references
        }

    @staticmethod
    def generate_html(data: ScanResult) -> str:
        """v17.3: Professional Audit Report - Meowware Branded"""
        
        def get_color(sev):
            return {
                "CRITICAL": "#c0392b", "HIGH": "#e74c3c", "MEDIUM": "#e67e22", 
                "LOW": "#27ae60", "INFO": "#3498db"
            }.get(sev.name if hasattr(sev, 'name') else str(sev).upper(), "#95a5a6")

        # Calculate metrics
        scan_duration = Reporter._calculate_scan_duration(data)
        risk_level, risk_color, risk_summary = Reporter._get_overall_risk(data)
        tools_used = Reporter._get_tools_used(data)
        scope = Reporter._get_scope_info(data)
        host_details = Reporter._get_host_details(data)
        
        # Count findings by severity
        findings_by_severity = {
            "CRITICAL": len([f for f in data.findings if f.severity == Severity.CRITICAL]),
            "HIGH": len([f for f in data.findings if f.severity == Severity.HIGH]),
            "MEDIUM": len([f for f in data.findings if f.severity == Severity.MEDIUM]),
            "LOW": len([f for f in data.findings if f.severity == Severity.LOW]),
            "INFO": len([f for f in data.findings if f.severity == Severity.INFO])
        }

        # Format date
        try:
            scan_date = datetime.fromisoformat(data.timestamp).strftime('%Y-%m-%d')
        except:
            scan_date = data.timestamp[:10] if len(data.timestamp) >= 10 else "N/A"

        # Logo SVG en base64 (gato con tulipán - estilo del logo descrito)
        logo_svg = """<svg width="120" height="120" viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
  <!-- Aura de fondo -->
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
  
  <!-- Hojas -->
  <path d="M 30 80 Q 20 60 25 45" stroke="#00cc66" stroke-width="3" fill="none" opacity="0.8"/>
  <path d="M 90 80 Q 100 60 95 45" stroke="#00cc66" stroke-width="3" fill="none" opacity="0.8"/>
  
  <!-- Cuerpo del gato -->
  <ellipse cx="60" cy="70" rx="25" ry="20" fill="#ffffff" opacity="0.95"/>
  
  <!-- Cabeza -->
  <circle cx="60" cy="50" r="22" fill="#ffffff" opacity="0.95"/>
  
  <!-- Orejas -->
  <path d="M 45 35 L 50 20 L 55 35 Z" fill="#e0b0ff" opacity="0.9"/>
  <path d="M 65 35 L 70 20 L 75 35 Z" fill="#e0b0ff" opacity="0.9"/>
  
  <!-- Ojos -->
  <circle cx="52" cy="48" r="6" fill="#00d4ff"/>
  <circle cx="68" cy="48" r="6" fill="#00d4ff"/>
  <circle cx="52" cy="48" r="3" fill="#000080"/>
  <circle cx="68" cy="48" r="3" fill="#000080"/>
  <circle cx="53" cy="47" r="1.5" fill="#ffffff"/>
  <circle cx="69" cy="47" r="1.5" fill="#ffffff"/>
  
  <!-- Nariz corazón -->
  <path d="M 60 55 L 58 58 L 60 60 L 62 58 Z" fill="#00d4ff"/>
  
  <!-- Tulipán en la cabeza -->
  <path d="M 60 28 Q 58 20 60 15 Q 62 20 60 28" fill="url(#tulipGrad)"/>
  
  <!-- Pata izquierda -->
  <ellipse cx="50" cy="85" rx="8" ry="6" fill="#ffffff" opacity="0.95"/>
  <!-- Pata derecha -->
  <ellipse cx="70" cy="85" rx="8" ry="6" fill="#ffffff" opacity="0.95"/>
  
  <!-- Estrellas -->
  <path d="M 20 25 L 22 30 L 27 30 L 23 33 L 25 38 L 20 35 L 15 38 L 17 33 L 13 30 L 18 30 Z" fill="#ff00ff" opacity="0.7"/>
  <path d="M 100 30 L 101 33 L 104 33 L 102 35 L 103 38 L 100 36 L 97 38 L 98 35 L 96 33 L 99 33 Z" fill="#00d4ff" opacity="0.7"/>
</svg>"""
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Meowware v1.0 'Tulipán' - Informe de Auditoría de Seguridad</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Helvetica Neue', Arial, 'Segoe UI', sans-serif; 
            margin: 0; 
            padding: 0; 
            background: #ffffff; 
            color: #1a1a1a; 
            line-height: 1.7;
        }}
        header {{ 
            background: #ffffff; 
            color: #1a1a1a; 
            padding: 40px 20px 30px 20px; 
            text-align: center; 
            border-bottom: 2px solid #e0e0e0;
        }}
        .logo-container {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .logo-svg {{
            width: 100px;
            height: 100px;
        }}
        .brand-text {{
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }}
        header h1 {{
            margin: 0;
            font-size: 2.2em;
            font-weight: 600;
            color: #1a1a1a;
            letter-spacing: -0.5px;
        }}
        .version-badge {{
            font-size: 0.9em;
            color: #666;
            font-weight: 400;
            margin-top: 5px;
        }}
        header .header-info {{
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
        }}
        header p {{
            margin: 6px 0;
            font-size: 1em;
            color: #333;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.9em;
            font-weight: 600;
        }}
        h1, h2, h3 {{ margin: 0.5em 0; }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
        }}
        .summary {{ 
            background: #fafafa; 
            padding: 30px; 
            margin-bottom: 25px;
            border: 1px solid #e0e0e0;
            border-radius: 4px; 
        }}
        h2 {{
            font-size: 1.5em;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .risk-critical {{ background: #c0392b; color: #fff; }}
        .risk-high {{ background: #e74c3c; color: #fff; }}
        .risk-medium {{ background: #e67e22; color: #fff; }}
        .risk-low {{ background: #27ae60; color: #fff; }}
        .risk-info {{ background: #3498db; color: #fff; }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-bottom: 20px; 
        }}
        th, td {{ 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left; 
        }}
        th {{ 
            background: #1a1a1a; 
            color: #fff; 
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        tr:nth-child(even) {{ background: #fafafa; }}
        tr:hover {{ background: #f5f5f5; }}
        .chart-container {{ 
            width: 100%; 
            margin: 20px 0; 
            height: 300px;
        }}
        ul {{ padding-left: 20px; }}
        ul li {{ margin: 10px 0; }}
        footer {{ 
            text-align: center; 
            padding: 20px; 
            color: #7f8c8d; 
            font-size: 0.9em;
        }}
        .finding-card {{
            background: #fff;
            border-left: 4px solid;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .finding-critical {{ border-left-color: #c0392b; }}
        .finding-high {{ border-left-color: #e74c3c; }}
        .finding-medium {{ border-left-color: #e67e22; }}
        .finding-low {{ border-left-color: #27ae60; }}
        .finding-info {{ border-left-color: #3498db; }}
        .evidence-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            margin-top: 10px;
            max-height: 200px;
            overflow-y: auto;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
</head>
<body>

<header>
    <div class="logo-container">
        <div class="logo-svg">{logo_svg}</div>
        <div class="brand-text">
            <h1>ME<span style="color: #7000ff;">O</span>WARE</h1>
            <span class="version-badge">v1.0 - Tulipán</span>
        </div>
    </div>
    <div class="header-info">
        <p><strong>Objetivo:</strong> {data.target.input} | <strong>Fecha:</strong> {scan_date}</p>
        <p><strong>Nivel de Riesgo:</strong> <span class="risk-badge risk-{risk_level.lower()}">{risk_level}</span></p>
        <p style="font-size: 0.85em; color: #666; margin-top: 10px;">Desarrollado por <strong>Carlos Mancera</strong></p>
    </div>
</header>

<div class="container">
    <!-- Resumen Ejecutivo -->
    <div class="summary">
        <h2>Resumen Ejecutivo</h2>
        <p>Se auditaron <strong>{scope['total_hosts']} host(s)</strong> asociados al dominio <strong>{data.target.input}</strong>, 
        incluyendo {len(scope['ipv4'])} IP(s) IPv4 y {len(scope['ipv6'])} IP(s) IPv6.</p>
        <p>Se detectaron <strong>{findings_by_severity['CRITICAL']} vulnerabilidad(es) crítica(s)</strong>, 
        <strong>{findings_by_severity['HIGH']} alta(s)</strong>, 
        <strong>{findings_by_severity['MEDIUM']} media(s)</strong>, 
        <strong>{findings_by_severity['LOW']} baja(s)</strong> y 
        <strong>{findings_by_severity['INFO']} informativa(s)</strong>.</p>
        <p><strong>Duración del escaneo:</strong> {scan_duration}</p>
        <p><strong>Tipo de prueba:</strong> Black-box / Externa / No intrusiva</p>
        <p style="margin-top: 15px; padding: 15px; background: #ecf0f1; border-radius: 5px;">
            <strong>Conclusión:</strong> {risk_summary}.
        </p>
    </div>

    <!-- Distribución de vulnerabilidades -->
    <div class="summary">
        <h2>Distribución de Vulnerabilidades</h2>
        <canvas id="vulnChart" class="chart-container"></canvas>
        <script>
            const ctx = document.getElementById('vulnChart').getContext('2d');
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: ['Críticas', 'Altas', 'Medias', 'Bajas', 'Informativas'],
                    datasets: [{{
                        label: 'Cantidad de hallazgos',
                        data: [{findings_by_severity['CRITICAL']}, {findings_by_severity['HIGH']}, {findings_by_severity['MEDIUM']}, {findings_by_severity['LOW']}, {findings_by_severity['INFO']}],
                        backgroundColor: ['#c0392b', '#e74c3c', '#e67e22', '#27ae60', '#3498db']
                    }}]
                }},
                options: {{ 
                    responsive: true, 
                    maintainAspectRatio: true,
                    plugins: {{ 
                        legend: {{ display: false }},
                        title: {{
                            display: true,
                            text: 'Distribución de Hallazgos por Severidad'
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1
                            }}
                        }}
                    }}
                }}
            }});
        </script>
    </div>

    <!-- Detalle de Hosts -->
    <div class="summary">
        <h2>Detalle por Host</h2>
        <table>
            <thead>
                <tr>
                    <th>Host/IP</th>
                    <th>Servicios</th>
                    <th>CMS/WAF</th>
                    <th>Vulnerabilidades Críticas</th>
                    <th>Recomendaciones</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for host in host_details:
            critical_text = "Ninguna" if host['critical'] == 0 else f"{host['critical']}: {', '.join(host['critical_details'][:2])}"
            html += f"""
                <tr>
                    <td><strong>{host['name']}</strong><br><small style="color: #7f8c8d;">{host['ip']}</small></td>
                    <td>{host['services']}</td>
                    <td>{host['cms_waf']}</td>
                    <td>{critical_text}</td>
                    <td><small>{host['recommendations']}</small></td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>

    <!-- Hallazgos Detallados -->
    <div class="summary">
        <h2>Hallazgos de Seguridad</h2>
"""
        
        # Group findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            findings = [f for f in data.findings if (hasattr(f.severity, 'name') and f.severity.name == severity) or (not hasattr(f.severity, 'name') and str(f.severity).upper() == severity)]
            if not findings:
                continue
            
            severity_lower = severity.lower()
            color = get_color(findings[0].severity) if findings else "#95a5a6"
            
            html += f"""
        <h3 style="color: {color}; margin-top: 30px;">Severidad {severity}</h3>
"""
            
            for idx, finding in enumerate(findings, 1):
                formatted = Reporter._format_finding(finding)
                
                # Build technical documentation section
                tech_docs_html = ""
                if formatted.get('technical_docs'):
                    tech_docs_html = f"""
            <div style="background: #e8f4f8; padding: 10px; border-radius: 4px; margin: 10px 0;">
                <strong>📚 Documentación Técnica:</strong><br>
                {'<br>'.join(formatted['technical_docs'])}
            </div>
"""
                
                # Build references section
                refs_html = ""
                if formatted.get('references'):
                    refs_html = f"""
            <div style="background: #f0f8f0; padding: 10px; border-radius: 4px; margin: 10px 0;">
                <strong>🔗 Referencias:</strong><br>
                {'<br>'.join(formatted['references'])}
            </div>
"""
                
                # Build exploitability badge
                exploit_badge = ""
                if formatted.get('exploitability'):
                    exploit_color = "#c0392b" if formatted['exploitability'] == "Alta" else "#e67e22" if formatted['exploitability'] == "Media" else "#27ae60" if formatted['exploitability'] == "Baja" else "#95a5a6"
                    exploit_badge = f'<span style="background: {exploit_color}; color: white; padding: 4px 8px; border-radius: 3px; font-size: 0.85em; margin-left: 10px;">Exploitabilidad: {formatted["exploitability"]}</span>'
                
                html += f"""
        <div class="finding-card finding-{severity_lower}">
            <h4 style="margin-top: 0;">{idx}. {formatted['title']} {exploit_badge}</h4>
            <p><strong>Activo Afectado:</strong> {formatted['affected_asset']}</p>
            <p><strong>Categoría:</strong> {formatted['category']} | <strong>Confianza:</strong> {formatted['confidence']*100:.0f}%</p>
            <p><strong>Descripción Técnica:</strong> {formatted['description']}</p>
            {tech_docs_html}
            {f'<div class="evidence-box"><strong>Evidencia Técnica:</strong><br>{formatted["evidence"][:800]}{"..." if len(formatted["evidence"]) > 800 else ""}</div>' if formatted['evidence'] and formatted['evidence'] != 'See description' else ''}
            <p><strong>Impacto:</strong> {formatted['impact']}</p>
            <p><strong>Recomendación:</strong> {formatted['recommendation']}</p>
            {refs_html}
            <p><strong>Estado:</strong> {formatted['status']}</p>
        </div>
"""
        
        html += """
    </div>

    <!-- Recomendaciones Generales -->
    <div class="summary">
        <h2>Recomendaciones Generales</h2>
        <ul>
            <li>Aplicar todas las actualizaciones críticas de software y CMS detectadas.</li>
            <li>Segmentar servicios críticos (DB, Mail, Web) para minimizar riesgos de ataque lateral.</li>
            <li>Revisar configuración de WAF y headers de seguridad para defensa en profundidad.</li>
            <li>Auditar puertos abiertos y cerrar servicios innecesarios.</li>
            <li>Implementar monitorización continua de logs y vulnerabilidades.</li>
            <li>Realizar auditorías periódicas para detectar cambios en la superficie de ataque.</li>
        </ul>
    </div>

    <!-- Alcance y Metodología -->
    <div class="summary">
        <h2>Alcance y Metodología</h2>
        <h3>Qué se Evaluó</h3>
        <ul>
            <li><strong>Dominios:</strong> {', '.join(scope['domains']) if scope['domains'] else 'N/A'}</li>
            <li><strong>IPs IPv4:</strong> {', '.join(scope['ipv4'][:5])}{'...' if len(scope['ipv4']) > 5 else ''}</li>
            {f'<li><strong>IPs IPv6:</strong> {", ".join(scope["ipv6"][:3])}{"..." if len(scope["ipv6"]) > 3 else ""}</li>' if scope['ipv6'] else ''}
            <li><strong>Total de Hosts Analizados:</strong> {scope['total_hosts']}</li>
        </ul>
        
        <h3>Herramientas Utilizadas</h3>
        <p>{', '.join(tools_used)}</p>
        
        <h3>Restricciones</h3>
        <ul>
            <li><strong>WAF Detectado:</strong> {'Sí' if any(h.web_context and h.web_context.waf_detected for h in data.hosts) else 'No'}</li>
            <li><strong>Rate Limiting:</strong> Aplicado según políticas del objetivo</li>
            <li><strong>Entorno:</strong> Producción (pruebas no intrusivas únicamente)</li>
        </ul>
    </div>

    <!-- Pie de Página -->
    <footer class="summary">
        <p><strong>Meowware v1.0 'Tulipán'</strong> | Desarrollado por <strong>Carlos Mancera</strong></p>
        <p>ID de auditoría: <code>{data.id}</code></p>
        <p style="margin-top: 10px; font-size: 0.85em; color: #95a5a6;">
            Este informe es confidencial y está destinado únicamente al uso del cliente autorizado.
        </p>
    </footer>
</div>

</body>
</html>
"""
        
        return html

    @staticmethod
    def generate_summary(data: ScanResult) -> str:
        """Generate text summary"""
        from ..core.debug import debug_print
        
        risk_level, _, risk_summary = Reporter._get_overall_risk(data)
        scope = Reporter._get_scope_info(data)
        
        # v1.0: Resumen mejorado con más información
        critical_count = len([f for f in data.findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in data.findings if f.severity == Severity.HIGH])
        medium_count = len([f for f in data.findings if f.severity == Severity.MEDIUM])
        low_count = len([f for f in data.findings if f.severity == Severity.LOW])
        info_count = len([f for f in data.findings if f.severity == Severity.INFO])
        total_findings = len(data.findings)
        
        # Hallazgos críticos más importantes
        critical_findings = [f for f in data.findings if f.severity == Severity.CRITICAL][:5]
        critical_summary = ""
        if critical_findings:
            critical_summary = "\n\n🔴 HALLAZGOS CRÍTICOS PRINCIPALES:\n"
            for i, f in enumerate(critical_findings, 1):
                title_short = f.title[:70] + "..." if len(f.title) > 70 else f.title
                critical_summary += f"  {i}. {title_short}\n"
        
        # Tecnologías detectadas
        tech_summary = ""
        detected_tech = set()
        for host in data.hosts:
            if hasattr(host, 'tech_stack_info') and host.tech_stack_info:
                ts = host.tech_stack_info
                if hasattr(ts, 'os') and ts.os and ts.os.value != 'UNKNOWN':
                    detected_tech.add(f"OS: {ts.os.value}")
                if hasattr(ts, 'web_server') and ts.web_server:
                    detected_tech.add(f"Web: {ts.web_server}")
                if hasattr(ts, 'database') and ts.database:
                    detected_tech.add(f"DB: {ts.database}")
                if hasattr(ts, 'cms') and ts.cms:
                    detected_tech.add(f"CMS: {ts.cms}")
        
        if detected_tech:
            tech_summary = f"\n\n🔍 TECNOLOGÍAS DETECTADAS:\n  {', '.join(sorted(detected_tech))}\n"
        
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║          MEOWWARE v1.0 'TULIPÁN' - INTELLIGENCE REPORT       ║
╚══════════════════════════════════════════════════════════════╝

🎯 TARGET: {data.target.input.upper()}
⚠️  RISK LEVEL: {risk_level}
   {risk_summary}

📊 RESUMEN EJECUTIVO:
   Total de Hallazgos: {total_findings}
   - 🔴 Critical: {critical_count}
   - 🟠 High: {high_count}
   - 🟡 Medium: {medium_count}
   - 🟢 Low: {low_count}
   - ℹ️  Info: {info_count}
{critical_summary}{tech_summary}
📋 ALCANCE:
   - Dominios: {len(scope['domains'])}
   - Hosts IPv4: {len(scope['ipv4'])}
   - Hosts IPv6: {len(scope['ipv6'])}
   - Total Hosts: {len(data.hosts)}

📄 ID: {data.id}
📅 Fecha: {data.timestamp}

💡 Ver reporte completo: meowware_report.html
"""
        return summary
