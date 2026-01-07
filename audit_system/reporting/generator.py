import json
from typing import Dict, Any, List
from datetime import datetime
from ..core.models import ScanResult, Severity, HostRole
from ..analysis.risk_scorer import RiskScorer, EnhancedRiskScorer
from ..analysis.per_host_risk import PerHostRiskScorer
from ..analysis.correlation import CorrelationEngine
from .simple_explainer import SimpleExplainer

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
        """v19.0: Format finding with enhanced documentation and structured data parsing"""
        import re
        import json
        
        # v19.0: Try to parse structured data from raw_output
        structured_data = None
        if finding.raw_output:
            try:
                structured_data = json.loads(finding.raw_output)
            except (json.JSONDecodeError, TypeError):
                structured_data = None
        
        # Extract CVEs from title/description
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = list(set(re.findall(cve_pattern, finding.title + " " + finding.description, re.IGNORECASE)))
        
        # Extract version numbers
        version_pattern = r'v?\d+\.\d+(?:\.\d+)?'
        versions = list(set(re.findall(version_pattern, finding.title + " " + finding.description)))[:3]
        
        # v19.0: Extract structured information if available
        if structured_data:
            # Extract users if present
            if 'user_list' in structured_data or 'users' in structured_data:
                users = structured_data.get('user_list', structured_data.get('users', []))
                if users and isinstance(users, list):
                    finding.description += f"\n\n**Lista Completa de Usuarios ({len(users)}):**\n" + "\n".join([f"- {u}" for u in users[:30]])
            
            # Extract plugins if present
            if 'plugin_list' in structured_data or 'plugins' in structured_data:
                plugins = structured_data.get('plugin_list', structured_data.get('plugins', []))
                if plugins and isinstance(plugins, list):
                    finding.description += f"\n\n**Lista Completa de Plugins ({len(plugins)}):**\n" + "\n".join([f"- {p}" for p in plugins[:30]])
            
            # Extract components if present
            if 'components' in structured_data:
                components = structured_data.get('components', [])
                if components and isinstance(components, list):
                    comp_list = "\n".join([f"- {c.get('name', c) if isinstance(c, dict) else c}" for c in components[:30]])
                    finding.description += f"\n\n**Componentes Detectados ({len(components)}):**\n{comp_list}"
            
            # Extract modules if present
            if 'modules' in structured_data:
                modules = structured_data.get('modules', [])
                if modules and isinstance(modules, list):
                    finding.description += f"\n\n**Módulos Detectados ({len(modules)}):**\n" + "\n".join([f"- {m}" for m in modules[:30]])
        
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
        
        # v19.0: Enhanced impact description with simple explanations
        impact_details = finding.recommendation.split('.')[0] if finding.recommendation else "Ver recomendación"
        if finding.severity == Severity.CRITICAL:
            impact_details = f"🔴 CRÍTICO: {impact_details}. Riesgo de compromiso total del sistema."
        elif finding.severity == Severity.HIGH:
            impact_details = f"🟠 ALTO: {impact_details}. Riesgo significativo de acceso no autorizado."
        
        # v19.0: PoC and Reproduction Steps
        reproduction_steps = ""
        poc_payload = ""
        if finding.raw_output and "[PoC Payload]" in finding.raw_output:
            try:
                poc_payload = finding.raw_output.split("[PoC Payload]")[1].split("\n\n")[0].strip()
                reproduction_steps = f"""
                <div class="reproduction-block" style="background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; margin-top: 10px; font-family: monospace;">
                    <strong style="color: #e74c3c;">[Proof of Concept]</strong><br>
                    <pre style="white-space: pre-wrap; word-wrap: break-word;">{poc_payload}</pre>
                </div>
                """
            except: pass

        # v19.0: Get simple explanation for non-technical users
        simple_info = SimpleExplainer.format_finding_for_non_tech(
            finding.title, finding.description, finding.severity, finding.recommendation
        )
        
        return {
            "title": finding.title,
            "title_simple": simple_info["title_simple"],
            "severity": finding.severity.name if hasattr(finding.severity, 'name') else str(finding.severity),
            "severity_simple": simple_info["severity_info"]["simple"],
            "severity_explanation": simple_info["severity_info"]["explanation"],
            "severity_analogy": simple_info["severity_info"].get("analogy", ""),
            "affected_asset": host_ip or "Multiple",
            "description": finding.description,
            "description_simple": simple_info["description_simple"],
            "what_this_means": simple_info["what_this_means"],
            "why_it_matters": simple_info["why_it_matters"],
            "when_to_fix": simple_info["when_to_fix"],
            "explained_terms": simple_info["explained_terms"],
            "evidence": getattr(finding, 'raw_output', '') or "See description",
            "reproduction_steps": reproduction_steps,  # New field
            "impact": impact_details,
            "recommendation": finding.recommendation,
            "recommendation_simple": simple_info["recommendation_simple"],
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
    def _get_anomalies_and_patterns(data: ScanResult) -> List[Dict[str, Any]]:
        """Extract anomalies and suspicious patterns from findings"""
        anomalies = []
        for finding in data.findings:
            if "Anomaly" in finding.title or "Anomaly" in finding.category:
                anomalies.append({
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.name if hasattr(finding.severity, 'name') else str(finding.severity),
                    "evidence": getattr(finding, 'raw_output', ''),
                    "recommendation": finding.recommendation
                })
        return anomalies
    
    @staticmethod
    def _get_technology_analysis(data: ScanResult) -> Dict[str, Any]:
        """Extract technology stack and architecture information"""
        tech_info = {
            "os": [],
            "cms": [],
            "databases": [],
            "web_servers": [],
            "frameworks": [],
            "waf": [],
            "exposed_services": [],
            "segmentation_issues": [],
            "all_versions": {}  # Store all detected versions
        }
        
        for host in data.hosts:
            # OS detection
            if hasattr(host, 'tech_stack_info') and host.tech_stack_info:
                ts = host.tech_stack_info
                if hasattr(ts, 'os') and ts.os and ts.os.value != 'UNKNOWN':
                    os_str = ts.os.value
                    if os_str not in tech_info["os"]:
                        tech_info["os"].append(os_str)
            
            # Web context - CMS, versions, web servers
            if host.web_context:
                # CMS detection
                if host.web_context.cms_detected:
                    cms_str = host.web_context.cms_detected
                    if host.web_context.cms_version:
                        cms_str += f" {host.web_context.cms_version}"
                        tech_info["all_versions"][host.web_context.cms_detected] = host.web_context.cms_version
                    if cms_str not in tech_info["cms"]:
                        tech_info["cms"].append(cms_str)
                
                # WAF
                if host.web_context.waf_detected:
                    waf_str = host.web_context.waf_name or "WAF"
                    if waf_str not in tech_info["waf"]:
                        tech_info["waf"].append(waf_str)
                
                # Tech versions (web servers, frameworks, etc.)
                if hasattr(host.web_context, 'tech_versions') and host.web_context.tech_versions:
                    for tech_name, version in host.web_context.tech_versions.items():
                        tech_info["all_versions"][tech_name] = version
                        
                        # Categorize technologies
                        tech_lower = tech_name.lower()
                        if any(x in tech_lower for x in ['apache', 'nginx', 'iis', 'lighttpd', 'caddy']):
                            web_str = f"{tech_name} {version}" if version else tech_name
                            if web_str not in tech_info["web_servers"]:
                                tech_info["web_servers"].append(web_str)
                        elif any(x in tech_lower for x in ['php', 'python', 'ruby', 'node', 'java', 'asp.net']):
                            framework_str = f"{tech_name} {version}" if version else tech_name
                            if framework_str not in tech_info["frameworks"]:
                                tech_info["frameworks"].append(framework_str)
            
            # Services and segmentation
            if hasattr(host, 'services'):
                db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis', 1433: 'MSSQL'}
                web_ports = [80, 443, 8080, 8443]
                has_db = False
                has_web = False
                
                for s in host.services:
                    if s.state == 'open':
                        # Database detection
                        if s.port in db_ports:
                            has_db = True
                            db_name = db_ports[s.port]
                            version_str = f" {s.version}" if s.version else ""
                            db_str = f"{db_name}{version_str} (puerto {s.port})"
                            if db_str not in tech_info["databases"]:
                                tech_info["databases"].append(db_str)
                            if s.version:
                                tech_info["all_versions"][db_name] = s.version
                            
                            tech_info["exposed_services"].append(f"{host.ip}:{s.port} ({db_name})")
                        
                        # Web ports
                        elif s.port in web_ports:
                            has_web = True
                        
                        # Insecure protocols
                        elif s.port in [21, 23, 3389]:
                            protocol_name = {21: 'FTP', 23: 'Telnet', 3389: 'RDP'}.get(s.port, 'Unknown')
                            tech_info["exposed_services"].append(f"{host.ip}:{s.port} ({protocol_name})")
                
                # Segmentation issues
                if has_db and has_web:
                    tech_info["segmentation_issues"].append({
                        "host": host.hostname or host.ip,
                        "issue": "Database and web services on same host - poor segmentation"
                    })
        
        return tech_info
    
    @staticmethod
    def _get_risk_evaluation(data: ScanResult) -> Dict[str, Any]:
        """Calculate comprehensive risk evaluation"""
        risk_eval = EnhancedRiskScorer.calculate_comprehensive_risk(
            data.findings, data.hosts
        )
        
        # Per-host risk
        host_risks = []
        for host in data.hosts:
            host_findings = [f for f in data.findings if f"({host.ip})" in f.title or (host.hostname and host.hostname in f.title)]
            if host_findings:
                host_risk = PerHostRiskScorer.calculate_host_risk(host, host_findings)
                host_risks.append(host_risk)
        
        return {
            "global": risk_eval,
            "per_host": host_risks
        }
    
    @staticmethod
    def _get_remediation_priorities(data: ScanResult) -> List[Dict[str, Any]]:
        """Generate prioritized remediation list"""
        priorities = []
        
        # Critical findings - immediate action
        critical = [f for f in data.findings if f.severity == Severity.CRITICAL]
        for f in critical:
            priorities.append({
                "priority": "INMEDIATO (0-24 horas)",
                "severity": "CRITICAL",
                "title": f.title,
                "action": f.recommendation.split('.')[0] if f.recommendation else "Revisar y corregir",
                "impact": "Riesgo de compromiso total del sistema"
            })
        
        # High findings - urgent
        high = [f for f in data.findings if f.severity == Severity.HIGH][:5]
        for f in high:
            priorities.append({
                "priority": "URGENTE (1-7 días)",
                "severity": "HIGH",
                "title": f.title,
                "action": f.recommendation.split('.')[0] if f.recommendation else "Revisar y corregir",
                "impact": "Riesgo significativo de acceso no autorizado"
            })
        
        return priorities
    
    @staticmethod
    def generate_html(data: ScanResult) -> str:
        """v19.0: Professional Audit Report with Complete Structure - Meowware Branded"""
        
        def get_color(sev):
            return {
                "CRITICAL": "#c0392b", "HIGH": "#e74c3c", "MEDIUM": "#e67e22", 
                "LOW": "#27ae60", "INFO": "#3498db"
            }.get(sev.name if hasattr(sev, 'name') else str(sev).upper(), "#95a5a6")

        def get_status_style(status_val):
            status = str(status_val).upper()
            if "CONFIRMED" in status: return "background: #c0392b; color: white;" # Red
            if "LIKELY" in status: return "background: #e67e22; color: white;" # Orange
            if "ARCHITECTURAL" in status: return "background: #8e44ad; color: white;" # Purple
            if "CONFIGURATION" in status: return "background: #f39c12; color: white;" # Yellow
            if "POTENTIAL" in status: return "background: #3498db; color: white;" # Blue
            if "MITIGADO" in status: return "background: #27ae60; color: white;" # Green
            return "background: #95a5a6; color: white;" # Grey


        # Calculate metrics
        scan_duration = Reporter._calculate_scan_duration(data)
        risk_level, risk_color, risk_summary = Reporter._get_overall_risk(data)
        tools_used = Reporter._get_tools_used(data)
        scope = Reporter._get_scope_info(data)
        host_details = Reporter._get_host_details(data)
        
        # v19.0: Get additional data for new sections
        anomalies = Reporter._get_anomalies_and_patterns(data)
        tech_analysis = Reporter._get_technology_analysis(data)
        risk_evaluation = Reporter._get_risk_evaluation(data)
        remediation_priorities = Reporter._get_remediation_priorities(data)
        
        # Get top critical findings for executive summary
        top_critical = [f for f in data.findings if f.severity == Severity.CRITICAL][:5]
        
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

        # v19.0: Load logo from meo.png file
        import os
        import base64
        logo_img_tag = ""
        
        # Try multiple possible paths for the logo
        possible_paths = [
            "meo.png",  # Current directory
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "meo.png"),  # Project root
            os.path.join(os.getcwd(), "meo.png"),  # Working directory
        ]
        
        logo_path = None
        for path in possible_paths:
            if os.path.exists(path):
                logo_path = path
                break
        
        # Try to load logo and convert to base64
        if logo_path:
            try:
                with open(logo_path, "rb") as img_file:
                    img_data = img_file.read()
                    logo_base64 = base64.b64encode(img_data).decode('utf-8')
                    # Detect image type from file extension
                    if logo_path.lower().endswith('.png'):
                        logo_mime = 'image/png'
                    elif logo_path.lower().endswith('.jpg') or logo_path.lower().endswith('.jpeg'):
                        logo_mime = 'image/jpeg'
                    elif logo_path.lower().endswith('.svg'):
                        logo_mime = 'image/svg+xml'
                    else:
                        logo_mime = 'image/png'  # Default
                    logo_img_tag = f'<img src="data:{logo_mime};base64,{logo_base64}" alt="Meowware Logo" style="max-width: 120px; max-height: 120px; width: auto; height: auto;">'
            except Exception as e:
                # Fallback to text if image can't be loaded
                logo_img_tag = '<div style="width: 120px; height: 120px; background: linear-gradient(135deg, #7000ff 0%, #00d4ff 100%); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2em; color: white; font-weight: bold;">MEO</div>'
        else:
            # Fallback if logo file doesn't exist
            logo_img_tag = '<div style="width: 120px; height: 120px; background: linear-gradient(135deg, #7000ff 0%, #00d4ff 100%); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2em; color: white; font-weight: bold;">MEO</div>'
        
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
            width: 120px;
            height: 120px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .logo-svg img {{
            max-width: 100%;
            max-height: 100%;
            width: auto;
            height: auto;
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
        <div class="logo-svg">{logo_img_tag}</div>
        <div class="brand-text">
            <h1>ME<span style="color: #7000ff;">O</span>WARE</h1>
            <span class="version-badge">v1.0 - Tulipán</span>
        </div>
    </div>
    <div class="header-info">
        <p><strong>ID del Reporte:</strong> <code style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px;">{data.id}</code></p>
        <p><strong>Cliente/Objetivo:</strong> {data.target.input}</p>
        <p><strong>Fecha y Hora de Ejecución:</strong> {datetime.fromisoformat(data.timestamp).strftime('%Y-%m-%d %H:%M:%S') if 'T' in data.timestamp else scan_date}</p>
        <p><strong>Nivel de Riesgo Global:</strong> <span class="risk-badge risk-{risk_level.lower()}">{risk_level}</span></p>
        <p style="font-size: 0.85em; color: #666; margin-top: 10px;">Desarrollado por <strong>Carlos Mancera</strong></p>
    </div>
</header>

<div class="container">
    <!-- Resumen Ejecutivo -->
    <div class="summary">
        <h2>📊 Resumen Ejecutivo</h2>
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <p>Se realizó una auditoría de seguridad sobre <strong>{scope['total_hosts']} host(s)</strong> del objetivo <strong>{data.target.input}</strong> 
            mediante técnicas de reconocimiento y análisis de vulnerabilidades.</p>
            <p><strong>Resumen de hallazgos por severidad:</strong></p>
            <ul style="margin: 10px 0; padding-left: 25px;">
                {f'<li><strong style="color: #c0392b;">CRÍTICO:</strong> {findings_by_severity["CRITICAL"]} hallazgo(s) - Requieren acción inmediata (0-24 horas)</li>' if findings_by_severity['CRITICAL'] > 0 else ''}
                {f'<li><strong style="color: #e74c3c;">ALTO:</strong> {findings_by_severity["HIGH"]} hallazgo(s) - Requieren atención urgente (1-7 días)</li>' if findings_by_severity['HIGH'] > 0 else ''}
                {f'<li><strong style="color: #e67e22;">MEDIO:</strong> {findings_by_severity["MEDIUM"]} hallazgo(s) - Requieren corrección (1-4 semanas)</li>' if findings_by_severity['MEDIUM'] > 0 else ''}
                {f'<li><strong style="color: #27ae60;">BAJO:</strong> {findings_by_severity["LOW"]} hallazgo(s) - Mejoras recomendadas</li>' if findings_by_severity['LOW'] > 0 else ''}
                {f'<li><strong style="color: #3498db;">INFO:</strong> {findings_by_severity["INFO"]} hallazgo(s) - Informativo</li>' if findings_by_severity['INFO'] > 0 else ''}
            </ul>
        </div>
        
        <div style="background: #fafafa; padding: 15px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #555;">Niveles de Severidad</h3>
            <ul style="margin: 10px 0; padding-left: 25px;">
                <li><strong style="color: #c0392b;">CRÍTICO:</strong> Vulnerabilidades que permiten compromiso total del sistema o acceso no autorizado inmediato. Acción requerida: 0-24 horas.</li>
                <li><strong style="color: #e74c3c;">ALTO:</strong> Vulnerabilidades que permiten acceso no autorizado o exposición significativa de datos. Acción requerida: 1-7 días.</li>
                <li><strong style="color: #e67e22;">MEDIO:</strong> Debilidades de seguridad que requieren corrección pero no representan riesgo inmediato. Acción requerida: 1-4 semanas.</li>
                <li><strong style="color: #27ae60;">BAJO:</strong> Mejoras de seguridad recomendadas que no representan riesgo significativo. Acción requerida: 1-3 meses.</li>
            </ul>
        </div>
        
        <p><strong>Duración del escaneo:</strong> {scan_duration}</p>
        <p><strong>Tipo de prueba:</strong> Auditoría externa no intrusiva</p>
        <p style="margin-top: 15px; padding: 15px; background: #ecf0f1; border-radius: 5px;">
            <strong>Conclusión:</strong> {risk_summary}
        </p>
        
        <!-- Hallazgos Críticos Destacados -->
        {f'''
        <div style="background: #ffebee; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #c0392b;">
            <h3 style="margin-top: 0; color: #c0392b;">Hallazgos Críticos Destacados</h3>
            <ol style="line-height: 1.8;">
                {''.join([f'<li><strong>{f.title[:80]}{"..." if len(f.title) > 80 else ""}</strong><br><small style="color: #666;">{f.description[:150]}{"..." if len(f.description) > 150 else ""}</small></li>' for f in top_critical])}
            </ol>
        </div>
        ''' if top_critical else ''}
        
        {f'''
        <div style="background: #fff3e0; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #ff9800;">
            <h3 style="margin-top: 0; color: #e65100;">Acciones Inmediatas Recomendadas</h3>
            <ul style="line-height: 1.8;">
                {''.join([f'<li><strong>{p["title"][:70]}{"..." if len(p["title"]) > 70 else ""}</strong> - {p["action"]}</li>' for p in remediation_priorities[:3]])}
            </ul>
        </div>
        ''' if remediation_priorities else ''}
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

    <!-- 5. Hallazgos Detallados -->
    <div class="summary">
        <h2>5. 🔍 Hallazgos Detallados</h2>
        <p style="margin-bottom: 20px; color: #666;">A continuación se presenta una tabla resumen y el detalle completo de cada hallazgo:</p>
        
        <!-- Tabla Resumen de Hallazgos -->
        <table style="margin-bottom: 30px;">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Hallazgo</th>
                    <th>Severidad</th>
                    <th>Activo Afectado</th>
                    <th>Probabilidad</th>
                    <th>Impacto</th>
                    <th>Estado</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # Build findings table first
        finding_num = 0
        for finding in data.findings:
            finding_num += 1
            formatted = Reporter._format_finding(finding)
            prob = formatted.get('exploitability', 'Media')
            prob_color = "#c0392b" if prob == "Alta" else "#e67e22" if prob == "Media" else "#27ae60"
            sev_name = formatted['severity']
            sev_color = get_color(finding.severity)
            
            # v19.0: Status Badge
            status_style = get_status_style(formatted['status'])
            
            html += f"""
                <tr>
                    <td><strong>#{finding_num}</strong></td>
                    <td>{formatted['title'][:60]}{'...' if len(formatted['title']) > 60 else ''}</td>
                    <td><span style="background: {sev_color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em;">{sev_name}</span></td>
                    <td>{formatted['affected_asset']}</td>
                    <td><span style="color: {prob_color}; font-weight: bold;">{prob}</span></td>
                    <td>{formatted['impact'][:50]}{'...' if len(formatted['impact']) > 50 else ''}</td>
                    <td><span style="{status_style} padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; white-space: nowrap;">{formatted['status']}</span></td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
        
        <h3 style="margin-top: 30px; color: #555;">Detalle Completo de Hallazgos</h3>
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
                
                # v19.0: Build impact section (more professional)
                impact_section = ""
                if formatted.get('why_it_matters') or formatted.get('when_to_fix'):
                    impact_section = f"""
            <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #666;">
                <h5 style="margin-top: 0; color: #333; font-size: 1.1em;">Impacto y Priorización</h5>
                {f'<p style="margin: 10px 0;"><strong>Impacto:</strong> {formatted["why_it_matters"]}</p>' if formatted.get('why_it_matters') else ''}
                {f'<p style="margin: 10px 0;"><strong>Prioridad de Corrección:</strong> {formatted["when_to_fix"]}</p>' if formatted.get('when_to_fix') else ''}
            </div>
"""
                
                # Build technical terms section (simplified)
                terms_section = ""
                if formatted.get('explained_terms'):
                    terms_list = []
                    for term_info in formatted['explained_terms'][:2]:  # Limit to 2 terms
                        term_html = f"""
                    <div style="margin: 10px 0; padding: 10px; background: #f5f5f5; border-radius: 4px; border-left: 3px solid #666;">
                        <strong>{term_info['term']}:</strong> {term_info['explanation']}
                    </div>
"""
                        terms_list.append(term_html)
                    
                    if terms_list:
                        terms_section = f"""
            <div style="background: #fafafa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                <h5 style="margin-top: 0; color: #555;">Términos Técnicos</h5>
                {''.join(terms_list)}
            </div>
"""
                
                # v19.0: Confidence & Status Display
                confidence_pct = int(formatted['confidence'] * 100)
                conf_color = "#27ae60" if confidence_pct > 80 else "#f39c12" if confidence_pct > 50 else "#e74c3c"
                status_style_card = get_status_style(formatted['status'])

                html += f"""
        <div class="finding-card finding-{severity_lower}">
            <h4 style="margin-top: 0;">
                {idx}. {formatted.get('title_simple', formatted['title'])} 
                <span style="font-size: 0.8em; color: #666; font-weight: normal;">({formatted.get('severity_simple', formatted['severity'])})</span>
                {exploit_badge}
            </h4>
            {impact_section}
            <div style="background: #f5f5f5; padding: 12px; border-radius: 4px; margin: 10px 0;">
                <p style="margin: 5px 0;"><strong>📍 Activo Afectado:</strong> {formatted['affected_asset']}</p>
                <div style="margin: 8px 0; display: flex; align-items: center;">
                    <strong style="margin-right: 10px;">🎯 Confianza:</strong> 
                    <div style="flex-grow: 1; max-width: 150px; height: 10px; background: #e0e0e0; border-radius: 5px; overflow: hidden; margin-right: 10px;">
                        <div style="width: {confidence_pct}%; height: 100%; background: {conf_color};"></div>
                    </div>
                    <span style="font-weight: bold; font-size: 0.9em; color: {conf_color};">{confidence_pct}%</span>
                </div>
                <div style="margin: 8px 0;">
                     <strong>🏷️ Estado:</strong> <span style="{status_style_card} padding: 3px 10px; border-radius: 12px; font-size: 0.85em; font-weight: bold;">{formatted['status']}</span>
                </div>
                 <p style="margin: 5px 0;"><strong>📂 Categoría:</strong> {formatted['category']}</p>
            </div>
            <div style="margin: 15px 0;">
                <h5 style="color: #555; margin-bottom: 8px;">Descripción Técnica Detallada:</h5>
                <p style="background: #fafafa; padding: 10px; border-radius: 4px;">{formatted['description']}</p>
            </div>
            {formatted.get('reproduction_steps', '')}
            {terms_section}
            {tech_docs_html}
            {f'<div class="evidence-box"><strong>🔍 Evidencia Técnica:</strong><br>{formatted["evidence"][:800]}{"..." if len(formatted["evidence"]) > 800 else ""}</div>' if formatted['evidence'] and formatted['evidence'] != 'See description' else ''}
            <div style="background: #e3f2fd; padding: 12px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #2196f3;">
                <p style="margin: 5px 0;"><strong>Recomendación:</strong></p>
                <p style="margin: 5px 0;">{formatted['recommendation']}</p>
            </div>
            {refs_html}
        </div>
"""
        
        # Pre-evaluate all tech analysis sections to avoid f-string nesting issues
        os_html = '<ul style="line-height: 1.8;">' + ''.join([f'<li><strong>{os_name}</strong></li>' for os_name in tech_analysis['os']]) + '</ul>' if tech_analysis.get('os') else '<p>No se pudo determinar el sistema operativo con certeza.</p>'
        cms_html = '<ul style="line-height: 1.8;">' + ''.join([f'<li><strong>{cms}</strong></li>' for cms in tech_analysis['cms']]) + '</ul>' if tech_analysis.get('cms') else '<p>No se detectaron CMS conocidos.</p>'
        web_servers_html = '<ul style="line-height: 1.8;">' + ''.join([f'<li><strong>{ws}</strong></li>' for ws in tech_analysis['web_servers']]) + '</ul>' if tech_analysis.get('web_servers') else '<p>No se detectaron servidores web específicos.</p>'
        databases_html = '<ul style="line-height: 1.8;">' + ''.join([f'<li><strong>{db}</strong></li>' for db in tech_analysis['databases']]) + '</ul>' if tech_analysis.get('databases') else '<p>No se detectaron bases de datos expuestas.</p>'
        frameworks_html = '<ul style="line-height: 1.8;">' + ''.join([f'<li><strong>{fw}</strong></li>' for fw in tech_analysis['frameworks']]) + '</ul>' if tech_analysis.get('frameworks') else '<p>No se detectaron frameworks específicos.</p>'
        
        versions_table_html = ''
        if tech_analysis.get('all_versions'):
            versions_rows = ''.join([f'<tr><td><strong>{tech}</strong></td><td>{version}</td></tr>' for tech, version in tech_analysis['all_versions'].items()])
            versions_table_html = f'''
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Resumen de Versiones Detectadas</h3>
            <table style="width: 100%;">
                <thead>
                    <tr>
                        <th>Tecnología</th>
                        <th>Versión</th>
                    </tr>
                </thead>
                <tbody>
                    {versions_rows}
                </tbody>
            </table>
        </div>
        '''
        
        segmentation_html = ''
        if tech_analysis.get('segmentation_issues'):
            segmentation_items = ''.join([f'<li><strong>{issue["host"]}:</strong> {issue["issue"]}</li>' for issue in tech_analysis['segmentation_issues']])
            segmentation_html = f'''
            <div style="background: #ffebee; padding: 15px; border-radius: 4px; margin: 10px 0;">
                <h4 style="color: #c62828; margin-top: 0;">⚠️ Problemas de Segmentación Detectados</h4>
                <ul>
                    {segmentation_items}
                </ul>
            </div>
            '''
        else:
            segmentation_html = '<p style="color: #2e7d32;">✅ No se detectaron problemas evidentes de segmentación.</p>'
        
        waf_html = f'<p><strong>WAF Detectado:</strong> {", ".join(tech_analysis["waf"])}</p>' if tech_analysis.get('waf') else '<p><strong>WAF:</strong> ❌ No se detectó un WAF activo. Se recomienda implementar protección.</p>'
        
        exposed_services_html = ''
        if tech_analysis.get('exposed_services'):
            services_list = ''.join([f'<li>{service}</li>' for service in tech_analysis['exposed_services'][:10]])
            exposed_services_html = f'''
            <p><strong>Servicios Críticos Expuestos:</strong></p>
            <ul>
                {services_list}
            </ul>
            <p style="margin-top: 10px; color: #c62828;"><strong>Total de servicios críticos expuestos:</strong> {len(tech_analysis['exposed_services'])}</p>
            '''
        else:
            exposed_services_html = '<p>No se detectaron servicios críticos expuestos públicamente.</p>'
        
        html += f"""
    </div>

    <!-- 6. Análisis de Tecnologías y Arquitectura -->
    <div class="summary">
        <h2>6. 🏗️ Análisis de Tecnologías y Arquitectura</h2>
        
        <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #1565c0;">Sistema Operativo y Versiones Detectadas</h3>
            {os_html}
        </div>
        
        <div style="background: #f3e5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #7b1fa2;">CMS y Versiones</h3>
            {cms_html}
        </div>
        
        <div style="background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #2e7d32;">Servidores Web y Versiones</h3>
            {web_servers_html}
        </div>
        
        <div style="background: #fff3e0; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #e65100;">Bases de Datos y Versiones</h3>
            {databases_html}
        </div>
        
        <div style="background: #fce4ec; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #c2185b;">Frameworks y Lenguajes de Programación</h3>
            {frameworks_html}
        </div>
        
        {versions_table_html}
        
        <div style="background: #fff3e0; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #e65100;">Configuración de Red y Segmentación de Servicios</h3>
            {segmentation_html}
        </div>
        
        <div style="background: #e0f2f1; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #00695c;">WAF y Mecanismos de Protección Existentes</h3>
            {waf_html}
        </div>
        
        <div style="background: #fce4ec; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #c2185b;">Exposición de Servicios Críticos y Análisis de Superficie de Ataque</h3>
            {exposed_services_html}
        </div>
    </div>
"""
        
        # Pre-evaluate anomalies section
        anomalies_html = ''
        if anomalies:
            anomalies_list = []
            for anom in anomalies:
                evidence_html = ''
                if anom.get('evidence'):
                    evidence_str = str(anom['evidence'])[:200]
                    evidence_html = f'<p><strong>Evidencia:</strong> <code style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px;">{evidence_str}{"..." if len(str(anom["evidence"])) > 200 else ""}</code></p>'
                
                severity_color = get_color(Severity[anom['severity']]) if hasattr(Severity, anom['severity']) else '#95a5a6'
                anomalies_list.append(f'''
        <div style="background: #fff3e0; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #ff9800;">
            <h4 style="margin-top: 0; color: #e65100;">{anom['title']}</h4>
            <p><strong>Severidad:</strong> <span style="background: {severity_color}; color: white; padding: 2px 8px; border-radius: 3px;">{anom['severity']}</span></p>
            <p><strong>Descripción:</strong> {anom['description']}</p>
            {evidence_html}
            <p><strong>Recomendación:</strong> {anom['recommendation']}</p>
        </div>
        ''')
            anomalies_html = f'<p>Se detectaron {len(anomalies)} anomalía(s) que requieren atención:</p>' + ''.join(anomalies_list)
        else:
            anomalies_html = '<p style="color: #2e7d32;">No se detectaron anomalías significativas.</p>'
        
        html += f"""
    <!-- 7. Anomalías y Patrones Sospechosos -->
    <div class="summary">
        <h2>7. ⚠️ Anomalías y Patrones Sospechosos</h2>
        {anomalies_html}
    </div>
"""
        
        # Pre-evaluate risk evaluation sections
        risk_global_html = ''
        if risk_evaluation.get('global'):
            risk_global_html = f'''
            <p><strong>Score Global de Riesgo:</strong> {risk_evaluation['global'].get('total_score', 'N/A')}/100</p>
            <p><strong>Nivel de Riesgo Global:</strong> <span class="risk-badge risk-{risk_level.lower()}">{risk_level}</span></p>
            <p style="margin-top: 15px;"><strong>Desglose del Score:</strong></p>
            <ul>
                <li>Vulnerabilidades: {risk_evaluation['global'].get('vulnerability_score', 0):.1f}</li>
                <li>Exposición: {risk_evaluation['global'].get('exposure_score', 0):.1f}</li>
                <li>Déficit de Protección: {risk_evaluation['global'].get('protection_deficit', 0):.1f}</li>
                <li>Penalización por Segmentación: {risk_evaluation['global'].get('segmentation_penalty', 0):.1f}</li>
            </ul>
            '''
        else:
            risk_global_html = '<p>No se pudo calcular el score de riesgo global.</p>'
        
        risk_per_host_html = ''
        if risk_evaluation.get('per_host'):
            risk_rows = ''.join([f'''
                    <tr>
                        <td><strong>{hr["hostname"] or hr["ip"]}</strong><br><small>{hr["ip"]}</small></td>
                        <td>{hr["total_score"]}</td>
                        <td><span class="risk-badge risk-{hr["risk_level"].lower()}">{hr["risk_level"]}</span></td>
                        <td>{len(hr["critical_services"])}</td>
                        <td>{hr["vulnerability_count"]}</td>
                    </tr>
                    ''' for hr in risk_evaluation.get('per_host', [])])
            risk_per_host_html = f'''
        <div style="background: #f3e5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #7b1fa2;">Evaluación de Riesgo por Host</h3>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Score</th>
                        <th>Nivel de Riesgo</th>
                        <th>Servicios Críticos</th>
                        <th>Vulnerabilidades</th>
                    </tr>
                </thead>
                <tbody>
                    {risk_rows}
                </tbody>
            </table>
        </div>
        '''
        
        html += f"""
    <!-- 8. Evaluación de Riesgo -->
    <div class="summary">
        <h2>8. 📊 Evaluación de Riesgo</h2>
        
        <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #1565c0;">Score Global y por Host</h3>
            {risk_global_html}
        </div>
        
        {risk_per_host_html}
        
        <div style="background: #fff3e0; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #e65100;">Clasificación de Riesgo de Negocio</h3>
            <p>El riesgo de negocio se calcula considerando:</p>
            <ul style="line-height: 1.8;">
                <li>Exposición de servicios críticos (bases de datos, sistemas de administración)</li>
                <li>Vulnerabilidades con exploits públicos disponibles</li>
                <li>Falta de segmentación de red</li>
                <li>Ausencia de mecanismos de protección (WAF, rate limiting)</li>
            </ul>
        </div>
    </div>
"""
        
        # Pre-evaluate remediation sections
        critical_actions_html = ''
        if any(p['severity'] == 'CRITICAL' for p in remediation_priorities):
            critical_items = ''.join([f'''
                <li>
                    <strong>{p["title"][:80]}{"..." if len(p["title"]) > 80 else ""}</strong><br>
                    <small style="color: #666;">{p["action"]}</small><br>
                    <small style="color: #c62828;"><strong>Impacto:</strong> {p["impact"]}</small>
                </li>
                ''' for p in remediation_priorities if p['severity'] == 'CRITICAL'])
            critical_actions_html = f'<ol style="line-height: 1.8;">{critical_items}</ol>'
        else:
            critical_actions_html = '<p>No hay acciones críticas pendientes.</p>'
        
        high_actions_html = ''
        if any(p['severity'] == 'HIGH' for p in remediation_priorities):
            high_items = ''.join([f'''
                <li>
                    <strong>{p["title"][:80]}{"..." if len(p["title"]) > 80 else ""}</strong><br>
                    <small style="color: #666;">{p["action"]}</small>
                </li>
                ''' for p in remediation_priorities if p['severity'] == 'HIGH'])
            high_actions_html = f'<ol style="line-height: 1.8;">{high_items}</ol>'
        else:
            high_actions_html = '<p>No hay acciones urgentes pendientes.</p>'
        
        html += f"""
    <!-- 9. Resumen de Remediaciones -->
    <div class="summary">
        <h2>9. 🔧 Resumen de Remediaciones</h2>
        
        <div style="background: #ffebee; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #c0392b;">
            <h3 style="margin-top: 0; color: #c62828;">Acciones Críticas (0-24 horas)</h3>
            {critical_actions_html}
        </div>
        
        <div style="background: #fff3e0; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #ff9800;">
            <h3 style="margin-top: 0; color: #e65100;">Acciones Urgentes (1-7 días)</h3>
            {high_actions_html}
        </div>
        
        <div style="background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #2e7d32;">Mitigaciones Temporales y Preventivas</h3>
            <ul style="line-height: 1.8;">
                <li>Implementar rate limiting en servicios expuestos</li>
                <li>Configurar firewall para restringir acceso a servicios críticos</li>
                <li>Habilitar logging y monitoreo de accesos sospechosos</li>
                <li>Revisar y actualizar credenciales por defecto</li>
            </ul>
        </div>
    </div>
"""
        
        html += f"""
    <!-- 10. Anexos -->
    <div class="summary">
        <h2>10. 📎 Anexos</h2>
        
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #555;">Referencias Externas</h3>
            <ul style="line-height: 1.8;">
                <li><a href="https://cve.mitre.org/" target="_blank">CVE Database - Base de datos de vulnerabilidades conocidas</a></li>
                <li><a href="https://owasp.org/" target="_blank">OWASP - Open Web Application Security Project</a></li>
                <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">CISA Known Exploited Vulnerabilities Catalog</a></li>
            </ul>
        </div>
        
        <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #1565c0;">Información del Reporte</h3>
            <table>
                <tr>
                    <td><strong>ID del Reporte:</strong></td>
                    <td><code>{data.id}</code></td>
                </tr>
                <tr>
                    <td><strong>Fecha de Generación:</strong></td>
                    <td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
                <tr>
                    <td><strong>Duración del Escaneo:</strong></td>
                    <td>{scan_duration}</td>
                </tr>
                <tr>
                    <td><strong>Total de Hallazgos:</strong></td>
                    <td>{len(data.findings)}</td>
                </tr>
                <tr>
                    <td><strong>Herramientas Utilizadas:</strong></td>
                    <td>{', '.join(tools_used)}</td>
                </tr>
            </table>
        </div>
        
        <div style="background: #fff9e6; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #856404;">Notas Técnicas</h3>
            <p>Los logs completos de herramientas, capturas de tráfico y resultados detallados de escaneo están disponibles en formato JSON mediante la opción <code>--json</code> de Meowware.</p>
            <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                Para obtener información técnica detallada sobre un hallazgo específico, consulte el campo "Evidencia Técnica" en la sección de Hallazgos Detallados.
            </p>
        </div>
    </div>
"""
        
        html += f"""
    <!-- Recomendaciones Generales -->
    <div class="summary">
        <h2>💡 Recomendaciones Generales</h2>
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Recomendaciones Generales</h3>
            <ul style="line-height: 1.8;">
                <li>Aplicar todas las actualizaciones críticas de software y CMS detectadas.</li>
                <li>Segmentar servicios críticos (DB, Mail, Web) para minimizar riesgos de ataque lateral.</li>
                <li>Revisar configuración de WAF y headers de seguridad para defensa en profundidad.</li>
                <li>Auditar puertos abiertos y cerrar servicios innecesarios.</li>
                <li>Implementar monitorización continua de logs y vulnerabilidades.</li>
                <li>Realizar auditorías periódicas para detectar cambios en la superficie de ataque.</li>
            </ul>
        </div>
    </div>
"""
        
        # Pre-evaluate scope info
        subdomains_count = len(scope['domains']) - 1 if len(scope['domains']) > 1 else 0
        domains_list = ', '.join(scope['domains']) if scope.get('domains') else 'N/A'
        
        html += f"""
    <!-- 3. Alcance de la Auditoría -->
    <div class="summary">
        <h2>3. 📋 Alcance de la Auditoría</h2>
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Dominios y Subdominios Auditados</h3>
            <ul style="line-height: 1.8;">
                <li><strong>Dominio Principal:</strong> {data.target.input}</li>
                <li><strong>Subdominios Detectados:</strong> {subdomains_count}</li>
                <li><strong>Lista Completa:</strong> {domains_list}</li>
            </ul>
        </div>
"""
        
        # Pre-evaluate scope sections
        ipv4_text = f"{len(scope['ipv4'])} dirección(es) - {', '.join(scope['ipv4'][:5])}{'...' if len(scope['ipv4']) > 5 else ''}"
        ipv6_text = ''
        if scope.get('ipv6'):
            ipv6_text = f"{len(scope['ipv6'])} dirección(es) - {', '.join(scope['ipv6'][:3])}{'...' if len(scope['ipv6']) > 3 else ''}"
        
        databases_detected = 'Detectadas' if tech_analysis.get('databases') or any('3306' in str(f.title) or 'MySQL' in f.title or 'PostgreSQL' in f.title for f in data.findings) else 'No detectadas'
        cms_text = ', '.join(tech_analysis['cms']) if tech_analysis.get('cms') else 'No detectados'
        
        html += f"""
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Rango de IPs Revisadas</h3>
            <ul style="line-height: 1.8;">
                <li><strong>IPv4:</strong> {ipv4_text}</li>
                <li><strong>IPv6:</strong> {ipv6_text if ipv6_text else 'No detectado'}</li>
                <li><strong>Total de Hosts Auditados:</strong> {scope['total_hosts']}</li>
            </ul>
        </div>
        
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Tecnologías y Servicios Incluidos</h3>
            <ul style="line-height: 1.8;">
                <li><strong>Servicios Web:</strong> HTTP/HTTPS (puertos 80, 443)</li>
                <li><strong>Bases de Datos:</strong> {databases_detected}</li>
                <li><strong>Protocolos de Red:</strong> SSH, FTP, SMTP, DNS, y otros servicios expuestos</li>
                <li><strong>CMS y Frameworks:</strong> {cms_text}</li>
            </ul>
        </div>
        
        <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Exclusiones</h3>
            <p>Pruebas no intrusivas. Solo auditoría externa sin modificación de sistemas.</p>
        </div>
    </div>
"""
        
        # Pre-evaluate tools section
        tools_html = ''.join([f'<div style="background: #fff; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #ddd;"><strong>{tool}</strong></div>' for tool in tools_used])
        
        html += f"""
    <!-- 4. Metodología -->
    <div class="summary">
        <h2>4. 🔧 Metodología</h2>
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Herramientas Utilizadas</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 15px 0;">
                {tools_html}
            </div>
        </div>
        
        <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #1565c0;">Fases de la Auditoría</h3>
            <ol style="line-height: 2;">
                <li><strong>Reconocimiento:</strong> Identificación de dominios, subdominios y rangos de IPs</li>
                <li><strong>Escaneo:</strong> Descubrimiento de puertos abiertos y servicios activos mediante Nmap</li>
                <li><strong>Enumeración:</strong> Identificación de tecnologías, versiones y configuraciones mediante WhatWeb y escáneres especializados</li>
                <li><strong>Análisis de Vulnerabilidades:</strong> Búsqueda de vulnerabilidades conocidas mediante Nuclei, WPScan, SQLMap y otras herramientas</li>
                <li><strong>Verificación:</strong> Validación de hallazgos y análisis de impacto</li>
            </ol>
        </div>
        
        <div style="background: #f3e5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #7b1fa2;">Criterios para Priorizar Hallazgos</h3>
            <ul style="line-height: 1.8;">
                <li><strong>Exposición Pública:</strong> Servicios accesibles desde Internet sin autenticación</li>
                <li><strong>Servicios Críticos:</strong> Bases de datos, sistemas de administración y protocolos inseguros</li>
                <li><strong>Configuración Insegura:</strong> Versiones desactualizadas, configuraciones por defecto y falta de cifrado</li>
                <li><strong>Exploitabilidad:</strong> Existencia de exploits públicos o vectores de ataque conocidos</li>
            </ul>
        </div>
        
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Uso de Motores de IA y Análisis de Comportamiento</h3>
            <ul style="line-height: 1.8;">
                <li>Decisión inteligente de herramientas basada en contexto detectado</li>
                <li>Detección de anomalías y patrones sospechosos</li>
                <li>Generación de hipótesis sobre vulnerabilidades</li>
                <li>Priorización automática según riesgo de negocio</li>
            </ul>
        </div>
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
