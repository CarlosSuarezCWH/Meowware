"""
Per-Host Risk Scoring

Calculates individual risk scores for each scanned host to help prioritize remediation efforts.
"""

from typing import List, Dict, Any
from ..core.models import Host, Finding, Severity
from .risk_scorer import RiskScorer

class PerHostRiskScorer:
    """
    Calculates risk scores for individual hosts.
    """
    
    # Service risk multipliers
    CRITICAL_SERVICES = {
        21: 2.0,    # FTP
        22: 0.5,    # SSH
        23: 3.0,    # Telnet
        3306: 2.5,  # MySQL
        5432: 2.5,  # PostgreSQL
        1433: 2.5,  # MSSQL
        27017: 2.5, # MongoDB
        6379: 2.0,  # Redis
        9200: 2.0,  # Elasticsearch
        3389: 2.0,  # RDP
        445: 1.5,   # SMB
    }
    
    @staticmethod
    def calculate_host_risk(host: Host, findings: List[Finding]) -> Dict[str, Any]:
        """
        Calculate risk score for a specific host.
        
        Returns:
            {
                'hostname': str,
                'ip': str,
                'total_score': int,
                'risk_level': str,
                'critical_services': List[int],
                'vulnerability_count': int,
                'breakdown': {
                    'vulnerabilities': float,
                    'exposed_services': float,
                    'configuration': float
                }
            }
        """
        score = 0
        breakdown = {
            'vulnerabilities': 0,
            'exposed_services': 0,
            'configuration': 0
        }
        
        # Count findings for this host
        host_findings = [f for f in findings if host.hostname in f.title or host.ip in f.title]
        
        # Score from vulnerabilities
        vuln_count = 0
        for finding in host_findings:
            # v12.5: Phase 6 Confidence Weighting
            w_base = RiskScorer.WEIGHTS.get(finding.severity, 0)
            confidence = getattr(finding, 'evidence_score', 0.5)
            weight = w_base * confidence
            
            if finding.category in ['Vulnerability', 'CVE', 'Protocol Security', 'Exploit']:
                breakdown['vulnerabilities'] += weight
                if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                    vuln_count += 1
            elif finding.category in ['DNS', 'Email', 'Crypto', 'Defense']:
                breakdown['configuration'] += weight
            else:
                breakdown['configuration'] += weight * 0.5
        
        # Score from exposed services
        critical_services_found = []
        for service in host.services:
            if service.state == 'open':
                port = service.port
                if port in PerHostRiskScorer.CRITICAL_SERVICES:
                    risk_multiplier = PerHostRiskScorer.CRITICAL_SERVICES[port]
                    breakdown['exposed_services'] += risk_multiplier
                    critical_services_found.append(port)
        
        # Calculate total
        score = sum(breakdown.values())
        
        # Determine risk level
        if score >= 50:
            risk_level = "CRITICAL"
        elif score >= 25:
            risk_level = "HIGH"
        elif score >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'hostname': host.hostname,
            'ip': host.ip,
            'total_score': int(score),
            'risk_level': risk_level,
            'critical_services': critical_services_found,
            'vulnerability_count': vuln_count,
            'open_ports': len([s for s in host.services if s.state == 'open']),
            'breakdown': breakdown
        }
    
    @staticmethod
    def rank_hosts(hosts: List[Host], findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Calculate risk scores for all hosts and return sorted by risk (highest first).
        """
        host_risks = []
        
        for host in hosts:
            risk_data = PerHostRiskScorer.calculate_host_risk(host, findings)
            host_risks.append(risk_data)
        
        # Sort by score (highest first)
        host_risks.sort(key=lambda x: x['total_score'], reverse=True)
        
        return host_risks
    
    @staticmethod
    def get_risk_summary(host_risks: List[Dict[str, Any]]) -> str:
        """
        Generate human-readable summary of host risks.
        """
        if not host_risks:
            return "No hosts analyzed."
        
        lines = []
        lines.append("HOST RISK ANALYSIS")
        lines.append("-" * 60)
        
        for idx, risk in enumerate(host_risks[:10], 1):  # Top 10 hosts
            lines.append(f"\n{idx}. {risk['hostname']} ({risk['ip']}): {risk['risk_level']} (Score: {risk['total_score']})")
            
            if risk['vulnerability_count'] > 0:
                lines.append(f"   - {risk['vulnerability_count']} critical vulnerabilities")
            
            if risk['critical_services']:
                services_str = ', '.join(str(p) for p in risk['critical_services'][:5])
                lines.append(f"   - Critical services: {services_str}")
            
            lines.append(f"   - {risk['open_ports']} open ports")
            
            # Breakdown
            b = risk['breakdown']
            if b['vulnerabilities'] > 0:
                lines.append(f"   - Vulnerability risk: {b['vulnerabilities']:.1f}")
            if b['exposed_services'] > 0:
                lines.append(f"   - Service exposure: {b['exposed_services']:.1f}")
        
        return "\n".join(lines)
