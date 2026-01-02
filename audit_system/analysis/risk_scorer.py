"""
Enhanced Hierarchical Risk Scoring Engine

Scoring based on:
1. Service Exposure (quantity + criticality)
2. Vulnerabilities (severity + exploitability)
3. Protection Level (WAF, TLS, hardening)
4. Attack Surface Size
5. Segmentation Quality
6. Defense Depth

Produces:
- Numeric score (0-100)
- Risk level (INFO → CRITICAL)
- Detailed breakdown with explanation
- Actionable insights
"""

from typing import List, Dict, Any, Optional
from ..core.models import Finding, Severity, Host


class EnhancedRiskScorer:
    """
    Professional Risk Scoring with explainability
    """
    
    # Base weights for severity
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0
    }
    
    # Service criticality multipliers
    SERVICE_CRITICALITY = {
        # Databases (highest risk if exposed)
        3306: {"name": "MySQL", "multiplier": 2.0, "category": "database"},
        5432: {"name": "PostgreSQL", "multiplier": 2.0, "category": "database"},
        27017: {"name": "MongoDB", "multiplier": 2.0, "category": "database"},
        6379: {"name": "Redis", "multiplier": 1.8, "category": "database"},
        1433: {"name": "MSSQL", "multiplier": 2.0, "category": "database"},
        
        # Insecure protocols
        21: {"name": "FTP", "multiplier": 1.5, "category": "insecure"},
        23: {"name": "Telnet", "multiplier": 1.8, "category": "insecure"},
        
        # Admin interfaces
        3389: {"name": "RDP", "multiplier": 1.6, "category": "admin"},
        5900: {"name": "VNC", "multiplier": 1.6, "category": "admin"},
        
        # Standard services
        22: {"name": "SSH", "multiplier": 0.8, "category": "secure"},
        25: {"name": "SMTP", "multiplier": 1.0, "category": "mail"},
        443: {"name": "HTTPS", "multiplier": 0.4, "category": "web"},
        80: {"name": "HTTP", "multiplier": 0.6, "category": "web"},
    }
    
    @staticmethod
    def calculate_comprehensive_risk(findings: List[Finding], hosts: List[Host], 
                                     correlations: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score with full context
        """
        score_components = {
            "vulnerability_score": 0.0,
            "exposure_score": 0.0,
            "protection_deficit": 0.0,
            "segmentation_penalty": 0.0,
            "attack_surface_score": 0.0
        }
        
        explanations = []
        severity_counts = {s.name.lower(): 0 for s in Severity}
        max_severity = Severity.INFO
        
        # 1. VULNERABILITY SCORING
        for finding in findings:
            sev = finding.severity if isinstance(finding.severity, Severity) else Severity[finding.severity.upper()]
            
            # Track max severity
            if list(Severity).index(sev) > list(Severity).index(max_severity):
                max_severity = sev
            
            severity_counts[sev.name.lower()] += 1
            
            # Base weight
            base_weight = EnhancedRiskScorer.SEVERITY_WEIGHTS.get(sev, 0)
            
            # Confidence multiplier
            confidence = getattr(finding, 'confidence_score', 0.7)
            
            # Evidence type multiplier
            from ..core.models import EvidenceType
            evidence_weight = {
                EvidenceType.VULNERABILITY: 1.0,
                EvidenceType.MISCONFIG: 0.8,
                EvidenceType.RECON: 0.4,
                EvidenceType.HEURISTIC: 0.2
            }.get(finding.evidence_type, 0.6)
            
            # Exploitability factor (public exploits = higher score)
            exploit_bonus = 1.2 if "exploit" in finding.title.lower() or "rce" in finding.title.lower() else 1.0
            
            final_weight = base_weight * confidence * evidence_weight * exploit_bonus
            score_components["vulnerability_score"] += final_weight
        
        # Add explanation for vulnerabilities
        if score_components["vulnerability_score"] > 0:
            explanations.append({
                "component": "Vulnerabilities",
                "score": score_components["vulnerability_score"],
                "explanation": f"Found {severity_counts['critical']} critical, {severity_counts['high']} high, "
                              f"{severity_counts['medium']} medium severity issues"
            })
        
        # 2. EXPOSURE SCORING (Open Services)
        open_service_count = 0
        critical_services_exposed = []
        
        for host in hosts:
            open_services = [s for s in host.services if s.state == 'open']
            open_service_count += len(open_services)
            
            for service in open_services:
                service_info = EnhancedRiskScorer.SERVICE_CRITICALITY.get(service.port, 
                    {"name": f"Port {service.port}", "multiplier": 0.5, "category": "other"})
                
                # Base exposure points
                exposure_points = 1.0 * service_info["multiplier"]
                
                # WAF mitigation
                if host.web_context and host.web_context.waf_detected:
                    if host.web_context.waf_type == "ACTIVE":
                        exposure_points *= 0.4  # Active WAF significantly reduces risk
                    else:
                        exposure_points *= 0.7  # Passive WAF provides some protection
                
                # TLS protection for web services
                if service.port in [443, 8443]:
                    exposure_points *= 0.7  # HTTPS is better than HTTP
                
                score_components["exposure_score"] += exposure_points
                
                # Track critical exposures
                if service_info["category"] in ["database", "insecure", "admin"]:
                    critical_services_exposed.append(f"{service_info['name']} ({host.ip})")
        
        if score_components["exposure_score"] > 0:
            explanations.append({
                "component": "Service Exposure",
                "score": score_components["exposure_score"],
                "explanation": f"{open_service_count} services exposed"
                              + (f", including critical services: {', '.join(critical_services_exposed[:3])}" 
                                 if critical_services_exposed else "")
            })
        
        # 3. PROTECTION DEFICIT
        web_hosts = [h for h in hosts if any(s.port in [80, 443, 8080, 8443] for s in h.services if s.state == 'open')]
        
        if web_hosts:
            # Check WAF coverage
            waf_protected = [h for h in web_hosts if h.web_context and h.web_context.waf_detected]
            waf_coverage = len(waf_protected) / len(web_hosts)
            
            if waf_coverage < 0.5:
                deficit = (1.0 - waf_coverage) * 10
                score_components["protection_deficit"] += deficit
                explanations.append({
                    "component": "Protection Deficit",
                    "score": deficit,
                    "explanation": f"Only {waf_coverage*100:.0f}% of web apps have WAF protection"
                })
            
            # Check TLS coverage
            tls_enabled = [h for h in web_hosts if any(s.port in [443, 8443] for s in h.services if s.state == 'open')]
            tls_coverage = len(tls_enabled) / len(web_hosts)
            
            if tls_coverage < 1.0:
                deficit = (1.0 - tls_coverage) * 8
                score_components["protection_deficit"] += deficit
                explanations.append({
                    "component": "Encryption Gap",
                    "score": deficit,
                    "explanation": f"{(1-tls_coverage)*100:.0f}% of web services lack HTTPS"
                })
        
        # 4. SEGMENTATION PENALTY
        if correlations and "network_segmentation" in correlations:
            seg = correlations["network_segmentation"]
            if seg["quality"] == "Poor":
                penalty = 15
                score_components["segmentation_penalty"] = penalty
                explanations.append({
                    "component": "Segmentation Issues",
                    "score": penalty,
                    "explanation": "Poor network segmentation - services not properly isolated"
                })
            elif seg["quality"] == "Fair":
                penalty = 8
                score_components["segmentation_penalty"] = penalty
                explanations.append({
                    "component": "Segmentation Issues",
                    "score": penalty,
                    "explanation": "Fair network segmentation - some isolation concerns"
                })
        
        # 5. ATTACK SURFACE SIZE
        if open_service_count > 20:
            surface_penalty = (open_service_count - 20) * 0.5
            score_components["attack_surface_score"] = surface_penalty
            explanations.append({
                "component": "Large Attack Surface",
                "score": surface_penalty,
                "explanation": f"Excessive service exposure: {open_service_count} open ports"
            })
        
        # CALCULATE TOTAL SCORE
        total_score = sum(score_components.values())
        
        # Cap at 100
        total_score = min(total_score, 100)
        
        # DETERMINE RISK LEVEL
        # Logic: Score-based, but influenced by max finding severity
        if total_score >= 60 or max_severity == Severity.CRITICAL:
            risk_level = Severity.CRITICAL
        elif total_score >= 35 or max_severity == Severity.HIGH:
            risk_level = Severity.HIGH
        elif total_score >= 15 or max_severity == Severity.MEDIUM:
            risk_level = Severity.MEDIUM
        elif total_score >= 5:
            risk_level = Severity.LOW
        else:
            risk_level = Severity.INFO
        
        # Generate risk summary text
        risk_summary = EnhancedRiskScorer._generate_risk_summary(
            total_score, risk_level, score_components, severity_counts, explanations
        )
        
        return {
            "total_score": int(total_score),
            "risk_level": risk_level.name,
            "max_severity": max_severity.name,
            "score_components": score_components,
            "severity_counts": severity_counts,
            "explanations": explanations,
            "risk_summary": risk_summary,
            "grade": EnhancedRiskScorer._score_to_grade(total_score)
        }
    
    @staticmethod
    def _score_to_grade(score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 60: return "F"
        elif score >= 35: return "D"
        elif score >= 15: return "C"
        elif score >= 5: return "B"
        else: return "A"
    
    @staticmethod
    def _generate_risk_summary(score: float, risk_level: Severity, 
                               components: Dict[str, float], 
                               severity_counts: Dict[str, int],
                               explanations: List[Dict]) -> str:
        """Generate human-readable risk summary"""
        
        lines = []
        lines.append(f"Overall Risk: {risk_level.name} (Score: {int(score)}/100, Grade: {EnhancedRiskScorer._score_to_grade(score)})")
        lines.append("")
        lines.append("Risk Breakdown:")
        
        for exp in explanations:
            lines.append(f"  • {exp['component']}: +{exp['score']:.1f} points")
            lines.append(f"    → {exp['explanation']}")
        
        lines.append("")
        lines.append("Severity Distribution:")
        lines.append(f"  Critical: {severity_counts.get('critical', 0)}")
        lines.append(f"  High: {severity_counts.get('high', 0)}")
        lines.append(f"  Medium: {severity_counts.get('medium', 0)}")
        lines.append(f"  Low: {severity_counts.get('low', 0)}")
        lines.append(f"  Info: {severity_counts.get('info', 0)}")
        
        return "\n".join(lines)


# Backward compatibility
class RiskScorer:
    """Legacy wrapper for compatibility"""
    
    WEIGHTS = EnhancedRiskScorer.SEVERITY_WEIGHTS
    SERVICE_PRIORITY = {k: v["multiplier"] for k, v in EnhancedRiskScorer.SERVICE_CRITICALITY.items()}
    
    @staticmethod
    def calculate_risk_score(findings: List[Finding], hosts: List[Host]) -> Dict[str, Any]:
        """Legacy method - redirects to enhanced scorer"""
        result = EnhancedRiskScorer.calculate_comprehensive_risk(findings, hosts)
        
        # Convert to legacy format
        return {
            'total_score': result['total_score'],
            'risk_level': result['risk_level'],
            'breakdown': result['score_components'],
            'severity_counts': result['severity_counts'],
            'max_severity': result['max_severity']
        }
    
    @staticmethod
    def get_risk_summary(risk_data: Dict[str, Any]) -> str:
        """Legacy summary method"""
        if "risk_summary" in risk_data:
            return risk_data["risk_summary"]
        
        res = [f"Overall Risk: {risk_data['risk_level']} (Score: {risk_data['total_score']})"]
        res.append(f"Highest Finding: {risk_data['max_severity']}")
        res.append("\nBreakdown:")
        for k, v in risk_data.get('breakdown', {}).items():
            if v > 0: 
                res.append(f"  - {k.replace('_', ' ').title()}: {v:.1f}")
        return "\n".join(res)

        # 3. Aggregation
        score = sum(breakdown.values()) + critical_bonus
        
        # 4. Final Risk Level Determination (Hierarchical Capping)
        # We start with score-based level
        if score >= 40: score_level = Severity.CRITICAL
        elif score >= 20: score_level = Severity.HIGH
        elif score >= 10: score_level = Severity.MEDIUM
        elif score >= 4: score_level = Severity.LOW
        else: score_level = Severity.INFO
        
        # Capping Rule: The level cannot be more than one step above the highest finding
        # Unless there are MANY findings (implied by score).
        # Actually, let's keep it simple: max(score_level, max_severity_found)
        # But if there are NO findings, even with open ports, it shouldn't be HIGH.
        final_level = score_level
        if max_severity_found == Severity.INFO and score_level.value != Severity.INFO.value:
            # No findings, but ports open? Cap at LOW/MEDIUM
             if score_level in [Severity.HIGH, Severity.CRITICAL]:
                 final_level = Severity.MEDIUM
        
        # Final override: If there's a CRITICAL finding, risk is CRITICAL.
        if list(Severity).index(max_severity_found) > list(Severity).index(final_level):
            final_level = max_severity_found

        return {
            'total_score': int(score),
            'risk_level': final_level.name,
            'breakdown': breakdown,
            'severity_counts': sev_counts,
            'max_severity': max_severity_found.name
        }

    @staticmethod
    def get_risk_summary(risk_data: Dict[str, Any]) -> str:
        res = [f"Overall Risk: {risk_data['risk_level']} (Score: {risk_data['total_score']})"]
        res.append(f"Highest Finding: {risk_data['max_severity']}")
        res.append("\nBreakdown:")
        for k, v in risk_data['breakdown'].items():
            if v > 0: res.append(f"  - {k.capitalize()}: {v:.1f}")
        return "\n".join(res)
