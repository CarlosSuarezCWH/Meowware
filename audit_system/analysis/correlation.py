"""
Intelligent Correlation Engine
Correlates findings to avoid false positives and provide context
"""
from typing import List, Dict, Any, Set
from ..core.models import Host, Finding, Severity, Service


class CorrelationEngine:
    """
    Correlates findings across:
    - Services + Location + Context
    - Technology + Exposure + Protection
    - Attack Surface + Control Absence
    """
    
    @staticmethod
    def correlate_findings(hosts: List[Host], findings: List[Finding]) -> Dict[str, Any]:
        """
        Main correlation logic
        Returns enriched findings with context and risk relationships
        """
        correlations = {
            "network_segmentation": CorrelationEngine._analyze_segmentation(hosts),
            "defense_posture": CorrelationEngine._analyze_defenses(hosts),
            "attack_chains": CorrelationEngine._identify_attack_chains(hosts, findings),
            "risk_clusters": CorrelationEngine._cluster_risks(hosts, findings),
            "false_positive_filter": CorrelationEngine._filter_false_positives(findings),
            "contextual_insights": []
        }
        
        # Generate contextual insights
        correlations["contextual_insights"] = CorrelationEngine._generate_insights(
            hosts, findings, correlations
        )
        
        return correlations
    
    @staticmethod
    def _analyze_segmentation(hosts: List[Host]) -> Dict[str, Any]:
        """
        Analyze network segmentation quality
        
        BAD: Web + DB on same host
        GOOD: Web separated from DB
        """
        segmentation = {
            "quality": "Unknown",
            "issues": [],
            "score": 0.0
        }
        
        for host in hosts:
            web_ports = [s for s in host.services if s.port in [80, 443, 8080, 8443] and s.state == 'open']
            db_ports = [s for s in host.services if s.port in [3306, 5432, 27017, 1433, 6379] and s.state == 'open']
            
            if web_ports and db_ports:
                segmentation["issues"].append({
                    "host": host.ip,
                    "issue": "Web and Database on same host",
                    "severity": Severity.HIGH,
                    "description": f"{host.ip} runs both web services and databases - poor segmentation increases risk",
                    "impact": "Compromising web app gives direct DB access"
                })
                segmentation["score"] -= 30
            
            # Check for everything on one host
            if len(host.services) > 15:
                segmentation["issues"].append({
                    "host": host.ip,
                    "issue": "Monolithic Architecture",
                    "severity": Severity.MEDIUM,
                    "description": f"{host.ip} runs {len(host.services)} services - single point of failure",
                    "impact": "One compromise affects multiple services"
                })
                segmentation["score"] -= 20
        
        # Determine quality
        if segmentation["score"] < -40:
            segmentation["quality"] = "Poor"
        elif segmentation["score"] < -20:
            segmentation["quality"] = "Fair"
        else:
            segmentation["quality"] = "Good"
        
        return segmentation
    
    @staticmethod
    def _analyze_defenses(hosts: List[Host]) -> Dict[str, Any]:
        """
        Analyze defensive posture
        - WAF presence
        - TLS usage
        - Security headers
        """
        defense_analysis = {
            "waf_coverage": 0,
            "tls_coverage": 0,
            "weaknesses": [],
            "strengths": []
        }
        
        web_hosts = [h for h in hosts if any(s.port in [80, 443, 8080, 8443] for s in h.services if s.state == 'open')]
        
        if web_hosts:
            waf_protected = [h for h in web_hosts if h.web_context and h.web_context.waf_detected]
            defense_analysis["waf_coverage"] = len(waf_protected) / len(web_hosts) * 100
            
            tls_enabled = [h for h in web_hosts if any(s.port in [443, 8443] for s in h.services if s.state == 'open')]
            defense_analysis["tls_coverage"] = len(tls_enabled) / len(web_hosts) * 100
            
            # Analyze weaknesses
            if defense_analysis["waf_coverage"] < 50:
                defense_analysis["weaknesses"].append({
                    "issue": "Insufficient WAF Coverage",
                    "description": f"Only {defense_analysis['waf_coverage']:.1f}% of web hosts protected by WAF",
                    "recommendation": "Deploy WAF on all public-facing web applications"
                })
            else:
                defense_analysis["strengths"].append("Good WAF deployment")
            
            if defense_analysis["tls_coverage"] < 100:
                defense_analysis["weaknesses"].append({
                    "issue": "Incomplete TLS Deployment",
                    "description": f"{defense_analysis['tls_coverage']:.1f}% TLS coverage - some HTTP-only services",
                    "recommendation": "Enable HTTPS on all web services"
                })
            else:
                defense_analysis["strengths"].append("Full TLS encryption")
        
        return defense_analysis
    
    @staticmethod
    def _identify_attack_chains(hosts: List[Host], findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Identify potential attack chains
        Example: Exposed admin panel + weak auth + DB on same host = critical chain
        """
        chains = []
        
        for host in hosts:
            chain_risk = []
            
            # Chain 1: Web + DB + No WAF
            web_services = [s for s in host.services if s.port in [80, 443, 8080, 8443] and s.state == 'open']
            db_services = [s for s in host.services if s.port in [3306, 5432, 27017] and s.state == 'open']
            has_waf = host.web_context and host.web_context.waf_detected
            
            if web_services and db_services and not has_waf:
                chain_risk.append("web_db_no_waf")
                chains.append({
                    "host": host.ip,
                    "chain": "Web → SQLi → Database Compromise",
                    "steps": [
                        "1. Web application exposed without WAF protection",
                        "2. SQL injection possible in web app",
                        "3. Database on same host = direct access after SQLi",
                        "4. Potential data exfiltration and lateral movement"
                    ],
                    "severity": Severity.CRITICAL,
                    "likelihood": "High",
                    "recommendation": "Separate web and DB tiers, deploy WAF, use parameterized queries"
                })
            
            # Chain 2: CMS + Outdated Plugins + No Updates
            if host.web_context and host.web_context.cms_detected:
                cms_findings = [f for f in findings if "plugin" in f.title.lower() or "theme" in f.title.lower()]
                if len(cms_findings) > 3:
                    chains.append({
                        "host": host.ip,
                        "chain": "Vulnerable CMS → RCE → Server Takeover",
                        "steps": [
                            f"1. {host.web_context.cms_detected} CMS detected",
                            f"2. {len(cms_findings)} vulnerable plugins/themes identified",
                            "3. Exploit plugin vulnerability for code execution",
                            "4. Escalate to full server compromise"
                        ],
                        "severity": Severity.HIGH,
                        "likelihood": "Medium",
                        "recommendation": "Update all plugins and themes immediately, remove unused components"
                    })
            
            # Chain 3: SSH + Weak Creds + Internal Services
            ssh_services = [s for s in host.services if s.port == 22 and s.state == 'open']
            internal_services = [s for s in host.services if s.port in [3306, 5432, 6379, 27017] and s.state == 'open']
            
            if ssh_services and internal_services:
                chains.append({
                    "host": host.ip,
                    "chain": "SSH Brute Force → Internal Services Access",
                    "steps": [
                        "1. SSH exposed publicly",
                        "2. Brute force or credential stuffing attack",
                        "3. Access to internal services (DB, cache, etc.)",
                        "4. Data access and lateral movement"
                    ],
                    "severity": Severity.HIGH,
                    "likelihood": "Medium",
                    "recommendation": "Restrict SSH to VPN, use key-based auth, enable fail2ban"
                })
        
        return chains
    
    @staticmethod
    def _cluster_risks(hosts: List[Host], findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Group related risks into clusters for better understanding
        """
        clusters = []
        
        # Cluster 1: Encryption Issues
        encryption_findings = [f for f in findings if any(
            keyword in f.title.lower() or keyword in f.category.lower()
            for keyword in ['ssl', 'tls', 'encryption', 'cipher', 'certificate']
        )]
        
        if encryption_findings:
            clusters.append({
                "cluster": "Encryption & Transport Security",
                "count": len(encryption_findings),
                "severity": max([f.severity for f in encryption_findings], key=lambda s: list(Severity).index(s)),
                "summary": "Multiple encryption-related issues detected",
                "findings": encryption_findings[:5]  # Top 5
            })
        
        # Cluster 2: Authentication & Access Control
        auth_findings = [f for f in findings if any(
            keyword in f.title.lower()
            for keyword in ['auth', 'login', 'credential', 'password', 'user enum']
        )]
        
        if auth_findings:
            clusters.append({
                "cluster": "Authentication & Access Control",
                "count": len(auth_findings),
                "severity": max([f.severity for f in auth_findings], key=lambda s: list(Severity).index(s)),
                "summary": "Authentication weaknesses identified",
                "findings": auth_findings[:5]
            })
        
        # Cluster 3: Information Disclosure
        disclosure_findings = [f for f in findings if any(
            keyword in f.title.lower()
            for keyword in ['disclosure', 'exposed', 'leak', 'version', 'banner']
        )]
        
        if disclosure_findings:
            clusters.append({
                "cluster": "Information Disclosure",
                "count": len(disclosure_findings),
                "severity": max([f.severity for f in disclosure_findings], key=lambda s: list(Severity).index(s)),
                "summary": "Excessive information exposure detected",
                "findings": disclosure_findings[:5]
            })
        
        # Cluster 4: CMS & Web Application
        cms_findings = [f for f in findings if any(
            keyword in f.category.lower()
            for keyword in ['cms', 'web', 'plugin', 'theme']
        )]
        
        if cms_findings:
            clusters.append({
                "cluster": "CMS & Web Application Security",
                "count": len(cms_findings),
                "severity": max([f.severity for f in cms_findings], key=lambda s: list(Severity).index(s)),
                "summary": "CMS-specific vulnerabilities found",
                "findings": cms_findings[:5]
            })
        
        return clusters
    
    @staticmethod
    def _filter_false_positives(findings: List[Finding]) -> Dict[str, Any]:
        """
        Identify and filter potential false positives
        """
        filtered = {
            "likely_false_positives": [],
            "requires_verification": [],
            "high_confidence": []
        }
        
        for finding in findings:
            confidence = getattr(finding, 'confidence_score', 0.5)
            
            # Low confidence = potential FP
            if confidence < 0.3:
                filtered["likely_false_positives"].append({
                    "finding": finding.title,
                    "reason": "Low confidence score from automated tool",
                    "confidence": confidence
                })
            
            # Medium confidence = verify
            elif confidence < 0.7:
                filtered["requires_verification"].append({
                    "finding": finding.title,
                    "confidence": confidence
                })
            
            # High confidence
            else:
                filtered["high_confidence"].append({
                    "finding": finding.title,
                    "confidence": confidence
                })
        
        return filtered
    
    @staticmethod
    def _generate_insights(hosts: List[Host], findings: List[Finding], 
                          correlations: Dict[str, Any]) -> List[str]:
        """
        Generate high-level contextual insights
        """
        insights = []
        
        # Insight 1: Overall exposure
        total_services = sum(len([s for s in h.services if s.state == 'open']) for h in hosts)
        insights.append(
            f"Total Attack Surface: {total_services} open services across {len(hosts)} hosts"
        )
        
        # Insight 2: Segmentation quality
        seg = correlations.get("network_segmentation", {})
        if seg.get("quality") == "Poor":
            insights.append(
                "⚠️ CRITICAL: Poor network segmentation detected - services are not properly isolated"
            )
        
        # Insight 3: Defense depth
        defense = correlations.get("defense_posture", {})
        if defense.get("waf_coverage", 0) < 50:
            insights.append(
                f"⚠️ Limited WAF deployment: Only {defense.get('waf_coverage', 0):.1f}% of web apps protected"
            )
        
        # Insight 4: Critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            insights.append(
                f"🔴 {len(critical_findings)} CRITICAL findings require immediate attention"
            )
        
        # Insight 5: Attack chains
        chains = correlations.get("attack_chains", [])
        if chains:
            insights.append(
                f"⛓️ {len(chains)} potential attack chains identified - multi-step exploitation possible"
            )
        
        # Insight 6: CMS risks
        cms_hosts = [h for h in hosts if h.web_context and h.web_context.cms_detected]
        if cms_hosts:
            cms_list = list(set([h.web_context.cms_detected for h in cms_hosts]))
            insights.append(
                f"CMS Detected: {', '.join(cms_list)} - Requires specialized monitoring and patching"
            )
        
        return insights
