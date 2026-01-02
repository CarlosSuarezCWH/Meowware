"""
Actionable Recommendations Engine (Senior Grade)

Generates professional remediation instructions based on exposure levels and context.
"""

from typing import Dict, List
from ..core.models import Finding, Severity

class RecommendationEngine:
    """
    Provides detailed, context-aware remediation steps for security findings.
    """
    
    # Professional remediation templates
    RECOMMENDATIONS = {
        "MySQL Unauthenticated Access (Level 3)": {
            "steps": [
                "1. CRITICAL: Immediate Action Required.",
                "2. Set strong root password: ALTER USER 'root'@'localhost' IDENTIFIED BY '...';",
                "3. Restrict binding to 127.0.0.1 in my.cnf.",
                "4. Disable remote root login.",
                "5. Implement firewall (iptables/nftables) to drop external traffic to 3306."
            ],
            "verification": "Attempt 'mysql -h <target> -u root' from external IP.",
            "risk": "CRITICAL - Full database exposure/compromise."
        },
        
        "MySQL Banner Grabbing (Level 1)": {
            "steps": [
                "1. Low priority cleanup.",
                "2. Update/Patch MySQL to latest stable version.",
                "3. Ensure 'version_compile_os' and other metadata are not easily enumerable.",
                "4. Restrict port visibility to known administrative IPs only."
            ],
            "verification": "Run 'nmap -sV -p 3306' and check for explicit version disclosure.",
            "risk": "LOW - Reconnaissance aid."
        },

        "SMTP Open Relay": {
            "steps": [
                "1. Disable open relay in MTA configuration (Postfix/Exim).",
                "2. Implement SASL authentication for mail submission.",
                "3. Restrict relaying to trusted internal networks only.",
                "4. Enable STARTTLS for all connections."
            ],
            "verification": "Use an Open Relay checker or manual telnet/swaks test.",
            "risk": "CRITICAL - Domain reputation/SPAM risk."
        },

        "Weak Crypto": {
            "steps": [
                "1. Disable TLS 1.0, 1.1 and all versions of SSL.",
                "2. Remove legacy ciphers (CBC, RC4, DES, 3DES).",
                "3. Standardize on TLS 1.2+ with GCM/CHACHA20 suites.",
                "4. Implement HSTS headers if applicable."
            ],
            "verification": "Run 'sslscan' or 'testssl.sh'.",
            "risk": "MEDIUM - Potential for MITM/Downgrade attacks."
        }
    }
    
    @staticmethod
    def get_recommendation(finding: Finding) -> str:
        """
        Retrieves professional recommendation based on finding title.
        """
        title = finding.title.split('(')[0].strip()
        
        # Match against our structured templates
        for key, rec in RecommendationEngine.RECOMMENDATIONS.items():
            if key in title:
                lines = [f"\n   [REMEDIATION PLAN]"]
                lines.append(f"   Severity: {finding.severity.name}")
                lines.append(f"   Impact: {rec['risk']}")
                lines.append("\n   Action Steps:")
                for step in rec['steps']:
                    lines.append(f"     {step}")
                lines.append(f"\n   Verification:")
                lines.append(f"     {rec['verification']}")
                return "\n".join(lines)
        
        # Default simple extraction if no template matches
        return finding.recommendation
    
    @staticmethod
    def enhance_findings(findings: List[Finding]) -> List[Finding]:
        """
        Enhance finding objects with detailed remediation plans.
        """
        for finding in findings:
            if finding.severity in [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]:
                finding.recommendation = RecommendationEngine.get_recommendation(finding)
        return findings
