"""
Business Risk Prioritization
v16.2: Dynamic prioritization based on business context

Meowware - Developed by Carlos Mancera
"""
from typing import Dict, Any, List
from ..core.models import Host, Finding, Severity
from ..core.debug import debug_print

class BusinessRiskPrioritizer:
    """Prioritizes findings based on business context, not just technical severity"""
    
    # Business risk multipliers based on context
    BUSINESS_CONTEXT_WEIGHTS = {
        # Authentication/Authorization contexts
        "login_page": 2.5,
        "auth_endpoint": 2.5,
        "admin_panel": 3.0,
        "api_auth": 2.0,
        
        # Data storage contexts
        "database_public": 3.0,
        "database_internal": 2.0,
        "file_storage": 1.5,
        
        # API contexts
        "api_endpoint": 1.8,
        "graphql": 2.0,
        "rest_api": 1.8,
        
        # Payment/Financial contexts
        "payment": 3.5,
        "checkout": 3.0,
        "billing": 2.5,
        
        # User data contexts
        "user_data": 2.5,
        "profile": 2.0,
        "personal_info": 2.5,
        
        # Infrastructure contexts
        "edge_node": 0.3,  # Cloudflare, etc.
        "static_content": 0.5,
        "cdn": 0.4,
        
        # Critical services
        "mail_server": 2.0,
        "dns_server": 1.8,
        "ssh_server": 2.2,
    }
    
    # Keywords to detect context
    CONTEXT_KEYWORDS = {
        "login_page": ["login", "signin", "auth", "authentication", "sign-in"],
        "admin_panel": ["admin", "administrator", "dashboard", "panel", "manage"],
        "api_endpoint": ["/api", "/rest", "/graphql", "/v1", "/v2"],
        "database_public": ["mysql", "postgresql", "mongodb", "redis", "database"],
        "payment": ["payment", "checkout", "billing", "stripe", "paypal", "credit"],
        "user_data": ["user", "profile", "account", "personal"],
        "mail_server": ["smtp", "imap", "pop3", "mail"],
    }
    
    def prioritize_findings(self, findings: List[Finding], hosts: List[Host]) -> List[Finding]:
        """
        Re-prioritize findings based on business context
        
        Args:
            findings: List of findings
            hosts: List of hosts for context
        
        Returns:
            Re-prioritized findings with adjusted severity
        """
        prioritized = []
        
        for finding in findings:
            # Detect business context
            context_score = self._detect_business_context(finding, hosts)
            
            # Adjust severity if context is high-risk
            if context_score >= 2.0:
                # Upgrade severity for high business risk
                if finding.severity == Severity.LOW:
                    finding.severity = Severity.MEDIUM
                elif finding.severity == Severity.MEDIUM:
                    finding.severity = Severity.HIGH
                elif finding.severity == Severity.HIGH and context_score >= 3.0:
                    finding.severity = Severity.CRITICAL
                
                # Add business context note
                finding.description += f"\n\n[Business Risk Context]: High business impact detected (multiplier: {context_score:.1f}x)."
                debug_print(f"  [Business Risk] Upgraded {finding.title} due to business context (score: {context_score:.1f}x)")
            
            prioritized.append(finding)
        
        # Sort by severity (now adjusted)
        prioritized.sort(key=lambda f: self._severity_weight(f.severity), reverse=True)
        
        return prioritized
    
    def _detect_business_context(self, finding: Finding, hosts: List[Host]) -> float:
        """Detect business context and return multiplier"""
        max_score = 1.0
        
        # Check finding title and description
        text = f"{finding.title} {finding.description}".lower()
        
        # Check for context keywords
        for context, keywords in self.CONTEXT_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                weight = self.BUSINESS_CONTEXT_WEIGHTS.get(context, 1.0)
                max_score = max(max_score, weight)
        
        # Check host context
        for host in hosts:
            if hasattr(finding, 'title') and host.ip in finding.title:
                # Check hostname for context
                hostname = (host.hostname or "").lower()
                if any(keyword in hostname for keyword in ["admin", "login", "api", "payment"]):
                    max_score = max(max_score, 2.0)
                
                # Check services
                if hasattr(host, 'services'):
                    for service in host.services:
                        if service.name.lower() in ["mysql", "postgresql", "mongodb"]:
                            max_score = max(max_score, 2.5)
                        elif service.name.lower() in ["smtp", "imap"]:
                            max_score = max(max_score, 2.0)
        
        return max_score
    
    def _severity_weight(self, severity: Severity) -> int:
        """Get numeric weight for severity"""
        weights = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        return weights.get(severity, 1)



