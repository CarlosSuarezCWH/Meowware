"""
JavaScript Deep Analyzer
Extracts secrets, API endpoints, and DOM sinks from JS files.
Meowware v19.0 - Web Deep Dive
"""
import re
from typing import List, Dict, Any, Set
from ..core.models import Finding, Severity, EvidenceType

class JSAnalyzer:
    """
    Analyzes JavaScript content for offensive intelligence.
    """
    
    def __init__(self):
        # Regex for secrets
        self.secret_patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z_\-]{35}",
            "Generic API Key": r"(?i)api_key\s*[:=]\s*['\"]([a-zA-Z0-9.\-_]{20,})['\"]",
            "JWT Token": r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}"
        }
        
        # Regex for endpoints
        self.endpoint_pattern = r"(?i)['\"](/[a-z0-9_./\-]+|https?://[a-z0-9_./\-]+)['\"]"
        
        # DOM Sinks (DOM XSS)
        self.sink_patterns = [
            "innerHTML", "outerHTML", "document.write", 
            "location.href", "eval(", "setTimeout(", "setInterval("
        ]

    def analyze_js(self, js_content: str, url: str) -> List[Finding]:
        """
        Analyze a single JS file content.
        """
        findings = []
        
        # 1. Secret Detection
        findings.extend(self._find_secrets(js_content, url))
        
        # 2. Endpoint Extraction (Information Gathering)
        # We don't make findings for every endpoint, but could aggregate them.
        # For this implementation, we report interesting ones (e.g. /api/v1/admin)
        endpoints = self._find_endpoints(js_content)
        admin_endpoints = [e for e in endpoints if "admin" in e.lower() or "private" in e.lower()]
        
        if admin_endpoints:
            findings.append(Finding(
                title=f"Sensitive Endpoints in JS",
                description=f"Found sensitive endpoints in {url}:\n" + "\n".join(admin_endpoints[:10]),
                recommendation="Review exposed endpoints for access control.",
                severity=Severity.MEDIUM,
                category="Information Leak",
                evidence_type=EvidenceType.STATIC_ANALYSIS,
                confidence_score=1.0
            ))
            
        # 3. DOM Sink Detection
        # Simple heuristic: if sink exists + looks like it takes input
        # Refinement: Just report usage of dangerous functions for now
        sinks_found = [sink for sink in self.sink_patterns if sink in js_content]
        if sinks_found:
             findings.append(Finding(
                title=f"Dangerous DOM Sinks in JS",
                description=f"Dangerous functions found in {url}: {', '.join(sinks_found)}.\nPotential DOM XSS.",
                recommendation="Audit usage of these sinks with user input.",
                severity=Severity.LOW, # Requires manual verification usually
                category="DOM XSS",
                evidence_type=EvidenceType.STATIC_ANALYSIS,
                confidence_score=0.6
            ))

        return findings
    
    def _find_secrets(self, content: str, url: str) -> List[Finding]:
        findings = []
        for name, pattern in self.secret_patterns.items():
            matches = re.findall(pattern, content)
            for match in matches:
                # Basic False Positive Reduction
                if "EXAMPLE" in match or "test" in match.lower():
                    continue
                    
                finding = Finding(
                    title=f"Leaked {name} in JS",
                    description=f"Found potential {name} in {url}.\nMatch: {match[:5]}...{match[-5:]}",
                    recommendation="Rotate key and remove from client-side code.",
                    severity=Severity.CRITICAL if "live" in match or "key" in name.lower() else Severity.HIGH,
                    category="Secret Leak",
                    evidence_type=EvidenceType.STATIC_ANALYSIS,
                    confidence_score=0.9
                )
                findings.append(finding)
        return findings

    def _find_endpoints(self, content: str) -> Set[str]:
        matches = re.findall(self.endpoint_pattern, content)
        # Filter junk
        valid = set()
        for m in matches:
            if len(m) < 4 or " " in m or "\n" in m: continue
            if m.endswith(".js") or m.endswith(".css") or m.endswith(".png"): continue
            valid.add(m)
        return valid
