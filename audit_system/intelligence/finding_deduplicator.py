"""
Finding Deduplication System
v17.4: Fingerprinting and grouping of similar findings

Meowware - Developed by Carlos Mancera
"""
import hashlib
from typing import List, Dict, Any, Set
from ..core.models import Finding, Severity
from ..core.debug import debug_print

class FindingDeduplicator:
    """Deduplicates and groups similar findings"""
    
    def __init__(self):
        self.fingerprint_cache = {}  # Cache of fingerprints seen
    
    def fingerprint_finding(self, finding: Finding) -> str:
        """Generate unique fingerprint for a finding"""
        # v17.6: Improved fingerprinting - group by security control, not tool
        # Extract security control from title/description
        title_lower = finding.title.lower().strip()
        desc_lower = finding.description[:200].lower().strip() if finding.description else ""
        
        # Normalize security controls (e.g., "DNSSEC Missing" = "DNSSEC")
        security_control = title_lower
        if "dnssec" in title_lower or "dnssec" in desc_lower:
            security_control = "dnssec"
        elif "dmarc" in title_lower or "dmarc" in desc_lower:
            security_control = "dmarc"
        elif "spf" in title_lower or "spf" in desc_lower:
            security_control = "spf"
        elif "sql injection" in title_lower or "sqli" in title_lower:
            security_control = "sql_injection"
        elif "xss" in title_lower:
            security_control = "xss"
        elif "mysql" in title_lower and "exposed" in title_lower:
            security_control = "mysql_exposure"
        elif "hsts" in title_lower or "hsts" in desc_lower:
            security_control = "hsts"
        elif "ssl" in title_lower or "tls" in title_lower:
            security_control = "ssl_tls"
        
        # Create fingerprint based on security control, not tool
        key_parts = [
            security_control,
            finding.category.lower().strip(),
            str(finding.severity),
            # Extract host IP if available
            self._extract_host_ip(finding.title) or "unknown"
        ]
        
        fingerprint_str = "|".join(key_parts)
        fingerprint = hashlib.md5(fingerprint_str.encode()).hexdigest()
        return fingerprint
    
    def _extract_host_ip(self, title: str) -> str:
        """Extract host IP from finding title"""
        import re
        ip_match = re.search(r'\(([0-9a-fA-F:.]+)\)', title)
        return ip_match.group(1) if ip_match else ""
    
    def deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on fingerprinting"""
        seen_fingerprints: Set[str] = set()
        unique_findings = []
        duplicates_count = 0
        
        for finding in findings:
            fingerprint = self.fingerprint_finding(finding)
            
            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                unique_findings.append(finding)
                self.fingerprint_cache[fingerprint] = finding
            else:
                duplicates_count += 1
                # Update existing finding if this one has more evidence
                existing = self.fingerprint_cache.get(fingerprint)
                if existing and finding.raw_output and (not existing.raw_output or len(finding.raw_output) > len(existing.raw_output)):
                    # Replace with more detailed finding
                    idx = unique_findings.index(existing)
                    unique_findings[idx] = finding
                    self.fingerprint_cache[fingerprint] = finding
        
        if duplicates_count > 0:
            debug_print(f"    [Deduplicator] Removed {duplicates_count} duplicate findings")
        
        return unique_findings
    
    def group_similar_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by similarity (same category, severity, host)"""
        groups = {}
        
        for finding in findings:
            # Create group key based on category, severity, and host
            host_ip = ""
            if finding.title:
                # Try to extract IP from title
                import re
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', finding.title)
                if ip_match:
                    host_ip = ip_match.group(0)
            
            group_key = f"{finding.category}_{finding.severity}_{host_ip}"
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(finding)
        
        return groups
    
    def consolidate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Consolidate similar findings into single entries"""
        # First deduplicate
        unique_findings = self.deduplicate_findings(findings)
        
        # Group by similarity
        groups = self.group_similar_findings(unique_findings)
        
        consolidated = []
        for group_key, group_findings in groups.items():
            if len(group_findings) == 1:
                consolidated.append(group_findings[0])
            else:
                # Consolidate multiple similar findings
                primary = group_findings[0]
                
                # Update description to mention multiple occurrences
                if len(group_findings) > 1:
                    primary.description = f"{primary.description} (Found in {len(group_findings)} locations)"
                    # Combine raw outputs
                    all_outputs = [f.raw_output for f in group_findings if f.raw_output]
                    if all_outputs:
                        primary.raw_output = "\n---\n".join(all_outputs)
                
                consolidated.append(primary)
                debug_print(f"    [Deduplicator] Consolidated {len(group_findings)} similar findings into 1")
        
        return consolidated

