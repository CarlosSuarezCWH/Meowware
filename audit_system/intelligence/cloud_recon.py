"""
Cloud Reconnaissance Module
Enumerates public cloud resources (S3, Azure, GCP) and checks for DNS misconfigurations.
Meowware v19.0 - Offensive Recon
"""
import requests
import socket
import re
from typing import List, Dict, Any
from ..core.models import Finding, Host, Severity, EvidenceType
from ..core.debug import debug_print

class CloudRecon:
    """
    Advanced Cloud Enumeration & DNS Analysis.
    Focuses on high-impact cloud leaks and subdomain takeovers.
    """
    
    def __init__(self):
        # Known patterns for cloud storage
        self.bucket_patterns = [
            # AWS S3
            "http://{name}.s3.amazonaws.com",
            "http://s3.amazonaws.com/{name}",
            # Azure Blob
            "http://{name}.blob.core.windows.net",
            # GCP Storage
            "http://storage.googleapis.com/{name}"
        ]
        
        # Permutations to try
        self.permutations = [
            "", "-dev", "-test", "-prod", "-backup", "-static", "-assets", 
            "-internal", "-staging", ".bak", "_bak"
        ]

    def check_cloud_exposure(self, host: Host) -> List[Finding]:
        """
        Check for exposed cloud buckets related to the host/domain.
        """
        debug_print(f"    [CloudRecon] Enumerating cloud assets for {host.hostname or host.ip}")
        findings = []
        
        target_name = self._extract_base_name(host)
        if not target_name:
            return []

        # 1. Bucket Enumeration
        for pattern in self.bucket_patterns:
            for perm in self.permutations:
                guess_name = f"{target_name}{perm}"
                url = pattern.format(name=guess_name)
                
                try:
                    # Low timeout to be fast. We care about existence.
                    res = requests.head(url, timeout=2)
                    
                    if res.status_code == 200:
                        # Publicly listable or accessible file found (rare for root, but checking)
                        findings.append(self._create_bucket_finding(url, "Publicly Accessible", Severity.HIGH))
                    elif res.status_code == 403:
                        # Exists but protected. Still finding because it confirms cloud usage.
                        # Important for "Enumeration" phase.
                        findings.append(self._create_bucket_finding(url, "Protected (Exists)", Severity.INFO))
                        
                except Exception:
                    continue

        return findings

    def analyze_dns_history(self, host: Host) -> List[Finding]:
        """
        Analyze DNS for potential subdomain takeovers (CNAMEs to dead services).
        """
        # This would typically use an external API. 
        # For this simulated environment, we check current CNAMEs if available.
        findings = []
        
        # Mock logic: If we had a way to resolve CNAMEs here.
        # In real tools: `dig CNAME domain`
        
        return findings

    def _extract_base_name(self, host: Host) -> str:
        """Extract base name for permutation (e.g., 'example.com' -> 'example')"""
        if not host.hostname:
            return ""
        
        # Remove TLD
        parts = host.hostname.split('.')
        if len(parts) >= 2:
            return parts[0]
        return host.hostname

    def _create_bucket_finding(self, url: str, status: str, severity: Severity) -> Finding:
        return Finding(
            title=f"Cloud Bucket Found: {url}",
            description=f"Enumerated cloud storage bucket. Status: {status}.\nURL: {url}",
            recommendation="Ensure permissions are restricted. Check for sensitive data.",
            severity=severity,
            category="Cloud",
            evidence_type=EvidenceType.RECON,
            confidence_score=1.0 # It exists
        )
