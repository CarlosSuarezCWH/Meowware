"""
v17.6: Finding Validator - Ensures findings have proper evidence before marking as CRITICAL
Prevents false positives and over-confidence in findings
"""
from typing import Dict, Any, Optional
from enum import Enum
from ..core.models import Finding, Severity, EvidenceType, FindingStatus
from ..core.debug import debug_print


class FindingValidator:
    """Validates findings and adjusts severity based on evidence"""
    
    @staticmethod
    def validate_sql_injection(finding: Finding) -> Dict[str, Any]:
        """
        Validates SQL Injection findings.
        CRITICAL only if CONFIRMED with evidence.
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        
        # Check for evidence indicators
        has_payload = any(marker in desc_lower for marker in [
            'payload', 'injection point', 'parameter', 'vulnerable parameter',
            'sqlmap', 'injectable', 'time-based', 'boolean-based', 'error-based'
        ])
        
        has_response = any(marker in desc_lower for marker in [
            'response', 'differential', 'time delay', 'error message',
            'database error', 'syntax error'
        ])
        
        has_parameter = any(marker in desc_lower for marker in [
            'parameter', 'query string', 'post data', 'get parameter'
        ])
        
        # Determine status
        if has_payload and has_response:
            status = FindingStatus.CONFIRMED
            severity = Severity.CRITICAL
            confidence = 0.95
        elif has_parameter and (has_response or has_payload):
            status = FindingStatus.LIKELY
            severity = Severity.HIGH
            confidence = 0.75
        elif 'mysql' in desc_lower and 'exposed' in desc_lower:
            # MySQL exposed + web = architectural risk, not confirmed SQLi
            status = FindingStatus.ARCHITECTURAL_RISK
            severity = Severity.HIGH  # Not CRITICAL without evidence
            confidence = 0.60
            # Update description to be more accurate
            finding.description = (
                "Architectural Risk: Database (MySQL) and web services are on the same host without proper network segmentation. "
                "This increases the impact of potential web vulnerabilities but does not confirm SQL injection. "
                "Recommendation: Implement network segmentation and verify SQL injection through controlled testing."
            )
        else:
            status = FindingStatus.POTENTIAL
            severity = Severity.MEDIUM  # Downgrade from CRITICAL
            confidence = 0.50
        
        return {
            'status': status,
            'severity': severity,
            'confidence': confidence,
            'has_evidence': has_payload and has_response,
            'reason': 'Confirmed SQLi' if status == FindingStatus.CONFIRMED else 
                     'Likely SQLi' if status == FindingStatus.LIKELY else
                     'Architectural risk' if status == FindingStatus.ARCHITECTURAL_RISK else
                     'Potential SQLi (no evidence)'
        }
    
    @staticmethod
    def validate_finding(finding: Finding) -> Finding:
        """
        Validates and adjusts a finding based on evidence.
        Returns adjusted finding.
        """
        title_lower = finding.title.lower()
        
        # General Status Classification (New in v19.0)
        if "configuration" in finding.category.lower() or "misconfig" in finding.evidence_type.value:
            finding.status = FindingStatus.CONFIGURATION_WEAKNESS
        elif finding.evidence_type == EvidenceType.RECON:
            finding.status = FindingStatus.POTENTIAL
        
        # SQL Injection validation specifically
        if 'sql injection' in title_lower or 'sqli' in title_lower:
            validation = FindingValidator.validate_sql_injection(finding)
            
            # Adjust severity and confidence
            finding.severity = validation['severity']
            finding.confidence_score = validation['confidence']
            finding.status = validation['status']
            
            # Add status to description if not CONFIRMED
            if validation['status'] != FindingStatus.CONFIRMED:
                status_note = f"\n\n[STATUS: {validation['status'].value}] {validation['reason']}"
                if validation['status'] == FindingStatus.ARCHITECTURAL_RISK:
                    status_note += " - This is an architectural risk, not a confirmed vulnerability."
                elif validation['status'] == FindingStatus.POTENTIAL:
                    status_note += " - Evidence required to confirm. Manual verification recommended."
                
                if status_note not in finding.description:
                    finding.description += status_note
                
                # Update evidence type
                if validation['status'] == FindingStatus.ARCHITECTURAL_RISK:
                    finding.evidence_type = EvidenceType.HEURISTIC
                elif not validation['has_evidence']:
                    finding.evidence_type = EvidenceType.HEURISTIC
            
            debug_print(f"    [Validator] SQL Injection: {validation['status'].value} → Severity: {validation['severity'].name}, Confidence: {validation['confidence']:.0%}")
        
        # Critical Severity Guard (New in v19.0)
        # Prevent CRITICAL findings without strong evidence
        if finding.severity == Severity.CRITICAL:
            if not FindingValidator.has_sufficient_evidence(finding):
                 debug_print(f"    [Validator] Downgrading CRITICAL finding '{finding.title}' due to lack of evidence")
                 finding.severity = Severity.HIGH
                 finding.status = FindingStatus.LIKELY if finding.status == FindingStatus.CONFIRMED else finding.status
                 if finding.confidence_score > 0.8:
                     finding.confidence_score = 0.8

        return finding
    
    @staticmethod
    def requires_evidence(severity: Severity) -> bool:
        """Check if a severity level requires evidence"""
        return severity in [Severity.CRITICAL] # v19.0: Only CRITICAL strictly requires evidence, HIGH is acceptable for likely risks
    
    @staticmethod
    def has_sufficient_evidence(finding: Finding) -> bool:
        """Check if finding has sufficient evidence for its severity"""
        if not FindingValidator.requires_evidence(finding.severity):
            return True  # Low/Info/Medium/High don't strictly *need* evidence to exist (though encouraged)
        
        # for CRITICAL, we need strong evidence
        
        # Check for evidence indicators
        has_raw_output = bool(finding.raw_output and finding.raw_output.strip() and len(finding.raw_output) > 20)
        has_detailed_desc = len(finding.description) > 100
        
        # Check for technical evidence
        desc_lower = finding.description.lower()
        has_technical_evidence = any(marker in desc_lower for marker in [
            'payload', 'response', 'evidence', 'proof', 'confirmed',
            'vulnerable', 'exploitable', 'cve-', 'exploit', 'shell', 'root'
        ])

        # If it came from a trusted tool with non-empty output, it's generally good
        # But for CRITICAL we want to be sure
        
        return (has_raw_output and has_technical_evidence) or (finding.status == FindingStatus.CONFIRMED)



