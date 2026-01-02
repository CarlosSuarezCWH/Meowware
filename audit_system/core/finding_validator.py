"""
v17.6: Finding Validator - Ensures findings have proper evidence before marking as CRITICAL
Prevents false positives and over-confidence in findings
"""
from typing import Dict, Any, Optional
from enum import Enum
from ..core.models import Finding, Severity, EvidenceType
from ..core.debug import debug_print

class FindingStatus(str, Enum):
    """Status of a finding based on evidence"""
    POTENTIAL = "POTENTIAL"  # Risk identified but not confirmed
    LIKELY = "LIKELY"  # Strong indicators but no direct proof
    CONFIRMED = "CONFIRMED"  # Direct evidence of vulnerability
    ARCHITECTURAL_RISK = "ARCHITECTURAL_RISK"  # Bad practice, not direct vulnerability

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
        
        # SQL Injection validation
        if 'sql injection' in title_lower or 'sqli' in title_lower:
            validation = FindingValidator.validate_sql_injection(finding)
            
            # Adjust severity and confidence
            finding.severity = validation['severity']
            finding.confidence_score = validation['confidence']
            
            # Add status to description if not CONFIRMED
            if validation['status'] != FindingStatus.CONFIRMED:
                status_note = f"\n\n[STATUS: {validation['status'].value}] {validation['reason']}"
                if validation['status'] == FindingStatus.ARCHITECTURAL_RISK:
                    status_note += " - This is an architectural risk, not a confirmed vulnerability."
                elif validation['status'] == FindingStatus.POTENTIAL:
                    status_note += " - Evidence required to confirm. Manual verification recommended."
                
                finding.description += status_note
                
                # Update evidence type
                if validation['status'] == FindingStatus.ARCHITECTURAL_RISK:
                    finding.evidence_type = EvidenceType.HEURISTIC
                elif not validation['has_evidence']:
                    finding.evidence_type = EvidenceType.HEURISTIC
            
            debug_print(f"    [Validator] SQL Injection: {validation['status'].value} → Severity: {validation['severity'].name}, Confidence: {validation['confidence']:.0%}")
        
        return finding
    
    @staticmethod
    def requires_evidence(severity: Severity) -> bool:
        """Check if a severity level requires evidence"""
        return severity in [Severity.CRITICAL, Severity.HIGH]
    
    @staticmethod
    def has_sufficient_evidence(finding: Finding) -> bool:
        """Check if finding has sufficient evidence for its severity"""
        if not FindingValidator.requires_evidence(finding.severity):
            return True  # Low/Info don't need strong evidence
        
        # Check for evidence indicators
        has_raw_output = bool(finding.raw_output and finding.raw_output.strip())
        has_detailed_desc = len(finding.description) > 100
        
        # Check for technical evidence
        desc_lower = finding.description.lower()
        has_technical_evidence = any(marker in desc_lower for marker in [
            'payload', 'response', 'evidence', 'proof', 'confirmed',
            'vulnerable', 'exploitable', 'cve-', 'exploit'
        ])
        
        return has_raw_output or (has_detailed_desc and has_technical_evidence)


