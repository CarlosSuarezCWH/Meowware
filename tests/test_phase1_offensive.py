
import unittest
from unittest.mock import MagicMock
from audit_system.core.models import Finding, Severity, Host, EvidenceType
from audit_system.exploitation.mitre_attack import MITREAttackChainBuilder, ATTACKTactic
from audit_system.exploitation.safe_verifier import SafeExploitVerifier

class TestPhase1Offensive(unittest.TestCase):
    
    def setUp(self):
        self.host = Host(ip="192.168.1.100")
    
    def test_attack_chain_builder(self):
        """Test probabilistic attack chain generation"""
        findings = [
            Finding(
                title="SQL Injection in login", 
                category="Injection",
                severity=Severity.CRITICAL,
                description="Confirmed SQLi via sqlmap",
                recommendation="Fix it",
                confidence_score=0.9
            ),
            Finding(
                title="Weak SSH Password",
                category="Auth",
                severity=Severity.HIGH,
                description="Default credentials root:root",
                recommendation="Change password",
                confidence_score=1.0
            )
        ]
        
        builder = MITREAttackChainBuilder()
        chain = builder.build_chain(self.host, findings)
        
        # Check if chain has steps
        self.assertTrue(len(chain.steps) > 0)
        
        # Check for specific tactics we expect from the graph logic
        tactics = [s.tactic for s in chain.steps]
        self.assertIn(ATTACKTactic.INITIAL_ACCESS, tactics) # From SQLi or Creds
        
        # Check impact score (should be high due to critical findings)
        self.assertGreater(chain.impact_score, 0)
        
        # Check graph connectivity (internal method check if needed, but integration test covers build_chain)

    def test_safe_verifier_sqli(self):
        """Test SafeVerifier logic for SQLi"""
        verifier = SafeExploitVerifier()
        finding = Finding(
            title="Potential SQL Injection",
            severity=Severity.HIGH,
            description="Parameter 'id' appears vulnerable to time-based blind SQLi (sleep)",
            recommendation="Fix inputs",
            category="Injection"
        )
        
        # Since our mock implementation basically checks description for keywords (Simulation)
        result = verifier.verify(finding, self.host)
        
        self.assertTrue(result['verified'])
        self.assertIn("time-based", result['method'])

    def test_safe_verifier_xss(self):
        """Test SafeVerifier logic for XSS"""
        verifier = SafeExploitVerifier()
        finding = Finding(
            title="Reflected XSS",
            severity=Severity.MEDIUM,
            description="Input reflected in response body.",
            recommendation="Encode output",
            category="XSS"
        )
        
        result = verifier.verify(finding, self.host)
        
        self.assertTrue(result['verified'])
        self.assertIn("Reflection", result['method'])

if __name__ == '__main__':
    unittest.main()
