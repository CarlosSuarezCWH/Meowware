
import unittest
from unittest.mock import MagicMock, patch
from audit_system.exploitation.exploit_engine import ExploitEngine
from audit_system.exploitation.payload_generator import PayloadGenerator
from audit_system.core.models import Finding, Host, Severity, EvidenceType

class TestPhase4Integration(unittest.TestCase):
    
    @patch('audit_system.exploitation.safe_verifier.SafeExploitVerifier.verify')
    def test_rce_payload_generation(self, mock_verify):
        # Setup: Mock safe verifier to return True (Confirmed)
        mock_verify.return_value = (True, "Command output: uid=0(root)")
        
        # Setup: Engine and Host
        host = Host(ip="10.10.10.5", os_guess="linux")
        engine = ExploitEngine(MagicMock())
        
        # Scenario: RCE Finding
        finding = Finding(
            title="Remote Code Execution (RCE)", 
            description="Vulnerable parameter id", 
            severity=Severity.CRITICAL,
            category="RCE",
            recommendation="Patch it"
        )
        
        # Act
        verified = engine.verify_finding_safely(finding, host)
        
        # Assert
        self.assertTrue(verified)
        self.assertIn("CONFIRMED", finding.status)
        self.assertIn("[PoC Payload]", finding.raw_output)
        self.assertIn("bash", finding.raw_output) # Default RCE payload type

    @patch('audit_system.exploitation.safe_verifier.SafeExploitVerifier.verify')
    def test_lfi_payload_generation(self, mock_verify):
        mock_verify.return_value = (True, "root:x:0:0")
        
        host = Host(ip="10.10.10.6", os_guess="linux")
        engine = ExploitEngine(MagicMock())
        
        finding = Finding(
            title="LFI Vulnerability",
            description="File include",
            severity=Severity.HIGH,
            category="LFI",
            recommendation="Fix"
        )
        
        verified = engine.verify_finding_safely(finding, host)
        
        self.assertTrue(verified)
        self.assertIn("passwd", finding.raw_output)

if __name__ == '__main__':
    unittest.main()
