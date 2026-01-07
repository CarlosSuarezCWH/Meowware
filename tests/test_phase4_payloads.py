
import unittest
from audit_system.exploitation.payload_generator import PayloadGenerator

class TestPhase4Payloads(unittest.TestCase):
    
    def test_lfi_payloads(self):
        linux_payload = PayloadGenerator.generate_lfi_payload("linux")
        self.assertIn("etc/passwd", linux_payload)
        
        win_payload = PayloadGenerator.generate_lfi_payload("windows")
        self.assertIn("win.ini", win_payload)
        
        php_payload = PayloadGenerator.generate_lfi_payload("linux", "base64_wrapper")
        self.assertIn("php://filter", php_payload)

    def test_rce_payloads(self):
        bash_payload = PayloadGenerator.generate_rce_payload("linux", "10.10.10.10", 9001, "bash")
        self.assertIn("bash", bash_payload)
        self.assertIn("base64", bash_payload) # It should be encoded
        
        nc_payload = PayloadGenerator.generate_rce_payload("linux", "10.0.0.1", 4444, "netcat")
        self.assertIn("nc -e", nc_payload)

    def test_reproduction_steps(self):
        steps = PayloadGenerator.generate_repr_steps("Critical LFI", "../../../etc/passwd", "http://target.com")
        self.assertIn("**Target**: `http://target.com`", steps)
        self.assertIn("passwd", steps)

if __name__ == '__main__':
    unittest.main()
