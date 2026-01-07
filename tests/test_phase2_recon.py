
import unittest
from unittest.mock import MagicMock, patch
from audit_system.core.models import Host, Finding, Severity, WebContext
from audit_system.intelligence.cloud_recon import CloudRecon
from audit_system.intelligence.js_analyzer import JSAnalyzer

class TestPhase2Recon(unittest.TestCase):
    
    def setUp(self):
        self.host = Host(ip="1.2.3.4", hostname="target.com")
        
    def test_cloud_bucket_permutations(self):
        """Test that CloudRecon generates correct bucket URLs"""
        recon = CloudRecon()
        # Mocking requests.head to avoid real network calls
        with patch('requests.head') as mock_head:
            mock_head.return_value.status_code = 404 # Default
            
            # Simulate one bucket existing
            def side_effect(url, timeout=2):
                mock = MagicMock()
                if "target-dev.s3.amazonaws.com" in url:
                    mock.status_code = 200
                else:
                    mock.status_code = 404
                return mock
                
            mock_head.side_effect = side_effect
            
            findings = recon.check_cloud_exposure(self.host)
            
            self.assertTrue(len(findings) > 0)
            self.assertIn("target-dev.s3.amazonaws.com", findings[0].description)
            self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_js_secret_extraction(self):
        """Test JSAnalyzer secret detection"""
        analyzer = JSAnalyzer()
        js_content = """
        const apiKey = "AKIAABCDEFGHIJKLMNOP"; // Fake AWS Key (20 chars)
        const mapKey = "AIzaSyD-FakeGoogleKey123456789012345678"; // 39 chars total (AIza + 35)
        """
        
        findings = analyzer.analyze_js(js_content, "http://target.com/app.js")
        
        # Should find AWS and Google keys
        self.assertTrue(len(findings) >= 2)
        titles = [f.title for f in findings]
        self.assertTrue(any("AWS Key" in t for t in titles))
        self.assertTrue(any("Google API Key" in t for t in titles))

    def test_js_endpoint_extraction(self):
        """Test that endpoints are extracted correctly"""
        analyzer = JSAnalyzer()
        js_content = """
        fetch('/api/v1/users');
        axios.post('/api/private/admin/delete');
        """
        
        # We only really report sensitive endpoints like 'admin' in findings
        findings = analyzer.analyze_js(js_content, "http://target.com/main.js")
        
        self.assertTrue(len(findings) > 0)
        self.assertIn("/api/private/admin/delete", findings[0].description)

if __name__ == '__main__':
    unittest.main()
