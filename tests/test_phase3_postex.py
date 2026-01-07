
import unittest
from audit_system.exploitation.post_exploit import PostExploitationEngine
from audit_system.core.models import Host, Finding, Severity, EvidenceType

class TestPhase3PostEx(unittest.TestCase):
    
    def test_post_exploit_suggestion(self):
        engine = PostExploitationEngine()
        host = Host(ip="10.0.0.5")
        
        # Scenario: RCE Found
        findings = [
            Finding(title="RCE via File Upload (10.0.0.5)", category="RCE", severity=Severity.CRITICAL, description="Shell popped", recommendation="Fix it")
        ]
        
        actions = engine.suggest_post_exploit_actions(host, findings)
        
        self.assertTrue(len(actions) > 0)
        self.assertIn("Automate Local Enumeration", actions[0].title)
        self.assertEqual(actions[0].severity, Severity.HIGH)

    def test_shell_context_analysis(self):
        engine = PostExploitationEngine()
        host = Host(ip="10.0.0.6")
        
        # Scenario: Root shell + SUID vim
        shell_output = """
        uid=0(root) gid=0(root) groups=0(root)
        /usr/bin/vim
        /usr/bin/passwd
        """
        
        findings = engine.analyze_shell_context(shell_output, host)
        
        # Should detect Root Access and SUID vim
        self.assertTrue(len(findings) >= 2)
        titles = [f.title for f in findings]
        self.assertTrue(any("Root/System Access Confirmed" in t for t in titles))
        self.assertTrue(any("SUID PrivEsc: vim" in t for t in titles))

if __name__ == '__main__':
    unittest.main()
