import subprocess
import shutil
from typing import Dict, Any, List
from .base import BaseTool

class SSLScanTool(BaseTool):
    @property
    def name(self) -> str:
        return "sslscan"

    def run(self, target: str) -> Dict[str, Any]:
        """
        Runs sslscan to check for weak ciphers/protocols.
        Returns dict with "weak_protocols", "weak_ciphers", "heartbleed".
        """
        if not shutil.which("sslscan"):
            return {}

        # sslscan --no-colour --xml=- <target>
        # We'll use text output parsing for simplicity in MVP or XML if robust.
        # Let's simple grep for keywords for MVP speed.
        
        cmd = ["sslscan", "--no-colour", target]
        findings = {
            "protocols": [],
            "weak_ciphers": [],
            "issues": []
        }

        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            output = res.stdout

            # Heuristic Parsing
            for line in output.splitlines():
                if "SSLv2" in line and "enabled" in line:
                    findings["protocols"].append("SSLv2")
                if "SSLv3" in line and "enabled" in line:
                    findings["protocols"].append("SSLv3")
                if "TLSv1.0" in line and "enabled" in line:
                    findings["protocols"].append("TLSv1.0")
                
                if "Heartbleed" in line and "vulnerable" in line:
                    findings["issues"].append("Heartbleed Vulnerability")

                if "RC4" in line:
                    findings["weak_ciphers"].append("RC4")
                if "DES" in line:
                    findings["weak_ciphers"].append("DES")

        except Exception:
            pass
            
        return findings
