"""
Advanced Security Tools
Nikto, TestSSL, SQLMap Detection, etc.
"""
import subprocess
import shutil
import json
import re
from typing import Dict, Any, List
from .base import BaseTool
from ..core.models import Severity


class NiktoTool(BaseTool):
    """Nikto web vulnerability scanner"""
    @property
    def name(self) -> str:
        return "nikto"
    
    def run(self, target: str, port: int = 80) -> List[Dict[str, Any]]:
        """Run Nikto against target"""
        if not shutil.which("nikto"):
            return []
        
        findings = []
        try:
            cmd = ["nikto", "-h", target, "-port", str(port), "-Format", "json", "-Tuning", "x", "-timeout", "30"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=180)
            
            # Nikto JSON can be messy, parse line by line
            for line in result.stdout.split('\n'):
                if '"msg":' in line or '"description":' in line:
                    # Extract severity indicators
                    severity = Severity.LOW
                    if any(word in line.lower() for word in ['critical', 'vulnerable', 'exploit']):
                        severity = Severity.HIGH
                    elif any(word in line.lower() for word in ['warning', 'outdated', 'exposed']):
                        severity = Severity.MEDIUM
                    
                    findings.append({
                        "type": "web_vuln",
                        "issue": "Nikto Finding",
                        "message": line.strip(),
                        "severity": severity,
                        "description": "Web vulnerability or misconfiguration detected by Nikto.",
                        "recommendation": "Review and remediate identified issues."
                    })
        
        except subprocess.TimeoutExpired:
            findings.append({
                "type": "info",
                "message": "Nikto scan timeout",
                "severity": Severity.INFO
            })
        except Exception:
            pass
        
        return findings[:10]  # Limit to top 10 findings


class TestSSLTool(BaseTool):
    """TestSSL.sh for SSL/TLS analysis"""
    @property
    def name(self) -> str:
        return "testssl.sh"
    
    def run(self, target: str, port: int = 443) -> List[Dict[str, Any]]:
        """Analyze SSL/TLS configuration"""
        testssl_path = shutil.which("testssl") or shutil.which("testssl.sh")
        if not testssl_path:
            return []
        
        findings = []
        try:
            cmd = [testssl_path, "--jsonfile", "-", "--quiet", f"{target}:{port}"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
            
            # Parse JSON output
            try:
                data = json.loads(result.stdout)
                for item in data:
                    severity_map = {
                        "CRITICAL": Severity.CRITICAL,
                        "HIGH": Severity.HIGH,
                        "MEDIUM": Severity.MEDIUM,
                        "LOW": Severity.LOW,
                        "OK": Severity.INFO
                    }
                    
                    finding_sev = item.get('severity', 'INFO').upper()
                    if finding_sev in ['CRITICAL', 'HIGH', 'MEDIUM']:
                        findings.append({
                            "type": "tls_vuln",
                            "issue": item.get('id', 'TLS Issue'),
                            "message": item.get('finding', 'SSL/TLS issue detected'),
                            "severity": severity_map.get(finding_sev, Severity.INFO),
                            "description": item.get('cve', 'TLS configuration issue'),
                            "recommendation": "Update TLS configuration and disable weak ciphers."
                        })
            except json.JSONDecodeError:
                # Fallback to text parsing
                if "vulnerable" in result.stdout.lower() or "weak" in result.stdout.lower():
                    findings.append({
                        "type": "tls_vuln",
                        "issue": "TLS Weaknesses Detected",
                        "message": "Weak TLS configuration",
                        "severity": Severity.MEDIUM,
                        "description": "SSL/TLS vulnerabilities or weak ciphers detected.",
                        "recommendation": "Strengthen TLS configuration."
                    })
        
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        
        return findings


class SQLMapDetector(BaseTool):
    """SQLMap for SQL injection detection (passive mode only)"""
    @property
    def name(self) -> str:
        return "sqlmap"
    
    def run(self, target: str, aggressive: bool = False) -> List[Dict[str, Any]]:
        """
        Detect SQL injection vulnerabilities
        NOTE: Only runs in detection mode, never exploitation
        """
        if not shutil.which("sqlmap") or aggressive:  # Never run in aggressive mode
            return []
        
        findings = []
        try:
            # Ultra-safe parameters: only detection, no exploitation
            cmd = [
                "sqlmap", "-u", target,
                "--batch",  # Non-interactive
                "--level=1", "--risk=1",  # Minimal risk
                "--smart",  # Smart detection
                "--test-filter=basic",  # Basic tests only
                "--technique=B",  # Boolean-based blind only (safest)
                "--threads=1",
                "--timeout=10",
                "--retries=1"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
            
            if "is vulnerable" in result.stdout.lower() or "injectable" in result.stdout.lower():
                # v17.6: Only mark as CRITICAL if sqlmap confirms with evidence
                # Check for evidence in output
                has_evidence = any(marker in result.stdout.lower() for marker in [
                    'parameter', 'payload', 'injectable', 'vulnerable parameter',
                    'time-based', 'boolean-based', 'error-based'
                ])
                
                if has_evidence:
                    # Confirmed SQLi with evidence
                    findings.append({
                        "type": "sql_injection",
                        "issue": "SQL Injection (CONFIRMED)",
                        "message": "SQL injection vulnerability confirmed by sqlmap",
                        "severity": Severity.CRITICAL,
                        "description": f"SQL injection vulnerability confirmed. {result.stdout[:300]}",
                        "recommendation": "Implement parameterized queries and input validation immediately."
                    })
                else:
                    # Potential but not confirmed
                    findings.append({
                        "type": "sql_injection",
                        "issue": "Potential SQL Injection",
                        "message": "SQL injection indicators detected - manual verification required",
                        "severity": Severity.HIGH,  # Not CRITICAL without evidence
                        "description": "Potential SQL injection vulnerability detected. Manual verification and controlled testing required to confirm.",
                        "recommendation": "Perform manual SQL injection testing with controlled payloads to confirm vulnerability."
                    })
        
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        
        return findings


class GitDumperTool(BaseTool):
    """Detect exposed .git directories"""
    @property
    def name(self) -> str:
        return "git-dumper"
    
    def run(self, target: str) -> List[Dict[str, Any]]:
        """Check for exposed .git directory"""
        findings = []
        
        try:
            import requests
            git_url = f"{target}/.git/HEAD"
            resp = requests.get(git_url, timeout=5, verify=False, allow_redirects=False)
            
            if resp.status_code == 200 and "ref:" in resp.text:
                findings.append({
                    "type": "exposure",
                    "issue": "Exposed .git Directory",
                    "message": "Git repository exposed",
                    "severity": Severity.CRITICAL,
                    "description": "The .git directory is publicly accessible, potentially exposing source code and secrets.",
                    "recommendation": "Remove or block access to .git directory immediately."
                })
        except Exception:
            pass
        
        return findings


class SubdomainTakeoverTool(BaseTool):
    """Detect potential subdomain takeover"""
    @property
    def name(self) -> str:
        return "subjack"
    
    def run(self, domain: str, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Check for subdomain takeover vulnerabilities"""
        if not shutil.which("subjack"):
            return []
        
        findings = []
        
        # Create temporary subdomain list
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
            temp_file = f.name
        
        try:
            cmd = ["subjack", "-w", temp_file, "-t", "20", "-timeout", "10", "-o", "-", "-ssl"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
            
            if result.stdout and "takeover" in result.stdout.lower():
                findings.append({
                    "type": "takeover",
                    "issue": "Subdomain Takeover Possible",
                    "message": "Potential subdomain takeover detected",
                    "severity": Severity.HIGH,
                    "description": "One or more subdomains may be vulnerable to takeover.",
                    "recommendation": "Review DNS records and remove dangling CNAME entries."
                })
        
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        finally:
            import os
            try:
                os.unlink(temp_file)
            except:
                pass
        
        return findings


class CORSTesterTool(BaseTool):
    """Test CORS misconfigurations"""
    @property
    def name(self) -> str:
        return "cors-tester"
    
    def run(self, target: str) -> List[Dict[str, Any]]:
        """Test for CORS misconfigurations"""
        findings = []
        
        try:
            import requests
            
            # Test with malicious origin
            headers = {"Origin": "https://evil.com"}
            resp = requests.get(target, headers=headers, timeout=10, verify=False)
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            # Critical: Reflects any origin + credentials
            if acao == "https://evil.com" and acac.lower() == "true":
                findings.append({
                    "type": "cors_vuln",
                    "issue": "Critical CORS Misconfiguration",
                    "message": "CORS allows arbitrary origins with credentials",
                    "severity": Severity.CRITICAL,
                    "description": "The application reflects arbitrary origins and allows credentials.",
                    "recommendation": "Restrict CORS to trusted origins only."
                })
            
            # High: Wildcard with credentials
            elif acao == "*" and acac.lower() == "true":
                findings.append({
                    "type": "cors_vuln",
                    "issue": "CORS Wildcard with Credentials",
                    "message": "Dangerous CORS configuration",
                    "severity": Severity.HIGH,
                    "description": "CORS allows wildcard origin with credentials enabled.",
                    "recommendation": "Remove wildcard or disable credentials."
                })
            
            # Medium: Overly permissive
            elif acao == "*":
                findings.append({
                    "type": "cors_config",
                    "issue": "Permissive CORS Policy",
                    "message": "CORS allows all origins",
                    "severity": Severity.MEDIUM,
                    "description": "CORS policy allows requests from any origin.",
                    "recommendation": "Restrict CORS to necessary origins."
                })
        
        except Exception:
            pass
        
        return findings


class SecurityHeaderAnalyzer(BaseTool):
    """Advanced security header analysis"""
    @property
    def name(self) -> str:
        return "security-headers"
    
    def run(self, target: str) -> List[Dict[str, Any]]:
        """Analyze security headers comprehensively"""
        findings = []
        
        try:
            import requests
            resp = requests.get(target, timeout=10, verify=False, allow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            # Critical Security Headers
            critical_headers = {
                "strict-transport-security": {
                    "name": "HSTS",
                    "severity": Severity.HIGH,
                    "recommendation": "Add Strict-Transport-Security header with max-age >= 31536000"
                },
                "content-security-policy": {
                    "name": "CSP",
                    "severity": Severity.MEDIUM,
                    "recommendation": "Implement Content-Security-Policy to prevent XSS"
                },
                "x-frame-options": {
                    "name": "Clickjacking Protection",
                    "severity": Severity.MEDIUM,
                    "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN"
                },
                "x-content-type-options": {
                    "name": "MIME Sniffing Protection",
                    "severity": Severity.LOW,
                    "recommendation": "Add X-Content-Type-Options: nosniff"
                }
            }
            
            for header, config in critical_headers.items():
                if header not in headers:
                    findings.append({
                        "type": "missing_header",
                        "issue": f"Missing {config['name']} Header",
                        "message": f"{config['name']} header not set",
                        "severity": config["severity"],
                        "description": f"Security header {header} is missing.",
                        "recommendation": config["recommendation"]
                    })
            
            # Check for information disclosure
            if "server" in headers:
                server_value = headers["server"]
                if any(ver in server_value.lower() for ver in ["apache/2.", "nginx/1.", "microsoft-iis/"]):
                    findings.append({
                        "type": "info_disclosure",
                        "issue": "Server Version Disclosure",
                        "message": f"Server header reveals version: {server_value}",
                        "severity": Severity.LOW,
                        "description": "Server version information is exposed.",
                        "recommendation": "Remove or obfuscate server version."
                    })
            
            if "x-powered-by" in headers:
                findings.append({
                    "type": "info_disclosure",
                    "issue": "Technology Disclosure",
                    "message": f"X-Powered-By: {headers['x-powered-by']}",
                    "severity": Severity.LOW,
                    "description": "Technology stack is disclosed via headers.",
                    "recommendation": "Remove X-Powered-By header."
                })
        
        except Exception:
            pass
        
        return findings
