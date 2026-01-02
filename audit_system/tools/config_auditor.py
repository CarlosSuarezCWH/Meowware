"""
Security Configuration Auditor
v16.2: Comprehensive security configuration testing

Meowware - Developed by Carlos Mancera
"""
import requests
import ssl
import socket
from typing import Dict, Any, List
from datetime import datetime
from .base import BaseTool
from ..core.debug import debug_print
from ..core.models import Finding, Severity
from ..core.http_pool import get_http_pool

class ConfigAuditor(BaseTool):
    """Audits security configurations: headers, TLS, certificates"""
    
    @property
    def name(self) -> str:
        return "config_auditor"
    
    def run(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Comprehensive security configuration audit
        
        Args:
            target_url: URL to audit
        
        Returns:
            List of configuration findings
        """
        findings = []
        http_pool = get_http_pool()
        
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"https://{target_url}"
        
        debug_print(f"  [Config Auditor] Auditing security configuration for {target_url}...")
        
        try:
            response = http_pool.get(target_url, timeout=10, verify=False)
            headers = response.headers
            
            # 1. Security Headers Audit
            findings.extend(self._audit_security_headers(headers, target_url))
            
            # 2. TLS/SSL Configuration
            if target_url.startswith('https://'):
                findings.extend(self._audit_tls_config(target_url))
            
            # 3. Certificate Validation
            if target_url.startswith('https://'):
                findings.extend(self._audit_certificate(target_url))
            
            # 4. HTTP/2 and HTTP/3
            findings.extend(self._audit_http_versions(response, target_url))
            
        except Exception as e:
            debug_print(f"    ⚠️ Config audit failed: {e}")
        
        return findings
    
    def _audit_security_headers(self, headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        """Audit security headers"""
        findings = []
        
        # Required security headers
        required_headers = {
            'Strict-Transport-Security': {
                'name': 'HSTS',
                'severity': Severity.MEDIUM,
                'description': 'Strict-Transport-Security header missing. Allows downgrade attacks.',
                'recommendation': 'Implement HSTS with max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'name': 'CSP',
                'severity': Severity.LOW,
                'description': 'Content-Security-Policy missing. Increased risk of XSS attacks.',
                'recommendation': 'Implement CSP to restrict resource loading and prevent XSS'
            },
            'X-Frame-Options': {
                'name': 'X-Frame-Options',
                'severity': Severity.LOW,
                'description': 'X-Frame-Options missing. Site can be embedded in malicious iframes (clickjacking).',
                'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'name': 'X-Content-Type-Options',
                'severity': Severity.INFO,
                'description': 'X-Content-Type-Options missing. MIME type sniffing not prevented.',
                'recommendation': 'Set X-Content-Type-Options: nosniff'
            },
            'Referrer-Policy': {
                'name': 'Referrer-Policy',
                'severity': Severity.INFO,
                'description': 'Referrer-Policy missing. May leak sensitive URLs in referrer headers.',
                'recommendation': 'Set Referrer-Policy to strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'name': 'Permissions-Policy',
                'severity': Severity.INFO,
                'description': 'Permissions-Policy missing. Browser features may be accessible without restriction.',
                'recommendation': 'Implement Permissions-Policy to restrict browser features'
            }
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header_name, config in required_headers.items():
            header_key = header_name.lower()
            if header_key not in headers_lower:
                findings.append({
                    "issue": f"{config['name']} Missing ({url})",
                    "severity": config['severity'],
                    "description": config['description'],
                    "recommendation": config['recommendation'],
                    "evidence": f"Header {header_name} not present in response"
                })
            else:
                # Validate header value
                value = headers_lower[header_key]
                if header_key == 'strict-transport-security':
                    if 'max-age' not in value.lower():
                        findings.append({
                            "issue": f"HSTS Misconfigured ({url})",
                            "severity": Severity.MEDIUM,
                            "description": f"HSTS header present but misconfigured: {value}",
                            "recommendation": "Set HSTS with max-age=31536000; includeSubDomains",
                            "evidence": f"HSTS header value: {value}"
                        })
        
        return findings
    
    def _audit_tls_config(self, url: str) -> List[Dict[str, Any]]:
        """Audit TLS/SSL configuration"""
        findings = []
        
        try:
            hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
            port = 443
            
            # Get TLS version and cipher info
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check TLS version
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        findings.append({
                            "issue": f"Weak TLS Version: {protocol} ({hostname})",
                            "severity": Severity.HIGH,
                            "description": f"Server uses deprecated TLS version {protocol}. Vulnerable to attacks.",
                            "recommendation": "Upgrade to TLS 1.2 or higher (preferably TLS 1.3)",
                            "evidence": f"TLS version detected: {protocol}"
                        })
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.lower() for weak in ['rc4', 'md5', 'sha1', 'des', '3des']):
                            findings.append({
                                "issue": f"Weak Cipher Suite: {cipher_name} ({hostname})",
                                "severity": Severity.MEDIUM,
                                "description": f"Server uses weak cipher suite {cipher_name}.",
                                "recommendation": "Disable weak ciphers. Use only strong cipher suites (AES-GCM, ChaCha20-Poly1305)",
                                "evidence": f"Cipher suite: {cipher_name}"
                            })
        except Exception as e:
            debug_print(f"    ⚠️ TLS audit failed: {e}")
        
        return findings
    
    def _audit_certificate(self, url: str) -> List[Dict[str, Any]]:
        """Audit SSL certificate"""
        findings = []
        
        try:
            hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
            port = 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        findings.append({
                            "issue": f"Certificate Expiring Soon ({hostname})",
                            "severity": Severity.MEDIUM if days_until_expiry < 7 else Severity.LOW,
                            "description": f"SSL certificate expires in {days_until_expiry} days.",
                            "recommendation": "Renew certificate before expiration to avoid service disruption",
                            "evidence": f"Certificate expires: {cert['notAfter']}"
                        })
                    
                    # Check certificate chain
                    issuer = cert.get('issuer', [])
                    subject = cert.get('subject', [])
                    
                    # Check for self-signed certificates
                    if len(issuer) > 0 and len(subject) > 0:
                        issuer_cn = [x[0][1] for x in issuer if x[0][0] == 'commonName']
                        subject_cn = [x[0][1] for x in subject if x[0][0] == 'commonName']
                        
                        if issuer_cn and subject_cn and issuer_cn[0] == subject_cn[0]:
                            findings.append({
                                "issue": f"Self-Signed Certificate ({hostname})",
                                "severity": Severity.HIGH,
                                "description": "Server uses self-signed certificate. Cannot be verified by browsers.",
                                "recommendation": "Use certificate from trusted Certificate Authority (Let's Encrypt, etc.)",
                                "evidence": f"Self-signed certificate detected"
                            })
        except Exception as e:
            debug_print(f"    ⚠️ Certificate audit failed: {e}")
        
        return findings
    
    def _audit_http_versions(self, response, url: str) -> List[Dict[str, Any]]:
        """Audit HTTP version support"""
        findings = []
        
        # Check HTTP version from response
        http_version = getattr(response.raw, 'version', None) if hasattr(response, 'raw') else None
        
        # Try to detect HTTP/2 or HTTP/3
        # Note: This is simplified - full detection requires more complex checks
        if http_version == 11:  # HTTP/1.1
            findings.append({
                "issue": f"HTTP/2 Not Supported ({url})",
                "severity": Severity.INFO,
                "description": "Server only supports HTTP/1.1. HTTP/2 provides better performance and security.",
                "recommendation": "Enable HTTP/2 support for improved performance and security",
                "evidence": "HTTP/1.1 detected"
            })
        
        return findings



