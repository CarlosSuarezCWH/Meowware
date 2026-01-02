import subprocess
import shutil
import json
from typing import Dict, Any, List
from .base import BaseTool
from ..core.exceptions import ToolError
from ..core.debug import debug_print
import requests

class WhatWebTool(BaseTool):
    @property
    def name(self) -> str:
        return "whatweb"

    def run(self, target: str) -> Dict[str, Any]:
        """
        Runs whatweb to detect technologies.
        Returns a dict with 'tech_stack' (list) and 'waf_detected' (bool).
        """
        # Check if installed
        if not shutil.which("whatweb"):
             # Fallback or error? For now, return empty info to not block pipeline.
             return {"tech_stack": [], "tech_versions": {}, "waf_detected": False, "waf_name": "", "cms": ""}

        # Command: whatweb --log-json - <target> --quiet
        cmd = ["whatweb", "--log-json", "-", "--quiet", target]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False) # Check=False because it might fail on some
            output_json = json.loads(result.stdout)
            
            # WhatWeb returns a list of targets, we scan one, so take first
            if not output_json:
                return {"tech_stack": [], "waf_detected": False}
                
            data = output_json[0]
            plugins = data.get('plugins', {})
            http_headers = data.get('http_headers', {}) # Some versions use this
            
            tech_stack = []
            waf_detected = False
            waf_name = ""
            waf_type = "PASSIVE"
            cms = ""

            # Extract versions and technologies
            tech_versions = {}
            
            for name, info in plugins.items():
                tech_stack.append(name)
                
                # v16.2: Enhanced version extraction - multiple methods
                if isinstance(info, dict):
                    # Try multiple version fields
                    version = (info.get('version', '') or 
                              info.get('string', '') or 
                              info.get('version_string', '') or
                              info.get('version[0]', ''))
                    
                    # Also check nested structures
                    if not version and isinstance(info.get('version'), list):
                        version = info.get('version')[0] if info.get('version') else ''
                    
                    # Clean version string (remove common prefixes/suffixes)
                    if version:
                        version = str(version).strip()
                        # Remove common prefixes
                        for prefix in ['v', 'version', 'Version', 'VERSION']:
                            if version.startswith(prefix):
                                version = version[len(prefix):].strip()
                        # Remove trailing dots, spaces
                        version = version.rstrip('. ')
                        
                        if version:
                            tech_versions[name] = version
                            debug_print(f"    [Version] {name}: {version}")
                
                # v13.0: Active vs Passive WAF classification
                # The original WAF detection logic is replaced by the enhanced detection below.
                # However, we still need to detect CMS within this loop.
                if name in ["WordPress", "Joomla", "Drupal", "Magento"]:
                    cms = name

            # v13.0: Enhanced WAF Detection
            waf_detected = False
            waf_name = "Unknown"
            waf_type = "PASSIVE"
            
            # Check for specific WAF providers
            waf_providers = {
                "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cf-cache-status"],
                "Akamai": ["akamai", "akamai-ghost"],
                "Sucuri": ["sucuri", "x-sucuri-id"],
                "Incapsula": ["incapsula", "visid_incap"],
                "F5 BIG-IP": ["f5-traffic-shield", "ts_cookie"],
                "AWS WAF": ["aws-waf", "x-amzn-requestid"]
            }
            
            for provider, markers in waf_providers.items():
                if any(marker in str(result.stdout).lower() or marker in str(http_headers).lower() for marker in markers) or provider in tech_stack:
                    waf_detected = True
                    waf_name = provider
                    waf_type = "ACTIVE"
                    break
            
            # Fallback to generic WAF header detection
            if not waf_detected and (any(h in str(http_headers).lower() for h in ["x-waf-event", "x-denied-reason", "x-firewall-id"]) or "WAF" in tech_stack):
                waf_detected = True
                waf_type = "PASSIVE"
                waf_name = "Generic WAF"

            # Passive fallback: attempt lightweight fetch to spot WordPress markers when WhatWeb is blinded by WAF/CDN
            if not cms:
                try:
                    resp = requests.get(target, timeout=8, verify=False)
                    body_l = resp.text.lower()
                    hdr_l = {k.lower(): v.lower() for k, v in resp.headers.items()}
                    wp_cookie = any("wordpress" in v for v in hdr_l.values())
                    if "wp-content" in body_l or "wp-json" in body_l or wp_cookie:
                        cms = "WordPress"
                        tech_stack.append("WordPress")
                except Exception:
                    pass

            # Extract web server version from headers if not in plugins
            if not tech_versions.get("Apache") and not tech_versions.get("Nginx") and not tech_versions.get("IIS"):
                server_header = http_headers.get('Server', '') or http_headers.get('server', '')
                if server_header:
                    # Parse Server header: "Apache/2.4.49" or "nginx/1.21.0"
                    import re
                    server_match = re.match(r'([^/]+)/([\d.]+)', server_header, re.IGNORECASE)
                    if server_match:
                        server_name = server_match.group(1).strip()
                        server_version = server_match.group(2).strip()
                        tech_versions[server_name] = server_version
                        if server_name not in [t for t in tech_stack]:
                            tech_stack.append(server_name)
            
            return {
                "tech_stack": tech_stack,
                "tech_versions": tech_versions,
                "waf_detected": waf_detected,
                "waf_name": waf_name,
                "waf_type": waf_type,
                "cms": cms,
                "headers": http_headers
            }
            
        except (subprocess.CalledProcessError, json.JSONDecodeError):
             # Fail gracefully
             return {"tech_stack": [], "tech_versions": {}, "waf_detected": False}

class SecurityHeaderTool(BaseTool):
    @property
    def name(self) -> str:
        return "security_headers"

    def run(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        debug_print(f"  [Web Security] Auditing headers for {url}...")
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            checks = {
                "Strict-Transport-Security": ("MEDIUM", "HSTS Missing: Domain doesn't enforce HTTPS strictly."),
                "Content-Security-Policy": ("LOW", "CSP Missing: Increased risk of XSS and data injection."),
                "X-Frame-Options": ("LOW", "Anti-Clickjacking Missing: Site can be embedded in malicious iframes."),
                "X-Content-Type-Options": ("INFO", "MIME Sniffing Prevention Missing.")
            }
            
            for header, (sev, desc) in checks.items():
                if header not in headers:
                    findings.append({
                        "issue": f"{sev}: {header} Missing",
                        "severity": sev,
                        "description": desc,
                        "recommendation": f"Implement {header} header."
                    })
                    
            # Cookie Checks
            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure or not (hasattr(cookie, 'has_nonstandard_attr') and cookie.has_nonstandard_attr('HttpOnly')):
                    findings.append({
                        "issue": f"MEDIUM: Insecure Cookie ({cookie.name})",
                        "severity": "MEDIUM",
                        "description": f"Cookie '{cookie.name}' lacks Secure or HttpOnly flags.",
                        "recommendation": "Set Secure and HttpOnly flags on all sensitive cookies."
                    })
        except: pass
        return findings

class BehavioralProbe(BaseTool):
    @property
    def name(self) -> str:
        return "behavioral_fingerprint"

    def run(self, url: str) -> Dict[str, Any]:
        """
        Analyzes server behavior for advanced fingerprinting.
        timing, error patterns, method support.
        """
        debug_print(f"  [Behavioral Audit] Analyzing {url}...")
        results = {"timing": {}, "error_style": "unknown"}
        try:
            import time
            import uuid
            # Test timing for invalid method
            start = time.time()
            try: requests.options(url, timeout=5, verify=False)
            except: pass
            results["timing"]["options"] = round(time.time() - start, 3)
            
            # Test error page
            invalid_url = f"{url}/meow_{uuid.uuid4().hex}"
            try:
                resp = requests.get(invalid_url, timeout=5, verify=False)
                if "Apache" in resp.text: results["error_style"] = "Apache Standard"
                elif "nginx" in resp.text: results["error_style"] = "Nginx Standard"
                elif resp.status_code == 404: results["error_style"] = "Custom/Clean 404"
            except: pass
            
        except Exception as e:
            debug_print(f"  Behavioral probe failed: {e}")
        return results
