"""
WAF Bypass and Advanced Evasion
WAF bypass (encoding, obfuscation), IDS/IPS evasion, antivirus evasion, rate limiting bypass

Meowware v17.0 - Developed by Carlos Mancera
"""
import urllib.parse
import base64
import random
import string
from typing import List, Dict, Any, Optional
from ..core.debug import debug_print

class WAFBypass:
    """
    Advanced WAF bypass and evasion techniques.
    """
    
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        self.current_user_agent_index = 0
    
    def bypass_waf(self, payload: str, technique: str = "auto") -> List[Dict[str, Any]]:
        """
        Generate WAF bypass payloads using multiple techniques.
        Returns list of modified payloads with technique names.
        """
        bypass_payloads = []
        
        if technique == "auto" or technique == "all":
            techniques = [
                "url_encoding",
                "double_url_encoding",
                "unicode_encoding",
                "case_variation",
                "comment_injection",
                "parameter_pollution",
                "http_method_override",
                "header_injection",
                "base64_encoding",
                "hex_encoding",
                "mixed_encoding"
            ]
        else:
            techniques = [technique]
        
        for tech in techniques:
            modified = self._apply_technique(payload, tech)
            if modified:
                bypass_payloads.append({
                    "technique": tech,
                    "payload": modified,
                    "original": payload
                })
        
        return bypass_payloads
    
    def _apply_technique(self, payload: str, technique: str) -> Optional[str]:
        """Apply specific bypass technique"""
        techniques = {
            "url_encoding": self._url_encode,
            "double_url_encoding": self._double_url_encode,
            "unicode_encoding": self._unicode_encode,
            "case_variation": self._case_variation,
            "comment_injection": self._comment_injection,
            "parameter_pollution": self._parameter_pollution,
            "http_method_override": lambda p: p,  # Handled at request level
            "header_injection": lambda p: p,  # Handled at request level
            "base64_encoding": self._base64_encode,
            "hex_encoding": self._hex_encode,
            "mixed_encoding": self._mixed_encode
        }
        
        func = techniques.get(technique)
        return func(payload) if func else None
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload)
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join([f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload])
    
    def _case_variation(self, payload: str) -> str:
        """Random case variation"""
        return ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
    
    def _comment_injection(self, payload: str) -> str:
        """Inject comments to break WAF patterns"""
        # SQL comment injection
        if any(keyword in payload.lower() for keyword in ['select', 'union', 'insert', 'delete']):
            return payload.replace(' ', '/**/').replace('SELECT', 'SEL/**/ECT')
        # HTML comment injection
        elif '<' in payload and '>' in payload:
            return payload.replace('<', '<!-- --><')
        return payload
    
    def _parameter_pollution(self, payload: str) -> str:
        """Parameter pollution technique"""
        # Add duplicate parameters
        if '=' in payload:
            parts = payload.split('=')
            if len(parts) == 2:
                return f"{parts[0]}=&{parts[0]}={parts[1]}"
        return payload
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        try:
            return base64.b64encode(payload.encode()).decode()
        except:
            return payload
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join([f'%{ord(c):02x}' for c in payload])
    
    def _mixed_encode(self, payload: str) -> str:
        """Mixed encoding (URL + Base64)"""
        b64 = self._base64_encode(payload)
        return self._url_encode(b64)
    
    def rotate_user_agent(self) -> str:
        """Rotate user agent"""
        ua = self.user_agents[self.current_user_agent_index]
        self.current_user_agent_index = (self.current_user_agent_index + 1) % len(self.user_agents)
        return ua
    
    def bypass_rate_limiting(self, requests_count: int = 0) -> Dict[str, Any]:
        """
        Generate rate limiting bypass strategy.
        """
        strategies = {
            "delay": min(2.0, 0.5 + (requests_count * 0.1)),  # Increasing delay
            "ip_rotation": True,  # If proxy available
            "user_agent_rotation": True,
            "cookie_rotation": True,
            "request_spacing": True
        }
        
        return strategies
    
    def evade_ids_ips(self, payload: str) -> List[Dict[str, Any]]:
        """
        Generate IDS/IPS evasion techniques.
        """
        evasion_payloads = []
        
        # 1. Fragmentación
        evasion_payloads.append({
            "technique": "fragmentation",
            "payload": self._fragment_payload(payload),
            "description": "Fragment payload across multiple packets"
        })
        
        # 2. Timing evasion
        evasion_payloads.append({
            "technique": "timing",
            "payload": payload,
            "delay": random.uniform(0.5, 2.0),
            "description": "Add delays between requests"
        })
        
        # 3. Protocol tunneling
        evasion_payloads.append({
            "technique": "protocol_tunneling",
            "payload": self._base64_encode(payload),
            "description": "Tunnel through different protocol"
        })
        
        return evasion_payloads
    
    def _fragment_payload(self, payload: str, chunk_size: int = 10) -> List[str]:
        """Fragment payload into chunks"""
        return [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    
    def evade_antivirus(self, payload: str) -> str:
        """
        Evade antivirus detection using obfuscation.
        """
        # Simple obfuscation techniques
        obfuscated = payload
        
        # String splitting
        if len(payload) > 10:
            mid = len(payload) // 2
            obfuscated = payload[:mid] + "/*" + payload[mid:] + "*/"
        
        # Variable name obfuscation (for code payloads)
        if '$' in payload or 'var ' in payload.lower():
            obfuscated = obfuscated.replace('var ', 'var _0x' + ''.join(random.choices(string.hexdigits, k=4)) + '=')
        
        return obfuscated
    
    def generate_bypass_request(self, url: str, payload: str, method: str = "GET") -> Dict[str, Any]:
        """
        Generate complete HTTP request with WAF bypass techniques.
        """
        bypass_payloads = self.bypass_waf(payload, technique="auto")
        
        if not bypass_payloads:
            return {
                "url": url,
                "method": method,
                "payload": payload,
                "headers": {
                    "User-Agent": self.rotate_user_agent()
                }
            }
        
        # Use first bypass technique
        bypass = bypass_payloads[0]
        
        request = {
            "url": url,
            "method": method,
            "payload": bypass["payload"],
            "technique": bypass["technique"],
            "headers": {
                "User-Agent": self.rotate_user_agent(),
                "X-Forwarded-For": self._generate_random_ip(),
                "X-Real-IP": self._generate_random_ip()
            }
        }
        
        # Add HTTP method override if POST
        if method.upper() == "POST":
            request["headers"]["X-HTTP-Method-Override"] = "GET"
        
        return request
    
    def _generate_random_ip(self) -> str:
        """Generate random IP for header spoofing"""
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"


